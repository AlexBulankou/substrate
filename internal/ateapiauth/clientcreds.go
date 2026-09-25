//  Copyright 2026 Google LLC
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package ateapiauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"sync"

	"google.golang.org/grpc/credentials"
)

// reloadingRootsCreds are TLS transport credentials that re-read their trust
// anchors for every handshake.
//
// A tls.Config's RootCAs is frozen once the config is handed to the TLS stack,
// so a pool read at startup pins the CA this client trusts for the lifetime of
// the process: after a CA rotation the dial fails and stays failing until the
// pod restarts. The server side solves this with GetConfigForClient, which has
// no client-side counterpart, so the reload has to happen one level up — in
// ClientHandshake, which runs per connection.
//
// Everything other than the pool comes from a template the caller supplies,
// and each handshake delegates to credentials.NewTLS over that template, so
// ALPN enforcement, SPIFFE ID extraction and authority handling stay exactly
// as grpc-go implements them.
type reloadingRootsCreds struct {
	// loadRoots yields the current trust anchors. credbundle.PoolLoader caches
	// on a stat triple, so the steady-state cost of a handshake is one stat.
	loadRoots func() (*x509.CertPool, error)

	// mu guards template, which OverrideServerName mutates.
	mu sync.Mutex
	// template carries every setting other than RootCAs, which is filled in
	// per handshake.
	template *tls.Config
}

var _ credentials.TransportCredentials = (*reloadingRootsCreds)(nil)

// newReloadingRootsCreds returns transport credentials that behave like
// credentials.NewTLS(template) except that RootCAs is taken from loadRoots at
// each handshake. Any RootCAs already set on template is ignored.
func newReloadingRootsCreds(template *tls.Config, loadRoots func() (*x509.CertPool, error)) *reloadingRootsCreds {
	cloned := template.Clone()
	cloned.RootCAs = nil
	return &reloadingRootsCreds{loadRoots: loadRoots, template: cloned}
}

// current builds the delegate credentials for one handshake.
func (c *reloadingRootsCreds) current() (credentials.TransportCredentials, error) {
	roots, err := c.loadRoots()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	cfg := c.template.Clone()
	c.mu.Unlock()
	cfg.RootCAs = roots
	return credentials.NewTLS(cfg), nil
}

func (c *reloadingRootsCreds) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	delegate, err := c.current()
	if err != nil {
		return nil, nil, fmt.Errorf("ateapiauth: loading trust anchors for handshake with %q: %w", authority, err)
	}
	return delegate.ClientHandshake(ctx, authority, rawConn)
}

// ServerHandshake always fails: these credentials exist to dial, and serving
// with them would silently accept whatever the delegate's zero client-auth
// setting allows.
func (c *reloadingRootsCreds) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, fmt.Errorf("ateapiauth: reloading client credentials cannot be used to serve")
}

// Info reports the delegate's protocol info. Its ServerName is load-bearing:
// grpc-go derives a channel's authority from it when it is set.
func (c *reloadingRootsCreds) Info() credentials.ProtocolInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return credentials.NewTLS(c.template).Info()
}

// Clone returns credentials with an independent template and the same loader,
// so clones share the parsed-pool cache rather than each re-reading the file.
func (c *reloadingRootsCreds) Clone() credentials.TransportCredentials {
	c.mu.Lock()
	defer c.mu.Unlock()
	return &reloadingRootsCreds{loadRoots: c.loadRoots, template: c.template.Clone()}
}

func (c *reloadingRootsCreds) OverrideServerName(serverName string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.template.ServerName = serverName
	return nil
}
