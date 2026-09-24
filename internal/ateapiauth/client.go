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

	"github.com/agent-substrate/substrate/internal/credbundle"
	"github.com/agent-substrate/substrate/internal/k8sresolver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"k8s.io/client-go/kubernetes"
)

const DefaultServiceAccountCAFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

// roundRobinServiceConfig spreads RPCs across every address the resolver
// returns.
const roundRobinServiceConfig = `{"loadBalancingConfig": [{"round_robin":{}}]}`

// ClientConfig configures how to dial the ateapi gRPC server with mutual TLS.
// The credential bundle and the CA bundle are both re-read on every handshake,
// so in-place pod-certificate and control-plane CA rotations are picked up.
type ClientConfig struct {
	// CAFile is a PEM file containing CA certs that sign the server cert.
	// Required.
	CAFile string

	// ServerName overrides SNI / hostname verification. Optional.
	ServerName string

	// ClientCredBundle is a PEM file containing the client certificate chain
	// and PKCS8 private key presented to the server. Required.
	ClientCredBundle string

	// K8sClient is an optional Kubernetes client. When provided, an EndpointSlice
	// resolver builder using this client will be attached to DialOptions.
	K8sClient kubernetes.Interface
}

// DialOptions returns the grpc.DialOption set described by cfg, suitable to
// pass to grpc.NewClient.
func DialOptions(cfg ClientConfig) ([]grpc.DialOption, error) {
	creds, err := transportCredentials(cfg)
	if err != nil {
		return nil, err
	}
	opts := []grpc.DialOption{
		grpc.WithDefaultServiceConfig(roundRobinServiceConfig),
	}
	if cfg.K8sClient != nil {
		opts = append(opts, grpc.WithResolvers(k8sresolver.NewBuilder(cfg.K8sClient)))
	}
	return append(opts, grpc.WithTransportCredentials(creds)), nil
}

// transportCredentials is the whole of the TLS half of DialOptions, split out
// so a test can exercise the credentials the daemons actually dial with rather
// than a re-creation of them.
func transportCredentials(cfg ClientConfig) (credentials.TransportCredentials, error) {
	if cfg.CAFile == "" {
		return nil, fmt.Errorf("ateapiauth: CAFile is required")
	}
	if cfg.ClientCredBundle == "" {
		return nil, fmt.Errorf("ateapiauth: a client credential bundle (mTLS) is required")
	}
	// Read once here so a missing or malformed CA file fails the caller at
	// startup rather than at its first RPC. PoolLoader caches the parse, so the
	// per-handshake reload below costs a stat until the file actually changes.
	loadRoots := credbundle.PoolLoader(cfg.CAFile)
	if _, err := loadRoots(); err != nil {
		return nil, fmt.Errorf("ateapiauth: reading CA file: %w", err)
	}
	return &rotatingRootCreds{
		base: &tls.Config{
			MinVersion:           tls.VersionTLS13,
			ServerName:           cfg.ServerName,
			GetClientCertificate: credbundle.ClientLoader(cfg.ClientCredBundle),
		},
		loadRoots: loadRoots,
	}, nil
}

// rotatingRootCreds verifies the server against a pool rebuilt on every
// handshake.
//
// It exists because tls.Config has no client-side counterpart to
// GetConfigForClient: RootCAs is read when a config goes into use and never
// consulted again, and grpc's CloneTLSConfig copies the pointer and overwrites
// only ServerName. A pool assigned once therefore outlives any number of
// reconnects, so a dialer whose certificate rotates correctly -- which is what
// GetClientCertificate above buys -- still refuses the server it is rotating
// alongside, for the life of the process.
type rotatingRootCreds struct {
	base      *tls.Config
	loadRoots func() (*x509.CertPool, error)
}

func (c *rotatingRootCreds) ClientHandshake(ctx context.Context, authority string, conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	roots, err := c.loadRoots()
	if err != nil {
		// Refusing here is deliberate. The alternative -- carrying on with the
		// last good pool -- turns an unreadable trust bundle into a silent
		// downgrade to a trust anchor nobody can see from the filesystem.
		return nil, nil, fmt.Errorf("ateapiauth: reloading CA pool: %w", err)
	}
	cfg := c.base.Clone()
	cfg.RootCAs = roots
	return credentials.NewTLS(cfg).ClientHandshake(ctx, authority, conn)
}

// ServerHandshake is never called: these credentials are only ever installed
// with grpc.WithTransportCredentials. It refuses rather than delegating, so
// mistakenly serving with them is a startup error and not a server whose peer
// verification silently does nothing.
func (c *rotatingRootCreds) ServerHandshake(net.Conn) (net.Conn, credentials.AuthInfo, error) {
	return nil, nil, fmt.Errorf("ateapiauth: rotatingRootCreds are client credentials and cannot serve")
}

func (c *rotatingRootCreds) Info() credentials.ProtocolInfo {
	return credentials.NewTLS(c.base).Info()
}

func (c *rotatingRootCreds) Clone() credentials.TransportCredentials {
	return &rotatingRootCreds{base: c.base.Clone(), loadRoots: c.loadRoots}
}

func (c *rotatingRootCreds) OverrideServerName(name string) error {
	c.base.ServerName = name
	return nil
}
