// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package testca mints throwaway certificate authorities and leaf certificates
// for tests that need to drive a real TLS handshake.
//
// Several packages grew their own near-identical copy of this (grep for
// newTestCA). New tests should use this one; the existing copies are a separate
// cleanup.
package testca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"
)

// CA is a self-signed certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
	// PEM is Cert, PEM-encoded: what a trust-bundle file holds.
	PEM []byte
}

// New returns a CA valid from an hour ago to an hour from now, so a test is
// unaffected by modest clock skew in either direction.
func New(t *testing.T, commonName string) *CA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}
	return &CA{Cert: cert, Key: key, PEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// Pool returns a trust pool holding just this CA.
func (c *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.Cert)
	return pool
}

// LeafOpts selects the SANs and extended key usages of an issued certificate.
// The zero value issues a leaf good for both client and server authentication,
// which is what a handshake test usually wants; set ExtKeyUsage to pin one
// direction.
type LeafOpts struct {
	DNSNames []string
	// IPAddresses sets IP SANs. A test server reached over loopback needs one:
	// when the name being verified is an IP literal, Go checks IP SANs and
	// ignores DNS names entirely.
	IPAddresses []net.IP
	URIs        []string
	ExtKeyUsage []x509.ExtKeyUsage
}

// Leaf is an issued certificate together with its private key.
type Leaf struct {
	DER []byte
	Key *ecdsa.PrivateKey
}

// Issue signs a leaf certificate with c.
func (c *CA) Issue(t *testing.T, opts LeafOpts) Leaf {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	var uris []*url.URL
	for _, u := range opts.URIs {
		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatalf("parsing URI SAN %q: %v", u, err)
		}
		uris = append(uris, parsed)
	}
	eku := opts.ExtKeyUsage
	if eku == nil {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}
	tmpl := &x509.Certificate{
		// Time-based rather than a counter: two leaves from the same CA in one
		// test must not collide on serial.
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
		DNSNames:     opts.DNSNames,
		IPAddresses:  opts.IPAddresses,
		URIs:         uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &key.PublicKey, c.Key)
	if err != nil {
		t.Fatalf("creating leaf certificate: %v", err)
	}
	return Leaf{DER: der, Key: key}
}

// WriteCredBundle writes leaf as a credential bundle -- certificate then PKCS8
// key, the layout credbundle.Parse expects -- and returns its path.
func WriteCredBundle(t *testing.T, leaf Leaf) string {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.Key)
	if err != nil {
		t.Fatalf("marshalling PKCS8 key: %v", err)
	}
	bundle := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.DER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...,
	)
	path := filepath.Join(t.TempDir(), "cred-bundle.pem")
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatalf("writing credential bundle: %v", err)
	}
	return path
}

// Handshake runs one TLS handshake against creds over a loopback socket,
// presenting clientCert -- or nothing at all, for the zero Leaf -- and trusting
// the server through serverRoots. It reports whether the server ended up with a
// verified client identity, and returns
// the server's error when the server rejected the peer and the client's error
// otherwise, so a caller sees the end that actually refused.
//
// Testing an optional-client-cert server needs the identified result, not just
// the error. A server advertises its ClientCAs in the CertificateRequest, and a
// Go client that holds nothing chaining to one of them sends no certificate at
// all rather than sending one that will fail: under VerifyClientCertIfGiven the
// handshake then succeeds with no client identity. Scored on the error alone
// that reads as acceptance, which is the opposite of what happened.
//
// The client offers "h2": gRPC's server credentials enforce ALPN, so a client
// that offers nothing is refused for a reason unrelated to what a test asks.
func Handshake(t *testing.T, creds credentials.TransportCredentials, serverRoots *x509.CertPool, serverName string, clientCert Leaf) (identified bool, err error) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()

	type serverResult struct {
		identified bool
		err        error
	}
	serverDone := make(chan serverResult, 1)
	go func() {
		conn, err := lis.Accept()
		if err != nil {
			serverDone <- serverResult{err: err}
			return
		}
		defer conn.Close()
		_, authInfo, err := creds.ServerHandshake(conn)
		if err != nil {
			serverDone <- serverResult{err: err}
			return
		}
		info, ok := authInfo.(credentials.TLSInfo)
		if !ok {
			t.Errorf("server AuthInfo is %T, want credentials.TLSInfo", authInfo)
		}
		serverDone <- serverResult{identified: len(info.State.PeerCertificates) > 0}
	}()

	clientCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    serverRoots,
		ServerName: serverName,
		NextProtos: []string{"h2"},
	}
	if clientCert.DER != nil {
		clientCfg.Certificates = []tls.Certificate{{Certificate: [][]byte{clientCert.DER}, PrivateKey: clientCert.Key}}
	}
	conn, clientErr := tls.Dial("tcp", lis.Addr().String(), clientCfg)
	if clientErr == nil {
		clientErr = conn.Handshake()
		conn.Close()
	}
	server := <-serverDone
	if server.err != nil {
		return false, server.err
	}
	return server.identified, clientErr
}

// ClientHandshake is the mirror of Handshake: it drives client credentials
// against a plain TLS server presenting serverCert, and returns the client's
// error. authority is passed through to creds.ClientHandshake, so it carries
// the host:port form a gRPC dialer would supply.
//
// The server offers "h2" because gRPC's credentials check the negotiated
// protocol after the handshake; a server that offers nothing fails the client
// for a reason unrelated to what a test asks.
func ClientHandshake(t *testing.T, creds credentials.TransportCredentials, serverCert Leaf, authority string) error {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()

	go func() {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		srv := tls.Server(conn, &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{{Certificate: [][]byte{serverCert.DER}, PrivateKey: serverCert.Key}},
			NextProtos:   []string{"h2"},
		})
		// The error is the client's to report: a server-side failure here is
		// always the far end of the rejection the test is about to see.
		_ = srv.Handshake()
	}()

	raw, err := net.Dial("tcp", lis.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	wrapped, _, err := creds.ClientHandshake(ctx, authority, raw)
	if wrapped != nil {
		wrapped.Close()
	}
	return err
}

// WriteBundle writes a trust-bundle file at the given mtime. Rotation tests
// have to set it explicitly: the loaders invalidate on a stat triple, and a
// rewrite of the same size within one filesystem timestamp tick is otherwise
// indistinguishable from no change at all.
func WriteBundle(t *testing.T, path string, pemBytes []byte, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatalf("setting mtime on %s: %v", path, err)
	}
}
