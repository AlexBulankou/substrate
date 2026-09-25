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

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"path/filepath"
	"testing"

	"github.com/agent-substrate/substrate/internal/testca"
	"google.golang.org/grpc/credentials"
)

// TestAteletServerTLSConfigReloadsClientCAs drives real handshakes against the
// config ateletServerTLSConfig returns, rewrites the projected trust bundle,
// and confirms a client certificate signed by the newly published CA verifies
// on a new connection without the config being rebuilt.
//
// This is the defect the per-connection reload fixes: a pool captured at
// startup keeps verifying against the retired CA, so after a pod-identity CA
// rotation ateapi — holding a freshly issued certificate — cannot reach this
// atelet at all until the process restarts.
func TestAteletServerTLSConfigReloadsClientCAs(t *testing.T) {
	servingCA := testca.New(t, "atelet-serving-ca")
	servingBundle := testca.WriteCredBundle(t, servingCA.Issue(t, testca.Opts{DNSNames: []string{"atelet.test"}}))
	servingRoots := servingCA.Pool()

	clientCA1 := testca.New(t, "pod-identity-ca-1")
	clientCA2 := testca.New(t, "pod-identity-ca-2")

	caPath := testca.WriteFile(t, "client-ca.pem", clientCA1.CertPEM)

	cfg, err := ateletServerTLSConfig(servingBundle, caPath, nil)
	if err != nil {
		t.Fatalf("ateletServerTLSConfig() error = %v", err)
	}
	creds := credentials.NewTLS(cfg)

	fromCA1 := clientCA1.Issue(t, testca.Opts{})
	fromCA2 := clientCA2.Issue(t, testca.Opts{})

	if err := mtlsHandshake(t, creds, servingRoots, "atelet.test", &fromCA1); err != nil {
		t.Fatalf("handshake with a CA1-signed client cert failed before rotation: %v", err)
	}
	if err := mtlsHandshake(t, creds, servingRoots, "atelet.test", &fromCA2); err == nil {
		t.Fatal("handshake with a CA2-signed client cert succeeded before rotation, want a chain failure")
	}

	// Publish CA2 as the projected bundle.
	testca.Republish(t, caPath, clientCA2.CertPEM)

	if err := mtlsHandshake(t, creds, servingRoots, "atelet.test", &fromCA2); err != nil {
		t.Fatalf("handshake with a CA2-signed client cert failed after rotation: %v", err)
	}
	if err := mtlsHandshake(t, creds, servingRoots, "atelet.test", &fromCA1); err == nil {
		t.Fatal("handshake with a CA1-signed client cert succeeded after rotation, want a chain failure")
	}
}

// TestAteletServerTLSConfigRequiresAClientCertificate pins the other half of
// the contract: the reload must not have relaxed client-cert verification.
func TestAteletServerTLSConfigRequiresAClientCertificate(t *testing.T) {
	servingCA := testca.New(t, "atelet-serving-ca")
	servingBundle := testca.WriteCredBundle(t, servingCA.Issue(t, testca.Opts{DNSNames: []string{"atelet.test"}}))
	servingRoots := servingCA.Pool()

	clientCA := testca.New(t, "pod-identity-ca")
	caPath := testca.WriteFile(t, "client-ca.pem", clientCA.CertPEM)

	cfg, err := ateletServerTLSConfig(servingBundle, caPath, nil)
	if err != nil {
		t.Fatalf("ateletServerTLSConfig() error = %v", err)
	}
	creds := credentials.NewTLS(cfg)

	if err := mtlsHandshake(t, creds, servingRoots, "atelet.test", nil); err == nil {
		t.Fatal("handshake with no client certificate succeeded, want it required")
	}

	// A certificate from an unrelated CA is refused even though one was
	// presented, so the failure above is not merely "no cert offered".
	other := testca.New(t, "unrelated-ca").Issue(t, testca.Opts{})
	if err := mtlsHandshake(t, creds, servingRoots, "atelet.test", &other); err == nil {
		t.Fatal("handshake with an untrusted client certificate succeeded, want a chain failure")
	}
}

// TestAteletServerTLSConfigAppliesVerifyConnection covers the credential
// broker's extra check. It is a parameter rather than a field the caller sets
// on the returned config because GetConfigForClient replaces that config
// wholesale — an externally assigned VerifyConnection would never run, and a
// dropped check of this kind fails open.
func TestAteletServerTLSConfigAppliesVerifyConnection(t *testing.T) {
	servingCA := testca.New(t, "atelet-serving-ca")
	servingBundle := testca.WriteCredBundle(t, servingCA.Issue(t, testca.Opts{DNSNames: []string{"atelet.test"}}))
	servingRoots := servingCA.Pool()

	clientCA := testca.New(t, "pod-identity-ca")
	caPath := testca.WriteFile(t, "client-ca.pem", clientCA.CertPEM)

	trusted := clientCA.Issue(t, testca.Opts{})

	called := 0
	cfg, err := ateletServerTLSConfig(servingBundle, caPath, func(tls.ConnectionState) error {
		called++
		return errRefusedByVerifyConnection
	})
	if err != nil {
		t.Fatalf("ateletServerTLSConfig() error = %v", err)
	}

	err = mtlsHandshake(t, credentials.NewTLS(cfg), servingRoots, "atelet.test", &trusted)
	if err == nil {
		t.Fatal("handshake succeeded despite VerifyConnection refusing it")
	}
	if called != 1 {
		t.Fatalf("VerifyConnection called %d times, want 1", called)
	}

	// Control: the same certificate is accepted when no extra check is
	// configured, so the refusal above came from VerifyConnection and not from
	// the chain.
	permissive, err := ateletServerTLSConfig(servingBundle, caPath, nil)
	if err != nil {
		t.Fatalf("ateletServerTLSConfig() error = %v", err)
	}
	if err := mtlsHandshake(t, credentials.NewTLS(permissive), servingRoots, "atelet.test", &trusted); err != nil {
		t.Fatalf("handshake with no extra check failed: %v", err)
	}
}

// TestAteletServerTLSConfigFailsFastOnABadBundle keeps the construction-time
// read: a missing or malformed projection has to fail atelet at startup rather
// than surface as a handshake error on the first ateapi call.
func TestAteletServerTLSConfigFailsFastOnABadBundle(t *testing.T) {
	servingCA := testca.New(t, "atelet-serving-ca")
	servingBundle := testca.WriteCredBundle(t, servingCA.Issue(t, testca.Opts{DNSNames: []string{"atelet.test"}}))
	dir := t.TempDir()

	garbage := filepath.Join(dir, "garbage.pem")
	testca.Republish(t, garbage, []byte("not a certificate\n"))

	for _, tc := range []struct {
		name string
		path string
	}{
		{name: "missing", path: filepath.Join(dir, "absent.pem")},
		{name: "unparseable", path: garbage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ateletServerTLSConfig(servingBundle, tc.path, nil); err == nil {
				t.Fatal("ateletServerTLSConfig() succeeded, want an error at construction")
			}
		})
	}
}

// errRefusedByVerifyConnection is returned by the test's VerifyConnection stub.
var errRefusedByVerifyConnection = errors.New("refused by VerifyConnection")

// mtlsHandshake performs one TLS handshake against creds, presenting
// clientCert (nil for none) and trusting the server with serverRoots. It
// reports the first end to fail.
func mtlsHandshake(t *testing.T, creds credentials.TransportCredentials, serverRoots *x509.CertPool, serverName string, clientCert *testca.Issued) error {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := lis.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		_, _, err = creds.ServerHandshake(conn)
		serverErr <- err
	}()

	clientCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    serverRoots,
		ServerName: serverName,
		// The gRPC server credentials enforce ALPN, so offer "h2".
		NextProtos: []string{"h2"},
	}
	if clientCert != nil {
		// GetClientCertificate rather than Certificates: a TLS 1.3 client
		// filters Certificates against the CA list the server advertises and
		// sends an empty certificate when none matches. That would make an
		// untrusted certificate look refused without the server ever verifying
		// a chain, so the negative cases below would pass against any pool.
		offered := tls.Certificate{Certificate: [][]byte{clientCert.CertDER}, PrivateKey: clientCert.Key}
		clientCfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &offered, nil
		}
	}
	conn, clientErr := tls.Dial("tcp", lis.Addr().String(), clientCfg)
	if clientErr == nil {
		clientErr = conn.Handshake()
		conn.Close()
	}

	if err := <-serverErr; err != nil {
		return err
	}
	return clientErr
}
