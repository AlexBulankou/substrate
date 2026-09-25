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
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"path/filepath"
	"testing"

	"github.com/agent-substrate/substrate/internal/testca"
	"google.golang.org/grpc/credentials"
)

// TestBuildServerCredsReloadsClientCAs rewrites the projected pod-identity
// trust bundle under a live set of credentials and confirms an mTLS caller
// holding a certificate from the newly published CA verifies on a new
// connection, with no restart.
//
// A pool captured at startup — which is what the replaced
// "TODO: Periodically reload these to handle rotations" stood for — keeps
// verifying against the retired CA and refuses every such caller at handshake.
func TestBuildServerCredsReloadsClientCAs(t *testing.T) {
	servingCA := testca.New(t, "ateapi-serving-ca")
	servingRoots := servingCA.Pool()

	clientCA1 := testca.New(t, "pod-identity-ca-1")
	clientCA2 := testca.New(t, "pod-identity-ca-2")
	caPath := testca.WriteFile(t, "pod-identity-ca.pem", clientCA1.CertPEM)

	// buildServerCreds reads these package-level flags.
	setFlagForTest(t, grpcServerCredBundle, testca.WriteCredBundle(t, servingCA.Issue(t, testca.Opts{DNSNames: []string{"ateapi.test"}})))
	setFlagForTest(t, podIdentityCACerts, caPath)

	creds, err := buildServerCreds(context.Background())
	if err != nil {
		t.Fatalf("buildServerCreds() error = %v", err)
	}

	fromCA1 := clientCA1.Issue(t, testca.Opts{})
	fromCA2 := clientCA2.Issue(t, testca.Opts{})

	if err := mtlsHandshake(t, creds, servingRoots, "ateapi.test", &fromCA1); err != nil {
		t.Fatalf("handshake with a CA1-signed client cert failed before rotation: %v", err)
	}
	if err := mtlsHandshake(t, creds, servingRoots, "ateapi.test", &fromCA2); err == nil {
		t.Fatal("handshake with a CA2-signed client cert succeeded before rotation, want a chain failure")
	}

	// Publish CA2 as the projected bundle.
	testca.Republish(t, caPath, clientCA2.CertPEM)

	if err := mtlsHandshake(t, creds, servingRoots, "ateapi.test", &fromCA2); err != nil {
		t.Fatalf("handshake with a CA2-signed client cert failed after rotation: %v", err)
	}
	if err := mtlsHandshake(t, creds, servingRoots, "ateapi.test", &fromCA1); err == nil {
		t.Fatal("handshake with a CA1-signed client cert succeeded after rotation, want a chain failure")
	}
}

// TestBuildServerCredsKeepsClientCertsOptional pins the mode the reload had to
// preserve: certless callers such as kubectl-ate authenticate with a Bearer
// token in the ateapiauth interceptor, so the transport must still let them
// complete a handshake.
func TestBuildServerCredsKeepsClientCertsOptional(t *testing.T) {
	servingCA := testca.New(t, "ateapi-serving-ca")
	servingRoots := servingCA.Pool()

	clientCA := testca.New(t, "pod-identity-ca")
	caPath := testca.WriteFile(t, "pod-identity-ca.pem", clientCA.CertPEM)

	setFlagForTest(t, grpcServerCredBundle, testca.WriteCredBundle(t, servingCA.Issue(t, testca.Opts{DNSNames: []string{"ateapi.test"}})))
	setFlagForTest(t, podIdentityCACerts, caPath)

	creds, err := buildServerCreds(context.Background())
	if err != nil {
		t.Fatalf("buildServerCreds() error = %v", err)
	}
	if err := mtlsHandshake(t, creds, servingRoots, "ateapi.test", nil); err != nil {
		t.Fatalf("handshake with no client certificate failed, want it accepted: %v", err)
	}
	// A certificate that is offered is still verified.
	untrusted := testca.New(t, "unrelated-ca").Issue(t, testca.Opts{})
	if err := mtlsHandshake(t, creds, servingRoots, "ateapi.test", &untrusted); err == nil {
		t.Fatal("handshake with an untrusted client certificate succeeded, want a chain failure")
	}
}

// TestBuildServerCredsWithoutAPodIdentityCA covers the unconfigured path, which
// stays static because there is no projection to follow. The flag help used to
// call this "client-cert verification is disabled"; it is not. ClientCAs nil
// verifies an offered certificate against the host system trust store, so a
// self-signed one is refused rather than waved through.
func TestBuildServerCredsWithoutAPodIdentityCA(t *testing.T) {
	servingCA := testca.New(t, "ateapi-serving-ca")
	servingRoots := servingCA.Pool()

	setFlagForTest(t, grpcServerCredBundle, testca.WriteCredBundle(t, servingCA.Issue(t, testca.Opts{DNSNames: []string{"ateapi.test"}})))
	setFlagForTest(t, podIdentityCACerts, "")

	creds, err := buildServerCreds(context.Background())
	if err != nil {
		t.Fatalf("buildServerCreds() error = %v", err)
	}
	if err := mtlsHandshake(t, creds, servingRoots, "ateapi.test", nil); err != nil {
		t.Fatalf("handshake with no client certificate failed, want it accepted: %v", err)
	}
	offered := testca.New(t, "unrelated-ca").Issue(t, testca.Opts{})
	if err := mtlsHandshake(t, creds, servingRoots, "ateapi.test", &offered); err == nil {
		t.Fatal("handshake with a self-signed client certificate succeeded, want verification against the host trust store")
	}
}

// TestBuildServerCredsFailsFastOnABadPodIdentityCA keeps the construction-time
// read: a missing or malformed projection has to fail ateapi at startup rather
// than surface as a handshake error on the first mTLS call.
func TestBuildServerCredsFailsFastOnABadPodIdentityCA(t *testing.T) {
	servingCA := testca.New(t, "ateapi-serving-ca")
	setFlagForTest(t, grpcServerCredBundle, testca.WriteCredBundle(t, servingCA.Issue(t, testca.Opts{DNSNames: []string{"ateapi.test"}})))

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
			setFlagForTest(t, podIdentityCACerts, tc.path)
			if _, err := buildServerCreds(context.Background()); err == nil {
				t.Fatal("buildServerCreds() succeeded, want an error at construction")
			}
		})
	}
}

// setFlagForTest points a package-level flag at a test value and restores it
// when the test ends.
func setFlagForTest(t *testing.T, flag *string, value string) {
	t.Helper()
	prev := *flag
	t.Cleanup(func() { *flag = prev })
	*flag = value
}

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
