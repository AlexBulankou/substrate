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
	"strings"
	"testing"
	"time"

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
	servingCA := mtlsNewCA(t, "ateapi-serving-ca")
	servingRoots := x509.NewCertPool()
	servingRoots.AddCert(servingCA.cert)

	clientCA1 := mtlsNewCA(t, "pod-identity-ca-1")
	clientCA2 := mtlsNewCA(t, "pod-identity-ca-2")
	caPath := filepath.Join(t.TempDir(), "pod-identity-ca.pem")
	mtlsWriteFileAt(t, caPath, clientCA1.certPEM, time.Now())

	// buildServerCreds reads these package-level flags.
	setFlagForTest(t, grpcServerCredBundle, mtlsWriteCredBundle(t, servingCA.issue(t, mtlsCertOpts{dnsNames: []string{"ateapi.test"}})))
	setFlagForTest(t, podIdentityCACerts, caPath)

	creds, err := buildServerCreds(context.Background())
	if err != nil {
		t.Fatalf("buildServerCreds() error = %v", err)
	}

	fromCA1 := clientCA1.issue(t, mtlsCertOpts{})
	fromCA2 := clientCA2.issue(t, mtlsCertOpts{})

	if err := mtlsHandshake(t, creds, servingRoots, "ateapi.test", &fromCA1); err != nil {
		t.Fatalf("handshake with a CA1-signed client cert failed before rotation: %v", err)
	}
	if err := mtlsHandshake(t, creds, servingRoots, "ateapi.test", &fromCA2); err == nil {
		t.Fatal("handshake with a CA2-signed client cert succeeded before rotation, want a chain failure")
	}

	// Publish CA2. The mtime bump keeps the change visible where filesystem
	// timestamps are coarse.
	mtlsWriteFileAt(t, caPath, clientCA2.certPEM, time.Now().Add(time.Second))

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
	servingCA := mtlsNewCA(t, "ateapi-serving-ca")
	servingRoots := x509.NewCertPool()
	servingRoots.AddCert(servingCA.cert)

	clientCA := mtlsNewCA(t, "pod-identity-ca")
	caPath := filepath.Join(t.TempDir(), "pod-identity-ca.pem")
	mtlsWriteFileAt(t, caPath, clientCA.certPEM, time.Now())

	setFlagForTest(t, grpcServerCredBundle, mtlsWriteCredBundle(t, servingCA.issue(t, mtlsCertOpts{dnsNames: []string{"ateapi.test"}})))
	setFlagForTest(t, podIdentityCACerts, caPath)

	creds, err := buildServerCreds(context.Background())
	if err != nil {
		t.Fatalf("buildServerCreds() error = %v", err)
	}
	if err := mtlsHandshake(t, creds, servingRoots, "ateapi.test", nil); err != nil {
		t.Fatalf("handshake with no client certificate failed, want it accepted: %v", err)
	}
	// A certificate that is offered is still verified.
	untrusted := mtlsNewCA(t, "unrelated-ca").issue(t, mtlsCertOpts{})
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
	servingCA := mtlsNewCA(t, "ateapi-serving-ca")
	servingRoots := x509.NewCertPool()
	servingRoots.AddCert(servingCA.cert)

	setFlagForTest(t, grpcServerCredBundle, mtlsWriteCredBundle(t, servingCA.issue(t, mtlsCertOpts{dnsNames: []string{"ateapi.test"}})))
	setFlagForTest(t, podIdentityCACerts, "")

	creds, err := buildServerCreds(context.Background())
	if err != nil {
		t.Fatalf("buildServerCreds() error = %v", err)
	}
	if err := mtlsHandshake(t, creds, servingRoots, "ateapi.test", nil); err != nil {
		t.Fatalf("handshake with no client certificate failed, want it accepted: %v", err)
	}
	offered := mtlsNewCA(t, "unrelated-ca").issue(t, mtlsCertOpts{})
	if err := mtlsHandshake(t, creds, servingRoots, "ateapi.test", &offered); err == nil {
		t.Fatal("handshake with a self-signed client certificate succeeded, want verification against the host trust store")
	}
}

// TestBuildServerCredsFailsFastOnABadPodIdentityCA keeps the construction-time
// read: a missing or malformed projection has to fail ateapi at startup rather
// than surface as a handshake error on the first mTLS call.
func TestBuildServerCredsFailsFastOnABadPodIdentityCA(t *testing.T) {
	servingCA := mtlsNewCA(t, "ateapi-serving-ca")
	setFlagForTest(t, grpcServerCredBundle, mtlsWriteCredBundle(t, servingCA.issue(t, mtlsCertOpts{dnsNames: []string{"ateapi.test"}})))

	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.pem")
	mtlsWriteFileAt(t, garbage, []byte("not a certificate\n"), time.Now())

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
func mtlsHandshake(t *testing.T, creds credentials.TransportCredentials, serverRoots *x509.CertPool, serverName string, clientCert *mtlsIssued) error {
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
		offered := tls.Certificate{Certificate: [][]byte{clientCert.certDER}, PrivateKey: clientCert.key}
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

// mtlsCA is a self-signed certificate authority used to issue test certificates.
type mtlsCA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

func mtlsNewCA(t *testing.T, cn string) *mtlsCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return &mtlsCA{cert: cert, key: key, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

type mtlsCertOpts struct {
	dnsNames []string
	uris     []string
}

// mtlsIssued is a leaf certificate and its private key.
type mtlsIssued struct {
	certDER []byte
	key     *ecdsa.PrivateKey
}

func (c *mtlsCA) issue(t *testing.T, opts mtlsCertOpts) mtlsIssued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	var uris []*url.URL
	for _, u := range opts.uris {
		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatalf("parse URI SAN %q: %v", u, err)
		}
		uris = append(uris, parsed)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: strings.Join(append(opts.dnsNames, "leaf"), "-")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     opts.dnsNames,
		URIs:         uris,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	return mtlsIssued{certDER: der, key: key}
}

// mtlsWriteCredBundle writes a credential bundle (leaf certificate + PKCS8 key)
// in the format credbundle.Parse expects and returns its path.
func mtlsWriteCredBundle(t *testing.T, leaf mtlsIssued) string {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.key)
	if err != nil {
		t.Fatalf("marshal PKCS8 key: %v", err)
	}
	bundle := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...,
	)
	path := filepath.Join(t.TempDir(), "serving-bundle.pem")
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatalf("write credential bundle: %v", err)
	}
	return path
}

func mtlsWriteFileAt(t *testing.T, path string, data []byte, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}
