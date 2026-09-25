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
	servingCA := mtlsNewCA(t, "atelet-serving-ca")
	servingBundle := mtlsWriteCredBundle(t, servingCA.issue(t, mtlsCertOpts{dnsNames: []string{"atelet.test"}}))
	servingRoots := x509.NewCertPool()
	servingRoots.AddCert(servingCA.cert)

	clientCA1 := mtlsNewCA(t, "pod-identity-ca-1")
	clientCA2 := mtlsNewCA(t, "pod-identity-ca-2")

	caPath := filepath.Join(t.TempDir(), "client-ca.pem")
	mtlsWriteFileAt(t, caPath, clientCA1.certPEM, time.Now())

	cfg, err := ateletServerTLSConfig(servingBundle, caPath, nil)
	if err != nil {
		t.Fatalf("ateletServerTLSConfig() error = %v", err)
	}
	creds := credentials.NewTLS(cfg)

	fromCA1 := clientCA1.issue(t, mtlsCertOpts{})
	fromCA2 := clientCA2.issue(t, mtlsCertOpts{})

	if err := mtlsHandshake(t, creds, servingRoots, "atelet.test", &fromCA1); err != nil {
		t.Fatalf("handshake with a CA1-signed client cert failed before rotation: %v", err)
	}
	if err := mtlsHandshake(t, creds, servingRoots, "atelet.test", &fromCA2); err == nil {
		t.Fatal("handshake with a CA2-signed client cert succeeded before rotation, want a chain failure")
	}

	// Publish CA2 as the projected bundle. The mtime bump keeps the change
	// visible where filesystem timestamps are coarse.
	mtlsWriteFileAt(t, caPath, clientCA2.certPEM, time.Now().Add(time.Second))

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
	servingCA := mtlsNewCA(t, "atelet-serving-ca")
	servingBundle := mtlsWriteCredBundle(t, servingCA.issue(t, mtlsCertOpts{dnsNames: []string{"atelet.test"}}))
	servingRoots := x509.NewCertPool()
	servingRoots.AddCert(servingCA.cert)

	clientCA := mtlsNewCA(t, "pod-identity-ca")
	caPath := filepath.Join(t.TempDir(), "client-ca.pem")
	mtlsWriteFileAt(t, caPath, clientCA.certPEM, time.Now())

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
	other := mtlsNewCA(t, "unrelated-ca").issue(t, mtlsCertOpts{})
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
	servingCA := mtlsNewCA(t, "atelet-serving-ca")
	servingBundle := mtlsWriteCredBundle(t, servingCA.issue(t, mtlsCertOpts{dnsNames: []string{"atelet.test"}}))
	servingRoots := x509.NewCertPool()
	servingRoots.AddCert(servingCA.cert)

	clientCA := mtlsNewCA(t, "pod-identity-ca")
	caPath := filepath.Join(t.TempDir(), "client-ca.pem")
	mtlsWriteFileAt(t, caPath, clientCA.certPEM, time.Now())

	trusted := clientCA.issue(t, mtlsCertOpts{})

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
	servingCA := mtlsNewCA(t, "atelet-serving-ca")
	servingBundle := mtlsWriteCredBundle(t, servingCA.issue(t, mtlsCertOpts{dnsNames: []string{"atelet.test"}}))
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
			if _, err := ateletServerTLSConfig(servingBundle, tc.path, nil); err == nil {
				t.Fatal("ateletServerTLSConfig() succeeded, want an error at construction")
			}
		})
	}
}

// errRefusedByVerifyConnection is returned by the test's VerifyConnection stub.
var errRefusedByVerifyConnection = &mtlsTestError{"refused by VerifyConnection"}

type mtlsTestError struct{ msg string }

func (e *mtlsTestError) Error() string { return e.msg }

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
