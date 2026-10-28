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

package oidcjwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestNewHTTPClientFollowsACARotation fetches from an issuer serving a CA-1
// certificate, republishes the trust bundle as CA-2, and fetches from an issuer
// serving a CA-2 certificate — same client, no restart.
//
// This is the defect the per-connection reload fixes: a pool set on the
// transport's TLSClientConfig is frozen for the lifetime of that transport, so
// once the issuer's serving certificate is reissued under a new CA, OIDC
// discovery and JWKS fetches fail and keep failing until ateapi restarts —
// which takes JWT authentication down with them.
func TestNewHTTPClientFollowsACARotation(t *testing.T) {
	ca1 := newTestCA(t, "issuer-ca-1")
	ca2 := newTestCA(t, "issuer-ca-2")
	caFile := writeTempFile(t, "ca.pem", ca1.certPEM)

	underCA1 := startIssuer(t, ca1)
	underCA2 := startIssuer(t, ca2)

	client, err := NewHTTPClient(underCA1.URL, caFile, "")
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}

	if err := fetch(client, underCA1.URL); err != nil {
		t.Fatalf("before rotation, fetch from the CA1 issuer failed: %v", err)
	}
	if err := fetch(client, underCA2.URL); err == nil {
		t.Fatal("before rotation, fetch from the CA2 issuer succeeded, want a chain failure")
	}

	// Publish CA2 as the projected trust bundle.
	republish(t, caFile, ca2.certPEM)

	if err := fetch(client, underCA2.URL); err != nil {
		t.Fatalf("after rotation, fetch from the CA2 issuer failed: %v", err)
	}

	// The reload applies to new connections, so the pooled connection to the
	// CA1 issuer keeps working until it is dropped. Drop it, then confirm the
	// retired CA no longer verifies — without which the assertion above would
	// also pass against a pool that simply trusts everything.
	client.CloseIdleConnections()
	if err := fetch(client, underCA1.URL); err == nil {
		t.Fatal("after rotation, fetch from the CA1 issuer succeeded on a fresh connection, want a chain failure")
	}
}

// TestNewHTTPClientStillNegotiatesHTTP2 guards the side effect of owning the
// dial: net/http upgrades to HTTP/2 over ALPN, which it can only arrange for
// itself when it also owns the dial, so taking that over means advertising the
// protocols by hand. Getting it wrong silently downgrades every issuer that
// speaks HTTP/2.
func TestNewHTTPClientStillNegotiatesHTTP2(t *testing.T) {
	ca := newTestCA(t, "issuer-ca")
	caFile := writeTempFile(t, "ca.pem", ca.certPEM)

	issued := ca.issueLoopbackServerCert(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{issued.certDER}, PrivateKey: issued.key}},
	}
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	client, err := NewHTTPClient(srv.URL, caFile, "")
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.Proto != "HTTP/2.0" {
		t.Errorf("response protocol = %q, want %q", resp.Proto, "HTTP/2.0")
	}
}

// TestNewHTTPClientFailsFastOnABadCAFile keeps the construction-time read: a
// missing or malformed CA file has to fail ateapi as it builds the provider,
// not on the first discovery request.
func TestNewHTTPClientFailsFastOnABadCAFile(t *testing.T) {
	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.pem")
	republish(t, garbage, []byte("not a certificate\n"))

	for _, tc := range []struct {
		name   string
		caFile string
	}{
		{name: "missing", caFile: filepath.Join(dir, "absent.pem")},
		{name: "unparseable", caFile: garbage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewHTTPClient("https://issuer.test", tc.caFile, ""); err == nil {
				t.Fatal("NewHTTPClient() error = nil, want an error at construction")
			}
		})
	}
}

// startIssuer runs a TLS server holding a certificate issued by ca.
func startIssuer(t *testing.T, ca *testCA) *httptest.Server {
	t.Helper()

	issued := ca.issueLoopbackServerCert(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{issued.certDER}, PrivateKey: issued.key}},
	}
	// The negative cases deliberately fail the handshake; leaving the default
	// logger in place prints those refusals as if the test had gone wrong.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func fetch(client *http.Client, url string) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// The helpers below mint a throwaway CA and a loopback serving certificate.
// They are deliberately local to this package rather than shared: the only
// other caller would be a trust-rotation test in another package, and pulling
// a new shared test-CA package into a fix this small is a bigger change than
// the fix.

// testCA is a self-signed certificate authority.
type testCA struct {
	cert *x509.Certificate
	// certPEM is cert, PEM-encoded: the form a projected trust bundle takes.
	certPEM []byte
	key     *ecdsa.PrivateKey
}

// newTestCA mints a self-signed CA valid for an hour either side of now.
func newTestCA(t *testing.T, commonName string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
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
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return &testCA{
		cert:    cert,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key:     key,
	}
}

// issuedCert is a leaf certificate and its private key.
type issuedCert struct {
	certDER []byte
	key     *ecdsa.PrivateKey
}

// issueLoopbackServerCert signs a serving certificate carrying a 127.0.0.1 IP
// SAN, which a test server bound to loopback needs: the client verifies
// against the address it connected to, not a name.
func (c *testCA) issueLoopbackServerCert(t *testing.T) issuedCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	return issuedCert{certDER: der, key: key}
}

// writeTempFile writes data to name under a fresh temporary directory and
// returns the path. Each call gets its own directory, so a caller can hold
// several files with the same name.
func writeTempFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	republish(t, path, data)
	return path
}

// republish writes data to path, standing in for the kubelet swapping a
// projected volume's contents.
//
// It advances the modification time past the previous one on purpose. Trust
// bundle caches invalidate on the stat triple, and a rotation written within
// the filesystem's timestamp granularity of the last one is invisible to them
// -- which would make this rotation test pass while the cache never noticed.
func republish(t *testing.T, path string, data []byte) {
	t.Helper()

	mtime := time.Now()
	if fi, err := os.Stat(path); err == nil {
		if next := fi.ModTime().Add(time.Second); next.After(mtime) {
			mtime = next
		}
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}
