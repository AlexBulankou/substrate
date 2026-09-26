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
// for tests, and writes them out in the shapes the substrate reads at runtime:
// a PEM trust bundle as projected from a ClusterTrustBundle, and a credential
// bundle as written by the Kubernetes Pod Certificates mechanism.
//
// It exists for the trust-rotation tests. Verifying that a component follows a
// CA rotation means having two CAs, leaves signed by each, and the ability to
// republish the bundle mid-test — plumbing that is otherwise copied into every
// package that needs it, and easy to get subtly wrong in ways that make the
// negative cases vacuous.
package testca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"testing"
	"time"
)

// CA is a self-signed certificate authority.
type CA struct {
	// Cert is the CA's own certificate.
	Cert *x509.Certificate
	// CertPEM is Cert, PEM-encoded: the form a projected trust bundle takes.
	CertPEM []byte

	key *ecdsa.PrivateKey
}

// New mints a self-signed CA with the given common name, valid for an hour
// either side of now.
func New(t *testing.T, commonName string) *CA {
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
	return &CA{
		Cert:    cert,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key:     key,
	}
}

// Pool returns a pool trusting just this CA.
func (c *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(c.Cert)
	return pool
}

// Opts selects the SANs a leaf certificate carries. A leaf is usable for both
// server and client authentication regardless.
type Opts struct {
	CommonName string
	DNSNames   []string
	// IPs are IP SANs, in the textual form net.ParseIP accepts. A test server
	// bound to a loopback address needs one, since the dialer verifies against
	// the address it connected to.
	IPs  []string
	URIs []string
	// Mutate, when non-nil, edits the leaf template just before it is signed.
	// It exists for negative cases: a test that needs a certificate broken in
	// exactly one way builds an otherwise-valid one and breaks that property
	// here, so the case cannot pass for an unrelated reason.
	Mutate func(*x509.Certificate)
}

// Issued is a leaf certificate and its private key.
type Issued struct {
	CertDER []byte
	Key     *ecdsa.PrivateKey
}

// Issue signs a leaf certificate, valid for an hour either side of now.
func (c *CA) Issue(t *testing.T, opts Opts) Issued {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	var uris []*url.URL
	for _, u := range opts.URIs {
		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatalf("parse URI SAN %q: %v", u, err)
		}
		uris = append(uris, parsed)
	}
	var ips []net.IP
	for _, raw := range opts.IPs {
		ip := net.ParseIP(raw)
		if ip == nil {
			t.Fatalf("parse IP SAN %q", raw)
		}
		ips = append(ips, ip)
	}
	commonName := opts.CommonName
	if commonName == "" {
		commonName = "leaf"
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     opts.DNSNames,
		IPAddresses:  ips,
		URIs:         uris,
		// A real leaf carries basicConstraints CA:FALSE, and Mutate is how a
		// test makes one look like a CA. Without this, Go omits the extension
		// entirely and setting IsCA there silently does nothing — the negative
		// case would pass by not being tested.
		BasicConstraintsValid: true,
	}
	if opts.Mutate != nil {
		opts.Mutate(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.Cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	return Issued{CertDER: der, Key: key}
}

// WriteCredBundle writes leaf as a credential bundle — the leaf certificate
// followed by its PKCS8 private key, the format credbundle.Parse reads — and
// returns the path.
func WriteCredBundle(t *testing.T, leaf Issued) string {
	t.Helper()
	keyDER, err := x509.MarshalPKCS8PrivateKey(leaf.Key)
	if err != nil {
		t.Fatalf("marshal PKCS8 key: %v", err)
	}
	bundle := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.CertDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...,
	)
	return WriteFile(t, "cred-bundle.pem", bundle)
}

// WriteFile writes data to name under a fresh temporary directory and returns
// the path. Each call gets its own directory, so a caller can hold several
// files with the same name.
func WriteFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := t.TempDir() + "/" + name
	Republish(t, path, data)
	return path
}

// Republish writes data to path, standing in for the kubelet swapping a
// projected volume's contents.
//
// It advances the file's modification time past the previous one. Trust-bundle
// caches invalidate on the stat triple, and a rotation written within the
// filesystem's timestamp granularity of the last one is otherwise invisible to
// them — which would make a rotation test pass while the cache never noticed.
func Republish(t *testing.T, path string, data []byte) {
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
