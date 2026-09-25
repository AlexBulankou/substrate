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

package csi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/pkg/api/v1alpha1"
	listersv1alpha1 "github.com/agent-substrate/substrate/pkg/client/listers/api/v1alpha1"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"k8s.io/apimachinery/pkg/labels"
)

const mockDriverName = "mock-driver"

// testCA is a self-signed CA that issues the server and client certificates for
// one test.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	cert, err := x509.ParseCertificate(createCert(t, tmpl, tmpl, &key.PublicKey, key))
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return &testCA{cert: cert, key: key}
}

// certPEM returns the CA certificate as a trust bundle would hold it.
func (ca *testCA) certPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
}

// pool returns a CertPool trusting this CA and nothing else.
func (ca *testCA) pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.certPEM())
	return pool
}

// serverCert issues a serving certificate valid for dnsName.
func (ca *testCA) serverCert(t *testing.T, dnsName string) tls.Certificate {
	t.Helper()
	key := newKey(t)
	der := createCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{dnsName},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca.cert, &key.PublicKey, ca.key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// serverCertForIP issues a serving certificate valid for an IP address, as a
// driver reached at a bare host:port endpoint needs.
func (ca *testCA) serverCertForIP(t *testing.T, ip string) tls.Certificate {
	t.Helper()
	key := newKey(t)
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("parse IP SAN %q", ip)
	}
	der := createCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "test-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{parsed},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca.cert, &key.PublicKey, ca.key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// clientBundle issues a client certificate in credential-bundle layout: a PKCS#8
// PRIVATE KEY block followed by the CERTIFICATE block
func (ca *testCA) clientBundle(t *testing.T) []byte {
	t.Helper()
	key := newKey(t)
	der := createCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, ca.cert, &key.PublicKey, ca.key)

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal client key: %v", err)
	}
	return append(
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...,
	)
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func createCert(t *testing.T, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatalf("create certificate %q: %v", tmpl.Subject.CommonName, err)
	}
	return der
}

// writeCreds lays out a credential bundle and a trust bundle on disk the way the
// projected pod-identity volumes do, and returns the paths to read them from.
func writeCreds(t *testing.T, clientBundle, trustBundle []byte) tlsPaths {
	t.Helper()
	dir := t.TempDir()
	paths := tlsPaths{
		clientCert: filepath.Join(dir, "credential-bundle.pem"),
		caCert:     filepath.Join(dir, "trust-bundle.pem"),
	}
	writeFile(t, paths.clientCert, clientBundle)
	writeFile(t, paths.caCert, trustBundle)
	return paths
}

// writeFile writes data to path, standing in for the kubelet swapping a
// projected volume's contents.
//
// It advances the file's modification time past the previous one. The trust
// bundle and credential bundle caches invalidate on the file's stat triple,
// and a rotation written within the filesystem's timestamp granularity of the
// last one is otherwise invisible to them — which would make a rotation test
// pass while the cache never noticed.
func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	mtime := time.Now()
	if fi, err := os.Stat(path); err == nil {
		if next := fi.ModTime().Add(time.Second); next.After(mtime) {
			mtime = next
		}
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

// startTLSServer serves the CSI Identity service over mTLS and returns its address.
func startTLSServer(t *testing.T, serverCert tls.Certificate, clientCAs *x509.CertPool) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS13,
	})))
	csi.RegisterIdentityServer(srv, &mockCSIDriver{})
	go func() { _ = srv.Serve(lis) }()

	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

func driverConfig(endpoint string, tlsCfg *v1alpha1.CSIDriverTLSConfig) *v1alpha1.CSIDriverConfig {
	return &v1alpha1.CSIDriverConfig{
		Spec: v1alpha1.CSIDriverConfigSpec{
			DriverName:         mockDriverName,
			ControllerEndpoint: endpoint,
			TLS:                tlsCfg,
		},
	}
}

// dialPlugin builds a controller plugin pointed at addr. newCSIPlugin issues a
// GetPluginInfo RPC before returning, so a nil error means the mTLS handshake
// and a real call both succeeded.
func dialPlugin(t *testing.T, addr, serverName string, paths tlsPaths) (*Plugin, error) {
	t.Helper()
	cfg := driverConfig("tcp://"+addr, &v1alpha1.CSIDriverTLSConfig{
		Enabled:        true,
		UsePodIdentity: true,
		ServerName:     serverName,
	})
	return newCSIPlugin(t.Context(), &mockLister{cfg: cfg}, mockDriverName, true /*isController*/, paths)
}

// mockLister serves a single CSIDriverConfig under mockDriverName.
type mockLister struct{ cfg *v1alpha1.CSIDriverConfig }

func (m *mockLister) List(labels.Selector) ([]*v1alpha1.CSIDriverConfig, error) {
	return []*v1alpha1.CSIDriverConfig{m.cfg}, nil
}

func (m *mockLister) Get(name string) (*v1alpha1.CSIDriverConfig, error) {
	if name != mockDriverName {
		return nil, fmt.Errorf("no CSIDriverConfig named %q", name)
	}
	return m.cfg, nil
}

var _ listersv1alpha1.CSIDriverConfigLister = (*mockLister)(nil)

func TestMTLSSucceeds(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	addr := startTLSServer(t, ca.serverCert(t, "localhost"), ca.pool())
	paths := writeCreds(t, ca.clientBundle(t), ca.certPEM())

	plugin, err := dialPlugin(t, addr, "localhost", paths)
	if err != nil {
		t.Fatalf("newCSIPlugin over mTLS: %v", err)
	}
	t.Cleanup(func() { plugin.client.Close() })
}

// The server presents a certificate from a CA the client does not trust.
func TestMTLSRejectsUntrustedServerCA(t *testing.T) {
	t.Parallel()
	serverCA, unauthClientCA := newTestCA(t), newTestCA(t)
	addr := startTLSServer(t, serverCA.serverCert(t, "localhost"), unauthClientCA.pool())
	paths := writeCreds(t, unauthClientCA.clientBundle(t), unauthClientCA.certPEM())

	if _, err := dialPlugin(t, addr, "localhost", paths); err == nil {
		t.Fatal("newCSIPlugin accepted a server certificate from an untrusted CA")
	}
}

// The server's certificate is trusted but was issued for a different name.
func TestMTLSRejectsServerNameMismatch(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	addr := startTLSServer(t, ca.serverCert(t, "localhost"), ca.pool())
	paths := writeCreds(t, ca.clientBundle(t), ca.certPEM())

	if _, err := dialPlugin(t, addr, "wrong.example", paths); err == nil {
		t.Fatal("newCSIPlugin accepted a server certificate issued for another name")
	}
}

// The client presents a certificate from a CA the server does not accept, which
// is what proves the connection is mutually authenticated and not one-way TLS.
func TestMTLSRejectsUntrustedClientCert(t *testing.T) {
	t.Parallel()
	ca, otherCA := newTestCA(t), newTestCA(t)
	addr := startTLSServer(t, ca.serverCert(t, "localhost"), otherCA.pool())
	paths := writeCreds(t, ca.clientBundle(t), ca.certPEM())

	if _, err := dialPlugin(t, addr, "localhost", paths); err == nil {
		t.Fatal("newCSIPlugin succeeded with a client certificate the server should reject")
	}
}

func TestResolveTLSConfigDisabled(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		cfg  *v1alpha1.CSIDriverConfig
	}{
		{"nil config", nil},
		{"no TLS block", driverConfig("", nil)},
		{"TLS disabled", driverConfig("", &v1alpha1.CSIDriverTLSConfig{Enabled: false})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveTransportCredentials(tc.cfg, defaultTLSPaths)
			if err != nil {
				t.Fatalf("resolveTransportCredentials: %v", err)
			}
			if got != nil {
				t.Errorf("resolveTransportCredentials = %v, want nil", got)
			}
		})
	}
}

func TestResolveTLSConfigRejectsManualCerts(t *testing.T) {
	t.Parallel()
	cfg := driverConfig("", &v1alpha1.CSIDriverTLSConfig{Enabled: true, UsePodIdentity: false})

	if _, err := resolveTransportCredentials(cfg, defaultTLSPaths); err == nil {
		t.Fatal("resolveTransportCredentials accepted usePodIdentity=false; manual certificates are unsupported")
	}
}

func TestResolveTLSConfigFields(t *testing.T) {
	t.Parallel()
	const serverName = "my-service.default.svc"
	ca := newTestCA(t)
	paths := writeCreds(t, ca.clientBundle(t), ca.certPEM())

	got := tlsTemplate(&v1alpha1.CSIDriverTLSConfig{
		Enabled:        true,
		UsePodIdentity: true,
		ServerName:     serverName,
	}, paths)

	if got.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want %d", got.MinVersion, tls.VersionTLS13)
	}
	// The trust anchors rotate, so they are supplied per handshake rather than
	// pinned here — but by reloading the pool, never by disabling verification
	// and re-implementing it. A hand-rolled verifier is what skipped the check
	// against the server's name when serverName was left unset.
	if got.InsecureSkipVerify {
		t.Error("InsecureSkipVerify = true, want the standard verification path")
	}
	if got.VerifyConnection != nil {
		t.Error("VerifyConnection is set, want the standard verification path")
	}
	if got.RootCAs != nil {
		t.Error("RootCAs is set, want the anchors to come from the per-handshake loader")
	}
	if got.GetClientCertificate == nil {
		t.Error("GetClientCertificate = nil, want the credential-bundle loader")
	}
	if got.ServerName != serverName {
		t.Errorf("ServerName = %q, want %q", got.ServerName, serverName)
	}
	if !slices.Equal(got.NextProtos, []string{"h2"}) {
		t.Errorf("NextProtos = %v, want [h2]", got.NextProtos)
	}
}

// TestMTLSRejectsAnUnrelatedNameWithoutAServerName is the fail-open this
// verification path was rebuilt to close.
//
// serverName is optional in the CRD, and the hand-rolled verifier passed it
// straight to x509.VerifyOptions.DNSName, where the empty string means "skip
// the name check entirely". A driver config that left it out therefore
// verified the chain but not the identity, so any peer holding a pod-identity
// certificate from the cluster CA — any workload in the mesh — could serve the
// controller endpoint and be accepted as the CSI driver.
func TestMTLSRejectsAnUnrelatedNameWithoutAServerName(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	addr := startTLSServer(t, ca.serverCert(t, "unrelated.example"), ca.pool())
	paths := writeCreds(t, ca.clientBundle(t), ca.certPEM())

	if _, err := dialPlugin(t, addr, "" /*serverName*/, paths); err == nil {
		t.Fatal("newCSIPlugin with no serverName accepted a certificate issued for an unrelated name")
	}
}

// TestMTLSSucceedsWithoutAServerName is the other half: leaving serverName out
// is a supported configuration, so closing the hole above must not close it.
// The name verified falls back to the endpoint's own host, which the server's
// certificate covers here with an IP SAN.
func TestMTLSSucceedsWithoutAServerName(t *testing.T) {
	t.Parallel()
	ca := newTestCA(t)
	addr := startTLSServer(t, ca.serverCertForIP(t, "127.0.0.1"), ca.pool())
	paths := writeCreds(t, ca.clientBundle(t), ca.certPEM())

	plugin, err := dialPlugin(t, addr, "" /*serverName*/, paths)
	if err != nil {
		t.Fatalf("newCSIPlugin with no serverName over mTLS: %v", err)
	}
	t.Cleanup(func() { plugin.client.Close() })
}

// TestMTLSPicksUpCARotation verifies that one set of credentials follows a CA
// rotation: it dials a server holding a CA-1 certificate, republishes the
// trust bundle as CA-2, and dials a server holding a CA-2 certificate.
//
// The credentials are resolved once and reused, which is what makes the test
// non-vacuous. Building fresh credentials for the second dial would pass
// against a pool frozen at construction — the very defect being guarded — so
// the reuse is load-bearing, as are the two negative dials that pin the
// retired CA as no longer trusted rather than everything being trusted.
func TestMTLSPicksUpCARotation(t *testing.T) {
	t.Parallel()
	ca1, ca2 := newTestCA(t), newTestCA(t)

	// The client bundle stays under ca1, so both servers accept this client and
	// only the server-side trust anchors are under test.
	paths := writeCreds(t, ca1.clientBundle(t), ca1.certPEM())
	underCA1 := startTLSServer(t, ca1.serverCert(t, "localhost"), ca1.pool())
	underCA2 := startTLSServer(t, ca2.serverCert(t, "localhost"), ca1.pool())

	creds, err := resolveTransportCredentials(driverConfig("", &v1alpha1.CSIDriverTLSConfig{
		Enabled:        true,
		UsePodIdentity: true,
		ServerName:     "localhost",
	}), paths)
	if err != nil {
		t.Fatalf("resolveTransportCredentials: %v", err)
	}

	if err := probe(t, underCA1, creds); err != nil {
		t.Fatalf("before rotation, the CA1 server was rejected: %v", err)
	}
	if err := probe(t, underCA2, creds); err == nil {
		t.Fatal("before rotation, the CA2 server was accepted, want a chain failure")
	}

	// Publish CA2 as the projected trust bundle.
	writeFile(t, paths.caCert, ca2.certPEM())

	if err := probe(t, underCA2, creds); err != nil {
		t.Fatalf("after rotation, the CA2 server was rejected: %v", err)
	}
	if err := probe(t, underCA1, creds); err == nil {
		t.Fatal("after rotation, the CA1 server was accepted, want a chain failure")
	}
}

// probe dials addr with creds and issues one RPC, so the error it returns
// covers the handshake as well as the call.
func probe(t *testing.T, addr string, creds credentials.TransportCredentials) error {
	t.Helper()
	client, err := NewCSIClient("tcp://"+addr, creds)
	if err != nil {
		t.Fatalf("NewCSIClient: %v", err)
	}
	defer client.Close()
	_, err = NewPlugin(client).DriverName(t.Context())
	return err
}
