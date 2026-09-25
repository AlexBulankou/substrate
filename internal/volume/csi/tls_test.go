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
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"path/filepath"
	"slices"
	"testing"

	"github.com/agent-substrate/substrate/internal/testca"
	"github.com/agent-substrate/substrate/pkg/api/v1alpha1"
	listersv1alpha1 "github.com/agent-substrate/substrate/pkg/client/listers/api/v1alpha1"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"k8s.io/apimachinery/pkg/labels"
)

const mockDriverName = "mock-driver"

// writeCreds lays out the two files the plugin reads as a projected volume.
// Both go under one directory so a rotation rewrites the same path the plugin
// already stat'd; testca.Republish is what keeps that rewrite visible to the
// stat-triple cache.
func writeCreds(t *testing.T, clientBundle, trustBundle []byte) tlsPaths {
	t.Helper()
	dir := t.TempDir()
	paths := tlsPaths{
		clientCert: filepath.Join(dir, "credential-bundle.pem"),
		caCert:     filepath.Join(dir, "trust-bundle.pem"),
	}
	testca.Republish(t, paths.clientCert, clientBundle)
	testca.Republish(t, paths.caCert, trustBundle)
	return paths
}

func issueBundle(t *testing.T, ca *testca.CA) []byte {
	t.Helper()
	leaf := ca.Issue(t, testca.Opts{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leaf.Key)
	return append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.CertDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...,
	)
}

func issueServerCert(t *testing.T, ca *testca.CA, dnsName string) tls.Certificate {
	t.Helper()
	leaf := ca.Issue(t, testca.Opts{DNSNames: []string{dnsName}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return tls.Certificate{Certificate: [][]byte{leaf.CertDER}, PrivateKey: leaf.Key}
}

func issueServerCertForIP(t *testing.T, ca *testca.CA, ip string) tls.Certificate {
	t.Helper()
	leaf := ca.Issue(t, testca.Opts{IPs: []string{ip}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return tls.Certificate{Certificate: [][]byte{leaf.CertDER}, PrivateKey: leaf.Key}
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
	ca := testca.New(t, "test-ca")
	addr := startTLSServer(t, issueServerCert(t, ca, "localhost"), ca.Pool())
	paths := writeCreds(t, issueBundle(t, ca), ca.CertPEM)

	plugin, err := dialPlugin(t, addr, "localhost", paths)
	if err != nil {
		t.Fatalf("newCSIPlugin over mTLS: %v", err)
	}
	t.Cleanup(func() { plugin.client.Close() })
}

// The server presents a certificate from a CA the client does not trust.
func TestMTLSRejectsUntrustedServerCA(t *testing.T) {
	t.Parallel()
	serverCA, unauthClientCA := testca.New(t, "test-ca"), testca.New(t, "test-ca")
	addr := startTLSServer(t, issueServerCert(t, serverCA, "localhost"), unauthClientCA.Pool())
	paths := writeCreds(t, issueBundle(t, unauthClientCA), unauthClientCA.CertPEM)

	if _, err := dialPlugin(t, addr, "localhost", paths); err == nil {
		t.Fatal("newCSIPlugin accepted a server certificate from an untrusted CA")
	}
}

// The server's certificate is trusted but was issued for a different name.
func TestMTLSRejectsServerNameMismatch(t *testing.T) {
	t.Parallel()
	ca := testca.New(t, "test-ca")
	addr := startTLSServer(t, issueServerCert(t, ca, "localhost"), ca.Pool())
	paths := writeCreds(t, issueBundle(t, ca), ca.CertPEM)

	if _, err := dialPlugin(t, addr, "wrong.example", paths); err == nil {
		t.Fatal("newCSIPlugin accepted a server certificate issued for another name")
	}
}

// The client presents a certificate from a CA the server does not accept, which
// is what proves the connection is mutually authenticated and not one-way TLS.
func TestMTLSRejectsUntrustedClientCert(t *testing.T) {
	t.Parallel()
	ca, otherCA := testca.New(t, "test-ca"), testca.New(t, "test-ca")
	addr := startTLSServer(t, issueServerCert(t, ca, "localhost"), otherCA.Pool())
	paths := writeCreds(t, issueBundle(t, ca), ca.CertPEM)

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
	ca := testca.New(t, "test-ca")
	paths := writeCreds(t, issueBundle(t, ca), ca.CertPEM)

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
	ca := testca.New(t, "test-ca")
	addr := startTLSServer(t, issueServerCert(t, ca, "unrelated.example"), ca.Pool())
	paths := writeCreds(t, issueBundle(t, ca), ca.CertPEM)

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
	ca := testca.New(t, "test-ca")
	addr := startTLSServer(t, issueServerCertForIP(t, ca, "127.0.0.1"), ca.Pool())
	paths := writeCreds(t, issueBundle(t, ca), ca.CertPEM)

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
	ca1, ca2 := testca.New(t, "test-ca"), testca.New(t, "test-ca")

	// The client bundle stays under ca1, so both servers accept this client and
	// only the server-side trust anchors are under test.
	paths := writeCreds(t, issueBundle(t, ca1), ca1.CertPEM)
	underCA1 := startTLSServer(t, issueServerCert(t, ca1, "localhost"), ca1.Pool())
	underCA2 := startTLSServer(t, issueServerCert(t, ca2, "localhost"), ca1.Pool())

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
	testca.Republish(t, paths.caCert, ca2.CertPEM)

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
