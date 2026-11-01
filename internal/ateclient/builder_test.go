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

package ateclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.ate.dev/substrate/internal/clustertrustbundle"
	certsv1 "k8s.io/api/certificates/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func TestInitTracingDisabledReturnsNoProvider(t *testing.T) {
	tp, err := initTracing(context.Background(), false)
	if err != nil {
		t.Fatalf("initTracing(disabled): %v", err)
	}
	if tp != nil {
		t.Error("initTracing(disabled) returned a provider; want nil so no traceparent is injected")
	}
}

func TestBearerTokenCreds(t *testing.T) {
	md, err := bearerTokenCreds("some-token").GetRequestMetadata(context.Background())
	if err != nil {
		t.Fatalf("GetRequestMetadata: %v", err)
	}
	if got, want := md["authorization"], "Bearer some-token"; got != want {
		t.Errorf("authorization=%q want %q", got, want)
	}

	if _, err := bearerTokenCreds("").GetRequestMetadata(context.Background()); err == nil {
		t.Error("GetRequestMetadata with empty token: want error, got nil")
	}

	if !bearerTokenCreds("some-token").RequireTransportSecurity() {
		t.Error("RequireTransportSecurity() = false, want true")
	}
}

func TestReadBearerToken(t *testing.T) {
	creds, err := readBearerToken(strings.NewReader("some-token\n"))
	if err != nil {
		t.Fatal(err)
	}
	if creds != "some-token" {
		t.Fatalf("credentials = %q, want some-token", creds)
	}
	if _, err := readBearerToken(strings.NewReader(" \n")); err == nil {
		t.Fatal("empty stdin token succeeded")
	}
}

func TestFileBearerTokenCreds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("first-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	creds := fileBearerTokenCreds(path)
	md, err := creds.GetRequestMetadata(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := md["authorization"]; got != "Bearer first-token" {
		t.Fatalf("authorization = %q, want Bearer first-token", got)
	}
	if !creds.RequireTransportSecurity() {
		t.Fatal("RequireTransportSecurity() = false, want true")
	}
}

// testCAPEM generates a self-signed CA and returns its PEM encoding.
// testCA is a self-signed CA together with the key needed to issue leaves
// from it, so a test can assert what a verifier accepts rather than only what
// a pool contains.
type testCA struct {
	pem  []byte
	cert *x509.Certificate
	key  ed25519.PrivateKey
}

func newTestCA(t *testing.T, cn string) testCA {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key for %s: %v", cn, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("creating CA cert for %s: %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA cert for %s: %v", cn, err)
	}
	return testCA{
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		cert: cert,
		key:  priv,
	}
}

// leafFor issues a serving certificate for dnsName from this CA, returned in
// the shape tls.ConnectionState.PeerCertificates carries.
func (ca testCA) leafFor(t *testing.T, dnsName string) []*x509.Certificate {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key for %s: %v", dnsName, err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, pub, ca.key)
	if err != nil {
		t.Fatalf("creating leaf for %s: %v", dnsName, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing leaf for %s: %v", dnsName, err)
	}
	return []*x509.Certificate{leaf}
}

func testCAPEM(t *testing.T, cn string) []byte {
	t.Helper()
	return newTestCA(t, cn).pem
}

// advanceTrustPoolClock moves the trust-pool cache's clock forward for the
// rest of the test, so a TTL expiry can be asserted without waiting for one.
func advanceTrustPoolClock(t *testing.T, d time.Duration) {
	t.Helper()
	prev := trustPoolNow
	t.Cleanup(func() { trustPoolNow = prev })
	trustPoolNow = func() time.Time { return prev().Add(d) }
}

func trustBundle(name, signer string, live bool, pemData []byte) *certsv1.ClusterTrustBundle {
	ctb := &certsv1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: certsv1.ClusterTrustBundleSpec{
			SignerName:  signer,
			TrustBundle: string(pemData),
		},
	}
	if live {
		ctb.ObjectMeta.Labels = map[string]string{"podcert.ate.dev/canarying": "live"}
	}
	return ctb
}

func TestServerTLSConfig(t *testing.T) {
	servicedns1 := newTestCA(t, "servicedns-ca-1")
	servicedns2 := newTestCA(t, "servicedns-ca-2")
	podidentity := newTestCA(t, "podidentity-ca")
	canary := newTestCA(t, "servicedns-ca-canary")
	servicednsCA1, servicednsCA2 := servicedns1.pem, servicedns2.pem
	podidentityCA, canaryCA := podidentity.pem, canary.pem

	objects := []runtime.Object{
		trustBundle("servicedns.podcert.ate.dev:identity:primary-bundle", serviceDNSSignerName, true, append(append([]byte{}, servicednsCA1...), servicednsCA2...)),
		trustBundle("podidentity.podcert.ate.dev:identity:primary-bundle", "podidentity.podcert.ate.dev/identity", true, podidentityCA),
		trustBundle("servicedns.podcert.ate.dev:identity:canary-bundle", serviceDNSSignerName, false, canaryCA),
	}

	for _, version := range []string{"v1", "v1beta1"} {
		t.Run(version, func(t *testing.T) {
			native := make([]runtime.Object, len(objects))
			for i, obj := range objects {
				native[i] = obj
				if version == "v1beta1" {
					native[i] = clustertrustbundle.ToBeta(obj.(*certsv1.ClusterTrustBundle))
				}
			}
			clientset := fake.NewSimpleClientset(native...)
			clientset.Resources = []*metav1.APIResourceList{{GroupVersion: "certificates.k8s.io/" + version, APIResources: []metav1.APIResource{{Name: "clustertrustbundles"}}}}
			cfg, err := serverTLSConfig(context.Background(), clientset, apiServerName())
			if err != nil {
				t.Fatalf("serverTLSConfig: %v", err)
			}

			if got, want := cfg.ServerName, "api.ate-system.svc"; got != want {
				t.Errorf("ServerName=%q want %q", got, want)
			}
			if cfg.MinVersion < tls.VersionTLS13 {
				t.Errorf("MinVersion=%x want at least %x", cfg.MinVersion, tls.VersionTLS13)
			}
			// The anchors are no longer pinned into the config: they are
			// re-read per handshake so a CA rotation applies without a
			// redial (#9518). InsecureSkipVerify is only safe because
			// VerifyConnection does the chain check instead, so assert the
			// pair together — dropping either one must red this test.
			if cfg.RootCAs != nil {
				t.Error("RootCAs is pinned into the config; the anchors must be re-read per handshake")
			}
			if !cfg.InsecureSkipVerify || cfg.VerifyConnection == nil {
				t.Fatalf("InsecureSkipVerify=%v VerifyConnection==nil:%v; want true with a verifier",
					cfg.InsecureSkipVerify, cfg.VerifyConnection == nil)
			}

			// What the pool-equality assertion used to say, said as
			// behaviour: exactly the live servicedns CAs are trusted — not
			// the podidentity bundle, and not the non-live canary bundle.
			for _, tc := range []struct {
				name   string
				chain  []*x509.Certificate
				accept bool
			}{
				{"live servicedns CA 1", servicedns1.leafFor(t, "api.ate-system.svc"), true},
				{"live servicedns CA 2", servicedns2.leafFor(t, "api.ate-system.svc"), true},
				{"other signer's CA", podidentity.leafFor(t, "api.ate-system.svc"), false},
				{"non-live canary CA", canary.leafFor(t, "api.ate-system.svc"), false},
				{"wrong server name", servicedns1.leafFor(t, "elsewhere.ate-system.svc"), false},
			} {
				err := cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: tc.chain})
				if tc.accept && err != nil {
					t.Errorf("VerifyConnection(%s): %v, want accepted", tc.name, err)
				}
				if !tc.accept && err == nil {
					t.Errorf("VerifyConnection(%s): accepted, want rejected", tc.name)
				}
			}

			// A peer that presents nothing is rejected rather than passing
			// for want of a certificate to check.
			if err := cfg.VerifyConnection(tls.ConnectionState{}); err == nil {
				t.Error("VerifyConnection(no peer certificates): accepted, want rejected")
			}
		})
	}
}

// TestServerTLSConfigFollowsRotation is the defect this change is about: a
// client built before a servicedns CA rotation must trust the new anchors
// once the TTL elapses, without being rebuilt.
func TestServerTLSConfigFollowsRotation(t *testing.T) {
	before := newTestCA(t, "servicedns-ca-before")
	after := newTestCA(t, "servicedns-ca-after")

	bundle := trustBundle("servicedns.podcert.ate.dev:identity:primary-bundle", serviceDNSSignerName, true, before.pem)
	clientset := fake.NewSimpleClientset(bundle)
	clientset.Resources = []*metav1.APIResourceList{{GroupVersion: "certificates.k8s.io/v1", APIResources: []metav1.APIResource{{Name: "clustertrustbundles"}}}}

	cfg, err := serverTLSConfig(context.Background(), clientset, apiServerName())
	if err != nil {
		t.Fatalf("serverTLSConfig: %v", err)
	}

	if err := cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: before.leafFor(t, "api.ate-system.svc")}); err != nil {
		t.Fatalf("pre-rotation leaf rejected before the rotation: %v", err)
	}

	// Rotate the published bundle, then let the TTL expire.
	rotated := trustBundle("servicedns.podcert.ate.dev:identity:primary-bundle", serviceDNSSignerName, true, after.pem)
	if err := clientset.Tracker().Update(
		certsv1.SchemeGroupVersion.WithResource("clustertrustbundles"), rotated, ""); err != nil {
		t.Fatalf("rotating the trust bundle: %v", err)
	}

	// Within the TTL the cached anchors still apply: the reload is bounded,
	// not per-handshake.
	if err := cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: after.leafFor(t, "api.ate-system.svc")}); err == nil {
		t.Error("post-rotation leaf accepted inside the TTL; the cache is not bounding the LIST rate")
	}

	// Age the cache out by moving its clock, not by sleeping for the TTL.
	advanceTrustPoolClock(t, trustPoolTTL+time.Second)

	if err := cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: after.leafFor(t, "api.ate-system.svc")}); err != nil {
		t.Errorf("post-rotation leaf still rejected after the TTL elapsed: %v", err)
	}
	if err := cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: before.leafFor(t, "api.ate-system.svc")}); err == nil {
		t.Error("pre-rotation leaf still accepted after the rotation; the retired CA is still trusted")
	}
}

func TestServerTLSConfigErrors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		objects []runtime.Object
	}{
		{name: "no bundles"},
		{
			name: "only other signers",
			objects: []runtime.Object{
				trustBundle("podidentity.podcert.ate.dev:identity:primary-bundle", "podidentity.podcert.ate.dev/identity", true, testCAPEM(t, "podidentity-ca")),
			},
		},
		{
			name: "bundle with no valid certificates",
			objects: []runtime.Object{
				trustBundle("servicedns.podcert.ate.dev:identity:primary-bundle", serviceDNSSignerName, true, []byte("not a pem")),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientset := fake.NewSimpleClientset(tc.objects...)
			clientset.Resources = []*metav1.APIResourceList{{GroupVersion: "certificates.k8s.io/v1", APIResources: []metav1.APIResource{{Name: "clustertrustbundles"}}}}
			if _, err := serverTLSConfig(context.Background(), clientset, apiServerName()); err == nil {
				t.Error("serverTLSConfig: want error, got nil")
			}
		})
	}
}

func TestFallbackPrincipal(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		sa        string
		want      string
	}{
		{"defaults", "", "", "system:serviceaccount:ate-system:ate-client"},
		{"overridden", "custom-ns", "custom-client", "system:serviceaccount:custom-ns:custom-client"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(NamespaceEnv, tc.namespace)
			t.Setenv(ClientServiceAccountEnv, tc.sa)
			if got := FallbackPrincipal(); got != tc.want {
				t.Errorf("FallbackPrincipal() = %q, want %q", got, tc.want)
			}
		})
	}
}
