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

package podidentitysigner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/localca"
	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/utils/ptr"
)

// fixedClock is a local clock.PassiveClock rather than
// k8s.io/utils/clock/testing.FakePassiveClock, because that package is not in
// the vendor tree and pulling it in to get two methods would make this change a
// vendor diff.
type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time                  { return c.now }
func (c fixedClock) Since(t time.Time) time.Duration { return c.now.Sub(t) }

// The assertions here are on the issued certificate as a verifying relying
// party would see it -- parsed out of the PEM chain in the PCR status and
// checked against the CA that supposedly signed it. A signer test that only
// asserts "MakeCert returned nil" passes just as happily when the SAN names the
// wrong workload, which is the failure that actually matters here.

const (
	testNamespace = "test-ns"
	testPodName   = "test-pod"
	testPodUID    = types.UID("pod-uid-1")
	testSAName    = "test-sa"
)

var testNow = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

func testPod(saName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testPodName,
			Namespace: testNamespace,
			UID:       testPodUID,
		},
		Spec: corev1.PodSpec{ServiceAccountName: saName},
	}
}

func testPCR(t *testing.T, saName string, podUID types.UID, maxExpirationSeconds *int32) *certsv1beta1.PodCertificateRequest {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate subject key: %v", err)
	}
	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal subject key: %v", err)
	}
	return &certsv1beta1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Name: "pcr-1", Namespace: testNamespace},
		Spec: certsv1beta1.PodCertificateRequestSpec{
			SignerName:           Name,
			PodName:              testPodName,
			PodUID:               podUID,
			ServiceAccountName:   saName,
			PKIXPublicKey:        pkix,
			MaxExpirationSeconds: maxExpirationSeconds,
		},
	}
}

func newTestImpl(t *testing.T, objs ...runtime.Object) (*Impl, *fake.Clientset, *localca.CA) {
	t.Helper()
	ca, err := localca.GenerateED25519CA("test-ca")
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	kc := fake.NewSimpleClientset(objs...)
	impl := NewImpl(kc, &localca.Pool{CAs: []*localca.CA{ca}}, fixedClock{now: testNow})
	return impl, kc, ca
}

// issuedCert runs MakeCert and returns the leaf certificate as it lands in the
// PCR status, i.e. after a full PEM round-trip rather than from the template.
func issuedCert(t *testing.T, impl *Impl, kc *fake.Clientset, pcr *certsv1beta1.PodCertificateRequest) (*x509.Certificate, *certsv1beta1.PodCertificateRequest) {
	t.Helper()
	if err := impl.MakeCert(context.Background(), pcr); err != nil {
		t.Fatalf("MakeCert: %v", err)
	}
	got, err := kc.CertificatesV1beta1().PodCertificateRequests(testNamespace).Get(
		context.Background(), pcr.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("read back PCR: %v", err)
	}
	block, _ := pem.Decode([]byte(got.Status.CertificateChain))
	if block == nil {
		t.Fatal("PCR status carries no PEM certificate")
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("PEM block type = %q, want CERTIFICATE", block.Type)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}
	return leaf, got
}

func TestMakeCertIssuesCertVerifiableAgainstTheCA(t *testing.T) {
	pcr := testPCR(t, testSAName, testPodUID, ptr.To(int32(3600)))
	impl, kc, ca := newTestImpl(t, testPod(testSAName), pcr)

	leaf, _ := issuedCert(t, impl, kc, pcr)

	// The property a relying party actually checks.
	if err := leaf.CheckSignatureFrom(ca.RootCertificate); err != nil {
		t.Errorf("issued cert does not verify against the CA root: %v", err)
	}
}

func TestMakeCertSANIsTheSPIFFEIDForTheServiceAccount(t *testing.T) {
	pcr := testPCR(t, testSAName, testPodUID, ptr.To(int32(3600)))
	impl, kc, _ := newTestImpl(t, testPod(testSAName), pcr)

	leaf, _ := issuedCert(t, impl, kc, pcr)

	if len(leaf.URIs) != 1 {
		t.Fatalf("cert carries %d URI SANs, want exactly 1", len(leaf.URIs))
	}
	want := "spiffe://cluster.local/ns/" + testNamespace + "/sa/" + testSAName
	if got := leaf.URIs[0].String(); got != want {
		t.Errorf("SPIFFE ID = %q, want %q", got, want)
	}
	// A cert with the right SAN and the wrong usage bits is still the wrong
	// credential, so pin both.
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %v, want DigitalSignature only", leaf.KeyUsage)
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want [ClientAuth]", leaf.ExtKeyUsage)
	}
}

// TestMakeCertRejectsPodUIDMismatch covers the anti-spoofing check: without it,
// a request naming a pod that has since been replaced would be issued an
// identity for the new pod. The second assertion is the load-bearing half --
// rejecting must also mean NOT issuing, and an early return that forgot to
// return would still satisfy "MakeCert returned an error".
func TestMakeCertRejectsPodUIDMismatch(t *testing.T) {
	pcr := testPCR(t, testSAName, types.UID("some-other-uid"), ptr.To(int32(3600)))
	impl, kc, _ := newTestImpl(t, testPod(testSAName), pcr)

	err := impl.MakeCert(context.Background(), pcr)
	if err == nil {
		t.Fatal("MakeCert issued a certificate for a PCR whose pod UID does not match")
	}
	if !strings.Contains(err.Error(), "UID mismatch") {
		t.Errorf("error = %v, want it to name the UID mismatch", err)
	}

	got, getErr := kc.CertificatesV1beta1().PodCertificateRequests(testNamespace).Get(
		context.Background(), pcr.Name, metav1.GetOptions{})
	if getErr != nil {
		t.Fatalf("read back PCR: %v", getErr)
	}
	if got.Status.CertificateChain != "" {
		t.Error("a certificate was issued despite the UID mismatch")
	}
}

func TestMakeCertLifetime(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		maxExpirationSeconds int32
		wantLifetime         time.Duration
	}{
		{"clamped to the 24h ceiling", int32((48 * time.Hour).Seconds()), 24 * time.Hour},
		{"shorter request is honoured", int32(time.Hour.Seconds()), time.Hour},
		{"exactly the ceiling", int32((24 * time.Hour).Seconds()), 24 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pcr := testPCR(t, testSAName, testPodUID, ptr.To(tc.maxExpirationSeconds))
			impl, kc, _ := newTestImpl(t, testPod(testSAName), pcr)

			leaf, got := issuedCert(t, impl, kc, pcr)

			// notBefore is backdated two minutes to absorb clock skew between
			// the signer and the verifying node.
			wantNotBefore := testNow.Add(-2 * time.Minute)
			if !leaf.NotBefore.Equal(wantNotBefore) {
				t.Errorf("NotBefore = %v, want %v", leaf.NotBefore, wantNotBefore)
			}
			if got := leaf.NotAfter.Sub(leaf.NotBefore); got != tc.wantLifetime {
				t.Errorf("lifetime = %v, want %v", got, tc.wantLifetime)
			}
			// The refresh point has to be strictly inside the validity window,
			// otherwise the client never gets a chance to rotate.
			wantRefresh := leaf.NotAfter.Add(-30 * time.Minute)
			if !got.Status.BeginRefreshAt.Time.Equal(wantRefresh) {
				t.Errorf("BeginRefreshAt = %v, want %v", got.Status.BeginRefreshAt, wantRefresh)
			}
			if !got.Status.BeginRefreshAt.Time.After(leaf.NotBefore) {
				t.Error("BeginRefreshAt is not inside the validity window")
			}
		})
	}
}

func TestMakeCertMarksTheRequestIssued(t *testing.T) {
	pcr := testPCR(t, testSAName, testPodUID, ptr.To(int32(3600)))
	impl, kc, _ := newTestImpl(t, testPod(testSAName), pcr)

	_, got := issuedCert(t, impl, kc, pcr)

	if len(got.Status.Conditions) != 1 {
		t.Fatalf("status carries %d conditions, want 1", len(got.Status.Conditions))
	}
	cond := got.Status.Conditions[0]
	if cond.Type != certsv1beta1.PodCertificateRequestConditionTypeIssued {
		t.Errorf("condition type = %q, want Issued", cond.Type)
	}
	if cond.Status != metav1.ConditionTrue {
		t.Errorf("condition status = %q, want True", cond.Status)
	}
	if !cond.LastTransitionTime.Time.Equal(testNow) {
		t.Errorf("LastTransitionTime = %v, want the clock's now (%v)", cond.LastTransitionTime, testNow)
	}
}

// The two tests below assert WHICH error comes back, not merely that one does.
// Both started out asserting only non-nil and both let a mutant through: with
// the pod-Get error swallowed, the fake returns an empty Pod whose UID is "",
// so the call still fails -- as a bogus "UID mismatch" rather than as the API
// error it was. With the public-key error swallowed, the nil key fails later
// inside x509.CreateCertificate. Each still fails closed, which is the property
// that matters most, but an operator reading the wrong cause is a real cost and
// a weak assertion is what hid it.

func TestMakeCertFailsWhenThePodIsGone(t *testing.T) {
	pcr := testPCR(t, testSAName, testPodUID, ptr.To(int32(3600)))
	impl, _, _ := newTestImpl(t, pcr) // no pod seeded

	err := impl.MakeCert(context.Background(), pcr)
	if err == nil {
		t.Fatal("MakeCert succeeded with no pod present; a missing pod must fail closed")
	}
	if !strings.Contains(err.Error(), "while getting pod") {
		t.Errorf("error = %v, want it to name the failed pod lookup", err)
	}
	if strings.Contains(err.Error(), "UID mismatch") {
		t.Errorf("error = %v; a missing pod is being reported as a UID mismatch", err)
	}
}

func TestMakeCertFailsWithoutASubjectPublicKey(t *testing.T) {
	pcr := testPCR(t, testSAName, testPodUID, ptr.To(int32(3600)))
	pcr.Spec.PKIXPublicKey = nil
	impl, _, _ := newTestImpl(t, testPod(testSAName), pcr)

	err := impl.MakeCert(context.Background(), pcr)
	if err == nil {
		t.Fatal("MakeCert succeeded with no subject public key")
	}
	// Deliberately not just "public key": if the PublicKey error were swallowed,
	// the nil key reaches x509.CreateCertificate, which rejects it as an
	// "unsupported public key type" -- a message that matches that looser
	// substring just as well. The point of the assertion is that the request is
	// rejected up front rather than at signing time.
	if !strings.Contains(err.Error(), "does not contain a public key") {
		t.Errorf("error = %v, want the up-front missing-public-key rejection", err)
	}
	if strings.Contains(err.Error(), "while signing subject cert") {
		t.Errorf("error = %v; the missing key reached the signing call instead of "+
			"being rejected when it was read", err)
	}
}

// TestMakeCertTrustsTheRequestedServiceAccountName documents CURRENT behaviour
// and is the reason this file exists rather than a bug report.
//
// MakeCert fetches the pod -- the comment above the call says "to get its
// ServiceAccount" -- but then builds the SPIFFE ID from
// pcr.Spec.ServiceAccountName and never reads pod.Spec.ServiceAccountName. So
// the identity in the issued certificate comes from the request, and the pod
// fetch only validates the UID.
//
// Whether that is exploitable depends on something outside this package: if the
// API server's PodCertificateRequest admission already rejects a spec whose
// serviceAccountName disagrees with the named pod, the signer is merely relying
// on a check it does not make itself. If it does not, this issues a certificate
// for an identity the requester asserted. Worth confirming upstream before
// changing anything -- but the defence-in-depth version costs one comparison
// against a pod the code has already fetched.
func TestMakeCertTrustsTheRequestedServiceAccountName(t *testing.T) {
	pcr := testPCR(t, "requested-sa", testPodUID, ptr.To(int32(3600)))
	impl, kc, _ := newTestImpl(t, testPod("actual-pod-sa"), pcr)

	leaf, _ := issuedCert(t, impl, kc, pcr)

	got := leaf.URIs[0].String()
	if strings.Contains(got, "actual-pod-sa") {
		t.Fatalf("SPIFFE ID = %q -- the signer now uses the pod's ServiceAccount. "+
			"That is a fix, not a regression: update this test to assert it.", got)
	}
	if want := "spiffe://cluster.local/ns/" + testNamespace + "/sa/requested-sa"; got != want {
		t.Errorf("SPIFFE ID = %q, want %q", got, want)
	}
}

func TestSignerName(t *testing.T) {
	impl, _, _ := newTestImpl(t)
	if got := impl.SignerName(); got != Name {
		t.Errorf("SignerName() = %q, want %q", got, Name)
	}
}

func TestDesiredClusterTrustBundlesCarriesTheCARoots(t *testing.T) {
	impl, _, ca := newTestImpl(t)

	ctbs := impl.DesiredClusterTrustBundles()
	if len(ctbs) != 1 {
		t.Fatalf("got %d trust bundles, want 1", len(ctbs))
	}
	ctb := ctbs[0]
	if ctb.Name != CTBPrefix+"primary-bundle" {
		t.Errorf("name = %q, want %q", ctb.Name, CTBPrefix+"primary-bundle")
	}
	if ctb.Spec.SignerName != Name {
		t.Errorf("signer name = %q, want %q", ctb.Spec.SignerName, Name)
	}
	if got := ctb.Labels["podcert.ate.dev/canarying"]; got != "live" {
		t.Errorf("canarying label = %q, want live", got)
	}

	// The bundle is only useful if the bytes in it are the CA that signs -- so
	// parse them back out rather than checking the string is non-empty.
	block, rest := pem.Decode([]byte(ctb.Spec.TrustBundle))
	if block == nil {
		t.Fatal("trust bundle contains no PEM block")
	}
	if len(rest) != 0 {
		t.Errorf("trust bundle has %d trailing bytes, want exactly one CA", len(rest))
	}
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse trust bundle cert: %v", err)
	}
	if !parsed.Equal(ca.RootCertificate) {
		t.Error("trust bundle does not contain the signing CA's root certificate")
	}
}
