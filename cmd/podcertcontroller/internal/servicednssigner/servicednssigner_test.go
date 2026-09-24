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

package servicednssigner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"sort"
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

// As in podidentitysigner_test.go, the assertions are on the certificate a
// relying party would see -- parsed back out of the PEM chain in the PCR status
// -- rather than on MakeCert's error being nil. The DNS SAN set is the whole
// output of this signer, so "it returned no error" says almost nothing.

// fixedClock is a local clock.PassiveClock: k8s.io/utils/clock/testing is not
// in the vendor tree, and pulling it in for two methods would make this change
// a vendor diff.
type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time                  { return c.now }
func (c fixedClock) Since(t time.Time) time.Duration { return c.now.Sub(t) }

const (
	testNamespace = "test-ns"
	testPodName   = "test-pod"
	testPodUID    = types.UID("pod-uid-1")
)

var (
	testNow    = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	testLabels = map[string]string{"app": "target"}
)

func testPod(name string, uid types.UID, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
			UID:       uid,
			Labels:    labels,
		},
	}
}

func testService(name string, typ corev1.ServiceType, selector map[string]string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: testNamespace},
		Spec:       corev1.ServiceSpec{Type: typ, Selector: selector},
	}
}

func testPCR(t *testing.T) *certsv1beta1.PodCertificateRequest {
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
			PodUID:               testPodUID,
			ServiceAccountName:   "test-sa",
			PKIXPublicKey:        pkix,
			MaxExpirationSeconds: ptr.To(int32(3600)),
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
	return NewImpl(kc, &localca.Pool{CAs: []*localca.CA{ca}}, fixedClock{now: testNow}), kc, ca
}

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
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}
	return leaf, got
}

func TestMakeCertIssuesCertVerifiableAgainstTheCA(t *testing.T) {
	pcr := testPCR(t)
	impl, kc, ca := newTestImpl(t,
		testPod(testPodName, testPodUID, testLabels),
		testService("svc-a", corev1.ServiceTypeClusterIP, testLabels),
		pcr)

	leaf, _ := issuedCert(t, impl, kc, pcr)

	if err := leaf.CheckSignatureFrom(ca.RootCertificate); err != nil {
		t.Errorf("issued cert does not verify against the CA root: %v", err)
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %v, want DigitalSignature only", leaf.KeyUsage)
	}
	// This signer's certs are used on both ends of a mesh connection, unlike
	// podidentitysigner's client-only certs.
	wantEKU := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	if len(leaf.ExtKeyUsage) != len(wantEKU) {
		t.Fatalf("ExtKeyUsage = %v, want %v", leaf.ExtKeyUsage, wantEKU)
	}
	for i, want := range wantEKU {
		if leaf.ExtKeyUsage[i] != want {
			t.Errorf("ExtKeyUsage[%d] = %v, want %v", i, leaf.ExtKeyUsage[i], want)
		}
	}
}

// TestMakeCertDNSNamesCoverOnlySelectingServices is the core of this signer:
// the SAN set must name every Service that selects the pod and nothing else.
// A signer that over-names lets a pod impersonate a service it is not part of.
func TestMakeCertDNSNamesCoverOnlySelectingServices(t *testing.T) {
	otherLabels := map[string]string{"app": "other"}
	pcr := testPCR(t)
	impl, kc, _ := newTestImpl(t,
		testPod(testPodName, testPodUID, testLabels),
		testPod("other-pod", types.UID("other-uid"), otherLabels),
		testService("selects-us", corev1.ServiceTypeClusterIP, testLabels),
		testService("also-selects-us", corev1.ServiceTypeNodePort, testLabels),
		testService("selects-someone-else", corev1.ServiceTypeClusterIP, otherLabels),
		pcr)

	leaf, _ := issuedCert(t, impl, kc, pcr)

	got := append([]string(nil), leaf.DNSNames...)
	sort.Strings(got)
	want := []string{
		"also-selects-us." + testNamespace + ".svc",
		"selects-us." + testNamespace + ".svc",
	}
	if len(got) != len(want) {
		t.Fatalf("DNS names = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("DNS names = %v, want %v", got, want)
			break
		}
	}
}

// TestMakeCertSkipsServiceTypesThatDoNotSelectPods pins the type filter.
// ExternalName services have no selector and name something outside the
// cluster, so granting a pod that DNS name would be a real over-issue.
func TestMakeCertSkipsServiceTypesThatDoNotSelectPods(t *testing.T) {
	pcr := testPCR(t)
	impl, kc, _ := newTestImpl(t,
		testPod(testPodName, testPodUID, testLabels),
		testService("external", corev1.ServiceTypeExternalName, testLabels),
		pcr)

	leaf, _ := issuedCert(t, impl, kc, pcr)

	for _, name := range leaf.DNSNames {
		if strings.HasPrefix(name, "external.") {
			t.Errorf("cert names the ExternalName service: %v", leaf.DNSNames)
		}
	}
}

// TestMakeCertRequiresBothPodNameAndUID covers the two halves of the match
// separately, so that dropping either comparison is caught. A same-name pod
// with a different UID is the recycled-name case; a different pod with a
// coincidentally matching UID is the weaker half but is cheap to pin.
func TestMakeCertRequiresBothPodNameAndUID(t *testing.T) {
	for _, tc := range []struct {
		name    string
		podName string
		podUID  types.UID
	}{
		{"UID differs", testPodName, types.UID("recycled-name-different-uid")},
		{"name differs", "some-other-pod", testPodUID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pcr := testPCR(t)
			impl, kc, _ := newTestImpl(t,
				testPod(tc.podName, tc.podUID, testLabels),
				testService("svc-a", corev1.ServiceTypeClusterIP, testLabels),
				pcr)

			leaf, _ := issuedCert(t, impl, kc, pcr)

			if len(leaf.DNSNames) != 0 {
				t.Errorf("cert names %v for a pod that does not match the request", leaf.DNSNames)
			}
		})
	}
}

// TestMakeCertIssuesASANlessCertWhenNothingSelectsThePod documents CURRENT
// behaviour, and is the notable divergence from podidentitysigner.
//
// That signer fetches the pod and hard-fails on a UID mismatch. This one has no
// such check: the pod name/UID comparison happens per-service, so a request
// naming a pod that does not exist -- or whose UID has been recycled -- simply
// produces an empty DNS name set, and the PCR is then marked Issued with a
// certificate that carries no SANs at all.
//
// A SAN-less certificate is not directly dangerous (nothing will match it), but
// "Issued" is the wrong answer to a request that could not be satisfied: the
// requester gets a success it cannot use, and the mismatch that caused it is
// never surfaced. Pinned rather than changed, because denying instead would be
// a behaviour change with callers to check first.
func TestMakeCertIssuesASANlessCertWhenNothingSelectsThePod(t *testing.T) {
	pcr := testPCR(t)
	impl, kc, _ := newTestImpl(t, pcr) // no pods, no services

	leaf, got := issuedCert(t, impl, kc, pcr)

	if len(leaf.DNSNames) != 0 {
		t.Errorf("DNS names = %v, want none", leaf.DNSNames)
	}
	if len(got.Status.Conditions) != 1 ||
		got.Status.Conditions[0].Type != certsv1beta1.PodCertificateRequestConditionTypeIssued ||
		got.Status.Conditions[0].Status != metav1.ConditionTrue {
		t.Fatalf("conditions = %v; this signer marks an unsatisfiable request Issued today",
			got.Status.Conditions)
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			pcr := testPCR(t)
			pcr.Spec.MaxExpirationSeconds = ptr.To(tc.maxExpirationSeconds)
			impl, kc, _ := newTestImpl(t,
				testPod(testPodName, testPodUID, testLabels),
				testService("svc-a", corev1.ServiceTypeClusterIP, testLabels),
				pcr)

			leaf, got := issuedCert(t, impl, kc, pcr)

			wantNotBefore := testNow.Add(-2 * time.Minute)
			if !leaf.NotBefore.Equal(wantNotBefore) {
				t.Errorf("NotBefore = %v, want %v", leaf.NotBefore, wantNotBefore)
			}
			if lifetime := leaf.NotAfter.Sub(leaf.NotBefore); lifetime != tc.wantLifetime {
				t.Errorf("lifetime = %v, want %v", lifetime, tc.wantLifetime)
			}
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

func TestMakeCertFailsWithoutASubjectPublicKey(t *testing.T) {
	pcr := testPCR(t)
	pcr.Spec.PKIXPublicKey = nil
	impl, _, _ := newTestImpl(t, testPod(testPodName, testPodUID, testLabels), pcr)

	err := impl.MakeCert(context.Background(), pcr)
	if err == nil {
		t.Fatal("MakeCert succeeded with no subject public key")
	}
	// Not just "public key": if the read error were swallowed, the nil key
	// reaches x509.CreateCertificate, whose "unsupported public key type"
	// matches that looser substring too. Same trap as in podidentitysigner.
	if !strings.Contains(err.Error(), "does not contain a public key") {
		t.Errorf("error = %v, want the up-front missing-public-key rejection", err)
	}
	if strings.Contains(err.Error(), "while signing subject cert") {
		t.Errorf("error = %v; the missing key reached the signing call", err)
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
