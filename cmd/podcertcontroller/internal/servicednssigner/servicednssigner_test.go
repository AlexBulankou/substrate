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
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
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
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"
)

// As in podidentitysigner_test.go, the assertions are on the certificate a
// relying party would see -- parsed back out of the PEM chain in the PCR status
// -- rather than on MakeCert's error being nil. The DNS SAN set is the whole
// output of this signer, so "it returned no error" says almost nothing.

// MakeCert reads the wall clock directly rather than through an injected
// clock, so the validity-window assertions below are stated as tolerances
// around the moment the test ran.  A tolerance still pins the two things that
// matter -- the backdate and the lifetime arithmetic -- because the slack is
// far smaller than either.
const clockSlack = 2 * time.Minute

const (
	testNamespace = "test-ns"
	testPodName   = "test-pod"
	testPodUID    = types.UID("pod-uid-1")
)

var testLabels = map[string]string{"app": "target"}

// nearly reports whether got is within clockSlack of want.
func nearly(got, want time.Time) bool {
	d := got.Sub(want)
	if d < 0 {
		d = -d
	}
	return d <= clockSlack
}

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
	ca, err := localca.GenerateCA("test-ca", localca.KeyTypeED25519, 24*time.Hour)
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	kc := fake.NewSimpleClientset(objs...)
	pool := &localca.ConcretePool{CAs: []*localca.CA{ca}, ActiveForSigning: ca.ID}
	return NewImpl(kc, pool), kc, ca
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

	// The ExternalName service is the only Service in the namespace, so
	// skipping it leaves no DNS names and MakeCert refuses.  Assert on the
	// refusal rather than on an empty SAN set: this way the test still fails
	// if the type filter is dropped, because then the ExternalName service
	// WOULD produce a SAN and the call would succeed.
	err := impl.MakeCert(context.Background(), pcr)
	if err == nil {
		t.Fatal("MakeCert issued a cert naming an ExternalName service")
	}
	if !strings.Contains(err.Error(), "not (yet) selected by any Service") {
		t.Errorf("error = %v, want the no-DNS-SAN refusal", err)
	}
	assertNotIssued(t, kc, pcr)
}

// assertNotIssued checks that a refused request left no status behind.  A
// signer that writes an Issued condition and then returns an error would give
// the requester a cached, useless certificate for the next 24 hours.
func assertNotIssued(t *testing.T, kc *fake.Clientset, pcr *certsv1beta1.PodCertificateRequest) {
	t.Helper()
	got, err := kc.CertificatesV1beta1().PodCertificateRequests(testNamespace).Get(
		context.Background(), pcr.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get PCR: %v", err)
	}
	if len(got.Status.Conditions) != 0 {
		t.Errorf("refused request carries conditions %v, want none", got.Status.Conditions)
	}
	if got.Status.CertificateChain != "" {
		t.Error("refused request carries a certificate chain")
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

			// Neither half matching means no SANs, which MakeCert now
			// refuses outright.  The failure mode this guards against is the
			// opposite one: if either comparison were dropped, the
			// non-matching pod would satisfy the other half, a SAN would be
			// produced, and the call would succeed.
			err := impl.MakeCert(context.Background(), pcr)
			if err == nil {
				t.Fatal("MakeCert issued a cert for a pod that does not match the request")
			}
			if !strings.Contains(err.Error(), "not (yet) selected by any Service") {
				t.Errorf("error = %v, want the no-DNS-SAN refusal", err)
			}
			assertNotIssued(t, kc, pcr)
		})
	}
}

// TestMakeCertRefusesWhenNothingSelectsThePod pins the transient-error path.
//
// Unlike podidentitysigner, this signer never fetches the pod directly -- the
// name/UID comparison happens per-service -- so a request naming a pod that
// does not exist, or whose UID has been recycled, reaches the end of the loop
// with an empty DNS name set.  Returning an error there rather than issuing is
// what keeps a useless SAN-less certificate from being marked Issued and then
// cached by the requester for the certificate's whole lifetime.
//
// The error has to be transient rather than a denial: the ordinary way to hit
// this is a pod whose covering Service has not been created yet.
func TestMakeCertRefusesWhenNothingSelectsThePod(t *testing.T) {
	pcr := testPCR(t)
	impl, kc, _ := newTestImpl(t, pcr) // no pods, no services

	err := impl.MakeCert(context.Background(), pcr)
	if err == nil {
		t.Fatal("MakeCert issued a SAN-less certificate for an unsatisfiable request")
	}
	if !strings.Contains(err.Error(), "not (yet) selected by any Service") {
		t.Errorf("error = %v, want the no-DNS-SAN refusal", err)
	}
	// Naming the pod in the error is what makes it actionable; without it the
	// operator sees a bare refusal with nothing to look up.
	if !strings.Contains(err.Error(), testPodName) {
		t.Errorf("error = %v, want it to name the pod", err)
	}
	assertNotIssued(t, kc, pcr)
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

			before := time.Now()
			leaf, got := issuedCert(t, impl, kc, pcr)

			// The backdate is what lets a verifier with a slightly slow clock
			// accept a freshly issued cert, so it is worth pinning even
			// against a wall clock.
			if wantNotBefore := before.Add(-2 * time.Minute); !nearly(leaf.NotBefore, wantNotBefore) {
				t.Errorf("NotBefore = %v, want within %v of %v", leaf.NotBefore, clockSlack, wantNotBefore)
			}
			// The lifetime itself is exact: both endpoints derive from the
			// same notBefore, so the wall clock cancels out.
			if lifetime := leaf.NotAfter.Sub(leaf.NotBefore); lifetime != tc.wantLifetime {
				t.Errorf("lifetime = %v, want %v", lifetime, tc.wantLifetime)
			}
			// Compared at second granularity: the status field keeps the
			// nanoseconds MakeCert computed, while leaf.NotAfter has been
			// through an x509 encoding that only carries seconds.  The
			// 30-minute offset is what the assertion is about, and it is
			// unaffected.
			wantRefresh := leaf.NotAfter.Add(-30 * time.Minute)
			if gotRefresh := got.Status.BeginRefreshAt.Time.Truncate(time.Second); !gotRefresh.Equal(wantRefresh) {
				t.Errorf("BeginRefreshAt = %v, want %v", gotRefresh, wantRefresh)
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
	// A selecting Service is required, not incidental: the no-DNS-SAN refusal
	// runs before the public key is read, so without one this test would pass
	// on the wrong error.
	impl, _, _ := newTestImpl(t,
		testPod(testPodName, testPodUID, testLabels),
		testService("svc-a", corev1.ServiceTypeClusterIP, testLabels),
		pcr)

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

	ctbs, err := impl.DesiredClusterTrustBundles()
	if err != nil {
		t.Fatalf("DesiredClusterTrustBundles: %v", err)
	}
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

// failingPool is a localca.Pool whose two methods fail on demand, so that the
// signer's own error wrapping can be checked without a real CA.
type failingPool struct {
	createErr error
	anchorErr error
}

var _ localca.Pool = (*failingPool)(nil)

func (p *failingPool) CreateCertificate(*x509.Certificate, crypto.PublicKey) ([][]byte, error) {
	return nil, p.createErr
}

func (p *failingPool) TrustAnchors() ([]*x509.Certificate, error) {
	return nil, p.anchorErr
}

// TestMakeCertReportsWhichAPICallFailed asserts on the wrapper text of each
// error return, not merely that an error came back.
//
// All three calls here are against the same fake clientset, so an
// indiscriminate "return err" would satisfy a test that only checked for
// non-nil.  What an operator actually needs from a failed signing is which
// call failed --- the Services list, the per-Service Pods list, or the status
// write --- because each points at a different problem.
func TestMakeCertReportsWhichAPICallFailed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		verb     string
		resource string
		wantText string
	}{
		{"listing services", "list", "services", "while listing services"},
		{"listing pods for a service", "list", "pods", "while selecting pods for service"},
		{"writing the issued status", "update", "podcertificaterequests", "while updating PodCertificateRequest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pcr := testPCR(t)
			impl, kc, _ := newTestImpl(t,
				testPod(testPodName, testPodUID, testLabels),
				testService("svc-a", corev1.ServiceTypeClusterIP, testLabels),
				pcr)
			injected := errors.New("injected API failure")
			kc.PrependReactor(tc.verb, tc.resource, func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, injected
			})

			err := impl.MakeCert(context.Background(), pcr)
			if err == nil {
				t.Fatalf("MakeCert succeeded with %s %s failing", tc.verb, tc.resource)
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantText)
			}
			// The underlying cause has to survive the wrapping, or the
			// operator sees the stage and not the reason.
			if !errors.Is(err, injected) {
				t.Errorf("error = %v, want it to wrap the injected cause", err)
			}
		})
	}
}

// The per-Service pods list is the one error return that names the object it
// was working on.  Losing that detail turns a namespace with many Services
// into a guessing game, so it is pinned separately.
func TestMakeCertNamesTheServiceWhosePodListFailed(t *testing.T) {
	pcr := testPCR(t)
	impl, kc, _ := newTestImpl(t,
		testPod(testPodName, testPodUID, testLabels),
		testService("the-one-that-failed", corev1.ServiceTypeClusterIP, testLabels),
		pcr)
	kc.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("injected API failure")
	})

	err := impl.MakeCert(context.Background(), pcr)
	if err == nil {
		t.Fatal("MakeCert succeeded with the pods list failing")
	}
	if !strings.Contains(err.Error(), testNamespace+"/the-one-that-failed") {
		t.Errorf("error = %v, want it to name the Service", err)
	}
}

func TestMakeCertReportsASigningFailure(t *testing.T) {
	pcr := testPCR(t)
	injected := errors.New("injected signing failure")
	kc := fake.NewSimpleClientset(
		testPod(testPodName, testPodUID, testLabels),
		testService("svc-a", corev1.ServiceTypeClusterIP, testLabels),
		pcr)
	impl := NewImpl(kc, &failingPool{createErr: injected})

	err := impl.MakeCert(context.Background(), pcr)
	if err == nil {
		t.Fatal("MakeCert succeeded with the CA pool refusing to sign")
	}
	if !strings.Contains(err.Error(), "while signing certificate") {
		t.Errorf("error = %v, want the signing-stage wrapper", err)
	}
	if !errors.Is(err, injected) {
		t.Errorf("error = %v, want it to wrap the injected cause", err)
	}
	assertNotIssued(t, kc, pcr)
}

// TestDesiredClusterTrustBundlesReportsATrustAnchorFailure covers the branch
// that makes this method fallible at all.
//
// It matters more than a typical error path: the caller reconciles the
// returned set against the live ClusterTrustBundles, so a nil-and-no-error
// return here would read as "this signer wants no trust bundles" and could
// delete the bundle that relying parties are using to verify certificates.
func TestDesiredClusterTrustBundlesReportsATrustAnchorFailure(t *testing.T) {
	injected := errors.New("injected trust-anchor failure")
	impl := NewImpl(fake.NewSimpleClientset(), &failingPool{anchorErr: injected})

	ctbs, err := impl.DesiredClusterTrustBundles()
	if err == nil {
		t.Fatal("DesiredClusterTrustBundles succeeded with the CA pool failing")
	}
	if !strings.Contains(err.Error(), "while retrieving CA pool trust anchors") {
		t.Errorf("error = %v, want the trust-anchor-stage wrapper", err)
	}
	if !errors.Is(err, injected) {
		t.Errorf("error = %v, want it to wrap the injected cause", err)
	}
	if ctbs != nil {
		t.Errorf("got %d trust bundles alongside the error, want none", len(ctbs))
	}
}
