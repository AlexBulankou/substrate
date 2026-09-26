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

package signercontroller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/cmd/podcertcontroller/internal/podcertificate"
	"github.com/agent-substrate/substrate/cmd/podcertcontroller/internal/rendezvous"
	certsv1 "k8s.io/api/certificates/v1"
	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
)

// The assertions here are on what a reader of the cluster would see — the
// object that exists afterwards, the verb that reached the API — not on "the
// function returned". ensureBundles returns nothing at all, so a shape-based
// test of it would assert nothing.
//
// Four statements are deliberately left uncovered, because reaching them needs
// a hand-built invalid value rather than a realistic input. Recorded here so
// the next reader does not re-derive it:
//
//   - the three key-func error returns in the informer handlers. A running
//     informer only ever delivers typed API objects and (on delete)
//     tombstones, all of which key successfully; the branch needs a
//     non-object pushed past the informer's own typing.
//   - the non-NotFound error return in processNextWorkItem's GetCached. The
//     lister reads an in-memory indexer, whose only failure mode for a
//     well-formed key is NotFound.

const testSignerName = "ate.dev/test-signer"

// fakeSigner EMBEDS SignerImpl rather than implementing it. A method the test
// did not arrange for panics on the nil interface instead of returning a
// plausible zero value, so a controller that starts calling something new
// fails loudly rather than silently taking the zero-valued branch.
type fakeSigner struct {
	SignerImpl

	signerName string

	desiredCTBs    []*certsv1beta1.ClusterTrustBundle
	desiredCTBsErr error

	makeCertErr error
	madeCerts   []string
}

func (f *fakeSigner) SignerName() string { return f.signerName }

func (f *fakeSigner) DesiredClusterTrustBundles() ([]*certsv1beta1.ClusterTrustBundle, error) {
	return f.desiredCTBs, f.desiredCTBsErr
}

func (f *fakeSigner) MakeCert(_ context.Context, pcr *certsv1beta1.PodCertificateRequest) error {
	f.madeCerts = append(f.madeCerts, pcr.ObjectMeta.Namespace+"/"+pcr.ObjectMeta.Name)
	return f.makeCertErr
}

// fakeHasher answers the rendezvous question. assigned==nil means "everything
// is mine", the single-replica case.
type fakeHasher struct {
	assigned map[string]bool
	asked    []string
}

func (f *fakeHasher) AssignedToThisReplica(_ context.Context, item string) bool {
	f.asked = append(f.asked, item)
	if f.assigned == nil {
		return true
	}
	return f.assigned[item]
}

// newTestController wires a Controller over a fake clientset whose discovery
// serves the stable PCR API, and seeds the informer cache directly — the
// controller reads PCRs through GetCached, never through the API.
func newTestController(t *testing.T, signer *fakeSigner, hasher *fakeHasher, cached ...*certsv1.PodCertificateRequest) (*Controller, *fake.Clientset) {
	t.Helper()

	kc := fake.NewSimpleClientset()
	kc.Resources = []*metav1.APIResourceList{{
		GroupVersion: certsv1.SchemeGroupVersion.String(),
		APIResources: []metav1.APIResource{{Name: "podcertificaterequests", Namespaced: true}},
	}}

	pcrClient, err := podcertificate.NewClient(kc)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	for _, pcr := range cached {
		if err := pcrClient.Informer().GetIndexer().Add(pcr); err != nil {
			t.Fatalf("seed informer with %s/%s: %v", pcr.Namespace, pcr.Name, err)
		}
	}

	return New(clock.RealClock{}, signer, kc, hasher, pcrClient), kc
}

func pcrWithConditions(namespace, name, signerName string, condTypes ...string) *certsv1.PodCertificateRequest {
	pcr := &certsv1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       certsv1.PodCertificateRequestSpec{SignerName: signerName},
	}
	for _, condType := range condTypes {
		pcr.Status.Conditions = append(pcr.Status.Conditions, metav1.Condition{Type: condType, Status: metav1.ConditionTrue, Reason: "Test"})
	}
	return pcr
}

func TestHandlePCR(t *testing.T) {
	for _, tc := range []struct {
		name string
		pcr  *certsv1.PodCertificateRequest
		// assigned nil means the single-replica case: everything is ours.
		assigned    map[string]bool
		makeCertErr error

		wantErr      error
		wantErrText  string
		wantMadeCert bool
	}{
		{
			name: "signs a request for this signer",
			pcr:  pcrWithConditions("ns", "pcr", testSignerName),
			// A signer that never signs would pass every negative case below,
			// so the positive one carries the weight.
			wantMadeCert: true,
		},
		{
			// Another signer's controller will handle it; requeueing here
			// would spin forever, so this must be nil and not an error.
			name: "ignores a request for another signer",
			pcr:  pcrWithConditions("ns", "pcr", "ate.dev/some-other-signer"),
		},
		{
			name: "ignores an already-issued request",
			pcr:  pcrWithConditions("ns", "pcr", testSignerName, certsv1beta1.PodCertificateRequestConditionTypeIssued),
		},
		{
			name: "ignores a denied request",
			pcr:  pcrWithConditions("ns", "pcr", testSignerName, certsv1beta1.PodCertificateRequestConditionTypeDenied),
		},
		{
			name: "ignores a failed request",
			pcr:  pcrWithConditions("ns", "pcr", testSignerName, certsv1beta1.PodCertificateRequestConditionTypeFailed),
		},
		{
			// A terminal condition anywhere in the list must stop the signer,
			// not only one in first position.
			name: "ignores a request whose terminal condition is not first",
			pcr:  pcrWithConditions("ns", "pcr", testSignerName, "SomeUnrelatedCondition", certsv1beta1.PodCertificateRequestConditionTypeIssued),
		},
		{
			name:     "defers a request assigned to another replica",
			pcr:      pcrWithConditions("ns", "pcr", testSignerName),
			assigned: map[string]bool{},
			// Must be ErrNotAssigned specifically: processNextWorkItem
			// distinguishes it from a real failure and requeues quietly.
			wantErr: rendezvous.ErrNotAssigned,
		},
		{
			name:        "propagates a signing failure",
			pcr:         pcrWithConditions("ns", "pcr", testSignerName),
			makeCertErr: errors.New("signing key unavailable"),
			// Asserting the cause and not merely "an error" — an operator
			// reading the log needs the signer's own message, and a wrapper
			// that dropped it would still satisfy a non-nil check.
			wantErrText:  "signing key unavailable",
			wantMadeCert: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer := &fakeSigner{signerName: testSignerName, makeCertErr: tc.makeCertErr}
			hasher := &fakeHasher{assigned: tc.assigned}
			c, _ := newTestController(t, signer, hasher)

			beta := &certsv1beta1.PodCertificateRequest{
				ObjectMeta: tc.pcr.ObjectMeta,
				Spec:       certsv1beta1.PodCertificateRequestSpec{SignerName: tc.pcr.Spec.SignerName},
				Status:     certsv1beta1.PodCertificateRequestStatus(tc.pcr.Status),
			}
			err := c.handlePCR(t.Context(), beta)

			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("handlePCR err = %v, want %v", err, tc.wantErr)
				}
			case tc.wantErrText != "":
				if err == nil {
					t.Fatalf("handlePCR err = nil, want one mentioning %q", tc.wantErrText)
				}
				if got := err.Error(); !strings.Contains(got, tc.wantErrText) {
					t.Errorf("handlePCR err = %q, want it to mention %q", got, tc.wantErrText)
				}
			default:
				if err != nil {
					t.Errorf("handlePCR err = %v, want nil", err)
				}
			}

			if made := len(signer.madeCerts) > 0; made != tc.wantMadeCert {
				t.Errorf("MakeCert called = %v, want %v (calls: %v)", made, tc.wantMadeCert, signer.madeCerts)
			}
		})
	}
}

func TestHandlePCRSkipsRendezvousForOtherSigners(t *testing.T) {
	// The signer-name check must come first. Asking the rendezvous about every
	// PCR in the cluster — including the ones belonging to other signers —
	// would put every replica of every signer in that conversation.
	signer := &fakeSigner{signerName: testSignerName}
	hasher := &fakeHasher{}
	c, _ := newTestController(t, signer, hasher)

	err := c.handlePCR(t.Context(), &certsv1beta1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "pcr"},
		Spec:       certsv1beta1.PodCertificateRequestSpec{SignerName: "ate.dev/some-other-signer"},
	})
	if err != nil {
		t.Fatalf("handlePCR: %v", err)
	}
	if len(hasher.asked) != 0 {
		t.Errorf("rendezvous consulted for another signer's PCR: %v", hasher.asked)
	}
}

func TestProcessNextWorkItem(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  string
		// cached, when true, seeds the informer with a signable PCR at key.
		cached      bool
		assigned    map[string]bool
		makeCertErr error

		wantMadeCert bool
		wantRequeued bool
	}{
		{
			name:         "signs a cached request and forgets it",
			key:          "ns/pcr",
			cached:       true,
			wantMadeCert: true,
		},
		{
			// The PCR was deleted between enqueue and dequeue. Requeueing
			// would retry an object that is never coming back.
			name: "forgets a key whose object is gone",
			key:  "ns/pcr",
		},
		{
			// A malformed key cannot be repaired by retrying it.
			name: "drops an unparseable key",
			key:  "a/b/c",
		},
		{
			name:         "requeues a request owned by another replica",
			key:          "ns/pcr",
			cached:       true,
			assigned:     map[string]bool{},
			wantRequeued: true,
		},
		{
			name:         "requeues a request whose signing failed",
			key:          "ns/pcr",
			cached:       true,
			makeCertErr:  errors.New("transient signing failure"),
			wantMadeCert: true,
			wantRequeued: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer := &fakeSigner{signerName: testSignerName, makeCertErr: tc.makeCertErr}
			hasher := &fakeHasher{assigned: tc.assigned}

			var seed []*certsv1.PodCertificateRequest
			if tc.cached {
				seed = append(seed, pcrWithConditions("ns", "pcr", testSignerName))
			}
			c, _ := newTestController(t, signer, hasher, seed...)

			c.pcrQueue.Add(tc.key)
			if !c.processNextWorkItem(t.Context()) {
				t.Fatal("processNextWorkItem returned false, want true — the worker loop would exit")
			}

			if made := len(signer.madeCerts) > 0; made != tc.wantMadeCert {
				t.Errorf("MakeCert called = %v, want %v", made, tc.wantMadeCert)
			}

			// A rate-limited requeue is delayed, so the item is not back in
			// Len() synchronously; the rate-limiter's own count is what
			// distinguishes "requeued" from "forgotten".
			if requeued := c.pcrQueue.NumRequeues(tc.key) > 0; requeued != tc.wantRequeued {
				t.Errorf("requeued = %v, want %v", requeued, tc.wantRequeued)
			}
		})
	}
}

func TestProcessNextWorkItemForgetsAKeyThatEventuallySucceeds(t *testing.T) {
	// Forget is what resets the rate limiter. Without it a key that failed
	// once keeps its accumulated backoff forever, so a PCR that hits one
	// transient error is slower to sign for the rest of the process's life.
	signer := &fakeSigner{signerName: testSignerName, makeCertErr: errors.New("transient")}
	c, _ := newTestController(t, signer, &fakeHasher{}, pcrWithConditions("ns", "pcr", testSignerName))

	c.pcrQueue.Add("ns/pcr")
	c.processNextWorkItem(t.Context())
	if c.pcrQueue.NumRequeues("ns/pcr") == 0 {
		t.Fatal("the failing attempt was not requeued, so the retry below proves nothing")
	}

	signer.makeCertErr = nil
	c.pcrQueue.Add("ns/pcr")
	c.processNextWorkItem(t.Context())

	if got := c.pcrQueue.NumRequeues("ns/pcr"); got != 0 {
		t.Errorf("NumRequeues = %d after a successful retry, want 0 — the backoff was never cleared", got)
	}
}

func TestProcessNextWorkItemStopsOnShutdown(t *testing.T) {
	// runWorker loops until this returns false. If a shut-down queue did not
	// report it, the worker would spin.
	c, _ := newTestController(t, &fakeSigner{signerName: testSignerName}, &fakeHasher{})
	c.pcrQueue.ShutDown()
	if c.processNextWorkItem(t.Context()) {
		t.Error("processNextWorkItem returned true on a shut-down queue")
	}
}

func TestInformerEnqueuesEvents(t *testing.T) {
	// New registers add/update/delete handlers on the shared informer. A PCR
	// that never reaches the queue is never signed, and nothing else in this
	// package would notice. Driven through a running informer rather than by
	// calling the handler directly: the informer exposes no accessor for it,
	// and the registration itself is the part that can be lost.
	signer := &fakeSigner{signerName: testSignerName}
	c, kc := newTestController(t, signer, &fakeHasher{})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go c.pcrClient.Informer().Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), c.pcrClient.Informer().HasSynced) {
		t.Fatal("informer cache never synced")
	}

	pcrs := kc.CertificatesV1().PodCertificateRequests("ns")
	created, err := pcrs.Create(ctx, pcrWithConditions("ns", "pcr", testSignerName), metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	waitForKey(t, c, "add")

	created.Spec.MaxExpirationSeconds = ptr.To[int32](3600)
	if _, err := pcrs.Update(ctx, created, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update: %v", err)
	}
	waitForKey(t, c, "update")

	if err := pcrs.Delete(ctx, "pcr", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	waitForKey(t, c, "delete")
}

// waitForKey drains one "ns/pcr" off the queue, failing if none arrives. The
// informer delivers asynchronously, so a bare Len() check would race.
func waitForKey(t *testing.T, c *Controller, event string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for c.pcrQueue.Len() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("no key enqueued for the %s event", event)
		}
		time.Sleep(5 * time.Millisecond)
	}
	key, _ := c.pcrQueue.Get()
	c.pcrQueue.Done(key)
	if key != "ns/pcr" {
		t.Errorf("%s event enqueued %q, want %q", event, key, "ns/pcr")
	}
}

func TestEnsureBundles(t *testing.T) {
	wantCTB := func(name, bundle string, labels map[string]string) *certsv1beta1.ClusterTrustBundle {
		return &certsv1beta1.ClusterTrustBundle{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
			Spec:       certsv1beta1.ClusterTrustBundleSpec{SignerName: testSignerName, TrustBundle: bundle},
		}
	}

	t.Run("creates a missing bundle", func(t *testing.T) {
		signer := &fakeSigner{
			signerName:  testSignerName,
			desiredCTBs: []*certsv1beta1.ClusterTrustBundle{wantCTB("ctb-a", "PEM-A", nil)},
		}
		c, kc := newTestController(t, signer, &fakeHasher{})

		c.ensureBundles(t.Context())

		got, err := kc.CertificatesV1beta1().ClusterTrustBundles().Get(t.Context(), "ctb-a", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get ctb-a: %v", err)
		}
		if got.Spec.TrustBundle != "PEM-A" {
			t.Errorf("trust bundle = %q, want %q", got.Spec.TrustBundle, "PEM-A")
		}
	})

	t.Run("creates every missing bundle in one pass", func(t *testing.T) {
		// A signer with more than one desired bundle is the normal case during
		// a CA rotation: the old anchor and the new one are both wanted. If
		// only one lands per pass, the second is missing for a whole tick,
		// and every relying party that needed it fails closed in the meantime.
		signer := &fakeSigner{
			signerName: testSignerName,
			desiredCTBs: []*certsv1beta1.ClusterTrustBundle{
				wantCTB("ctb-a", "PEM-A", nil),
				wantCTB("ctb-b", "PEM-B", nil),
			},
		}
		c, kc := newTestController(t, signer, &fakeHasher{})

		c.ensureBundles(t.Context())

		for name, bundle := range map[string]string{"ctb-a": "PEM-A", "ctb-b": "PEM-B"} {
			got, err := kc.CertificatesV1beta1().ClusterTrustBundles().Get(t.Context(), name, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("get %s: %v", name, err)
			}
			if got.Spec.TrustBundle != bundle {
				t.Errorf("%s trust bundle = %q, want %q", name, got.Spec.TrustBundle, bundle)
			}
		}
	})

	t.Run("updates a bundle that has drifted", func(t *testing.T) {
		signer := &fakeSigner{
			signerName:  testSignerName,
			desiredCTBs: []*certsv1beta1.ClusterTrustBundle{wantCTB("ctb-a", "PEM-NEW", map[string]string{"want": "yes"})},
		}
		c, kc := newTestController(t, signer, &fakeHasher{})
		if _, err := kc.CertificatesV1beta1().ClusterTrustBundles().Create(t.Context(),
			wantCTB("ctb-a", "PEM-OLD", map[string]string{"stale": "yes"}), metav1.CreateOptions{}); err != nil {
			t.Fatalf("seed ctb-a: %v", err)
		}

		c.ensureBundles(t.Context())

		got, err := kc.CertificatesV1beta1().ClusterTrustBundles().Get(t.Context(), "ctb-a", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get ctb-a: %v", err)
		}
		if got.Spec.TrustBundle != "PEM-NEW" {
			t.Errorf("trust bundle = %q, want %q — a rotation did not land", got.Spec.TrustBundle, "PEM-NEW")
		}
		// Labels are replaced wholesale, not merged: the stale key must go.
		if _, stale := got.Labels["stale"]; stale {
			t.Errorf("labels = %v, want the stale key gone", got.Labels)
		}
		if got.Labels["want"] != "yes" {
			t.Errorf("labels = %v, want the desired key present", got.Labels)
		}
	})

	t.Run("does not write a bundle that is already correct", func(t *testing.T) {
		// ensureBundles runs every 5 seconds per signer. An unconditional
		// Update means a write to every trust bundle in the cluster at that
		// rate, each one bumping resourceVersion and waking every informer
		// watching ClusterTrustBundles — including the kubelet's, on every
		// node — for a change that is not there.
		want := wantCTB("ctb-a", "PEM-A", map[string]string{"k": "v"})
		signer := &fakeSigner{signerName: testSignerName, desiredCTBs: []*certsv1beta1.ClusterTrustBundle{want}}
		c, kc := newTestController(t, signer, &fakeHasher{})
		if _, err := kc.CertificatesV1beta1().ClusterTrustBundles().Create(t.Context(), want.DeepCopy(), metav1.CreateOptions{}); err != nil {
			t.Fatalf("seed ctb-a: %v", err)
		}
		kc.ClearActions()

		c.ensureBundles(t.Context())

		for _, action := range kc.Actions() {
			if action.GetVerb() == "update" || action.GetVerb() == "create" {
				t.Errorf("wrote to %s with verb %q, want read-only when already in the desired state",
					action.GetResource().Resource, action.GetVerb())
			}
		}
	})

	t.Run("does nothing when the bundles belong to another replica", func(t *testing.T) {
		// Only one replica maintains the bundles. If every replica did, they
		// would fight over the same object.
		signer := &fakeSigner{
			signerName:  testSignerName,
			desiredCTBs: []*certsv1beta1.ClusterTrustBundle{wantCTB("ctb-a", "PEM-A", nil)},
		}
		hasher := &fakeHasher{assigned: map[string]bool{}}
		c, kc := newTestController(t, signer, hasher)
		kc.ClearActions()

		c.ensureBundles(t.Context())

		if len(kc.Actions()) != 0 {
			t.Errorf("made %d API calls, want 0", len(kc.Actions()))
		}
		if len(hasher.asked) != 1 || hasher.asked[0] != "maintain-trust-bundles" {
			t.Errorf("rendezvous asked about %v, want exactly [maintain-trust-bundles]", hasher.asked)
		}
	})

	t.Run("makes no API calls when the signer cannot list its anchors", func(t *testing.T) {
		// The list is returned ALONGSIDE the error, which is what a signer
		// that read some anchors and then failed would do. Asserting against
		// a nil list would pass on a controller that ignored the error
		// entirely — the loop would simply have nothing to iterate, and the
		// test could not tell "stopped" from "found nothing to do".
		signer := &fakeSigner{
			signerName:     testSignerName,
			desiredCTBs:    []*certsv1beta1.ClusterTrustBundle{wantCTB("ctb-partial", "PEM-PARTIAL", nil)},
			desiredCTBsErr: errors.New("CA unreadable"),
		}
		c, kc := newTestController(t, signer, &fakeHasher{})
		kc.ClearActions()

		c.ensureBundles(t.Context())

		if len(kc.Actions()) != 0 {
			t.Errorf("made %d API calls after a DesiredClusterTrustBundles error, want 0", len(kc.Actions()))
		}
	})

	t.Run("abandons the pass when a get fails", func(t *testing.T) {
		// Pinning current behaviour, not endorsing it: a transient read error
		// on the first bundle stops the second from being reconciled this
		// pass. That is a defensible back-off — the next tick is 5s away —
		// but it is a choice, and this test will fail loudly if it changes.
		signer := &fakeSigner{
			signerName: testSignerName,
			desiredCTBs: []*certsv1beta1.ClusterTrustBundle{
				wantCTB("ctb-a", "PEM-A", nil),
				wantCTB("ctb-b", "PEM-B", nil),
			},
		}
		c, kc := newTestController(t, signer, &fakeHasher{})
		kc.PrependReactor("get", "clustertrustbundles", func(action ktesting.Action) (bool, runtime.Object, error) {
			if action.(ktesting.GetAction).GetName() == "ctb-a" {
				return true, nil, fmt.Errorf("apiserver unavailable")
			}
			return false, nil, nil
		})

		c.ensureBundles(t.Context())

		if _, err := kc.CertificatesV1beta1().ClusterTrustBundles().Get(t.Context(), "ctb-b", metav1.GetOptions{}); err == nil {
			t.Error("ctb-b was reconciled after ctb-a's get failed; current behaviour abandons the pass")
		}
	})

	t.Run("keeps reconciling after a create fails", func(t *testing.T) {
		// A create that fails is retried on the next tick, so the pass may
		// stop — but the error must not be swallowed into a state where the
		// bundle is believed present. Asserted by the absence of the object.
		signer := &fakeSigner{
			signerName:  testSignerName,
			desiredCTBs: []*certsv1beta1.ClusterTrustBundle{wantCTB("ctb-a", "PEM-A", nil)},
		}
		c, kc := newTestController(t, signer, &fakeHasher{})
		kc.PrependReactor("create", "clustertrustbundles", func(ktesting.Action) (bool, runtime.Object, error) {
			return true, nil, fmt.Errorf("quota exceeded")
		})

		c.ensureBundles(t.Context())

		if _, err := kc.CertificatesV1beta1().ClusterTrustBundles().Get(t.Context(), "ctb-a", metav1.GetOptions{}); err == nil {
			t.Error("ctb-a exists after its create failed")
		}
	})

	t.Run("continues past a failed update", func(t *testing.T) {
		// Unlike the get and create paths, a failed update only logs: the
		// loop goes on to the next bundle. One un-writable bundle must not
		// strand the others — that is the difference between one stale
		// anchor and a stalled rotation.
		signer := &fakeSigner{
			signerName: testSignerName,
			desiredCTBs: []*certsv1beta1.ClusterTrustBundle{
				wantCTB("ctb-a", "PEM-A-NEW", nil),
				wantCTB("ctb-b", "PEM-B-NEW", nil),
			},
		}
		c, kc := newTestController(t, signer, &fakeHasher{})
		for _, seed := range []*certsv1beta1.ClusterTrustBundle{wantCTB("ctb-a", "PEM-A-OLD", nil), wantCTB("ctb-b", "PEM-B-OLD", nil)} {
			if _, err := kc.CertificatesV1beta1().ClusterTrustBundles().Create(t.Context(), seed, metav1.CreateOptions{}); err != nil {
				t.Fatalf("seed %s: %v", seed.Name, err)
			}
		}
		kc.PrependReactor("update", "clustertrustbundles", func(action ktesting.Action) (bool, runtime.Object, error) {
			if action.(ktesting.UpdateAction).GetObject().(*certsv1beta1.ClusterTrustBundle).Name == "ctb-a" {
				return true, nil, fmt.Errorf("conflict")
			}
			return false, nil, nil
		})

		c.ensureBundles(t.Context())

		got, err := kc.CertificatesV1beta1().ClusterTrustBundles().Get(t.Context(), "ctb-b", metav1.GetOptions{})
		if err != nil {
			t.Fatalf("get ctb-b: %v", err)
		}
		if got.Spec.TrustBundle != "PEM-B-NEW" {
			t.Errorf("ctb-b trust bundle = %q, want %q — ctb-a's failure stranded it", got.Spec.TrustBundle, "PEM-B-NEW")
		}
	})
}

func TestRunSignsQueuedRequests(t *testing.T) {
	// Run is the only thing that connects the informer, the queue and the
	// worker. Each half is tested above; this asserts they are actually
	// wired to each other, with a worker count Run has to clamp.
	signer := &fakeSigner{signerName: testSignerName}
	c, kc := newTestController(t, signer, &fakeHasher{})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go c.pcrClient.Informer().Run(ctx.Done())

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Zero workers is clamped to one; without the clamp nothing drains
		// the queue and this test times out rather than passing vacuously.
		c.Run(ctx, 0)
	}()

	if _, err := kc.CertificatesV1().PodCertificateRequests("ns").Create(ctx,
		pcrWithConditions("ns", "pcr", testSignerName), metav1.CreateOptions{}); err != nil {
		t.Fatalf("create: %v", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for len(signer.madeCerts) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("Run never signed the queued request")
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}

func TestRunReturnsWhenTheCacheNeverSyncs(t *testing.T) {
	// Run blocks on WaitForCacheSync before starting any worker. A cancelled
	// context must unblock it — otherwise shutdown hangs on a controller whose
	// informer was never started.
	c, _ := newTestController(t, &fakeSigner{signerName: testSignerName}, &fakeHasher{})

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.Run(ctx, 1)
	}()
	cancel()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}

// testEventHandler returns the handler New registered on the informer. The
// informer exposes no accessor, so the test re-registers a recorder and reads
// the one under test by firing events at the shared multiplexer.
func testEventHandler(t *testing.T, c *Controller) interface {
	OnAdd(any, bool)
	OnUpdate(any, any)
	OnDelete(any)
} {
	t.Helper()
	return c.pcrClient.Informer().(interface {
		OnAdd(any, bool)
		OnUpdate(any, any)
		OnDelete(any)
	})
}
