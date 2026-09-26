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

// Tests for the signing controller's work-item lifecycle and its
// ClusterTrustBundle reconciliation.
//
// The controller is exercised at the seams the production code actually uses.
// Most tests place PodCertificateRequests directly in the informer's indexer
// (so the lister sees them without running the informer) and drive the queue
// one item at a time through processNextWorkItem.  The event-handler test
// instead runs the shared informer for real against the fake clientset's
// watch, because "does a Create enqueue the right key" is only a real
// question if the informer delivers the event itself.  Every assertion is
// about an observable effect -- whether the handler was called, whether the
// key was retried or forgotten, what was written to the API -- rather than
// about the controller returning nil.
//
// Not covered, deliberately:
//   - the two goroutines Run() starts after the cache syncs: runWorker and
//     ensureBundles are each driven directly, and wrapping them in
//     wait.UntilWithContext / wait.JitterUntilWithContext would assert only
//     that client-go's own restart loops behave as documented.  Run's
//     early-return-on-failed-sync path is covered.
//   - the slog.ErrorContext calls on the failure paths: the paths themselves
//     are covered, the logging is not an observable contract.
//   - the DeepCopy before ensureBundles mutates a fetched ClusterTrustBundle.
//     The object comes from a live API Get, not from the informer cache, so
//     both the real client and the fake hand back an object nobody else holds.
//     The copy is defensive against a future switch to a lister; removing it
//     changes nothing observable today.
package signercontroller

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/cmd/podcertcontroller/internal/podcertificate"
	"github.com/agent-substrate/substrate/cmd/podcertcontroller/internal/rendezvous"
	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/clock"
)

const testSignerName = "test.example.com/signer"

// fixedClock is a minimal clock.PassiveClock.  vendor/ does not carry
// k8s.io/utils/clock/testing, and adding it just for a timestamp would make
// this a vendor diff.
type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time                  { return c.now }
func (c fixedClock) Since(t time.Time) time.Duration { return c.now.Sub(t) }

var _ clock.PassiveClock = fixedClock{}

// fakeSigner records what the controller asked it to do.  runWorker calls into
// it from its own goroutine while the test reads the recordings, so the
// recordings are mutex-guarded and only reachable through accessors that hand
// back a copy.
type fakeSigner struct {
	name   string
	ctbs   []*certsv1beta1.ClusterTrustBundle
	ctbErr error
	err    error

	mu       sync.Mutex
	seen     []*certsv1beta1.PodCertificateRequest
	ctbCalls int
}

func (f *fakeSigner) SignerName() string { return f.name }

func (f *fakeSigner) DesiredClusterTrustBundles() ([]*certsv1beta1.ClusterTrustBundle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ctbCalls++
	// Deliberately returns ctbs alongside ctbErr rather than nil.  A fake that
	// returned nil on error would make "the controller checked the error" and
	// "the controller ignored the error and found nothing to do" produce
	// identical observable behaviour, so the test could not tell them apart.
	return f.ctbs, f.ctbErr
}

func (f *fakeSigner) MakeCert(_ context.Context, pcr *certsv1beta1.PodCertificateRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, pcr)
	return f.err
}

// setErr changes what MakeCert returns on subsequent calls.  MakeCert reads
// err under the mutex, so writes have to take it too.
func (f *fakeSigner) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// signed returns the requests MakeCert was called with, oldest first.
func (f *fakeSigner) signed() []*certsv1beta1.PodCertificateRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*certsv1beta1.PodCertificateRequest(nil), f.seen...)
}

// ctbCallCount returns how many times the controller asked for the desired
// ClusterTrustBundles.
func (f *fakeSigner) ctbCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ctbCalls
}

var _ SignerImpl = (*fakeSigner)(nil)

// fakeHasher assigns either everything or nothing to this replica, and records
// the items it was asked about.  Guarded for the same reason as fakeSigner.
type fakeHasher struct {
	assigned bool

	mu    sync.Mutex
	asked []string
}

func (f *fakeHasher) AssignedToThisReplica(_ context.Context, item string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, item)
	return f.assigned
}

// askedItems returns the items the hasher was consulted about, oldest first.
func (f *fakeHasher) askedItems() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.asked...)
}

var _ Hasher = (*fakeHasher)(nil)

func newTestController(t *testing.T, signer *fakeSigner, hasher *fakeHasher, objs ...runtime.Object) (*Controller, *fake.Clientset) {
	t.Helper()

	kc := fake.NewSimpleClientset(objs...)
	c := New(fixedClock{now: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}, signer, kc, hasher, betaClient(t, kc))
	t.Cleanup(func() { c.pcrQueue.ShutDown() })
	return c, kc
}

func testPCR(namespace, name, signerName string, conds ...metav1.Condition) *certsv1beta1.PodCertificateRequest {
	return &certsv1beta1.PodCertificateRequest{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec:       certsv1beta1.PodCertificateRequestSpec{SignerName: signerName},
		Status:     certsv1beta1.PodCertificateRequestStatus{Conditions: conds},
	}
}

func cond(condType string) metav1.Condition {
	return metav1.Condition{Type: condType, Status: metav1.ConditionTrue, Reason: "Reason"}
}

// waitForQueueLen polls until the queue reaches want.  A requeue goes through
// AddRateLimited, so it becomes visible after a rate-limiter delay rather than
// synchronously.
func waitForQueueLen(t *testing.T, c *Controller, want int) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c.pcrQueue.Len() == want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("queue length was %d after 5s, wanted %d", c.pcrQueue.Len(), want)
}

// --- handlePCR -------------------------------------------------------------

func TestHandlePCRIgnoresOtherSigners(t *testing.T) {
	signer := &fakeSigner{name: testSignerName}
	hasher := &fakeHasher{assigned: true}
	c, _ := newTestController(t, signer, hasher)

	err := c.handlePCR(context.Background(), testPCR("ns1", "pcr1", "other.example.com/signer"))
	if err != nil {
		t.Fatalf("handlePCR: %v", err)
	}

	if len(signer.signed()) != 0 {
		t.Errorf("signer was asked to sign a request belonging to another signer: %v", signer.signed())
	}
	// The assignment check must not even be consulted: a request for another
	// signer is not this controller's work regardless of which replica owns it.
	if len(hasher.askedItems()) != 0 {
		t.Errorf("hasher consulted for another signer's request: %v", hasher.askedItems())
	}
}

func TestHandlePCRIgnoresRequestsInATerminalState(t *testing.T) {
	for _, condType := range []string{
		certsv1beta1.PodCertificateRequestConditionTypeIssued,
		certsv1beta1.PodCertificateRequestConditionTypeDenied,
		certsv1beta1.PodCertificateRequestConditionTypeFailed,
	} {
		t.Run(condType, func(t *testing.T) {
			signer := &fakeSigner{name: testSignerName}
			hasher := &fakeHasher{assigned: true}
			c, _ := newTestController(t, signer, hasher)

			err := c.handlePCR(context.Background(), testPCR("ns1", "pcr1", testSignerName, cond(condType)))
			if err != nil {
				t.Fatalf("handlePCR: %v", err)
			}

			if len(signer.signed()) != 0 {
				t.Errorf("re-signed a request already in state %q", condType)
			}
		})
	}
}

func TestHandlePCRSignsARequestInANonTerminalState(t *testing.T) {
	signer := &fakeSigner{name: testSignerName}
	hasher := &fakeHasher{assigned: true}
	c, _ := newTestController(t, signer, hasher)

	// A condition that is not one of the three terminal ones must not stop
	// processing.
	pcr := testPCR("ns1", "pcr1", testSignerName, cond("SomeOtherCondition"))
	if err := c.handlePCR(context.Background(), pcr); err != nil {
		t.Fatalf("handlePCR: %v", err)
	}

	if len(signer.signed()) != 1 {
		t.Fatalf("MakeCert called %d times, want 1", len(signer.signed()))
	}
	if signer.signed()[0] != pcr {
		t.Errorf("MakeCert received a different PodCertificateRequest than the one handed to handlePCR")
	}
	if len(hasher.askedItems()) != 1 || hasher.askedItems()[0] != "ns1/pcr1" {
		t.Errorf("hasher asked about %v, want exactly [ns1/pcr1]", hasher.askedItems())
	}
}

func TestHandlePCRReturnsErrNotAssignedForAnotherReplicasWork(t *testing.T) {
	signer := &fakeSigner{name: testSignerName}
	hasher := &fakeHasher{assigned: false}
	c, _ := newTestController(t, signer, hasher)

	err := c.handlePCR(context.Background(), testPCR("ns1", "pcr1", testSignerName))
	if !errors.Is(err, rendezvous.ErrNotAssigned) {
		t.Fatalf("handlePCR returned %v, want ErrNotAssigned", err)
	}
	if len(signer.signed()) != 0 {
		t.Errorf("signed a request assigned to another replica")
	}
}

func TestHandlePCRWrapsSignerErrors(t *testing.T) {
	sentinel := errors.New("no CA available")
	signer := &fakeSigner{name: testSignerName, err: sentinel}
	hasher := &fakeHasher{assigned: true}
	c, _ := newTestController(t, signer, hasher)

	err := c.handlePCR(context.Background(), testPCR("ns1", "pcr1", testSignerName))
	if !errors.Is(err, sentinel) {
		t.Fatalf("handlePCR returned %v, want it to wrap %v", err, sentinel)
	}
	// It must not masquerade as the not-assigned signal: processNextWorkItem
	// distinguishes the two, and a signing failure is not a routing failure.
	if errors.Is(err, rendezvous.ErrNotAssigned) {
		t.Errorf("a signing failure was reported as ErrNotAssigned")
	}
}

// --- processNextWorkItem ---------------------------------------------------

func TestProcessNextWorkItemSignsAndForgets(t *testing.T) {
	signer := &fakeSigner{name: testSignerName}
	hasher := &fakeHasher{assigned: true}
	c, _ := newTestController(t, signer, hasher)

	pcr := testPCR("ns1", "pcr1", testSignerName)
	if err := c.pcrClient.Informer().GetIndexer().Add(pcr); err != nil {
		t.Fatalf("seeding indexer: %v", err)
	}
	c.pcrQueue.Add("ns1/pcr1")

	if !c.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem returned false while the queue was live")
	}

	if len(signer.signed()) != 1 {
		t.Fatalf("MakeCert called %d times, want 1", len(signer.signed()))
	}
	// A successful item is forgotten, not retried.  Give a rate-limited
	// requeue time to appear, then assert it did not.
	time.Sleep(50 * time.Millisecond)
	if got := c.pcrQueue.Len(); got != 0 {
		t.Errorf("queue length %d after a successful sign, want 0", got)
	}
}

func TestProcessNextWorkItemRetriesAnItemOwnedByAnotherReplica(t *testing.T) {
	signer := &fakeSigner{name: testSignerName}
	hasher := &fakeHasher{assigned: false}
	c, _ := newTestController(t, signer, hasher)

	if err := c.pcrClient.Informer().GetIndexer().Add(testPCR("ns1", "pcr1", testSignerName)); err != nil {
		t.Fatalf("seeding indexer: %v", err)
	}
	c.pcrQueue.Add("ns1/pcr1")

	if !c.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem returned false while the queue was live")
	}

	// Ownership can move between replicas, so the item must come back rather
	// than being dropped.
	waitForQueueLen(t, c, 1)
}

func TestProcessNextWorkItemRetriesAfterASigningFailure(t *testing.T) {
	signer := &fakeSigner{name: testSignerName, err: errors.New("transient")}
	hasher := &fakeHasher{assigned: true}
	c, _ := newTestController(t, signer, hasher)

	if err := c.pcrClient.Informer().GetIndexer().Add(testPCR("ns1", "pcr1", testSignerName)); err != nil {
		t.Fatalf("seeding indexer: %v", err)
	}
	c.pcrQueue.Add("ns1/pcr1")

	if !c.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem returned false while the queue was live")
	}

	waitForQueueLen(t, c, 1)
}

// TestProcessNextWorkItemForgetsAKeyThatEventuallySucceeds pins the Forget
// call on the success path.  Queue length cannot see it: a successful item is
// never re-added, so it stays at zero whether or not Forget ran.  The only
// observable is the rate limiter's retry count for the key, which Forget
// resets and which otherwise keeps climbing --- so a key that failed once and
// then succeeded would be rate-limited as though it were still failing.
func TestProcessNextWorkItemForgetsAKeyThatEventuallySucceeds(t *testing.T) {
	signer := &fakeSigner{name: testSignerName, err: errors.New("transient")}
	hasher := &fakeHasher{assigned: true}
	c, _ := newTestController(t, signer, hasher)

	if err := c.pcrClient.Informer().GetIndexer().Add(testPCR("ns1", "pcr1", testSignerName)); err != nil {
		t.Fatalf("seeding indexer: %v", err)
	}
	c.pcrQueue.Add("ns1/pcr1")

	// First pass fails, so the key is requeued with a retry count.
	if !c.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem returned false while the queue was live")
	}
	waitForQueueLen(t, c, 1)
	if got := c.pcrQueue.NumRequeues("ns1/pcr1"); got == 0 {
		t.Fatalf("NumRequeues = 0 after a failure, want a nonzero retry count")
	}

	// Second pass succeeds, which must clear the retry count.
	signer.setErr(nil)
	if !c.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem returned false while the queue was live")
	}
	if got := c.pcrQueue.NumRequeues("ns1/pcr1"); got != 0 {
		t.Errorf("NumRequeues = %d after a success, want 0 --- the key was not forgotten", got)
	}
}

func TestProcessNextWorkItemDropsAKeyWithNoObject(t *testing.T) {
	signer := &fakeSigner{name: testSignerName}
	hasher := &fakeHasher{assigned: true}
	c, _ := newTestController(t, signer, hasher)

	// Nothing seeded in the indexer: this is the deleted-before-processed
	// case, which must be forgotten rather than retried forever.
	c.pcrQueue.Add("ns1/gone")

	if !c.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem returned false while the queue was live")
	}

	if len(signer.signed()) != 0 {
		t.Errorf("signed something for a key with no object")
	}
	time.Sleep(50 * time.Millisecond)
	if got := c.pcrQueue.Len(); got != 0 {
		t.Errorf("queue length %d after a missing object, want 0", got)
	}
}

func TestProcessNextWorkItemDropsAnUnparseableKey(t *testing.T) {
	signer := &fakeSigner{name: testSignerName}
	hasher := &fakeHasher{assigned: true}
	c, _ := newTestController(t, signer, hasher)

	// SplitMetaNamespaceKey rejects a key with more than one separator.
	c.pcrQueue.Add("a/b/c")

	if !c.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem returned false while the queue was live")
	}
	if len(signer.signed()) != 0 {
		t.Errorf("signed something for an unparseable key")
	}
}

func TestProcessNextWorkItemReturnsFalseOnceTheQueueShutsDown(t *testing.T) {
	signer := &fakeSigner{name: testSignerName}
	hasher := &fakeHasher{assigned: true}
	c, _ := newTestController(t, signer, hasher)

	c.pcrQueue.ShutDown()

	// This is what stops runWorker's loop; if it ever returned true the worker
	// would spin.
	if c.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem returned true after shutdown")
	}
}

func TestRunWorkerDrainsTheQueueAndStopsOnShutdown(t *testing.T) {
	signer := &fakeSigner{name: testSignerName}
	hasher := &fakeHasher{assigned: true}
	c, _ := newTestController(t, signer, hasher)

	for _, name := range []string{"pcr1", "pcr2", "pcr3"} {
		if err := c.pcrClient.Informer().GetIndexer().Add(testPCR("ns1", name, testSignerName)); err != nil {
			t.Fatalf("seeding indexer: %v", err)
		}
		c.pcrQueue.Add("ns1/" + name)
	}

	done := make(chan struct{})
	go func() {
		c.runWorker(context.Background())
		close(done)
	}()

	// The worker loops until processNextWorkItem reports the queue is closed.
	deadline := time.Now().Add(5 * time.Second)
	for len(signer.signed()) < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("worker signed %d of 3 items within 5s", len(signer.signed()))
		}
		time.Sleep(2 * time.Millisecond)
	}

	c.pcrQueue.ShutDown()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runWorker did not return after the queue shut down")
	}
}

func TestRunReturnsWhenTheContextIsAlreadyCancelled(t *testing.T) {
	signer := &fakeSigner{name: testSignerName}
	hasher := &fakeHasher{assigned: true}
	c, _ := newTestController(t, signer, hasher)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Cache sync cannot succeed against a cancelled context, and Run must
	// return rather than block a shutting-down process.
	done := make(chan struct{})
	go func() {
		c.Run(ctx, 1)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return for a cancelled context")
	}
}

// --- informer event handlers ----------------------------------------------

// TestInformerEventsEnqueueTheObjectKey drives the handlers New() registers
// the way they are actually driven in production -- by running the shared
// informer against a watch -- rather than by reaching in and calling them.
// All three (add, update, delete) must enqueue: a delete has to be processed
// too, otherwise a key deleted mid-flight is never cleared from the queue's
// rate limiter.
func TestInformerEventsEnqueueTheObjectKey(t *testing.T) {
	signer := &fakeSigner{name: testSignerName}
	hasher := &fakeHasher{assigned: true}
	c, kc := newTestController(t, signer, hasher)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.pcrClient.Informer().Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), c.pcrClient.Informer().HasSynced) {
		t.Fatal("informer never synced")
	}

	pcrs := kc.CertificatesV1beta1().PodCertificateRequests("ns1")
	pcr := testPCR("ns1", "pcr1", testSignerName)

	created, err := pcrs.Create(ctx, pcr, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	expectKey(t, c, "ns1/pcr1", "add")

	updated := created.DeepCopy()
	updated.ObjectMeta.Labels = map[string]string{"touched": "yes"}
	if _, err := pcrs.Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update: %v", err)
	}
	expectKey(t, c, "ns1/pcr1", "update")

	if err := pcrs.Delete(ctx, "pcr1", metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	expectKey(t, c, "ns1/pcr1", "delete")
}

// expectKey waits for exactly one key to land in the queue and consumes it.
func expectKey(t *testing.T, c *Controller, want, event string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for c.pcrQueue.Len() == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("nothing enqueued within 5s after %s", event)
		}
		time.Sleep(2 * time.Millisecond)
	}

	key, _ := c.pcrQueue.Get()
	c.pcrQueue.Done(key)
	if key != want {
		t.Errorf("enqueued %q after %s, want %q", key, event, want)
	}
}

// --- ensureBundles ---------------------------------------------------------

func testCTB(name, bundle string) *certsv1beta1.ClusterTrustBundle {
	return &certsv1beta1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"podcert.ate.dev/canarying": "live"},
		},
		Spec: certsv1beta1.ClusterTrustBundleSpec{
			SignerName:  testSignerName,
			TrustBundle: bundle,
		},
	}
}

func TestEnsureBundlesDoesNothingOnAReplicaThatDoesNotOwnThem(t *testing.T) {
	signer := &fakeSigner{name: testSignerName, ctbs: []*certsv1beta1.ClusterTrustBundle{testCTB("b1", "PEM")}}
	hasher := &fakeHasher{assigned: false}
	c, kc := newTestController(t, signer, hasher)

	c.ensureBundles(context.Background())

	// Only one replica maintains the bundles; the others must not even ask the
	// signer what it wants, let alone write.
	if signer.ctbCallCount() != 0 {
		t.Errorf("DesiredClusterTrustBundles called %d times on an unassigned replica", signer.ctbCallCount())
	}
	if got := writeActions(kc); len(got) != 0 {
		t.Errorf("unassigned replica wrote to the API: %v", got)
	}
	if len(hasher.askedItems()) != 1 || hasher.askedItems()[0] != "maintain-trust-bundles" {
		t.Errorf("hasher asked about %v, want exactly [maintain-trust-bundles]", hasher.askedItems())
	}
}

func TestEnsureBundlesCreatesAMissingBundle(t *testing.T) {
	want := testCTB("b1", "PEM-ROOTS")
	signer := &fakeSigner{name: testSignerName, ctbs: []*certsv1beta1.ClusterTrustBundle{want}}
	hasher := &fakeHasher{assigned: true}
	c, kc := newTestController(t, signer, hasher)

	c.ensureBundles(context.Background())

	got, err := kc.CertificatesV1beta1().ClusterTrustBundles().Get(context.Background(), "b1", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("bundle was not created: %v", err)
	}
	if got.Spec.TrustBundle != "PEM-ROOTS" {
		t.Errorf("created bundle carries %q, want PEM-ROOTS", got.Spec.TrustBundle)
	}
	if got.Spec.SignerName != testSignerName {
		t.Errorf("created bundle carries signer %q, want %q", got.Spec.SignerName, testSignerName)
	}
}

func TestEnsureBundlesRewritesADriftedBundle(t *testing.T) {
	want := testCTB("b1", "PEM-ROOTS")
	stale := testCTB("b1", "STALE-ROOTS")
	stale.ObjectMeta.Labels = map[string]string{"podcert.ate.dev/canarying": "stale"}

	signer := &fakeSigner{name: testSignerName, ctbs: []*certsv1beta1.ClusterTrustBundle{want}}
	hasher := &fakeHasher{assigned: true}
	c, kc := newTestController(t, signer, hasher, stale)

	c.ensureBundles(context.Background())

	got, err := kc.CertificatesV1beta1().ClusterTrustBundles().Get(context.Background(), "b1", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("getting bundle: %v", err)
	}
	// Drifted roots are the case that matters: a stale trust bundle silently
	// breaks every verifier that reads it.
	if got.Spec.TrustBundle != "PEM-ROOTS" {
		t.Errorf("bundle still carries %q, want PEM-ROOTS", got.Spec.TrustBundle)
	}
	if got.ObjectMeta.Labels["podcert.ate.dev/canarying"] != "live" {
		t.Errorf("labels not reconciled: %v", got.ObjectMeta.Labels)
	}
}

// TestEnsureBundlesWritesEvenWhenTheBundleIsAlreadyCorrect pins current
// behaviour that looks unintended.  ensureBundles compares the desired and
// live bundle, logs "ClusterTrustBundle already in correct state" when they
// match -- and then falls through and issues the Update anyway.  The log line
// claims a decision the code does not take; the missing statement is a
// `continue`.
//
// Nothing is corrupted by the redundant write, which is why this is pinned
// rather than fixed: it is a write on every reconcile tick (the loop runs
// every ~5s per replica, per bundle) against an object that is already right.
// If the intent is an unconditional reconcile-write, delete this test; if the
// intent is the log line, add the `continue` and invert it.
func TestEnsureBundlesWritesEvenWhenTheBundleIsAlreadyCorrect(t *testing.T) {
	want := testCTB("b1", "PEM-ROOTS")
	signer := &fakeSigner{name: testSignerName, ctbs: []*certsv1beta1.ClusterTrustBundle{want}}
	hasher := &fakeHasher{assigned: true}
	c, kc := newTestController(t, signer, hasher, testCTB("b1", "PEM-ROOTS"))

	c.ensureBundles(context.Background())

	updates := 0
	for _, a := range writeActions(kc) {
		if a == "update" {
			updates++
		}
	}
	if updates != 1 {
		t.Errorf("got %d updates for an already-correct bundle, want 1 (current behaviour); "+
			"if this now reports 0, the redundant write was fixed -- delete this test", updates)
	}
}

// TestEnsureBundlesStopsAfterCreatingTheFirstMissingBundle pins the second
// oddity in the same loop: the create path ends in `return`, not `continue`,
// so a signer that wants several bundles gets at most one created per tick.
// The error paths return too, which means one failing bundle also skips the
// rest.  Both signers in this repo want exactly one bundle today, so this is
// latent -- but it is the kind of latent that bites the first time someone
// adds a second bundle.
func TestEnsureBundlesStopsAfterCreatingTheFirstMissingBundle(t *testing.T) {
	signer := &fakeSigner{
		name: testSignerName,
		ctbs: []*certsv1beta1.ClusterTrustBundle{testCTB("b1", "PEM-1"), testCTB("b2", "PEM-2")},
	}
	hasher := &fakeHasher{assigned: true}
	c, kc := newTestController(t, signer, hasher)

	c.ensureBundles(context.Background())

	if _, err := kc.CertificatesV1beta1().ClusterTrustBundles().Get(context.Background(), "b1", metav1.GetOptions{}); err != nil {
		t.Fatalf("first bundle was not created: %v", err)
	}
	_, err := kc.CertificatesV1beta1().ClusterTrustBundles().Get(context.Background(), "b2", metav1.GetOptions{})
	if err == nil {
		t.Errorf("second bundle was created -- the create path now continues instead of returning; " +
			"that is the better behaviour, so update this test rather than the code")
	} else if !strings.Contains(err.Error(), "not found") {
		t.Errorf("unexpected error getting the second bundle: %v", err)
	}
}

// TestEnsureBundlesHandlingOfAPIErrors exercises the three failure branches
// and pins how each one treats the *rest* of the sweep.  They do not agree:
//
//   - a failed Get   -> returns, so no later bundle is reconciled this tick
//   - a failed Create-> returns, same
//   - a failed Update-> logs and falls through, so the sweep carries on
//
// ensureBundles has no return value, so "gave up" is observable only as the
// absence of work on the second bundle.  The Update branch is arguably the
// right one -- one bad bundle should not starve the others -- which makes the
// other two the odd ones out.  Pinned rather than changed: the fix is a
// one-word edit either way, but which way is an upstream call.
func TestEnsureBundlesHandlingOfAPIErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		verb string
		// seed the store so the sweep reaches the intended branch
		existing *certsv1beta1.ClusterTrustBundle
		// does the sweep go on to reconcile the second bundle?
		continuesToSecond bool
	}{
		{name: "get fails", verb: "get", continuesToSecond: false},
		{name: "create fails", verb: "create", continuesToSecond: false},
		{name: "update fails", verb: "update", existing: testCTB("b1", "STALE"), continuesToSecond: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer := &fakeSigner{
				name: testSignerName,
				ctbs: []*certsv1beta1.ClusterTrustBundle{testCTB("b1", "PEM-1"), testCTB("b2", "PEM-2")},
			}
			hasher := &fakeHasher{assigned: true}

			var objs []runtime.Object
			if tc.existing != nil {
				objs = append(objs, tc.existing)
			}
			c, kc := newTestController(t, signer, hasher, objs...)

			kc.PrependReactor(tc.verb, "clustertrustbundles", func(a k8stesting.Action) (bool, runtime.Object, error) {
				// Fail only the first bundle, so the second one's fate shows
				// whether the sweep continued rather than whether it was also
				// broken.
				if named, ok := a.(interface{ GetName() string }); ok && named.GetName() == "b2" {
					return false, nil, nil
				}
				if ca, ok := a.(k8stesting.CreateAction); ok {
					if obj, ok := ca.GetObject().(*certsv1beta1.ClusterTrustBundle); ok && obj.ObjectMeta.Name == "b2" {
						return false, nil, nil
					}
				}
				return true, nil, errors.New("injected " + tc.verb + " failure")
			})

			// Must not panic whichever branch it takes.
			c.ensureBundles(context.Background())

			_, err := kc.CertificatesV1beta1().ClusterTrustBundles().Get(context.Background(), "b2", metav1.GetOptions{})
			reconciledSecond := err == nil
			if reconciledSecond != tc.continuesToSecond {
				t.Errorf("after a failed %s the sweep reconciled the second bundle = %v, want %v",
					tc.verb, reconciledSecond, tc.continuesToSecond)
			}
			if err != nil && !strings.Contains(err.Error(), "not found") {
				t.Errorf("unexpected error getting the second bundle: %v", err)
			}
		})
	}
}

func writeActions(kc *fake.Clientset) []string {
	out := []string{}
	for _, a := range kc.Actions() {
		switch a.GetVerb() {
		case "create", "update", "patch", "delete":
			out = append(out, a.GetVerb())
		}
	}
	return out
}

// TestEnsureBundlesTouchesNothingWhenTheSignerCannotSayWhatItWants covers the
// branch that makes DesiredClusterTrustBundles fallible.
//
// This is the one error return in ensureBundles where doing nothing is clearly
// right, and it is worth pinning precisely because the alternative is so
// damaging: if a failed trust-anchor read were treated as "this signer wants
// no bundles", the reconcile below would see a live bundle with no desired
// counterpart.  Today that is harmless -- the loop only creates and updates --
// but the moment anyone adds deletion of unwanted bundles, a transient CA-read
// failure would take out the bundle every relying party verifies against.
func TestEnsureBundlesTouchesNothingWhenTheSignerCannotSayWhatItWants(t *testing.T) {
	signer := &fakeSigner{
		name:   testSignerName,
		ctbErr: errors.New("injected trust-anchor failure"),
		// Non-empty, so a controller that ignored the error would visibly
		// reconcile these and fail the assertion below.
		ctbs: []*certsv1beta1.ClusterTrustBundle{testCTB("bundle-a", "anchor-a")},
	}
	hasher := &fakeHasher{assigned: true}
	c, kc := newTestController(t, signer, hasher)

	c.ensureBundles(context.Background())

	if got := signer.ctbCallCount(); got != 1 {
		t.Errorf("DesiredClusterTrustBundles called %d times, want 1", got)
	}
	for _, action := range kc.Actions() {
		if action.GetResource().Resource == "clustertrustbundles" {
			t.Errorf("ensureBundles issued %q against ClusterTrustBundles after the signer failed",
				action.GetVerb())
		}
	}
}

// The assignment check has to come first: a replica that is not the bundle
// maintainer should not even ask the signer for its trust anchors, which on a
// RefreshingPool means a disk read on every replica every five seconds.
func TestEnsureBundlesDoesNotConsultTheSignerWhenUnassigned(t *testing.T) {
	signer := &fakeSigner{
		name: testSignerName,
		ctbs: []*certsv1beta1.ClusterTrustBundle{testCTB("bundle-a", "anchor-a")},
	}
	hasher := &fakeHasher{assigned: false}
	c, _ := newTestController(t, signer, hasher)

	c.ensureBundles(context.Background())

	if got := signer.ctbCallCount(); got != 0 {
		t.Errorf("DesiredClusterTrustBundles called %d times on an unassigned replica, want 0", got)
	}
}

// betaClient builds a PodCertificateRequest client over the fake clientset,
// declaring the v1beta1 resource the client discovers. Mirrors the helper
// upstream already uses in podidentitysigner_test.go.
func betaClient(t *testing.T, kc *fake.Clientset) *podcertificate.Client {
	t.Helper()
	kc.Resources = []*metav1.APIResourceList{{GroupVersion: "certificates.k8s.io/v1beta1", APIResources: []metav1.APIResource{{Name: "podcertificaterequests"}}}}
	client, err := podcertificate.NewClient(kc)
	if err != nil {
		t.Fatal(err)
	}
	return client
}
