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

// Tests for the work-queue pump around reconcileOne.
//
// template_reconciler_test.go covers reconcileOne itself thoroughly; what it
// does not touch is the layer that decides what happens to a ref *after*
// reconcileOne returns -- retry it, forget it, revisit it later, or stop.
// Those decisions are what make the reconciler eventually consistent, and
// getting one wrong fails quietly: a ref that is never forgotten carries its
// backoff into the next genuine failure, and a ref that is never retried
// leaves a template stuck mid-transition with no error anywhere.
//
// The tests below drive processNextWorkItem directly rather than through
// Start.  Start fans out five goroutines under wait.UntilWithContext, so
// asserting on queue state through it would race; the pump is the part with
// the branches.
package controlapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/internal/resources"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
)

// enqueuedReconciler returns a reconciler whose queue already holds
// testTemplateRef, so a single processNextWorkItem call has exactly one item
// to take.
func enqueuedReconciler(t *testing.T, persistence *fakeTemplateStore) *ActorTemplateReconciler {
	t.Helper()
	r := newTestTemplateReconciler(persistence, &fakeGoldenControl{})
	r.queue.Add(testTemplateRef)
	return r
}

// TestProcessNextWorkItemReturnsFalseOnceTheQueueShutsDown pins the exit
// condition of the runWorker loop.  If a shut-down queue reported anything but
// quit, runWorker would spin on a dead queue for the life of the process.
func TestProcessNextWorkItemReturnsFalseOnceTheQueueShutsDown(t *testing.T) {
	r := newTestTemplateReconciler(newFakeTemplateStore(), &fakeGoldenControl{})
	r.queue.ShutDown()

	if r.processNextWorkItem(context.Background()) {
		t.Error("processNextWorkItem = true on a shut-down queue, want false so runWorker can exit")
	}
}

// TestProcessNextWorkItemRetriesAfterAReconcileFailure pins that a failed pass
// goes back on the queue.  Dropping it instead would strand the template until
// the next resync -- or forever, once resync starts skipping it.
//
// It also pins that the retry count *accumulates* across consecutive failures,
// which is what makes the backoff exponential.  A Forget on the failure path
// would still requeue the ref and still satisfy a single-failure assertion,
// while resetting the delay to its base every time -- so a backend that is
// down turns into a hot retry loop rather than a widening one.  Only the
// second failure distinguishes those.
func TestProcessNextWorkItemRetriesAfterAReconcileFailure(t *testing.T) {
	persistence := newFakeTemplateStore()
	persistence.leaseErr = errors.New("the lease backend is down")
	r := enqueuedReconciler(t, persistence)
	ctx := context.Background()

	if !r.processNextWorkItem(ctx) {
		t.Fatal("processNextWorkItem = false, want true: a failure must not stop the worker")
	}
	if got := r.queue.NumRequeues(testTemplateRef); got != 1 {
		t.Fatalf("NumRequeues = %d after one failed pass, want 1 -- the ref was not retried", got)
	}

	waitForQueue(t, r)
	r.processNextWorkItem(ctx)

	if got := r.queue.NumRequeues(testTemplateRef); got != 2 {
		t.Errorf("NumRequeues = %d after two failed passes, want 2 -- the backoff was reset instead of accumulating", got)
	}
}

// TestProcessNextWorkItemForgetsARefThatEventuallySucceeds is the counterpart,
// and the one queue length cannot observe: a successful ref is not re-added
// either way.  The observable is the rate limiter's retry count, which Forget
// resets.  Without the reset the ref keeps its accumulated backoff, so a
// template that failed a few times early would be retried minutes late the
// next time it genuinely needs attention.
func TestProcessNextWorkItemForgetsARefThatEventuallySucceeds(t *testing.T) {
	persistence := newFakeTemplateStore()
	persistence.leaseErr = errors.New("the lease backend is down")
	r := enqueuedReconciler(t, persistence)
	ctx := context.Background()

	// Fail twice so the ref carries a non-zero backoff into the success.
	for range 2 {
		r.processNextWorkItem(ctx)
	}
	if r.queue.NumRequeues(testTemplateRef) == 0 {
		t.Fatal("the ref accumulated no requeues; the success below would prove nothing")
	}

	// The template does not exist, so reconcileOne returns cleanly: the
	// success path without any golden-actor scaffolding.
	persistence.leaseErr = nil
	waitForQueue(t, r)
	r.processNextWorkItem(ctx)

	if got := r.queue.NumRequeues(testTemplateRef); got != 0 {
		t.Errorf("NumRequeues = %d after a successful pass, want 0 -- the ref was not forgotten", got)
	}
}

// TestProcessNextWorkItemDoesNotRetryATemplateThatIsGone pins the other clean
// return: a ref enqueued for a template that has since been deleted is dropped
// rather than retried forever.
func TestProcessNextWorkItemDoesNotRetryATemplateThatIsGone(t *testing.T) {
	r := enqueuedReconciler(t, newFakeTemplateStore())

	if !r.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem = false, want true")
	}

	if got := r.queue.NumRequeues(testTemplateRef); got != 0 {
		t.Errorf("NumRequeues = %d for a deleted template, want 0", got)
	}
	if got := r.queue.Len(); got != 0 {
		t.Errorf("queue length = %d, want 0: a deleted template must not be requeued", got)
	}
}

// TestProcessNextWorkItemRevisitsATemplateAfterTheDelayItAskedFor covers the
// third disposition, which is neither retry nor forget: reconcileOne returns a
// duration when it is waiting on a golden-snapshot deadline rather than on
// anything that failed.  Nothing else re-enqueues that template -- the only
// other producer is the resync list, which skips templates in a terminal
// state -- so dropping the delayed requeue leaves a template parked one step
// short of its snapshot with no error to notice it by.
//
// The existing table asserts the duration reconcileOne returns; this asserts
// the pump acts on it.
func TestProcessNextWorkItemRevisitsATemplateAfterTheDelayItAskedFor(t *testing.T) {
	// A deadline just far enough out that the ref cannot already be due when
	// processNextWorkItem returns, so an immediate Add could not pass for a
	// delayed one.
	persistence := newFakeTemplateStore(testTemplate(withoutWakeupProbe,
		withSnapshotDeadline(time.Now().Add(50*time.Millisecond))))
	r := newTestTemplateReconciler(persistence, &fakeGoldenControl{
		exists:      true,
		goldenState: ateapipb.ActorState_ACTOR_STATE_RUNNING,
	})
	r.queue.Add(testTemplateRef)

	if !r.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem = false, want true")
	}
	if got := r.queue.NumRequeues(testTemplateRef); got != 0 {
		t.Errorf("NumRequeues = %d for a template that is merely waiting, want 0: waiting is not failing", got)
	}

	waitForQueue(t, r)
}

// TestProcessNextWorkItemTreatsALeaseConflictAsSomeoneElsesWork pins that
// losing the lease race is not an error.  Counting it as one would make every
// replica but the winner back off exponentially on a template that is being
// reconciled perfectly well by its owner.
func TestProcessNextWorkItemTreatsALeaseConflictAsSomeoneElsesWork(t *testing.T) {
	persistence := newFakeTemplateStore()
	persistence.leaseErr = store.ErrLeaseConflict
	r := enqueuedReconciler(t, persistence)

	if !r.processNextWorkItem(context.Background()) {
		t.Fatal("processNextWorkItem = false, want true")
	}

	if got := r.queue.NumRequeues(testTemplateRef); got != 0 {
		t.Errorf("NumRequeues = %d after a lease conflict, want 0 -- another replica owning the template is not a failure", got)
	}
}

// TestRunWorkerDrainsTheQueueAndStopsOnShutdown covers the loop itself: it
// must keep taking items while any remain, and return once the queue is shut
// down rather than blocking a goroutine forever.
func TestRunWorkerDrainsTheQueueAndStopsOnShutdown(t *testing.T) {
	r := newTestTemplateReconciler(newFakeTemplateStore(), &fakeGoldenControl{})
	for _, name := range []string{"template-a", "template-b", "template-c"} {
		r.queue.Add(resources.ActorTemplateRef{Atespace: testAtespace, Name: name})
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.runWorker(context.Background())
	}()

	// Every template is absent from the store, so each pass returns cleanly
	// and the queue drains without requeues.
	waitForEmptyQueue(t, r)
	r.queue.ShutDown()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runWorker did not return after the queue shut down")
	}
}

// TestStartReconcilesAStoredTemplateAndShutsDownWithItsContext is the only
// test that runs the producer and the consumers together, which is the one
// thing Start is: the resync list is the sole event source for stored
// templates, so if the fan-out and the queue are not wired to each other
// nothing ever reconciles and nothing ever errors either.
//
// The shutdown half matters just as much.  Start's deferred ShutDown is what
// lets the five workers exit; without it a cancelled context leaves them
// blocked in Get forever and the process never terminates.
func TestStartReconcilesAStoredTemplateAndShutsDownWithItsContext(t *testing.T) {
	control := &fakeGoldenControl{}
	r := newTestTemplateReconciler(newFakeTemplateStore(testTemplate()), control)

	ctx, cancel := context.WithCancel(context.Background())
	r.Start(ctx)

	// The resync producer runs immediately rather than after the first
	// interval, so the template should reach a worker without waiting out
	// resyncInterval.
	waitFor(t, "the stored template to be reconciled", func() bool {
		creates, _, _ := control.callCounts()
		return creates > 0
	})

	cancel()
	waitFor(t, "the queue to shut down after the context was cancelled", r.queue.ShuttingDown)
}

// waitFor polls until cond holds, failing with what it was waiting for rather
// than deadlocking the test binary.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// waitForQueue blocks until a ref that was put back with a delay -- rate
// limited after a failure, or AddAfter'd for a future deadline -- becomes
// available again.
func waitForQueue(t *testing.T, r *ActorTemplateReconciler) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for r.queue.Len() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the ref that was requeued with a delay never became available again")
		}
		time.Sleep(time.Millisecond)
	}
}

// waitForEmptyQueue blocks until the worker has taken everything.
func waitForEmptyQueue(t *testing.T, r *ActorTemplateReconciler) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for r.queue.Len() > 0 {
		if time.Now().After(deadline) {
			t.Fatal("runWorker did not drain the queue")
		}
		time.Sleep(time.Millisecond)
	}
}
