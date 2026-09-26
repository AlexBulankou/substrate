// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controllers

// Error-path tests for WorkerPoolReconciler.
//
// The envtest tests in workerpool_controller_test.go cover the happy path well,
// but they reach it through a real API server that does not fail on demand, so
// every failure branch in Reconcile was unexercised -- including the
// ApplyFailed Warning event, which is the one an operator most needs and the
// one whose absence motivated the instrumentation in the first place. An event
// no test can fail on is not verifiable instrumentation; it is a comment that
// happens to compile.
//
// These tests call Reconcile directly against a fake client with interceptors,
// for the same reason the ActorTemplate error-path tests do: the package shares
// ONE manager (controller-runtime enforces controller-name uniqueness per
// process), so a client that fails on demand cannot be swapped into it without
// breaking every other test in the package. See the section header in
// actortemplate_reconcile_test.go for the full trade-off -- in short, a
// FakeRecorder proves "Eventf was called with these arguments", and the "an
// Event actually lands in the API server" half is proven separately against the
// real server by TestWorkerPoolEmitsSyncedEvent.
//
// wantEvent and wantNoEvents at the bottom of this file are shared with the
// NetworkPolicy and EgressMITMTrust error-path tests, which are in the same
// package and take the same approach for the same reason.

import (
	"context"
	"errors"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	atev1alpha1 "github.com/agent-substrate/substrate/pkg/api/v1alpha1"
)

// errInjected is the sentinel every injection below fails with, so a test can
// assert the controller propagated *this* error rather than merely some error.
var errInjected = errors.New("injected failure")

// newDirectWorkerPoolReconciler builds a WorkerPoolReconciler over a fake
// client the shared envtest manager cannot see, with the supplied interceptors
// wired in. It returns the reconciler and the recorder's event channel.
func newDirectWorkerPoolReconciler(t *testing.T, wp *atev1alpha1.WorkerPool, funcs interceptor.Funcs) (*WorkerPoolReconciler, chan string) {
	t.Helper()

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(atev1alpha1.AddToScheme(scheme))

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(wp).
		WithStatusSubresource(&atev1alpha1.WorkerPool{}).
		WithInterceptorFuncs(funcs).
		Build()

	rec := record.NewFakeRecorder(16)
	return &WorkerPoolReconciler{
		Client:   c,
		Scheme:   scheme,
		Recorder: rec,
	}, rec.Events
}

func reconcileWorkerPoolOnce(t *testing.T, r *WorkerPoolReconciler, wp *atev1alpha1.WorkerPool) error {
	t.Helper()
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: wp.Name, Namespace: wp.Namespace},
	})
	return err
}

// TestApplyFailureEmitsWarningEvent pins the breadcrumb an operator gets when
// the Deployment never appears. Without it the only evidence is in the
// controller's own logs, which assumes cluster-log access the operator
// debugging their own namespace does not have.
func TestApplyFailureEmitsWarningEvent(t *testing.T) {
	wp := makeWorkerPool("apply-fail", "default", 1, "example.com/ateom@sha256:abc")
	r, events := newDirectWorkerPoolReconciler(t, wp, interceptor.Funcs{
		Apply: func(ctx context.Context, c client.WithWatch, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
			return errInjected
		},
	})

	err := reconcileWorkerPoolOnce(t, r, wp)
	if err == nil {
		t.Fatal("expected the apply failure to be returned so the request is retried")
	}
	if !errors.Is(err, errInjected) {
		t.Fatalf("expected the injected error to be wrapped, got %v", err)
	}

	// The underlying error is part of the message on purpose. An event that
	// says only "apply failed" tells the operator what they already knew from
	// the missing pods; the cause is the part they cannot get without
	// cluster-log access, which is the whole reason this event exists.
	wantEvent(t, events, corev1.EventTypeWarning, reasonApplyFailed, errInjected.Error())
}

// TestGetDeploymentFailureIsNotSwallowed covers the read-back after a
// successful apply. NotFound there is benign (the cache has not caught up yet)
// and returns nil; anything else must propagate, or a broken read would look
// like a clean reconcile forever.
func TestGetDeploymentFailureIsNotSwallowed(t *testing.T) {
	wp := makeWorkerPool("get-dep-fail", "default", 1, "example.com/ateom@sha256:abc")
	r, events := newDirectWorkerPoolReconciler(t, wp, interceptor.Funcs{
		// The apply itself is not under test here; let it no-op so the
		// reconcile reaches the read-back.
		Apply: func(ctx context.Context, c client.WithWatch, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
			return nil
		},
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*appsv1.Deployment); ok {
				return k8errors.NewInternalError(errInjected)
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})

	if err := reconcileWorkerPoolOnce(t, r, wp); err == nil {
		t.Fatal("expected a non-NotFound read failure to propagate")
	}

	// A read failure is not an apply failure: emitting ApplyFailed here would
	// point the operator at the wrong half of the reconcile.
	wantNoEvents(t, events)
}

// TestWorkerPoolGetFailureIsNotSwallowed covers the initial fetch. Same shape
// as above one level up: NotFound means the pool was deleted and is a clean
// no-op, anything else is a real failure.
func TestWorkerPoolGetFailureIsNotSwallowed(t *testing.T) {
	wp := makeWorkerPool("get-wp-fail", "default", 1, "example.com/ateom@sha256:abc")
	r, events := newDirectWorkerPoolReconciler(t, wp, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*atev1alpha1.WorkerPool); ok {
				return k8errors.NewInternalError(errInjected)
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})

	if err := reconcileWorkerPoolOnce(t, r, wp); err == nil {
		t.Fatal("expected a non-NotFound fetch failure to propagate")
	}
	wantNoEvents(t, events)
}

// TestMissingWorkerPoolIsANoOp is the NotFound half of the branch above: a
// deleted pool must not be retried forever.
func TestMissingWorkerPoolIsANoOp(t *testing.T) {
	wp := makeWorkerPool("gone", "default", 1, "example.com/ateom@sha256:abc")
	r, events := newDirectWorkerPoolReconciler(t, wp, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*atev1alpha1.WorkerPool); ok {
				return k8errors.NewNotFound(schema.GroupResource{Group: atev1alpha1.GroupVersion.Group, Resource: "workerpools"}, key.Name)
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})

	if err := reconcileWorkerPoolOnce(t, r, wp); err != nil {
		t.Fatalf("a missing WorkerPool should reconcile cleanly, got %v", err)
	}
	wantNoEvents(t, events)
}

// TestTerminatingWorkerPoolIsANoOp pins that a pool under deletion is left
// alone. Re-applying its Deployment here would fight the garbage collector.
func TestTerminatingWorkerPoolIsANoOp(t *testing.T) {
	wp := makeWorkerPool("terminating", "default", 1, "example.com/ateom@sha256:abc")
	// A deletion timestamp is only durable on an object that has a finalizer;
	// without one the fake client drops the object outright and this would
	// silently re-test the missing-object branch above instead.
	wp.Finalizers = []string{"test.ate.dev/hold"}
	now := metav1.Now()
	wp.DeletionTimestamp = &now

	applied := false
	r, events := newDirectWorkerPoolReconciler(t, wp, interceptor.Funcs{
		Apply: func(ctx context.Context, c client.WithWatch, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
			applied = true
			return nil
		},
	})

	// Guard the guard: if the object did not survive with its timestamp, this
	// test proves nothing.
	got := &atev1alpha1.WorkerPool{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: wp.Name, Namespace: wp.Namespace}, got); err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	if got.DeletionTimestamp.IsZero() {
		t.Fatal("setup failed: the object is not actually terminating")
	}

	if err := reconcileWorkerPoolOnce(t, r, wp); err != nil {
		t.Fatalf("a terminating WorkerPool should reconcile cleanly, got %v", err)
	}
	if applied {
		t.Error("a terminating WorkerPool must not have its Deployment re-applied")
	}
	wantNoEvents(t, events)
}

// wantEvent drains the fake recorder looking for one event, and reports every
// event it saw when it does not find it. The reason and the message are
// checked together because a reason alone does not distinguish "the right
// event" from "an event of the right class about something else".
// The type is checked alongside the reason because it is what decides
// whether the event is surfaced at all: `kubectl get events
// --field-selector type=Warning` and most dashboards filter on it, so a
// failure downgraded to Normal is emitted and never seen.
func wantEvent(t *testing.T, events chan string, eventType, reason, msgSubstr string) {
	t.Helper()
	want := eventType + " " + reason
	var seen []string
	for {
		select {
		case e := <-events:
			seen = append(seen, e)
			if strings.HasPrefix(e, want) && strings.Contains(e, msgSubstr) {
				return
			}
		default:
			t.Fatalf("no %q event containing %q; saw %v", want, msgSubstr, seen)
		}
	}
}

// wantNoEvents is the assertion that a quiet path stayed quiet. It is the
// half that catches an emission moved out of its guard: a test that only ever
// asserts events were produced cannot fail on one produced too eagerly.
func wantNoEvents(t *testing.T, events chan string) {
	t.Helper()
	select {
	case e := <-events:
		t.Fatalf("expected no events, got %q", e)
	default:
	}
}

// TestSteadyStateReconcileIsQuiet pins the placement of the Synced emission
// rather than its content: it sits past the DeepEqual guard in syncStatus, so
// it fires on an actual status transition and not once per resync.
//
// That distinction is the difference between a useful event stream and an
// unusable one. The controller resyncs on a timer and on every Deployment
// watch event, so an emission hoisted above the guard would republish Synced
// indefinitely for a pool that has not changed -- burying the ApplyFailed and
// PhaseChanged events an operator is actually scrolling for, and aging them
// out of the API server's event TTL early.
//
// A test that only asserts events were produced cannot fail on one produced
// too eagerly, which is why this asserts the second pass is silent.
func TestSteadyStateReconcileIsQuiet(t *testing.T) {
	wp := makeWorkerPool("steady-state", "default", 1, "example.com/ateom@sha256:abc")
	r, events := newDirectWorkerPoolReconciler(t, wp, interceptor.Funcs{})

	if err := reconcileWorkerPoolOnce(t, r, wp); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	// The first pass is a real transition and must be heard, or the second
	// pass being silent would prove nothing.
	wantEvent(t, events, corev1.EventTypeNormal, reasonSynced, "Observed generation")

	if err := reconcileWorkerPoolOnce(t, r, wp); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	wantNoEvents(t, events)
}

// TestEventReasonsAreStable pins the reason strings to their wire form.
//
// Every wantEvent call in this package passes the reason *constant*, so those
// assertions move with a rename and cannot fail on one. A reason is not an
// internal identifier though: it is the key an operator filters on
// (`--field-selector reason=...`) and the one a runbook or alert rule hard-codes,
// so renaming it breaks a surface outside this repo. This table is the only
// place the literals appear, so a rename means editing it and seeing the cost.
//
// NetworkPolicyApplyFailed is deliberately not the shared ApplyFailed: both
// reconcilers publish onto the same WorkerPool, so one reason for both would
// leave reason=ApplyFailed ambiguous about which derived object failed.
func TestEventReasonsAreStable(t *testing.T) {
	for _, tc := range []struct {
		constant  string
		onTheWire string
	}{
		{reasonApplyFailed, "ApplyFailed"},
		{reasonSynced, "Synced"},
		{reasonNetworkPolicyApplyFailed, "NetworkPolicyApplyFailed"},
		{reasonTrustBundleInvalid, "TrustBundleInvalid"},
		{reasonTrustBundleApplyFailed, "TrustBundleApplyFailed"},
	} {
		if tc.constant != tc.onTheWire {
			t.Errorf("event reason is now %q, was %q: existing field selectors and alert rules match the old value", tc.constant, tc.onTheWire)
		}
	}
}
