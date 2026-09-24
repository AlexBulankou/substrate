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

import (
	"context"
	"errors"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
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

	// The Deployment name is part of the message on purpose -- it is what the
	// operator greps for when the pool has no pods.
	wantEvent(t, events, reasonApplyFailed, "apply-fail-deployment")
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
