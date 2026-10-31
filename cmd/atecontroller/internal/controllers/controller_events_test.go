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

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	appsv1ac "k8s.io/client-go/applyconfigurations/apps/v1"
	certsv1ac "k8s.io/client-go/applyconfigurations/certificates/v1"
	networkingv1ac "k8s.io/client-go/applyconfigurations/networking/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	atev1 "go.ate.dev/substrate/api/infra/k8s/ate/v1"
	"go.ate.dev/substrate/internal/installdefaults"
)

// errApply is the apply failure every test here injects. A reconcile that
// cannot write its derived object is the one case an operator cannot diagnose
// from the objects alone -- the derived object is simply absent, and absence
// has many causes -- so each controller is expected to say so on an object the
// operator is already looking at.
var errApply = errors.New("injected apply failure")

// failApplyOn builds an interceptor that fails the apply of the configurations
// match selects, and passes every other apply through. Matching on the
// configuration's type rather than failing all applies keeps a reconcile that
// writes several objects attributable to the one that failed.
func failApplyOn(match func(runtime.ApplyConfiguration) bool) interceptor.Funcs {
	return interceptor.Funcs{
		Apply: func(ctx context.Context, c client.WithWatch, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
			if match(obj) {
				return errApply
			}
			return c.Apply(ctx, obj, opts...)
		},
	}
}

// drainEvents returns everything buffered on rec without blocking. The
// recorders here are sized well above what the reconcile under test should
// emit, so a short read is a real finding rather than a truncation.
func drainEvents(rec *events.FakeRecorder) []string {
	var got []string
	for len(rec.Events) > 0 {
		got = append(got, <-rec.Events)
	}
	return got
}

// wantOneEvent asserts that exactly one of the emitted events carries the
// given type and reason, and that its note names the underlying cause. Other
// events are allowed through: a reconcile emits the sandbox-config events too,
// and those are not this assertion's subject. The type and reason are matched
// exactly because they are the stable identifiers operators filter on; the
// note is matched by substring because its wording is not.
func wantOneEvent(t *testing.T, got []string, eventType, reason, wantNote string) {
	t.Helper()
	prefix := eventType + " " + reason + " "
	var matched []string
	for _, e := range got {
		if strings.HasPrefix(e, prefix) {
			matched = append(matched, e)
		}
	}
	if len(matched) != 1 {
		t.Fatalf("events = %q, want exactly one starting %q", got, prefix)
	}
	if !strings.Contains(matched[0], wantNote) {
		t.Errorf("event = %q, want its note to contain %q", matched[0], wantNote)
	}
}

func eventTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatalf("add client-go scheme: %v", err)
	}
	if err := atev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add scheme: %v", err)
	}
	return scheme
}

// TestWorkerPoolApplyFailedEvent covers the WorkerPool reconciler's Warning on
// a Deployment that will not apply: without it, a pool whose workers never
// appear reports nothing but an unchanged status, and the reason lives only in
// the controller's log.
func TestWorkerPoolApplyFailedEvent(t *testing.T) {
	t.Parallel()
	scheme := eventTestScheme(t)
	wp := makeWorkerPool("pool", "default", 1, "ateom:v1")
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(wp, makeSandboxConfig("def", atev1.SandboxClassGvisor, true)).
		WithStatusSubresource(wp).
		WithInterceptorFuncs(failApplyOn(func(obj runtime.ApplyConfiguration) bool {
			_, ok := obj.(*appsv1ac.DeploymentApplyConfiguration)
			return ok
		})).Build()

	rec := events.NewFakeRecorder(10)
	r := &WorkerPoolReconciler{Client: c, APIReader: c, Scheme: scheme, Recorder: rec}
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(wp)}); !errors.Is(err, errApply) {
		t.Fatalf("Reconcile error = %v, want %v", err, errApply)
	}
	wantOneEvent(t, drainEvents(rec), corev1.EventTypeWarning, eventReasonApplyFailed, errApply.Error())
}

// TestWorkerPoolSyncStaysQuiet pins the other half of the decision: a
// reconcile that succeeds emits nothing of this controller's own. The pool's
// progress is reported by status.observedGeneration, a level field, so a
// per-reconcile "synced" event would only bury the Warning above.
func TestWorkerPoolSyncStaysQuiet(t *testing.T) {
	t.Parallel()
	scheme := eventTestScheme(t)
	wp := makeWorkerPool("pool", "default", 1, "ateom:v1")
	c := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(wp, makeSandboxConfig("def", atev1.SandboxClassGvisor, true)).
		WithStatusSubresource(wp).Build()

	rec := events.NewFakeRecorder(10)
	r := &WorkerPoolReconciler{Client: c, APIReader: c, Scheme: scheme, Recorder: rec}
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(wp)}); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// An exact set, not a filter: the point is that the only event on a
	// successful reconcile is the sandbox-config one this change did not add.
	// Re-introducing a per-reconcile "synced" event would fail here.
	want := []string{`Normal SandboxConfigSwitched sandbox class "gvisor" uses SandboxConfig "def"`}
	if got := drainEvents(rec); !slices.Equal(got, want) {
		t.Errorf("events = %q, want %q", got, want)
	}
}

// TestNetworkPolicyApplyFailedEvent covers the ingress policy's Warning. The
// reason is deliberately not the pool reconciler's bare ApplyFailed: both
// publish onto the same WorkerPool, so a shared reason would make
// `--field-selector reason=ApplyFailed` ambiguous about which derived object
// failed.
func TestNetworkPolicyApplyFailedEvent(t *testing.T) {
	t.Parallel()
	scheme := eventTestScheme(t)
	wp := makeWorkerPool("pool", "default", 1, "ateom:v1")
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(wp).
		WithInterceptorFuncs(failApplyOn(func(obj runtime.ApplyConfiguration) bool {
			_, ok := obj.(*networkingv1ac.NetworkPolicyApplyConfiguration)
			return ok
		})).Build()

	rec := events.NewFakeRecorder(10)
	r := &NetworkPolicyReconciler{Client: c, Scheme: scheme, SystemNamespace: installdefaults.SystemNamespace, Recorder: rec}
	if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(wp)}); !errors.Is(err, errApply) {
		t.Fatalf("Reconcile error = %v, want %v", err, errApply)
	}
	wantOneEvent(t, drainEvents(rec), corev1.EventTypeWarning, eventReasonNetworkPolicyApplyFailed, errApply.Error())
}

// TestEgressMITMTrustEvents covers both of the trust reconciler's Warnings.
// They publish onto the CA pool Secret rather than the derived
// ClusterTrustBundle: the Secret is what an operator edits when they rotate
// the pool, and a cluster-scoped bundle would file its events under the
// default namespace, away from the input that caused them.
func TestEgressMITMTrustEvents(t *testing.T) {
	t.Parallel()
	ref := EgressMITMCAPoolRef(installdefaults.SystemNamespace)

	t.Run("pool that will not parse", func(t *testing.T) {
		t.Parallel()
		// A Secret with no "pool" key: the shape an operator produces by
		// hand-creating the Secret instead of using `kubectl-ate admin
		// make-ca-pool`.
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: ref.Namespace, Name: ref.Name},
			Data:       map[string][]byte{"ca.crt": []byte("not a marshaled pool")},
		}
		c := fake.NewClientBuilder().WithScheme(egressMITMScheme(t)).WithObjects(secret).Build()
		rec := events.NewFakeRecorder(10)
		r := &EgressMITMTrustReconciler{Client: c, SystemNamespace: ref.Namespace, bundleV1: true, Recorder: rec}

		if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: ref}); err == nil {
			t.Fatal("Reconcile succeeded on an unparseable pool, want an error")
		}
		wantOneEvent(t, drainEvents(rec), corev1.EventTypeWarning, eventReasonTrustBundleInvalid, `secret has no "pool" key`)
	})

	t.Run("bundle that will not apply", func(t *testing.T) {
		t.Parallel()
		secret, _ := caPoolSecret(t, "initial")
		c := fake.NewClientBuilder().WithScheme(egressMITMScheme(t)).WithObjects(secret).
			WithInterceptorFuncs(failApplyOn(func(obj runtime.ApplyConfiguration) bool {
				_, ok := obj.(*certsv1ac.ClusterTrustBundleApplyConfiguration)
				return ok
			})).Build()
		rec := events.NewFakeRecorder(10)
		r := &EgressMITMTrustReconciler{Client: c, SystemNamespace: ref.Namespace, bundleV1: true, Recorder: rec}

		if _, err := r.Reconcile(t.Context(), ctrl.Request{NamespacedName: ref}); !errors.Is(err, errApply) {
			t.Fatalf("Reconcile error = %v, want %v", err, errApply)
		}
		wantOneEvent(t, drainEvents(rec), corev1.EventTypeWarning, eventReasonTrustBundleApplyFailed, errApply.Error())
	})
}

// TestEventReasonsAreStable pins the reason strings to their wire form.
//
// Every assertion above passes the reason *constant*, so those assertions
// move with a rename and cannot fail on one. A reason is not an internal
// identifier though: it is the key an operator filters on
// (`--field-selector reason=...`) and the one a runbook or alert rule
// hard-codes, so renaming it breaks a surface outside this repo. This table
// is the only place the literals appear, so a rename means editing it and
// seeing the cost.
//
// NetworkPolicyApplyFailed is deliberately not the shared ApplyFailed: both
// reconcilers publish onto the same WorkerPool, so one reason for both would
// leave reason=ApplyFailed ambiguous about which derived object failed.
func TestEventReasonsAreStable(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		constant  string
		onTheWire string
	}{
		{eventReasonApplyFailed, "ApplyFailed"},
		{eventReasonNetworkPolicyApplyFailed, "NetworkPolicyApplyFailed"},
		{eventReasonTrustBundleInvalid, "TrustBundleInvalid"},
		{eventReasonTrustBundleApplyFailed, "TrustBundleApplyFailed"},
	} {
		if tc.constant != tc.onTheWire {
			t.Errorf("reason = %q, want %q", tc.constant, tc.onTheWire)
		}
	}
}
