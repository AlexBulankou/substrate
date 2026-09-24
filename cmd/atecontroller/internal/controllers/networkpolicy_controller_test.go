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
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/agent-substrate/substrate/internal/installdefaults"
	"github.com/agent-substrate/substrate/internal/resources"
	atev1alpha1 "github.com/agent-substrate/substrate/pkg/api/v1alpha1"
)

func TestWorkerPoolCreatesNetworkPolicy(t *testing.T) {
	ctx := t.Context()
	wp := makeWorkerPool("test-netpolicy-create", "default", 2, "ateom:v1")
	if err := k8sClient.Create(ctx, wp); err != nil {
		t.Fatalf("create WorkerPool: %v", err)
	}
	deleteOnCleanup(t, wp)

	eventually(t, func(ctx context.Context) (bool, error) {
		npName := resources.NetworkPolicyName(wp.Name)
		np := &networkingv1.NetworkPolicy{}
		err := k8sClient.Get(ctx, types.NamespacedName{Name: npName, Namespace: wp.Namespace}, np)
		if err != nil {
			return false, nil
		}

		// Verify OwnerReference
		if len(np.OwnerReferences) == 0 || np.OwnerReferences[0].Name != wp.Name {
			return false, nil
		}

		// Verify metadata label matches the worker pool
		if np.Labels == nil || np.Labels["ate.dev/worker-pool"] != wp.Name {
			return false, nil
		}

		// Verify PodSelector matches the worker pool
		if np.Spec.PodSelector.MatchLabels == nil || np.Spec.PodSelector.MatchLabels["ate.dev/worker-pool"] != wp.Name {
			return false, nil
		}

		// Verify PolicyTypes contains Ingress
		hasIngress := false
		for _, pt := range np.Spec.PolicyTypes {
			if pt == networkingv1.PolicyTypeIngress {
				hasIngress = true
			}
		}
		if !hasIngress {
			return false, nil
		}

		// Verify Ingress Rules (Allow only ingress from ATE router)
		if len(np.Spec.Ingress) != 1 {
			return false, nil
		}
		ingressRule := np.Spec.Ingress[0]
		if len(ingressRule.From) != 1 {
			return false, nil
		}
		fromPeer := ingressRule.From[0]
		if fromPeer.NamespaceSelector == nil || fromPeer.NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"] != installdefaults.SystemNamespace {
			return false, nil
		}
		if fromPeer.PodSelector == nil || fromPeer.PodSelector.MatchLabels["app"] != atenetRouterAppName {
			return false, nil
		}

		// Verify Egress Rules are unmanaged (empty)
		if len(np.Spec.Egress) != 0 {
			return false, nil
		}

		return true, nil
	})
}

// TestBuildNetworkPolicyRelocatedNamespace pins the ingress peer to the
// reconciler's SystemNamespace rather than the canonical install namespace.
// The rest of the suite configures the reconciler with the default, so it
// passes just as well against a hardcoded "ate-system"; this is the case that
// catches that. A policy naming the wrong namespace admits nobody, and the CNI
// drops every request to the pool with no error from substrate itself.
func TestBuildNetworkPolicyRelocatedNamespace(t *testing.T) {
	const relocated = "substrate-test"

	r := &NetworkPolicyReconciler{SystemNamespace: relocated}
	np := r.buildNetworkPolicyApplyConfig(testWorkerPoolApplyConfig(nil))

	if len(np.Spec.Ingress) != 1 || len(np.Spec.Ingress[0].From) != 1 {
		t.Fatalf("expected exactly one ingress rule with one peer, got %+v", np.Spec.Ingress)
	}
	got := np.Spec.Ingress[0].From[0].NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"]
	if got != relocated {
		t.Errorf("ingress namespace selector = %q, want %q", got, relocated)
	}
}

// Error-path tests for NetworkPolicyReconciler.
//
// The envtest test above reaches the happy path through a real API server that
// does not fail on demand, so the apply-failure branch -- and with it the
// Warning event that is the only signal an operator gets when a pool's ingress
// policy never lands -- was unexercised. These call Reconcile directly against
// a fake client with interceptors, for the reason given at the top of
// workerpool_reconcile_test.go.

func newDirectNetworkPolicyReconciler(t *testing.T, wp *atev1alpha1.WorkerPool, funcs interceptor.Funcs) (*NetworkPolicyReconciler, chan string) {
	t.Helper()

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(atev1alpha1.AddToScheme(scheme))

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(wp).
		WithInterceptorFuncs(funcs).
		Build()

	rec := record.NewFakeRecorder(16)
	return &NetworkPolicyReconciler{
		Client:          c,
		Scheme:          scheme,
		Recorder:        rec,
		SystemNamespace: installdefaults.SystemNamespace,
	}, rec.Events
}

// TestNetworkPolicyApplyFailureEmitsWarningEvent covers the branch an operator
// most needs a breadcrumb for. A WorkerPool whose ingress policy never applies
// still runs -- the pods come up and serve -- so the only outward sign is that
// the pool is reachable from places the policy was supposed to exclude, which
// is a silence with security consequences rather than an outage anyone pages
// on.
func TestNetworkPolicyApplyFailureEmitsWarningEvent(t *testing.T) {
	wp := makeWorkerPool("np-apply-fail", "default", 1, "example.com/ateom@sha256:abc")
	r, events := newDirectNetworkPolicyReconciler(t, wp, interceptor.Funcs{
		Apply: func(ctx context.Context, c client.WithWatch, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
			return errInjected
		},
	})

	_, err := r.Reconcile(t.Context(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: wp.Name, Namespace: wp.Namespace},
	})
	if err == nil {
		t.Fatal("expected the apply failure to be returned so the request is retried")
	}
	if !errors.Is(err, errInjected) {
		t.Fatalf("expected the injected error to be wrapped, got %v", err)
	}

	// The cause travels in the message for the same reason it does on the
	// WorkerPool reconciler's ApplyFailed: without it the event restates what
	// the operator can already see.
	wantEvent(t, events, corev1.EventTypeWarning, reasonNetworkPolicyApplyFailed, errInjected.Error())
}

// TestNetworkPolicySuccessIsQuiet pins the deliberate absence of a Normal
// counterpart. This reconciler applies unconditionally -- there is no change
// guard -- so a success event would fire on every resync and bury the Warning
// above. If a Normal event is ever added here it needs a transition guard
// first, and this test is what says so.
//
// The apply is stubbed to succeed rather than left to run: the fake client
// cannot server-side-apply a NetworkPolicy at all ("expected objects with
// types from the same schema"), unlike the Deployment and ClusterTrustBundle
// applies elsewhere in this package. That the real apply works is covered by
// TestWorkerPoolCreatesNetworkPolicy against envtest; what this test is about
// is what the success branch publishes, which is nothing.
func TestNetworkPolicySuccessIsQuiet(t *testing.T) {
	wp := makeWorkerPool("np-quiet", "default", 1, "example.com/ateom@sha256:abc")
	r, events := newDirectNetworkPolicyReconciler(t, wp, interceptor.Funcs{
		Apply: func(ctx context.Context, c client.WithWatch, obj runtime.ApplyConfiguration, opts ...client.ApplyOption) error {
			return nil
		},
	})

	for i := range 2 {
		if _, err := r.Reconcile(t.Context(), ctrl.Request{
			NamespacedName: types.NamespacedName{Name: wp.Name, Namespace: wp.Namespace},
		}); err != nil {
			t.Fatalf("reconcile %d: %v", i, err)
		}
	}
	wantNoEvents(t, events)
}

// TestNetworkPolicySetupRefusesNilRecorder pins the fail-closed startup guard.
// Defaulting to a no-op sink would reproduce the exact defect the events were
// added to fix: a controller that reconciles fine and reports nothing.
func TestNetworkPolicySetupRefusesNilRecorder(t *testing.T) {
	mgr := newTestManager(t)
	err := (&NetworkPolicyReconciler{
		Client:          mgr.GetClient(),
		Scheme:          mgr.GetScheme(),
		SystemNamespace: installdefaults.SystemNamespace,
	}).SetupWithManager(mgr)
	if err == nil {
		t.Fatal("SetupWithManager accepted a nil Recorder")
	}
	if !strings.Contains(err.Error(), "Recorder") {
		t.Errorf("error does not name the missing dependency: %v", err)
	}
}
