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
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	atev1alpha1 "github.com/agent-substrate/substrate/pkg/api/v1alpha1"
)

const workerPoolFieldOwner = "workerpool-controller"

// Event reasons emitted on WorkerPool. Reasons are stable identifiers that
// operators filter on (`--field-selector reason=...`), so treat them as part
// of the surface: rename with the same care as a status field.
const (
	// reasonApplyFailed marks a failed apply of the managed Deployment.
	reasonApplyFailed = "ApplyFailed"
	// reasonSynced marks an observed change in the pool's status.
	reasonSynced = "Synced"
)

type WorkerPoolReconciler struct {
	client.Client
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder
}

//+kubebuilder:rbac:groups=ate.dev,resources=workerpools,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=ate.dev,resources=workerpools/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=ate.dev,resources=workerpools/finalizers,verbs=update
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
func (r *WorkerPoolReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Fetch worker pool
	wp := &atev1alpha1.WorkerPool{}
	if err := r.Get(ctx, req.NamespacedName, wp); err != nil {
		if k8errors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to get worker pool %q: %w", req.NamespacedName, err)
	}

	// Handle deletion
	if !wp.GetDeletionTimestamp().IsZero() {
		log.Info("WorkerPool is being deleted")
		return ctrl.Result{}, nil
	}

	if err := r.reconcileWorkerPool(ctx, wp); err != nil {
		log.Error(err, "Failed to reconcile worker pool")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *WorkerPoolReconciler) reconcileWorkerPool(ctx context.Context, wp *atev1alpha1.WorkerPool) error {
	log := log.FromContext(ctx)
	log.Info("Reconciling worker pool")

	if err := r.applyDeployment(ctx, wp); err != nil {
		// The failure path is the one an operator most needs a breadcrumb for:
		// without it, a Deployment that never appears is only visible in the
		// controller's own logs, which assumes cluster-log access.
		r.Recorder.Eventf(wp, corev1.EventTypeWarning, reasonApplyFailed,
			"Failed to apply Deployment %s: %v", deploymentName(wp.Name), err)
		return err
	}

	dep := &appsv1.Deployment{}
	if err := r.Get(ctx, types.NamespacedName{Name: deploymentName(wp.Name), Namespace: wp.Namespace}, dep); err != nil {
		if k8errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to get deployment: %w", err)
	}

	return r.syncStatus(ctx, wp, dep)
}

func (r *WorkerPoolReconciler) applyDeployment(ctx context.Context, wp *atev1alpha1.WorkerPool) error {
	depAC := buildDeploymentApplyConfig(wp)
	if err := r.Apply(ctx, depAC, client.FieldOwner(workerPoolFieldOwner), client.ForceOwnership); err != nil {
		return fmt.Errorf("failed to apply Deployment: %w", err)
	}
	return nil
}

func (r *WorkerPoolReconciler) syncStatus(ctx context.Context, wp *atev1alpha1.WorkerPool, dep *appsv1.Deployment) error {
	// ObservedGeneration is stamped here, after applyDeployment has returned
	// without error, so it means "the spec at this generation has been
	// applied" rather than "the controller saw this generation".
	// reconcileWorkerPool returns before this call both when the apply fails
	// and when the Deployment is not yet readable, so neither path can
	// advertise an unapplied generation as observed -- the status stays at
	// the older generation, which is the honest reading.
	want := atev1alpha1.WorkerPoolStatus{
		Replicas:           dep.Status.Replicas,
		ObservedGeneration: wp.Generation,
	}
	if equality.Semantic.DeepEqual(wp.Status, want) {
		return nil
	}

	wp.Status = want
	if err := r.Status().Update(ctx, wp); err != nil {
		return fmt.Errorf("failed to update WorkerPool status: %w", err)
	}

	// Emitted only past the DeepEqual guard above, so this fires on an actual
	// transition rather than once per resync -- a steady-state pool stays
	// quiet instead of burying the interesting events.
	r.Recorder.Eventf(wp, corev1.EventTypeNormal, reasonSynced,
		"Observed generation %d with %d replica(s)", want.ObservedGeneration, want.Replicas)

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *WorkerPoolReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// Refuse to start rather than run with events silently disabled. A nil
	// Recorder is the exact failure this instrumentation exists to fix -- a
	// controller that reconciles fine and emits nothing -- so it fails closed
	// at startup instead of being discovered from an empty `kubectl describe`.
	if r.Recorder == nil {
		return fmt.Errorf("WorkerPoolReconciler: Recorder must be set")
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&atev1alpha1.WorkerPool{}).
		Owns(&appsv1.Deployment{}).
		Complete(r)
}

func deploymentName(wpName string) string {
	return wpName + "-deployment"
}
