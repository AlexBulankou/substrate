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

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/agent-substrate/substrate/internal/ateattr"
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
	Scheme *runtime.Scheme
	// Recorder publishes the reconciler's events onto the WorkerPool, which is
	// where an operator reading `kubectl describe` looks first.
	Recorder     record.EventRecorder
	OTelEndpoint string
	// OTelMetricExportInterval is the OTEL_METRIC_EXPORT_INTERVAL propagated to
	// ateom pods. Empty keeps the SDK's default.
	OTelMetricExportInterval string
	// OTelMetricExportTimeout is the OTEL_METRIC_EXPORT_TIMEOUT propagated to
	// ateom pods. Empty keeps the SDK's default.
	OTelMetricExportTimeout string
	// OTelTracesSampler is the OTEL_TRACES_SAMPLER propagated to ateom pods.
	// Empty keeps the ateom binary's default.
	OTelTracesSampler string
	// OTelTracesSamplerArg is the OTEL_TRACES_SAMPLER_ARG propagated to ateom
	// pods. Ignored unless OTelTracesSampler is set.
	OTelTracesSamplerArg string
	// SystemNamespace is the namespace substrate's control plane runs in, and
	// AteletServiceAccount / RouterServiceAccount are the ServiceAccounts those
	// components run as. Together they name the SPIFFE identities that atunnel
	// authenticates inside each worker, which is why the ServiceAccount names
	// are configuration and not constants: a deployment that prefixes
	// resource names changes them.
	SystemNamespace      string
	AteletServiceAccount string
	RouterServiceAccount string

	desiredWorkers metric.Int64ObservableUpDownCounter
	readyWorkers   metric.Int64ObservableUpDownCounter
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
			"Failed to apply Deployment %s: %v", wp.Name, err)
		return err
	}

	dep := &appsv1.Deployment{}
	if err := r.Get(ctx, types.NamespacedName{Name: wp.Name, Namespace: wp.Namespace}, dep); err != nil {
		if k8errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to get deployment: %w", err)
	}

	return r.syncStatus(ctx, wp, dep)
}

func (r *WorkerPoolReconciler) applyDeployment(ctx context.Context, wp *atev1alpha1.WorkerPool) error {
	depAC := buildDeploymentApplyConfig(wp, ateomOTelSettings{
		Endpoint:             r.OTelEndpoint,
		MetricExportInterval: r.OTelMetricExportInterval,
		MetricExportTimeout:  r.OTelMetricExportTimeout,
		TracesSampler:        r.OTelTracesSampler,
		TracesSamplerArg:     r.OTelTracesSamplerArg,
	}, r.SystemNamespace, r.AteletServiceAccount, r.RouterServiceAccount)
	if err := r.Apply(ctx, depAC, client.FieldOwner(workerPoolFieldOwner), client.ForceOwnership); err != nil {
		return fmt.Errorf("failed to apply Deployment: %w", err)
	}
	return nil
}

func (r *WorkerPoolReconciler) syncStatus(ctx context.Context, wp *atev1alpha1.WorkerPool, dep *appsv1.Deployment) error {
	selector, err := metav1.LabelSelectorAsSelector(dep.Spec.Selector)
	if err != nil {
		return fmt.Errorf("failed to convert Deployment selector: %w", err)
	}

	// ObservedGeneration is stamped here, after applyDeployment has returned
	// without error, so it means "the spec at this generation has been
	// applied" rather than "the controller saw this generation".
	// reconcileWorkerPool returns before this call both when the apply fails
	// and when the Deployment is not yet readable, so neither path can
	// advertise an unapplied generation as observed -- the status stays at
	// the older generation, which is the honest reading.
	want := atev1alpha1.WorkerPoolStatus{
		Replicas:           dep.Status.Replicas,
		ReadyReplicas:      dep.Status.ReadyReplicas,
		Selector:           selector.String(),
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

// InitMetrics initializes the OpenTelemetry instruments for ate.workerpool.desired_workers
// and ate.workerpool.ready_workers and registers the asynchronous callback.
func (r *WorkerPoolReconciler) InitMetrics(meter metric.Meter) error {
	desiredWorkers, err := meter.Int64ObservableUpDownCounter(
		"ate.workerpool.desired_workers",
		metric.WithUnit("{worker}"),
		metric.WithDescription("number of worker pods requested for a WorkerPool (spec.replicas)"),
	)
	if err != nil {
		return fmt.Errorf("create ate.workerpool.desired_workers instrument: %w", err)
	}
	r.desiredWorkers = desiredWorkers

	readyWorkers, err := meter.Int64ObservableUpDownCounter(
		"ate.workerpool.ready_workers",
		metric.WithUnit("{worker}"),
		metric.WithDescription("number of worker pods currently ready for a WorkerPool (status.readyReplicas)"),
	)
	if err != nil {
		return fmt.Errorf("create ate.workerpool.ready_workers instrument: %w", err)
	}
	r.readyWorkers = readyWorkers

	_, err = meter.RegisterCallback(
		func(ctx context.Context, obs metric.Observer) error {
			var list atev1alpha1.WorkerPoolList
			if err := r.List(ctx, &list); err != nil {
				log.FromContext(ctx).Error(err, "failed to list worker pools to observe ate.workerpool.desired_workers and ate.workerpool.ready_workers")
				return nil
			}
			for _, wp := range list.Items {
				attrs := metric.WithAttributes(
					ateattr.WorkerPoolNamespaceKey.String(wp.Namespace),
					ateattr.WorkerPoolNameKey.String(wp.Name),
				)
				obs.ObserveInt64(r.desiredWorkers, int64(wp.Spec.Replicas), attrs)
				obs.ObserveInt64(r.readyWorkers, int64(wp.Status.ReadyReplicas), attrs)
			}
			return nil
		},
		r.desiredWorkers,
		r.readyWorkers,
	)
	if err != nil {
		return fmt.Errorf("register workerpool metrics callback: %w", err)
	}

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
	if err := r.InitMetrics(otel.Meter("atecontroller")); err != nil {
		return fmt.Errorf("failed to initialize workerpool metrics: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&atev1alpha1.WorkerPool{}).
		Owns(&appsv1.Deployment{}).
		Complete(r)
}
