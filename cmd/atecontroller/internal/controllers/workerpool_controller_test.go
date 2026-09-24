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
	"os"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8errors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	"github.com/agent-substrate/substrate/internal/envtestbins"
	atev1alpha1 "github.com/agent-substrate/substrate/pkg/api/v1alpha1"
)

var (
	testEnv    *envtest.Environment
	cfg        *rest.Config
	k8sClient  client.Client
	testCtx    context.Context
	testCancel context.CancelFunc
)

func TestMain(m *testing.M) {
	binaryAssetsDirectory, err := envtestbins.BinaryAssetsDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{"../../../../manifests/ate-install/generated"},
		BinaryAssetsDirectory: binaryAssetsDirectory,
	}

	cfg, err = testEnv.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "envtest start failed: %v\n", err)
		os.Exit(1)
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(atev1alpha1.AddToScheme(scheme))

	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		fmt.Fprintf(os.Stderr, "k8s client creation failed: %v\n", err)
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "manager creation failed: %v\n", err)
		os.Exit(1)
	}

	if err := (&WorkerPoolReconciler{
		Client:   mgr.GetClient(),
		Scheme:   mgr.GetScheme(),
		Recorder: mgr.GetEventRecorderFor("workerpool-controller"),
	}).SetupWithManager(mgr); err != nil {
		fmt.Fprintf(os.Stderr, "controller setup failed: %v\n", err)
		os.Exit(1)
	}

	testCtx, testCancel = context.WithCancel(context.Background())
	go func() {
		_ = mgr.Start(testCtx)
	}()

	code := m.Run()

	testCancel()
	_ = testEnv.Stop()
	os.Exit(code)
}

// TestWorkerPoolCreatesDeployment verifies that creating a WorkerPool causes
// the controller to create a correctly-configured Deployment.
func TestWorkerPoolCreatesDeployment(t *testing.T) {
	wp := makeWorkerPool("test-create", "default", 3, "ateom:v1")
	if err := k8sClient.Create(testCtx, wp); err != nil {
		t.Fatalf("create WorkerPool: %v", err)
	}
	t.Cleanup(func() { k8sClient.Delete(testCtx, wp) }) //nolint:errcheck

	eventually(t, func(ctx context.Context) (bool, error) {
		dep, err := getDeployment(ctx, wp)
		if err != nil {
			return false, nil
		}
		if dep.Spec.Replicas == nil || *dep.Spec.Replicas != 3 {
			return false, nil
		}
		if len(dep.Spec.Template.Spec.Containers) == 0 {
			return false, nil
		}
		container := dep.Spec.Template.Spec.Containers[0]
		if container.Image != "ateom:v1" || container.Name != "ateom" {
			return false, nil
		}
		if dep.Spec.Template.Labels["ate.dev/worker-pool"] != wp.Name {
			return false, nil
		}
		if len(dep.OwnerReferences) == 0 || dep.OwnerReferences[0].Name != wp.Name {
			return false, nil
		}
		return len(dep.Spec.Template.Spec.Volumes) == 1 &&
			dep.Spec.Template.Spec.Volumes[0].Name == "run-ateom", nil
	})
}

// TestWorkerPoolReplicasUpdate verifies that changing spec.replicas on a
// WorkerPool propagates to the managed Deployment.
func TestWorkerPoolReplicasUpdate(t *testing.T) {
	wp := makeWorkerPool("test-replicas", "default", 2, "ateom:v1")
	if err := k8sClient.Create(testCtx, wp); err != nil {
		t.Fatalf("create WorkerPool: %v", err)
	}
	t.Cleanup(func() { k8sClient.Delete(testCtx, wp) }) //nolint:errcheck

	eventually(t, func(ctx context.Context) (bool, error) {
		_, err := getDeployment(ctx, wp)
		return err == nil, nil
	})

	updateWorkerPool(t, types.NamespacedName{Name: wp.Name, Namespace: wp.Namespace},
		func(current *atev1alpha1.WorkerPool) {
			current.Spec.Replicas = 5
		})

	eventually(t, func(ctx context.Context) (bool, error) {
		dep, err := getDeployment(ctx, wp)
		if err != nil {
			return false, nil
		}
		return dep.Spec.Replicas != nil && *dep.Spec.Replicas == 5, nil
	})
}

// TestWorkerPoolImageUpdate verifies that changing spec.ateomImage on a
// WorkerPool propagates to the managed Deployment.
func TestWorkerPoolImageUpdate(t *testing.T) {
	wp := makeWorkerPool("test-image", "default", 1, "ateom:v1")
	if err := k8sClient.Create(testCtx, wp); err != nil {
		t.Fatalf("create WorkerPool: %v", err)
	}
	t.Cleanup(func() { k8sClient.Delete(testCtx, wp) }) //nolint:errcheck

	eventually(t, func(ctx context.Context) (bool, error) {
		_, err := getDeployment(ctx, wp)
		return err == nil, nil
	})

	updateWorkerPool(t, types.NamespacedName{Name: wp.Name, Namespace: wp.Namespace},
		func(current *atev1alpha1.WorkerPool) {
			current.Spec.AteomImage = "ateom:v2"
		})

	eventually(t, func(ctx context.Context) (bool, error) {
		dep, err := getDeployment(ctx, wp)
		if err != nil || len(dep.Spec.Template.Spec.Containers) == 0 {
			return false, nil
		}
		return dep.Spec.Template.Spec.Containers[0].Image == "ateom:v2", nil
	})
}

// TestSSAPreservesUnownedFields verifies that SSA leaves fields set by other
// field managers untouched during reconciliation.
func TestSSAPreservesUnownedFields(t *testing.T) {
	wp := makeWorkerPool("test-ssa-unowned", "default", 2, "ateom:v1")
	if err := k8sClient.Create(testCtx, wp); err != nil {
		t.Fatalf("create WorkerPool: %v", err)
	}
	t.Cleanup(func() { k8sClient.Delete(testCtx, wp) }) //nolint:errcheck

	eventually(t, func(ctx context.Context) (bool, error) {
		_, err := getDeployment(ctx, wp)
		return err == nil, nil
	})

	// An external manager sets revisionHistoryLimit — a field the controller
	// never declares in its apply config.
	revisionHistoryLimit := int32(7)
	updateDeployment(t, wp, func(dep *appsv1.Deployment) {
		dep.Spec.RevisionHistoryLimit = &revisionHistoryLimit
	})

	// The Deployment update triggers a reconcile via Owns(). Wait until the
	// reconcile has run (replicas still correct) and the field is still present.
	eventually(t, func(ctx context.Context) (bool, error) {
		d, err := getDeployment(ctx, wp)
		if err != nil {
			return false, nil
		}
		return d.Spec.Replicas != nil && *d.Spec.Replicas == 2 &&
			d.Spec.RevisionHistoryLimit != nil && *d.Spec.RevisionHistoryLimit == 7, nil
	})
}

// TestSSARevertsOwnedFields verifies that if an external actor changes a field
// owned by the workerpool-controller (e.g. replicas on the Deployment), the
// controller reverts it on the next reconcile.
func TestSSARevertsOwnedFields(t *testing.T) {
	wp := makeWorkerPool("test-ssa-owned", "default", 2, "ateom:v1")
	if err := k8sClient.Create(testCtx, wp); err != nil {
		t.Fatalf("create WorkerPool: %v", err)
	}
	t.Cleanup(func() { k8sClient.Delete(testCtx, wp) }) //nolint:errcheck

	eventually(t, func(ctx context.Context) (bool, error) {
		dep, err := getDeployment(ctx, wp)
		return err == nil && dep.Spec.Replicas != nil && *dep.Spec.Replicas == 2, nil
	})

	rogueReplicas := int32(99)
	updateDeployment(t, wp, func(dep *appsv1.Deployment) {
		dep.Spec.Replicas = &rogueReplicas
	})

	// The controller re-applies with ForceOwnership, reclaiming replicas.
	eventually(t, func(ctx context.Context) (bool, error) {
		d, err := getDeployment(ctx, wp)
		if err != nil {
			return false, nil
		}
		return d.Spec.Replicas != nil && *d.Spec.Replicas == 2, nil
	})
}

// TestDeletedDeploymentRecreated verifies that if the managed Deployment is
// deleted externally, the controller recreates it.
func TestDeletedDeploymentRecreated(t *testing.T) {
	wp := makeWorkerPool("test-recreate", "default", 2, "ateom:v1")
	if err := k8sClient.Create(testCtx, wp); err != nil {
		t.Fatalf("create WorkerPool: %v", err)
	}
	t.Cleanup(func() { k8sClient.Delete(testCtx, wp) }) //nolint:errcheck

	eventually(t, func(ctx context.Context) (bool, error) {
		_, err := getDeployment(ctx, wp)
		return err == nil, nil
	})

	dep, err := getDeployment(testCtx, wp)
	if err != nil {
		t.Fatalf("get Deployment: %v", err)
	}
	if err := k8sClient.Delete(testCtx, dep); err != nil {
		t.Fatalf("delete Deployment: %v", err)
	}

	eventually(t, func(ctx context.Context) (bool, error) {
		_, err := getDeployment(ctx, wp)
		return err == nil, nil
	})
}

// TestStatusReplicasPropagation verifies that the controller syncs the
// Deployment's status.replicas into WorkerPool.status.replicas.
func TestStatusReplicasPropagation(t *testing.T) {
	wp := makeWorkerPool("test-status", "default", 3, "ateom:v1")
	if err := k8sClient.Create(testCtx, wp); err != nil {
		t.Fatalf("create WorkerPool: %v", err)
	}
	t.Cleanup(func() { k8sClient.Delete(testCtx, wp) }) //nolint:errcheck

	eventually(t, func(ctx context.Context) (bool, error) {
		_, err := getDeployment(ctx, wp)
		return err == nil, nil
	})

	// Simulate the deployment controller reporting 3 running pods.
	updateDeploymentStatus(t, wp, func(dep *appsv1.Deployment) {
		dep.Status.Replicas = 3
	})

	eventually(t, func(ctx context.Context) (bool, error) {
		current := &atev1alpha1.WorkerPool{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: wp.Name, Namespace: wp.Namespace}, current); err != nil {
			return false, nil
		}
		return current.Status.Replicas == 3, nil
	})
}

// TestStatusObservedGenerationTracksSpec verifies that status.observedGeneration
// reports which spec generation the rest of the status describes.
//
// Without it a client cannot distinguish "the controller has applied this spec
// and the outcome is Replicas" from "the controller has not reached this spec
// yet and Replicas is left over from the previous one" -- the two are
// byte-identical on the wire.
//
// This also covers the CRD schema: an unpruned status field has to be declared
// in manifests/ate-install/generated, so if the generated CRD loses
// observedGeneration the API server prunes it and this test reads 0.
func TestStatusObservedGenerationTracksSpec(t *testing.T) {
	wp := makeWorkerPool("test-observedgen", "default", 1, "ateom:v1")
	if err := k8sClient.Create(testCtx, wp); err != nil {
		t.Fatalf("create WorkerPool: %v", err)
	}
	t.Cleanup(func() { k8sClient.Delete(testCtx, wp) }) //nolint:errcheck

	key := types.NamespacedName{Name: wp.Name, Namespace: wp.Namespace}

	var firstGen int64
	eventually(t, func(ctx context.Context) (bool, error) {
		current := &atev1alpha1.WorkerPool{}
		if err := k8sClient.Get(ctx, key, current); err != nil {
			return false, nil
		}
		if current.Generation == 0 || current.Status.ObservedGeneration != current.Generation {
			return false, nil
		}
		firstGen = current.Generation
		return true, nil
	})

	// Change the spec. The API server bumps metadata.generation, which leaves
	// the rest of status describing the OLD spec until the controller catches
	// up -- exactly the window this field exists to make visible.
	current := updateWorkerPool(t, key, func(current *atev1alpha1.WorkerPool) {
		current.Spec.Replicas = 4
	})

	// Drive the assertion to a second generation on purpose. A controller that
	// stamped a constant, or that stamped 1, would satisfy an equality check
	// taken only at creation time.
	secondGen := current.Generation
	if secondGen <= firstGen {
		t.Fatalf("spec update did not bump generation: %d, was %d", secondGen, firstGen)
	}

	eventually(t, func(ctx context.Context) (bool, error) {
		latest := &atev1alpha1.WorkerPool{}
		if err := k8sClient.Get(ctx, key, latest); err != nil {
			return false, nil
		}
		return latest.Status.ObservedGeneration == secondGen, nil
	})
}

// TestWorkerPoolEmitsSyncedEvent verifies the controller records a Kubernetes
// Event against the WorkerPool, readable the way an operator actually reads it.
//
// This asserts on real Event objects in the API server rather than on a fake
// recorder's channel on purpose: the defect in #1147 is that `kubectl describe
// workerpool` shows nothing, and only an end-to-end assertion can tell the
// difference between "Eventf was called" and "an Event exists to be described".
// A fake would stay green if the recorder were wired to a discarding sink.
func TestWorkerPoolEmitsSyncedEvent(t *testing.T) {
	wp := makeWorkerPool("test-events", "default", 2, "ateom:v1")
	if err := k8sClient.Create(testCtx, wp); err != nil {
		t.Fatalf("create WorkerPool: %v", err)
	}
	t.Cleanup(func() { k8sClient.Delete(testCtx, wp) }) //nolint:errcheck

	var found corev1.Event
	eventually(t, func(ctx context.Context) (bool, error) {
		events := &corev1.EventList{}
		if err := k8sClient.List(ctx, events, client.InNamespace(wp.Namespace)); err != nil {
			return false, nil
		}
		for _, e := range events.Items {
			// Match on the involved object, not just the reason: an Event
			// naming some other resource would otherwise satisfy this.
			if e.InvolvedObject.Kind == "WorkerPool" &&
				e.InvolvedObject.Name == wp.Name &&
				e.Reason == reasonSynced {
				found = e
				return true, nil
			}
		}
		return false, nil
	})

	if found.Type != corev1.EventTypeNormal {
		t.Errorf("Synced event type = %q, want %q", found.Type, corev1.EventTypeNormal)
	}
	// The message has to carry the generation, because "something synced" with
	// no generation is not actionable -- it cannot be correlated with a spec
	// edit, which is the whole reason the event is worth emitting.
	if !strings.Contains(found.Message, "Observed generation") {
		t.Errorf("Synced event message = %q, want it to report the observed generation", found.Message)
	}
	if found.ReportingController != "workerpool-controller" && found.Source.Component != "workerpool-controller" {
		t.Errorf("event attributed to %q/%q, want workerpool-controller",
			found.ReportingController, found.Source.Component)
	}
}

// TestSetupWithManagerRefusesNilRecorder pins the fail-closed startup guard.
//
// The bug #1147 reports is a controller that reconciles correctly and emits
// nothing, which is invisible until someone runs `kubectl describe` and finds
// an empty Events section. Defaulting a missing Recorder to a no-op would
// reproduce exactly that, so a missing one has to stop the process instead.
func TestSetupWithManagerRefusesNilRecorder(t *testing.T) {
	withoutRecorder := newTestManager(t)
	err := (&WorkerPoolReconciler{
		Client: withoutRecorder.GetClient(),
		Scheme: withoutRecorder.GetScheme(),
	}).SetupWithManager(withoutRecorder)
	if err == nil {
		t.Fatal("SetupWithManager accepted a nil Recorder; it must fail closed")
	}
	if !strings.Contains(err.Error(), "Recorder") {
		t.Errorf("error %q does not name the missing field", err)
	}

	// The positive control is TestMain, not a second registration here:
	// controller-runtime enforces controller-name uniqueness per PROCESS, not
	// per manager, so re-registering "workerpool" fails for an unrelated
	// reason no matter how fresh the manager is. TestMain calls
	// SetupWithManager with a populated Recorder and exits non-zero on error,
	// so reaching this test at all proves the populated case is accepted.
}

func sampleWorkerPoolPodTemplate() *atev1alpha1.WorkerPoolPodTemplate {
	return &atev1alpha1.WorkerPoolPodTemplate{
		NodeSelector: map[string]string{
			"workload": "substrate",
		},
		Tolerations: []corev1.Toleration{{
			Key:      "nvidia.com/gpu",
			Operator: corev1.TolerationOpExists,
			Effect:   corev1.TaintEffectNoSchedule,
		}},
		PriorityClassName: "substrate-workers",
		NodeAffinity: &corev1.NodeAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
				NodeSelectorTerms: []corev1.NodeSelectorTerm{{
					MatchExpressions: []corev1.NodeSelectorRequirement{{
						Key:      "workload",
						Operator: corev1.NodeSelectorOpIn,
						Values:   []string{"substrate"},
					}},
				}},
			},
		},
		Resources: &corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("1Gi"),
			},
			Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("1"),
				corev1.ResourceMemory: resource.MustParse("2Gi"),
			},
		},
	}
}

// TestWorkerPoolPodTemplatePropagation verifies that template fields propagate
// to the managed Deployment pod template.
func TestWorkerPoolPodTemplatePropagation(t *testing.T) {
	wp := makeWorkerPool("test-template-propagate", "default", 1, "ateom:v1")
	wp.Spec.Template = sampleWorkerPoolPodTemplate()
	if err := k8sClient.Create(testCtx, wp); err != nil {
		t.Fatalf("create WorkerPool: %v", err)
	}
	t.Cleanup(func() { k8sClient.Delete(testCtx, wp) }) //nolint:errcheck

	eventually(t, func(ctx context.Context) (bool, error) {
		dep, err := getDeployment(ctx, wp)
		if err != nil || len(dep.Spec.Template.Spec.Containers) == 0 {
			return false, nil
		}
		podSpec := dep.Spec.Template.Spec
		container := podSpec.Containers[0]

		if podSpec.NodeSelector["workload"] != "substrate" {
			return false, nil
		}
		if len(podSpec.Tolerations) != 1 || podSpec.Tolerations[0].Key != "nvidia.com/gpu" {
			return false, nil
		}
		if podSpec.PriorityClassName != "substrate-workers" {
			return false, nil
		}
		if podSpec.Affinity == nil || podSpec.Affinity.NodeAffinity == nil {
			return false, nil
		}
		return container.Resources.Requests.Cpu().String() == "500m" &&
			container.Resources.Requests.Memory().String() == "1Gi" &&
			container.Resources.Limits.Cpu().String() == "1" &&
			container.Resources.Limits.Memory().String() == "2Gi", nil
	})
}

// TestWorkerPoolPodTemplateUpdate verifies that changing template fields on a
// WorkerPool propagates to the managed Deployment.
func TestWorkerPoolPodTemplateUpdate(t *testing.T) {
	wp := makeWorkerPool("test-template-update", "default", 1, "ateom:v1")
	wp.Spec.Template = sampleWorkerPoolPodTemplate()
	if err := k8sClient.Create(testCtx, wp); err != nil {
		t.Fatalf("create WorkerPool: %v", err)
	}
	t.Cleanup(func() { k8sClient.Delete(testCtx, wp) }) //nolint:errcheck

	eventually(t, func(ctx context.Context) (bool, error) {
		dep, err := getDeployment(ctx, wp)
		return err == nil && dep.Spec.Template.Spec.NodeSelector["workload"] == "substrate", nil
	})

	updateWorkerPool(t, types.NamespacedName{Name: wp.Name, Namespace: wp.Namespace},
		func(current *atev1alpha1.WorkerPool) {
			current.Spec.Template.NodeSelector = map[string]string{"workload": "updated"}
		})

	eventually(t, func(ctx context.Context) (bool, error) {
		dep, err := getDeployment(ctx, wp)
		if err != nil || len(dep.Spec.Template.Spec.Containers) == 0 {
			return false, nil
		}
		podSpec := dep.Spec.Template.Spec
		return podSpec.NodeSelector["workload"] == "updated" &&
			podSpec.Containers[0].Resources.Requests.Cpu().String() == "500m", nil
	})
}

// TestWorkerPoolPodTemplateClear verifies that clearing template.nodeSelector
// removes it from the managed Deployment.
func TestWorkerPoolPodTemplateClear(t *testing.T) {
	wp := makeWorkerPool("test-template-clear", "default", 1, "ateom:v1")
	wp.Spec.Template = sampleWorkerPoolPodTemplate()
	if err := k8sClient.Create(testCtx, wp); err != nil {
		t.Fatalf("create WorkerPool: %v", err)
	}
	t.Cleanup(func() { k8sClient.Delete(testCtx, wp) }) //nolint:errcheck

	eventually(t, func(ctx context.Context) (bool, error) {
		dep, err := getDeployment(ctx, wp)
		return err == nil && dep.Spec.Template.Spec.NodeSelector["workload"] == "substrate", nil
	})

	updateWorkerPool(t, types.NamespacedName{Name: wp.Name, Namespace: wp.Namespace},
		func(current *atev1alpha1.WorkerPool) {
			current.Spec.Template.NodeSelector = nil
		})

	eventually(t, func(ctx context.Context) (bool, error) {
		dep, err := getDeployment(ctx, wp)
		if err != nil {
			return false, nil
		}
		return len(dep.Spec.Template.Spec.NodeSelector) == 0, nil
	})
}

// TestWorkerPoolPodTemplateClearAll verifies that removing spec.template clears
// all pod template fields owned by the workerpool-controller.
func TestWorkerPoolPodTemplateClearAll(t *testing.T) {
	wp := makeWorkerPool("test-template-clear-all", "default", 1, "ateom:v1")
	wp.Spec.Template = sampleWorkerPoolPodTemplate()
	if err := k8sClient.Create(testCtx, wp); err != nil {
		t.Fatalf("create WorkerPool: %v", err)
	}
	t.Cleanup(func() { k8sClient.Delete(testCtx, wp) }) //nolint:errcheck

	eventually(t, func(ctx context.Context) (bool, error) {
		dep, err := getDeployment(ctx, wp)
		if err != nil || len(dep.Spec.Template.Spec.Containers) == 0 {
			return false, nil
		}
		podSpec := dep.Spec.Template.Spec
		container := podSpec.Containers[0]
		return podSpec.NodeSelector["workload"] == "substrate" &&
			len(podSpec.Tolerations) == 1 &&
			podSpec.PriorityClassName == "substrate-workers" &&
			podSpec.Affinity != nil &&
			podSpec.Affinity.NodeAffinity != nil &&
			container.Resources.Requests.Cpu().String() == "500m", nil
	})

	updateWorkerPool(t, types.NamespacedName{Name: wp.Name, Namespace: wp.Namespace},
		func(current *atev1alpha1.WorkerPool) {
			current.Spec.Template = nil
		})

	eventually(t, func(ctx context.Context) (bool, error) {
		dep, err := getDeployment(ctx, wp)
		if err != nil || len(dep.Spec.Template.Spec.Containers) == 0 {
			return false, nil
		}
		podSpec := dep.Spec.Template.Spec
		container := podSpec.Containers[0]
		return len(podSpec.NodeSelector) == 0 &&
			len(podSpec.Tolerations) == 0 &&
			podSpec.PriorityClassName == "" &&
			(podSpec.Affinity == nil || podSpec.Affinity.NodeAffinity == nil) &&
			len(container.Resources.Limits) == 0 &&
			len(container.Resources.Requests) == 0, nil
	})
}

// TestSSARevertsOwnedPodTemplateFields verifies that if an external actor
// changes pod template fields owned by the workerpool-controller, the
// controller reverts them on the next reconcile.
func TestSSARevertsOwnedPodTemplateFields(t *testing.T) {
	wp := makeWorkerPool("test-ssa-template", "default", 1, "ateom:v1")
	wp.Spec.Template = sampleWorkerPoolPodTemplate()
	if err := k8sClient.Create(testCtx, wp); err != nil {
		t.Fatalf("create WorkerPool: %v", err)
	}
	t.Cleanup(func() { k8sClient.Delete(testCtx, wp) }) //nolint:errcheck

	eventually(t, func(ctx context.Context) (bool, error) {
		dep, err := getDeployment(ctx, wp)
		return err == nil && dep.Spec.Template.Spec.NodeSelector["workload"] == "substrate", nil
	})

	updateDeployment(t, wp, func(dep *appsv1.Deployment) {
		dep.Spec.Template.Spec.NodeSelector = map[string]string{"workload": "rogue"}
	})

	eventually(t, func(ctx context.Context) (bool, error) {
		dep, err := getDeployment(ctx, wp)
		if err != nil {
			return false, nil
		}
		return dep.Spec.Template.Spec.NodeSelector["workload"] == "substrate", nil
	})
}

// TestReplicasValidationRejectsNegative verifies that the API server rejects a
// WorkerPool whose spec.replicas is negative.
func TestReplicasValidationRejectsNegative(t *testing.T) {
	wp := makeWorkerPool("test-neg-replicas", "default", -1, "ateom:v1")
	err := k8sClient.Create(testCtx, wp)
	if err == nil {
		t.Cleanup(func() { k8sClient.Delete(testCtx, wp) }) //nolint:errcheck
		t.Fatal("expected creation with negative replicas to fail, but it succeeded")
	}
	if !k8errors.IsInvalid(err) {
		t.Fatalf("expected Invalid error, got: %v", err)
	}
}

// --- helpers ---

func makeWorkerPool(name, ns string, replicas int32, image string) *atev1alpha1.WorkerPool {
	return &atev1alpha1.WorkerPool{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: atev1alpha1.WorkerPoolSpec{
			Replicas:   replicas,
			AteomImage: image,
		},
	}
}

func getDeployment(ctx context.Context, wp *atev1alpha1.WorkerPool) (*appsv1.Deployment, error) {
	dep := &appsv1.Deployment{}
	err := k8sClient.Get(ctx, types.NamespacedName{
		Name:      deploymentName(wp.Name),
		Namespace: wp.Namespace,
	}, dep)
	return dep, err
}

// updateWorkerPool applies mutate to the named WorkerPool and returns the
// object as written, retrying on conflict.
//
// A plain get-then-update from a test races the controller: every reconcile
// writes .status, a status write bumps resourceVersion, and the test's stale
// copy is then rejected with "the object has been modified". The race predates
// the event recorder -- wiring one just added enough API traffic to widen the
// window from "rarely" to "most runs", which is how it was found.
func updateWorkerPool(t *testing.T, key types.NamespacedName, mutate func(*atev1alpha1.WorkerPool)) *atev1alpha1.WorkerPool {
	t.Helper()
	var out *atev1alpha1.WorkerPool
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &atev1alpha1.WorkerPool{}
		if err := k8sClient.Get(testCtx, key, current); err != nil {
			return err
		}
		mutate(current)
		if err := k8sClient.Update(testCtx, current); err != nil {
			return err
		}
		out = current
		return nil
	})
	if err != nil {
		t.Fatalf("update WorkerPool %s: %v", key.Name, err)
	}
	return out
}

// newTestManager builds an unstarted manager for tests that need to exercise
// SetupWithManager directly. Each call gets its own manager because
// controller-runtime rejects a second controller registered under the same
// name on one manager.
func newTestManager(t *testing.T) ctrl.Manager {
	t.Helper()
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:                 k8sClient.Scheme(),
		Metrics:                metricsserver.Options{BindAddress: "0"},
		HealthProbeBindAddress: "0",
	})
	if err != nil {
		t.Fatalf("create manager: %v", err)
	}
	return mgr
}

// updateDeployment applies mutate to the WorkerPool's managed Deployment,
// retrying on conflict. Same race as updateWorkerPool, from the other side:
// the controller re-applies the Deployment on every reconcile, so a test's
// get-then-update is working from a copy the controller may already have
// superseded.
func updateDeployment(t *testing.T, wp *atev1alpha1.WorkerPool, mutate func(*appsv1.Deployment)) {
	t.Helper()
	updateDeploymentWith(t, wp, mutate, func(dep *appsv1.Deployment) error {
		return k8sClient.Update(testCtx, dep)
	})
}

// updateDeploymentStatus is updateDeployment against the status subresource.
func updateDeploymentStatus(t *testing.T, wp *atev1alpha1.WorkerPool, mutate func(*appsv1.Deployment)) {
	t.Helper()
	updateDeploymentWith(t, wp, mutate, func(dep *appsv1.Deployment) error {
		return k8sClient.Status().Update(testCtx, dep)
	})
}

func updateDeploymentWith(t *testing.T, wp *atev1alpha1.WorkerPool, mutate func(*appsv1.Deployment), write func(*appsv1.Deployment) error) {
	t.Helper()
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		dep, err := getDeployment(testCtx, wp)
		if err != nil {
			return err
		}
		mutate(dep)
		return write(dep)
	})
	if err != nil {
		t.Fatalf("update Deployment for %s: %v", wp.Name, err)
	}
}

// eventually polls condition every 100ms until it returns true or 15s elapses.
func eventually(t *testing.T, condition func(ctx context.Context) (bool, error)) {
	t.Helper()
	if err := wait.PollUntilContextTimeout(context.Background(), 100*time.Millisecond, 15*time.Second, true, condition); err != nil {
		t.Fatalf("condition not met within timeout: %v", err)
	}
}
