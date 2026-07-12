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
	"testing"
	"time"

	atev1alpha1 "github.com/agent-substrate/substrate/pkg/api/v1alpha1"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// fakeControlClient is a hand-written ateapipb.ControlClient mock. Only
// SuspendActor is exercised by the PhaseWaitGoldenActor reconcile path under
// test; every other method is a no-op so the mock satisfies the 16-method
// interface without a code generator.
type fakeControlClient struct {
	suspendResp *ateapipb.SuspendActorResponse
	suspendErr  error
}

func (f *fakeControlClient) SuspendActor(ctx context.Context, in *ateapipb.SuspendActorRequest, opts ...grpc.CallOption) (*ateapipb.SuspendActorResponse, error) {
	return f.suspendResp, f.suspendErr
}

func (f *fakeControlClient) GetActor(ctx context.Context, in *ateapipb.GetActorRequest, opts ...grpc.CallOption) (*ateapipb.GetActorResponse, error) {
	return nil, nil
}
func (f *fakeControlClient) CreateActor(ctx context.Context, in *ateapipb.CreateActorRequest, opts ...grpc.CallOption) (*ateapipb.CreateActorResponse, error) {
	return nil, nil
}
func (f *fakeControlClient) UpdateActor(ctx context.Context, in *ateapipb.UpdateActorRequest, opts ...grpc.CallOption) (*ateapipb.UpdateActorResponse, error) {
	return nil, nil
}
func (f *fakeControlClient) PauseActor(ctx context.Context, in *ateapipb.PauseActorRequest, opts ...grpc.CallOption) (*ateapipb.PauseActorResponse, error) {
	return nil, nil
}
func (f *fakeControlClient) ResumeActor(ctx context.Context, in *ateapipb.ResumeActorRequest, opts ...grpc.CallOption) (*ateapipb.ResumeActorResponse, error) {
	return nil, nil
}
func (f *fakeControlClient) DeleteActor(ctx context.Context, in *ateapipb.DeleteActorRequest, opts ...grpc.CallOption) (*ateapipb.DeleteActorResponse, error) {
	return nil, nil
}
func (f *fakeControlClient) ListWorkers(ctx context.Context, in *ateapipb.ListWorkersRequest, opts ...grpc.CallOption) (*ateapipb.ListWorkersResponse, error) {
	return nil, nil
}
func (f *fakeControlClient) ListActors(ctx context.Context, in *ateapipb.ListActorsRequest, opts ...grpc.CallOption) (*ateapipb.ListActorsResponse, error) {
	return nil, nil
}
func (f *fakeControlClient) CreateAtespace(ctx context.Context, in *ateapipb.CreateAtespaceRequest, opts ...grpc.CallOption) (*ateapipb.CreateAtespaceResponse, error) {
	return nil, nil
}
func (f *fakeControlClient) GetAtespace(ctx context.Context, in *ateapipb.GetAtespaceRequest, opts ...grpc.CallOption) (*ateapipb.GetAtespaceResponse, error) {
	return nil, nil
}
func (f *fakeControlClient) ListAtespaces(ctx context.Context, in *ateapipb.ListAtespacesRequest, opts ...grpc.CallOption) (*ateapipb.ListAtespacesResponse, error) {
	return nil, nil
}
func (f *fakeControlClient) DeleteAtespace(ctx context.Context, in *ateapipb.DeleteAtespaceRequest, opts ...grpc.CallOption) (*ateapipb.DeleteAtespaceResponse, error) {
	return nil, nil
}
func (f *fakeControlClient) DebugClear(ctx context.Context, in *ateapipb.DebugClearRequest, opts ...grpc.CallOption) (*ateapipb.DebugClearResponse, error) {
	return nil, nil
}

// newWaitingTemplate returns an ActorTemplate parked in PhaseWaitGoldenActor
// with an already-elapsed snapshot deadline, so Reconcile proceeds straight to
// the SuspendActor call rather than requeuing on the warmup timer.
func newWaitingTemplate() *atev1alpha1.ActorTemplate {
	return &atev1alpha1.ActorTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "golden", Namespace: "default"},
		Status: atev1alpha1.ActorTemplateStatus{
			Phase:                atev1alpha1.PhaseWaitGoldenActor,
			GoldenActorID:        "actor-123",
			TakeGoldenSnapshotAt: metav1.NewTime(time.Now().Add(-time.Minute)),
		},
	}
}

func newReconciler(t *testing.T, at *atev1alpha1.ActorTemplate, ate ateapipb.ControlClient) *ActorTemplateReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := atev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("AddToScheme: %v", err)
	}
	cl := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(at).
		WithStatusSubresource(at).
		Build()
	return &ActorTemplateReconciler{Client: cl, Scheme: scheme, AteClient: ate}
}

// TestReconcile_WaitGoldenActor_RequeuesOnUnspecifiedSnapshot is the direct
// regression guard for candidate_3210 (issue #1296 / a#3210). Before the fix a
// SuspendActor response whose LatestSnapshotInfo.Type is the zero value
// (SNAPSHOT_TYPE_UNSPECIFIED — the transient state before the golden snapshot
// commits as external) fell through to the "unexpected snapshot type" branch and
// wedged the ActorTemplate on a hard error. The fix treats UNSPECIFIED as
// transient: requeue with backoff, no error.
func TestReconcile_WaitGoldenActor_RequeuesOnUnspecifiedSnapshot(t *testing.T) {
	at := newWaitingTemplate()
	ate := &fakeControlClient{
		suspendResp: &ateapipb.SuspendActorResponse{
			Actor: &ateapipb.Actor{
				ActorId: "actor-123",
				LatestSnapshotInfo: &ateapipb.SnapshotInfo{
					Type: ateapipb.SnapshotType_SNAPSHOT_TYPE_UNSPECIFIED,
				},
			},
		},
	}
	r := newReconciler(t, at, ate)

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "golden", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile returned error on transient UNSPECIFIED snapshot (the bug); want nil: %v", err)
	}
	if res.RequeueAfter != 10*time.Second {
		t.Fatalf("RequeueAfter = %v, want 10s (transient requeue)", res.RequeueAfter)
	}

	got := &atev1alpha1.ActorTemplate{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "golden", Namespace: "default"}, got); err != nil {
		t.Fatalf("get after reconcile: %v", err)
	}
	if got.Status.Phase != atev1alpha1.PhaseWaitGoldenActor {
		t.Fatalf("phase = %q, want to stay %q while snapshot is uncommitted", got.Status.Phase, atev1alpha1.PhaseWaitGoldenActor)
	}
}

// TestReconcile_WaitGoldenActor_ReadyOnExternalSnapshot is the discriminating
// companion: an EXTERNAL snapshot must still transition to PhaseReady. This
// proves the fix narrows the requeue to the UNSPECIFIED zero value only and does
// not swallow the healthy terminal transition.
func TestReconcile_WaitGoldenActor_ReadyOnExternalSnapshot(t *testing.T) {
	at := newWaitingTemplate()
	ate := &fakeControlClient{
		suspendResp: &ateapipb.SuspendActorResponse{
			Actor: &ateapipb.Actor{
				ActorId: "actor-123",
				LatestSnapshotInfo: &ateapipb.SnapshotInfo{
					Type: ateapipb.SnapshotType_SNAPSHOT_TYPE_EXTERNAL,
					Data: &ateapipb.SnapshotInfo_External{
						External: &ateapipb.ExternalSnapshotInfo{SnapshotUriPrefix: "gs://bucket/prefix"},
					},
				},
			},
		},
	}
	r := newReconciler(t, at, ate)

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "golden", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("Reconcile returned error on EXTERNAL snapshot; want nil: %v", err)
	}
	if res.RequeueAfter != 0 {
		t.Fatalf("RequeueAfter = %v, want 0 on terminal transition", res.RequeueAfter)
	}

	got := &atev1alpha1.ActorTemplate{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "golden", Namespace: "default"}, got); err != nil {
		t.Fatalf("get after reconcile: %v", err)
	}
	if got.Status.Phase != atev1alpha1.PhaseReady {
		t.Fatalf("phase = %q, want %q on external snapshot", got.Status.Phase, atev1alpha1.PhaseReady)
	}
	if got.Status.GoldenSnapshot != "gs://bucket/prefix" {
		t.Fatalf("GoldenSnapshot = %q, want the external URI prefix", got.Status.GoldenSnapshot)
	}
}

func TestGoldenSnapshotWarmupFor(t *testing.T) {
	probe := &atev1alpha1.ContainerReadyz{
		HTTPGet: &atev1alpha1.HTTPGetAction{Port: 80},
	}

	tests := []struct {
		name       string
		containers []atev1alpha1.Container
		wantZero   bool
	}{
		{
			name:       "no containers keeps default warmup",
			containers: nil,
			wantZero:   false,
		},
		{
			name: "all containers have readyz skips warmup",
			containers: []atev1alpha1.Container{
				{Name: "a", Readyz: probe},
				{Name: "b", Readyz: probe},
			},
			wantZero: true,
		},
		{
			name: "single container with readyz skips warmup",
			containers: []atev1alpha1.Container{
				{Name: "a", Readyz: probe},
			},
			wantZero: true,
		},
		{
			name: "mixed containers keep warmup",
			containers: []atev1alpha1.Container{
				{Name: "a", Readyz: probe},
				{Name: "b"},
			},
			wantZero: false,
		},
		{
			name: "no readyz anywhere keeps warmup",
			containers: []atev1alpha1.Container{
				{Name: "a"},
				{Name: "b"},
			},
			wantZero: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			at := &atev1alpha1.ActorTemplate{
				Spec: atev1alpha1.ActorTemplateSpec{Containers: tt.containers},
			}
			got := goldenSnapshotWarmupFor(at)
			if tt.wantZero && got != 0 {
				t.Errorf("goldenSnapshotWarmupFor = %v, want 0", got)
			}
			if !tt.wantZero && got != goldenSnapshotWarmup {
				t.Errorf("goldenSnapshotWarmupFor = %v, want %v", got, goldenSnapshotWarmup)
			}
		})
	}
}
