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
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	atev1alpha1 "github.com/agent-substrate/substrate/pkg/api/v1alpha1"
	ateapipb "github.com/agent-substrate/substrate/pkg/proto/ateapipb"
)

// fakeControlClient is a scriptable ateapipb.ControlClient for the
// ActorTemplate reconcile tests.
//
// ControlClient has 14 methods and the reconciler calls 4, so the interface is
// EMBEDDED rather than fully implemented: an unimplemented method panics on a
// nil interface instead of quietly returning a zero value. That is deliberate.
// A fake that answers calls the controller was never expected to make would
// hide exactly the kind of regression this harness exists to catch.
type fakeControlClient struct {
	ateapipb.ControlClient

	mu sync.Mutex

	// createActorErr fails CreateActor for one ActorTemplate, keyed by name.
	// Keying by template rather than by a global toggle keeps error injection
	// from leaking into a neighbouring test whose object is still reconciling.
	createActorErr map[string]error

	// snapshotURI is returned as the external snapshot prefix on suspend.
	snapshotURI string

	calls map[string]int
}

func newFakeControlClient() *fakeControlClient {
	return &fakeControlClient{
		createActorErr: map[string]error{},
		snapshotURI:    "gs://test-bucket/golden",
		calls:          map[string]int{},
	}
}

func (f *fakeControlClient) record(method string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[method]++
}

func (f *fakeControlClient) callCount(method string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[method]
}

// failCreateActorFor makes CreateActor fail for one template until cleanup.
func (f *fakeControlClient) failCreateActorFor(t *testing.T, templateName string, err error) {
	t.Helper()
	f.mu.Lock()
	f.createActorErr[templateName] = err
	f.mu.Unlock()
	t.Cleanup(func() {
		f.mu.Lock()
		delete(f.createActorErr, templateName)
		f.mu.Unlock()
	})
}

func (f *fakeControlClient) CreateAtespace(ctx context.Context, in *ateapipb.CreateAtespaceRequest, opts ...grpc.CallOption) (*ateapipb.CreateAtespaceResponse, error) {
	f.record("CreateAtespace")
	// The real server returns AlreadyExists once the golden atespace is
	// present, and the controller is written to tolerate that. Returning it
	// unconditionally keeps every test after the first on the same path the
	// production controller spends almost all its life on.
	return nil, status.Error(codes.AlreadyExists, "atespace exists")
}

func (f *fakeControlClient) CreateActor(ctx context.Context, in *ateapipb.CreateActorRequest, opts ...grpc.CallOption) (*ateapipb.CreateActorResponse, error) {
	f.record("CreateActor")
	f.mu.Lock()
	err := f.createActorErr[in.GetActorTemplateName()]
	f.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &ateapipb.CreateActorResponse{}, nil
}

func (f *fakeControlClient) ResumeActor(ctx context.Context, in *ateapipb.ResumeActorRequest, opts ...grpc.CallOption) (*ateapipb.ResumeActorResponse, error) {
	f.record("ResumeActor")
	return &ateapipb.ResumeActorResponse{}, nil
}

func (f *fakeControlClient) SuspendActor(ctx context.Context, in *ateapipb.SuspendActorRequest, opts ...grpc.CallOption) (*ateapipb.SuspendActorResponse, error) {
	f.record("SuspendActor")
	f.mu.Lock()
	uri := f.snapshotURI
	f.mu.Unlock()
	return &ateapipb.SuspendActorResponse{
		Actor: &ateapipb.Actor{
			LatestSnapshotInfo: &ateapipb.SnapshotInfo{
				Type: ateapipb.SnapshotType_SNAPSHOT_TYPE_EXTERNAL,
				Data: &ateapipb.SnapshotInfo_External{
					External: &ateapipb.ExternalSnapshotInfo{SnapshotUriPrefix: uri},
				},
			},
		},
	}, nil
}

// makeActorTemplate builds the smallest ActorTemplate the CRD will accept.
//
// Every container declares a readyz probe on purpose: goldenSnapshotWarmupFor
// returns 0 only in that case, and otherwise imposes a 20s wall-clock wait in
// PhaseWaitGoldenActor that no reasonable test timeout can absorb. A template
// without readyz would make these tests look flaky when they are merely slow.
func makeActorTemplate(name, namespace string) *atev1alpha1.ActorTemplate {
	return &atev1alpha1.ActorTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: atev1alpha1.ActorTemplateSpec{
			// Images must be digest-pinned -- changing an image invalidates
			// snapshots, so the CRD refuses a mutable tag.
			PauseImage: "registry.k8s.io/pause@sha256:" + strings.Repeat("a", 64),
			Containers: []atev1alpha1.Container{{
				Name:   "app",
				Image:  "example.com/app@sha256:" + strings.Repeat("b", 64),
				Readyz: &atev1alpha1.ContainerReadyz{HTTPGet: &atev1alpha1.HTTPGetAction{Port: 80}},
			}},
			SnapshotsConfig: atev1alpha1.SnapshotsConfig{Location: "gs://test-bucket"},
		},
	}
}

// TestActorTemplateReachesReady drives the golden-snapshot phase machine end
// to end: Initial -> ResumeGoldenActor -> WaitGoldenActor -> Ready.
//
// Before this harness existed, ActorTemplateReconciler.Reconcile had 0%
// coverage (#9499) -- every fix to this controller was correct-by-inspection
// only. The assertions below are on the persisted status rather than on the
// fake's call log, because what a client reads is the status, not the calls.
func TestActorTemplateReachesReady(t *testing.T) {
	at := makeActorTemplate("test-golden-ready", "default")
	if err := k8sClient.Create(testCtx, at); err != nil {
		t.Fatalf("create ActorTemplate: %v", err)
	}
	t.Cleanup(func() { k8sClient.Delete(testCtx, at) }) //nolint:errcheck

	key := types.NamespacedName{Name: at.Name, Namespace: at.Namespace}

	var final atev1alpha1.ActorTemplate
	eventually(t, func(ctx context.Context) (bool, error) {
		current := &atev1alpha1.ActorTemplate{}
		if err := k8sClient.Get(ctx, key, current); err != nil {
			return false, nil
		}
		if current.Status.Phase != atev1alpha1.PhaseReady {
			return false, nil
		}
		final = *current
		return true, nil
	})

	if final.Status.GoldenActorID == "" {
		t.Error("reached Ready with no GoldenActorID recorded")
	}
	if final.Status.GoldenSnapshot != "gs://test-bucket/golden" {
		t.Errorf("GoldenSnapshot = %q, want the URI the suspend response carried",
			final.Status.GoldenSnapshot)
	}

	// The phases must actually have been walked, not skipped: reaching Ready
	// without ever resuming or suspending would mean the machine short-circuited.
	if got := fakeAte.callCount("ResumeActor"); got == 0 {
		t.Error("reached Ready without ever calling ResumeActor")
	}
	if got := fakeAte.callCount("SuspendActor"); got == 0 {
		t.Error("reached Ready without ever calling SuspendActor")
	}
}

// TestActorTemplateReadyConditionIsSet pins the Ready condition as a surface a
// client can read, separately from .status.phase.
func TestActorTemplateReadyConditionIsSet(t *testing.T) {
	at := makeActorTemplate("test-golden-condition", "default")
	if err := k8sClient.Create(testCtx, at); err != nil {
		t.Fatalf("create ActorTemplate: %v", err)
	}
	t.Cleanup(func() { k8sClient.Delete(testCtx, at) }) //nolint:errcheck

	key := types.NamespacedName{Name: at.Name, Namespace: at.Namespace}

	eventually(t, func(ctx context.Context) (bool, error) {
		current := &atev1alpha1.ActorTemplate{}
		if err := k8sClient.Get(ctx, key, current); err != nil {
			return false, nil
		}
		for _, c := range current.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" {
				return true, nil
			}
		}
		return false, nil
	})
}

// TestActorTemplateCreateActorFailureHoldsPhase covers the error path: a failed
// CreateActor must NOT advance the phase, and must leave a Warning event an
// operator can find with `kubectl describe`.
//
// This is the retro-verification of the ActorTemplate half of #1147, which
// shipped unverified because no harness could reach this code.
func TestActorTemplateCreateActorFailureHoldsPhase(t *testing.T) {
	name := "test-golden-createfail"
	fakeAte.failCreateActorFor(t, name, status.Error(codes.Internal, "boom"))

	at := makeActorTemplate(name, "default")
	if err := k8sClient.Create(testCtx, at); err != nil {
		t.Fatalf("create ActorTemplate: %v", err)
	}
	t.Cleanup(func() { k8sClient.Delete(testCtx, at) }) //nolint:errcheck

	key := types.NamespacedName{Name: at.Name, Namespace: at.Namespace}

	var found corev1.Event
	eventually(t, func(ctx context.Context) (bool, error) {
		events := &corev1.EventList{}
		if err := k8sClient.List(ctx, events, client.InNamespace(at.Namespace)); err != nil {
			return false, nil
		}
		for _, e := range events.Items {
			if e.InvolvedObject.Kind == "ActorTemplate" &&
				e.InvolvedObject.Name == name &&
				e.Reason == reasonGoldenActorFailed {
				found = e
				return true, nil
			}
		}
		return false, nil
	})

	if found.Type != corev1.EventTypeWarning {
		t.Errorf("failure event type = %q, want Warning", found.Type)
	}
	if !strings.Contains(found.Message, "boom") {
		t.Errorf("event message %q does not carry the underlying error", found.Message)
	}

	// The phase must not have advanced on a failed create -- advertising
	// ResumeGoldenActor for an actor that was never created is the dishonest
	// reading this path has to avoid.
	current := &atev1alpha1.ActorTemplate{}
	if err := k8sClient.Get(testCtx, key, current); err != nil {
		t.Fatalf("get ActorTemplate: %v", err)
	}
	if current.Status.Phase != atev1alpha1.PhaseInitial {
		t.Errorf("phase = %q after a failed CreateActor, want it to hold at Initial",
			current.Status.Phase)
	}
	if current.Status.GoldenActorID != "" {
		t.Errorf("GoldenActorID = %q after a failed CreateActor, want empty",
			current.Status.GoldenActorID)
	}
}
