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
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

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

	// The fields below are unkeyed, so they are only safe on a fake owned by a
	// single direct-call test -- never on the package-level fakeAte, which is
	// shared by everything the background manager reconciles.
	createAtespaceErr error
	resumeActorErr    error
	suspendActorErr   error

	// snapshotType lets a test return a snapshot the controller must reject.
	snapshotType ateapipb.SnapshotType

	// snapshotURI is returned as the external snapshot prefix on suspend.
	snapshotURI string

	calls map[string]int
}

func newFakeControlClient() *fakeControlClient {
	return &fakeControlClient{
		createActorErr: map[string]error{},
		snapshotType:   ateapipb.SnapshotType_SNAPSHOT_TYPE_EXTERNAL,
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
	f.mu.Lock()
	injected := f.createAtespaceErr
	f.mu.Unlock()
	if injected != nil {
		return nil, injected
	}
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
	f.mu.Lock()
	injected := f.resumeActorErr
	f.mu.Unlock()
	if injected != nil {
		return nil, injected
	}
	return &ateapipb.ResumeActorResponse{}, nil
}

func (f *fakeControlClient) SuspendActor(ctx context.Context, in *ateapipb.SuspendActorRequest, opts ...grpc.CallOption) (*ateapipb.SuspendActorResponse, error) {
	f.record("SuspendActor")
	f.mu.Lock()
	injected, uri, typ := f.suspendActorErr, f.snapshotURI, f.snapshotType
	f.mu.Unlock()
	if injected != nil {
		return nil, injected
	}
	return &ateapipb.SuspendActorResponse{
		Actor: &ateapipb.Actor{
			LatestSnapshotInfo: &ateapipb.SnapshotInfo{
				Type: typ,
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

// --- Direct-call error-path tests -------------------------------------------
//
// The tests above run against the shared envtest manager, which is the right
// harness for "does an Event actually land in the API server" -- but it is the
// wrong one for the remaining error branches. Every test in this package shares
// ONE manager (controller-runtime enforces controller-name uniqueness per
// process), so unkeyed error injection leaks into whatever else is still
// reconciling, and two of these branches have nothing to key on: the atespace
// name is a compile-time constant and SuspendActor carries only the actor id.
//
// So these call Reconcile directly against a fake client the manager cannot
// see. The trade-off is deliberate and worth naming: a FakeRecorder proves
// "Eventf was called with these arguments", NOT "an Event exists for kubectl
// describe to show". That second property is the one that actually regressed in
// #1147, and it is proven once, against the real API server, by
// TestActorTemplateCreateActorFailureHoldsPhase above. Proving the plumbing
// once is enough; what is left to pin here is branch logic.

// newDirectReconciler builds an ActorTemplateReconciler over a fake client
// holding just `at`, wired to its own fake control client and recorder.
func newDirectReconciler(t *testing.T, at *atev1alpha1.ActorTemplate) (*ActorTemplateReconciler, *fakeControlClient, chan string) {
	t.Helper()

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(atev1alpha1.AddToScheme(scheme))

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(at).
		WithStatusSubresource(&atev1alpha1.ActorTemplate{}).
		Build()

	ate := newFakeControlClient()
	rec := record.NewFakeRecorder(16)
	return &ActorTemplateReconciler{
		Client:    c,
		Scheme:    scheme,
		AteClient: ate,
		Recorder:  rec,
	}, ate, rec.Events
}

func reconcileOnce(t *testing.T, r *ActorTemplateReconciler, at *atev1alpha1.ActorTemplate) error {
	t.Helper()
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: at.Name, Namespace: at.Namespace},
	})
	return err
}

// wantEvent drains the recorder and fails unless some event matches both the
// reason and a substring of the message. Matching on the message too is what
// separates "the right branch fired" from "some Warning fired".
func wantEvent(t *testing.T, events chan string, reason, msgSubstr string) {
	t.Helper()
	var seen []string
	for {
		select {
		case e := <-events:
			seen = append(seen, e)
			if strings.Contains(e, reason) && strings.Contains(e, msgSubstr) {
				return
			}
		default:
			t.Fatalf("no event with reason %q containing %q; saw %v", reason, msgSubstr, seen)
		}
	}
}

func wantNoEvents(t *testing.T, events chan string) {
	t.Helper()
	select {
	case e := <-events:
		t.Fatalf("expected no events, got %q", e)
	default:
	}
}

func reloadTemplate(t *testing.T, r *ActorTemplateReconciler, at *atev1alpha1.ActorTemplate) *atev1alpha1.ActorTemplate {
	t.Helper()
	out := &atev1alpha1.ActorTemplate{}
	key := types.NamespacedName{Name: at.Name, Namespace: at.Namespace}
	if err := r.Get(context.Background(), key, out); err != nil {
		t.Fatalf("reload ActorTemplate: %v", err)
	}
	return out
}

// TestAtespaceFailureIsNotTolerated pins the narrowness of the AlreadyExists
// tolerance: any other gRPC code must surface, not be swallowed as "the golden
// atespace was already there".
func TestAtespaceFailureIsNotTolerated(t *testing.T) {
	at := makeActorTemplate("direct-atespace-fail", "default")
	r, ate, events := newDirectReconciler(t, at)
	ate.createAtespaceErr = status.Error(codes.PermissionDenied, "nope")

	if err := reconcileOnce(t, r, at); err == nil {
		t.Fatal("PermissionDenied from CreateAtespace was swallowed; it must surface")
	}
	wantEvent(t, events, reasonAtespaceFailed, "nope")

	if got := ate.callCount("CreateActor"); got != 0 {
		t.Errorf("CreateActor called %d time(s) after the atespace failed; want 0", got)
	}
	if phase := reloadTemplate(t, r, at).Status.Phase; phase != atev1alpha1.PhaseInitial {
		t.Errorf("phase = %q after a failed atespace, want Initial", phase)
	}
}

// TestAtespaceAlreadyExistsIsTolerated is the other half: the one code the
// controller must NOT treat as a failure, because it is the steady state.
func TestAtespaceAlreadyExistsIsTolerated(t *testing.T) {
	at := makeActorTemplate("direct-atespace-exists", "default")
	r, ate, events := newDirectReconciler(t, at)
	ate.createAtespaceErr = status.Error(codes.AlreadyExists, "already there")

	if err := reconcileOnce(t, r, at); err != nil {
		t.Fatalf("AlreadyExists must be tolerated, got %v", err)
	}
	if got := ate.callCount("CreateActor"); got != 1 {
		t.Errorf("CreateActor called %d time(s); want 1", got)
	}
	wantEvent(t, events, reasonPhaseChanged, string(atev1alpha1.PhaseResumeGoldenActor))
}

func TestResumeFailureHoldsResumePhase(t *testing.T) {
	at := makeActorTemplate("direct-resume-fail", "default")
	at.Status.Phase = atev1alpha1.PhaseResumeGoldenActor
	at.Status.GoldenActorID = "actor-1"

	r, ate, events := newDirectReconciler(t, at)
	ate.resumeActorErr = status.Error(codes.Unavailable, "ateom down")

	if err := reconcileOnce(t, r, at); err == nil {
		t.Fatal("a failed ResumeActor must return an error so the request is retried")
	}
	wantEvent(t, events, reasonGoldenActorFailed, "ateom down")

	got := reloadTemplate(t, r, at)
	if got.Status.Phase != atev1alpha1.PhaseResumeGoldenActor {
		t.Errorf("phase = %q after a failed resume, want it to hold at ResumeGoldenActor", got.Status.Phase)
	}
	if !got.Status.TakeGoldenSnapshotAt.IsZero() {
		t.Error("TakeGoldenSnapshotAt was scheduled for an actor that never resumed")
	}
}

func TestSuspendFailureHoldsWaitPhase(t *testing.T) {
	at := makeActorTemplate("direct-suspend-fail", "default")
	at.Status.Phase = atev1alpha1.PhaseWaitGoldenActor
	at.Status.GoldenActorID = "actor-1"
	at.Status.TakeGoldenSnapshotAt = metav1.NewTime(time.Now().Add(-time.Minute))

	r, ate, events := newDirectReconciler(t, at)
	ate.suspendActorErr = status.Error(codes.Internal, "suspend exploded")

	if err := reconcileOnce(t, r, at); err == nil {
		t.Fatal("a failed SuspendActor must return an error so the request is retried")
	}
	wantEvent(t, events, reasonSnapshotFailed, "suspend exploded")

	got := reloadTemplate(t, r, at)
	if got.Status.Phase != atev1alpha1.PhaseWaitGoldenActor {
		t.Errorf("phase = %q after a failed suspend, want it to hold at WaitGoldenActor", got.Status.Phase)
	}
	if got.Status.GoldenSnapshot != "" {
		t.Errorf("GoldenSnapshot = %q after a failed suspend, want empty", got.Status.GoldenSnapshot)
	}
}

// TestNonExternalSnapshotIsRejected covers the branch that distinguishes "the
// suspend succeeded" from "the suspend produced something usable". Advancing to
// Ready here would publish an empty GoldenSnapshot as if it were a real one --
// a silent downgrade of a field other controllers read as ground truth.
func TestNonExternalSnapshotIsRejected(t *testing.T) {
	at := makeActorTemplate("direct-bad-snapshot", "default")
	at.Status.Phase = atev1alpha1.PhaseWaitGoldenActor
	at.Status.GoldenActorID = "actor-1"
	at.Status.TakeGoldenSnapshotAt = metav1.NewTime(time.Now().Add(-time.Minute))

	r, ate, events := newDirectReconciler(t, at)
	ate.snapshotType = ateapipb.SnapshotType_SNAPSHOT_TYPE_UNSPECIFIED

	if err := reconcileOnce(t, r, at); err == nil {
		t.Fatal("a non-external snapshot type was accepted; it must be rejected")
	}
	wantEvent(t, events, reasonSnapshotFailed, "Unexpected snapshot type")

	got := reloadTemplate(t, r, at)
	if got.Status.Phase == atev1alpha1.PhaseReady {
		t.Error("advanced to Ready on an unusable snapshot")
	}
	if got.Status.GoldenSnapshot != "" {
		t.Errorf("GoldenSnapshot = %q on an unusable snapshot, want empty", got.Status.GoldenSnapshot)
	}
}

// TestWaitPhaseRequeuesBeforeTheSnapshotDeadline pins the early-return: before
// the deadline the controller must requeue rather than suspend.
func TestWaitPhaseRequeuesBeforeTheSnapshotDeadline(t *testing.T) {
	at := makeActorTemplate("direct-wait-requeue", "default")
	at.Status.Phase = atev1alpha1.PhaseWaitGoldenActor
	at.Status.GoldenActorID = "actor-1"
	at.Status.TakeGoldenSnapshotAt = metav1.NewTime(time.Now().Add(time.Hour))

	r, ate, events := newDirectReconciler(t, at)

	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: at.Name, Namespace: at.Namespace},
	})
	if err != nil {
		t.Fatalf("waiting for the deadline is not an error, got %v", err)
	}
	if res.RequeueAfter <= 0 {
		t.Errorf("RequeueAfter = %v before the deadline; the template would stall", res.RequeueAfter)
	}
	if got := ate.callCount("SuspendActor"); got != 0 {
		t.Errorf("SuspendActor called %d time(s) before the deadline; want 0", got)
	}
	wantNoEvents(t, events)
}

// TestUnrecognizedPhaseErrors pins the default arm. A phase the controller does
// not know is a bug somewhere upstream, and returning nil would park the
// template forever with no signal.
func TestUnrecognizedPhaseErrors(t *testing.T) {
	at := makeActorTemplate("direct-bad-phase", "default")
	at.Status.Phase = atev1alpha1.PhaseType("Bogus")

	r, _, _ := newDirectReconciler(t, at)
	err := reconcileOnce(t, r, at)
	if err == nil {
		t.Fatal("an unrecognized phase must error, not be silently ignored")
	}
	if !strings.Contains(err.Error(), "Bogus") {
		t.Errorf("error %q does not name the offending phase", err)
	}
}

// TestMissingTemplateIsANoOp covers the first early return: a request for an
// object that is already gone must exit without touching the control plane.
func TestMissingTemplateIsANoOp(t *testing.T) {
	at := makeActorTemplate("direct-missing", "default")
	r, ate, events := newDirectReconciler(t, at)

	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "does-not-exist", Namespace: "default"},
	})
	if err != nil {
		t.Fatalf("a missing ActorTemplate must be a no-op, got %v", err)
	}
	if got := ate.callCount("CreateAtespace"); got != 0 {
		t.Errorf("CreateAtespace called %d time(s) for a missing object; want 0", got)
	}
	wantNoEvents(t, events)
}

// TestTerminatingTemplateIsANoOp covers the second early return: an object
// mid-deletion must not be driven further through the phase machine. Creating
// a golden actor for a template that is going away leaks the actor.
func TestTerminatingTemplateIsANoOp(t *testing.T) {
	at := makeActorTemplate("direct-terminating", "default")
	// A deletion timestamp is only durable on an object that has a finalizer;
	// without one the fake client drops the object outright and this would
	// silently re-test the missing-object branch above instead.
	at.Finalizers = []string{"test.ate.dev/hold"}
	now := metav1.Now()
	at.DeletionTimestamp = &now

	r, ate, events := newDirectReconciler(t, at)

	// Guard the guard: if the object did not survive, this test proves nothing.
	if got := reloadTemplate(t, r, at); got.DeletionTimestamp.IsZero() {
		t.Fatal("setup failed: the object is not actually terminating")
	}

	if err := reconcileOnce(t, r, at); err != nil {
		t.Fatalf("a terminating ActorTemplate must be a no-op, got %v", err)
	}
	if got := ate.callCount("CreateAtespace"); got != 0 {
		t.Errorf("CreateAtespace called %d time(s) for a terminating object; want 0", got)
	}
	if got := ate.callCount("CreateActor"); got != 0 {
		t.Errorf("CreateActor called %d time(s) for a terminating object; want 0", got)
	}
	wantNoEvents(t, events)
}

// TestActorTemplateSetupWithManagerRefusesNilRecorder is the ActorTemplate
// twin of TestSetupWithManagerRefusesNilRecorder in
// workerpool_controller_test.go. Both reconcilers grew the same fail-closed
// guard for the same reason -- a controller that reconciles correctly and
// emits nothing is invisible until someone runs `kubectl describe` and finds
// an empty Events section -- but only WorkerPool's guard was pinned, so
// ActorTemplate's could have been deleted without breaking a test.
//
// The positive control is TestMain, not a second registration here: controller
// name uniqueness is enforced per PROCESS, so re-registering "actortemplate"
// would fail for an unrelated reason however fresh the manager is.
func TestActorTemplateSetupWithManagerRefusesNilRecorder(t *testing.T) {
	withoutRecorder := newTestManager(t)
	err := (&ActorTemplateReconciler{
		Client:    withoutRecorder.GetClient(),
		Scheme:    withoutRecorder.GetScheme(),
		AteClient: newFakeControlClient(),
	}).SetupWithManager(withoutRecorder)
	if err == nil {
		t.Fatal("SetupWithManager accepted a nil Recorder; it must fail closed")
	}
	if !strings.Contains(err.Error(), "Recorder") {
		t.Errorf("error %q does not name the missing field", err)
	}
}
