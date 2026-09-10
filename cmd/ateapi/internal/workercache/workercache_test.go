// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package workercache_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/cmd/ateapi/internal/store"
	"github.com/agent-substrate/substrate/cmd/ateapi/internal/workercache"
	"github.com/agent-substrate/substrate/pkg/proto/ateapipb"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/protobuf/testing/protocmp"
	"k8s.io/apimachinery/pkg/util/wait"
)

func TestCache_NotReadyBeforeStart(t *testing.T) {
	c := workercache.New(newFakeStore(), time.Hour)
	_, err := c.Workers()
	if err == nil {
		t.Fatal("expected error from Workers before Start, got nil")
	}
	if _, err := c.Worker(workerName("ns", "pod")); err == nil {
		t.Fatal("expected error from Worker before Start, got nil")
	}
}

func TestCache_SyncsOnStart(t *testing.T) {
	w1 := makeWorker("ns", "pod1", 1)
	w2 := makeWorker("ns", "pod2", 1)

	c := workercache.New(newFakeStore(w1, w2), time.Hour)
	ctx := t.Context()

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	got, err := c.Workers()
	if err != nil {
		t.Fatalf("Workers: %v", err)
	}
	if diff := cmp.Diff([]*ateapipb.Worker{w1, w2}, got, protocmp.Transform(), workerSortOpt); diff != "" {
		t.Errorf("workers mismatch (-want +got):\n%s", diff)
	}
}

func TestCache_Worker(t *testing.T) {
	want := makeWorker("ns", "pod", 1)
	c := workercache.New(newFakeStore(want), time.Hour)
	if err := c.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	got, err := c.Worker(workerName("ns", "pod"))
	if err != nil {
		t.Fatalf("Worker: %v", err)
	}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("worker mismatch (-want +got):\n%s", diff)
	}
	if _, err := c.Worker(workerName("ns", "missing")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing Worker error = %v, want store.ErrNotFound", err)
	}
}

func TestCache_CreatedEvent(t *testing.T) {
	fs := newFakeStore()
	c := workercache.New(fs, time.Hour)
	ctx := t.Context()

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	w := makeWorker("ns", "pod1", 1)
	fs.send(store.WorkerEvent{Type: store.WorkerEventCreated, Worker: w})

	eventually(t, func() bool {
		workers, err := c.Workers()
		return err == nil && len(workers) == 1
	}, 2*time.Second)

	got, _ := c.Workers()
	if diff := cmp.Diff([]*ateapipb.Worker{w}, got, protocmp.Transform(), workerSortOpt); diff != "" {
		t.Errorf("workers mismatch (-want +got):\n%s", diff)
	}
}

func TestCache_UpdatedEvent_NewerVersionApplied(t *testing.T) {
	w := makeWorker("ns", "pod1", 1)
	fs := newFakeStore(w)
	c := workercache.New(fs, time.Hour)
	ctx := t.Context()

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	updated := makeWorker("ns", "pod1", 2)
	updated.Status.Allocated = &ateapipb.WorkerResources{Actors: 1}
	fs.send(store.WorkerEvent{Type: store.WorkerEventUpdated, Worker: updated})

	eventually(t, func() bool {
		workers, err := c.Workers()
		if err != nil || len(workers) != 1 {
			return false
		}
		return workers[0].GetStatus().GetAllocated().GetActors() == 1
	}, 2*time.Second)

	got, _ := c.Workers()
	if diff := cmp.Diff([]*ateapipb.Worker{updated}, got, protocmp.Transform(), workerSortOpt); diff != "" {
		t.Errorf("workers mismatch (-want +got):\n%s", diff)
	}
}

func TestCache_UpdatedEvent_OlderVersionIgnored(t *testing.T) {
	w := makeWorker("ns", "pod1", 5)
	fs := newFakeStore(w)
	c := workercache.New(fs, time.Hour)
	ctx := t.Context()

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Send a stale update followed by a sentinel we can detect.
	stale := makeWorker("ns", "pod1", 3)
	stale.Status.Allocated = &ateapipb.WorkerResources{Actors: 7}
	fs.send(store.WorkerEvent{Type: store.WorkerEventUpdated, Worker: stale})

	sentinel := makeWorker("ns", "pod2", 1)
	fs.send(store.WorkerEvent{Type: store.WorkerEventCreated, Worker: sentinel})

	// Wait for the sentinel to be processed so we know the stale event was also handled.
	eventually(t, func() bool {
		workers, err := c.Workers()
		return err == nil && len(workers) == 2
	}, 2*time.Second)

	got, _ := c.Workers()
	if diff := cmp.Diff([]*ateapipb.Worker{w, sentinel}, got, protocmp.Transform(), workerSortOpt); diff != "" {
		t.Errorf("workers mismatch (-want +got):\n%s", diff)
	}
}

func TestCache_DeletedEvent(t *testing.T) {
	w := makeWorker("ns", "pod1", 1)
	fs := newFakeStore(w)
	c := workercache.New(fs, time.Hour)
	ctx := t.Context()

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Delete events carry only the name.
	fs.send(store.WorkerEvent{
		Type:   store.WorkerEventDeleted,
		Worker: &ateapipb.Worker{Metadata: &ateapipb.ResourceMetadata{Name: workerName("ns", "pod1")}},
	})

	eventually(t, func() bool {
		workers, err := c.Workers()
		return err == nil && len(workers) == 0
	}, 2*time.Second)
}

func TestCache_Disconnect_ResyncsWithFreshSnapshot(t *testing.T) {
	w1 := makeWorker("ns", "pod1", 1)
	fs := newFakeStore(w1)
	c := workercache.New(fs, time.Hour)
	ctx := t.Context()

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Add a worker to the store snapshot and disconnect to trigger resync.
	w2 := makeWorker("ns", "pod2", 1)
	fs.setWorkers(w1, w2)
	fs.disconnect()

	// After resync the cache should reflect the updated snapshot.
	eventually(t, func() bool {
		workers, err := c.Workers()
		return err == nil && len(workers) == 2
	}, 2*time.Second)

	got, _ := c.Workers()
	if diff := cmp.Diff([]*ateapipb.Worker{w1, w2}, got, protocmp.Transform(), workerSortOpt); diff != "" {
		t.Errorf("workers after resync (-want +got):\n%s", diff)
	}
}

// TestCache_StaysReadyDuringResync guards against a watch-disconnect turning
// a brief cache lag into a hard failure for every in-flight caller. Workers()
// must keep serving the last-known-good snapshot for the whole resync window,
// not just after it completes — the same tolerance the periodic-relist path
// already gives a transient ListWorkers failure (see
// TestCache_Relist_FailureIsNonFatal).
func TestCache_StaysReadyDuringResync(t *testing.T) {
	w1 := makeWorker("ns", "pod1", 1)
	fs := newFakeStore(w1)
	c := workercache.New(fs, time.Hour)
	ctx := t.Context()

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	startListCalls := fs.getListCalls()

	// Arm the gate, then disconnect. watchEvents observes the closed watch
	// channel and calls resync(), which blocks inside ListWorkers on the
	// gate below -- simulating a slow relist during reconnect.
	block := make(chan struct{})
	fs.setBlockList(block)
	fs.disconnect()

	// Wait for resync's ListWorkers call to actually be in flight (blocked)
	// before asserting anything about Workers() -- otherwise the assertion
	// below would race the watchEvents goroutine noticing the disconnect.
	eventually(t, func() bool {
		return fs.getListCalls() > startListCalls
	}, 2*time.Second)

	// While resync is still blocked, Workers() must keep returning the
	// stale-but-valid snapshot rather than an error.
	got, err := c.Workers()
	if err != nil {
		t.Fatalf("Workers() during resync: got error %v, want the last-known-good snapshot", err)
	}
	if diff := cmp.Diff([]*ateapipb.Worker{w1}, got, protocmp.Transform(), workerSortOpt); diff != "" {
		t.Errorf("workers during resync (-want +got):\n%s", diff)
	}

	// Release the gate and confirm the cache converges normally afterward.
	close(block)
	eventually(t, func() bool {
		workers, err := c.Workers()
		return err == nil && len(workers) == 1
	}, 2*time.Second)
}

func TestCache_MultipleDisconnects(t *testing.T) {
	fs := newFakeStore()
	c := workercache.New(fs, time.Hour)
	ctx := t.Context()

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Disconnect three times, each time adding a worker to the snapshot.
	for i := range 3 {
		pod := makeWorker("ns", string(rune('a'+i)), 1)
		fs.setWorkers(append(fs.workers[:i], pod)...)
		fs.disconnect()

		want := i + 1
		eventually(t, func() bool {
			workers, err := c.Workers()
			return err == nil && len(workers) == want
		}, 2*time.Second)
	}
}

func TestCache_WatchClosedOnListWorkersFailure(t *testing.T) {
	fs := newFakeStore()
	fs.listErr = errors.New("store unavailable")
	c := workercache.New(fs, time.Hour)

	if err := c.Start(t.Context()); err == nil {
		t.Fatal("expected Start to fail when ListWorkers errors")
	}

	fs.mu.Lock()
	closes := fs.closes
	fs.mu.Unlock()
	if closes != 1 {
		t.Fatalf("expected watch to be closed once on sync failure, got %d closes", closes)
	}
}

func TestCache_WatchClosedOnShutdown(t *testing.T) {
	fs := newFakeStore()
	c := workercache.New(fs, time.Hour)
	ctx, cancel := context.WithCancel(t.Context())

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	cancel()

	eventually(t, func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return fs.closes == 1
	}, 2*time.Second)
}

func TestCache_WatchClosedOnDisconnectAndShutdown(t *testing.T) {
	fs := newFakeStore()
	c := workercache.New(fs, time.Hour)
	ctx, cancel := context.WithCancel(t.Context())

	if err := c.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Disconnect: the old watch should be closed and a new one opened.
	fs.disconnect()
	eventually(t, func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return fs.closes == 1
	}, 2*time.Second)

	// Shutdown: the new watch should also be closed.
	cancel()
	eventually(t, func() bool {
		fs.mu.Lock()
		defer fs.mu.Unlock()
		return fs.closes == 2
	}, 2*time.Second)
}

func TestCache_Relist_RecoversFromMissedCreate(t *testing.T) {
	w1 := makeWorker("ns", "pod1", 1)
	fs := newFakeStore(w1)
	c := workercache.New(fs, 10*time.Millisecond)

	if err := c.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Add a worker directly to the store without sending a watch event,
	// simulating a silent PUBLISH failure.
	w2 := makeWorker("ns", "pod2", 1)
	fs.setWorkers(w1, w2)

	eventually(t, func() bool {
		workers, err := c.Workers()
		return err == nil && len(workers) == 2
	}, 2*time.Second)

	got, _ := c.Workers()
	if diff := cmp.Diff([]*ateapipb.Worker{w1, w2}, got, protocmp.Transform(), workerSortOpt); diff != "" {
		t.Errorf("workers after relist (-want +got):\n%s", diff)
	}
}

func TestCache_Relist_RecoversFromMissedDelete(t *testing.T) {
	w1 := makeWorker("ns", "pod1", 1)
	w2 := makeWorker("ns", "pod2", 1)
	fs := newFakeStore(w1, w2)
	c := workercache.New(fs, 10*time.Millisecond)

	if err := c.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Remove a worker from the store without a watch event,
	// simulating a silent PUBLISH failure on delete.
	fs.setWorkers(w1)

	eventually(t, func() bool {
		workers, err := c.Workers()
		return err == nil && len(workers) == 1
	}, 2*time.Second)

	got, _ := c.Workers()
	if diff := cmp.Diff([]*ateapipb.Worker{w1}, got, protocmp.Transform(), workerSortOpt); diff != "" {
		t.Errorf("workers after relist (-want +got):\n%s", diff)
	}
}

func TestCache_Relist_FailureIsNonFatal(t *testing.T) {
	w1 := makeWorker("ns", "pod1", 1)
	fs := newFakeStore(w1)
	c := workercache.New(fs, 10*time.Millisecond)

	if err := c.Start(t.Context()); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Make ListWorkers fail to simulate a transient store error.
	fs.mu.Lock()
	fs.listErr = errors.New("store unavailable")
	fs.mu.Unlock()

	// Wait long enough for at least one relist attempt.
	time.Sleep(50 * time.Millisecond)

	// Clear the error; the cache should still be usable with the old snapshot.
	fs.mu.Lock()
	fs.listErr = nil
	fs.mu.Unlock()

	workers, err := c.Workers()
	if err != nil {
		t.Fatalf("Workers: %v", err)
	}
	if diff := cmp.Diff([]*ateapipb.Worker{w1}, workers, protocmp.Transform(), workerSortOpt); diff != "" {
		t.Errorf("workers mismatch (-want +got):\n%s", diff)
	}
}

type fakeStore struct {
	store.Interface

	mu        sync.Mutex
	workers   []*ateapipb.Worker
	watchCh   chan store.WorkerEvent
	listErr   error // if set, ListWorkers returns it
	closes    int   // number of times a returned watch was Closed
	listCalls int
	blockList chan struct{} // if set, ListWorkers blocks until this is closed
}

func newFakeStore(workers ...*ateapipb.Worker) *fakeStore {
	return &fakeStore{
		workers: workers,
		watchCh: make(chan store.WorkerEvent, 16),
	}
}

func (f *fakeStore) WatchWorkers(_ context.Context) (*store.WorkerWatch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return store.NewWorkerWatch(f.watchCh, func() {
		f.mu.Lock()
		f.closes++
		f.mu.Unlock()
	}), nil
}

func (f *fakeStore) ListWorkers(_ context.Context, _ store.ListOptions) (store.ListResponse[*ateapipb.Worker], error) {
	f.mu.Lock()
	f.listCalls++
	block := f.blockList
	f.mu.Unlock()

	if block != nil {
		<-block
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return store.ListResponse[*ateapipb.Worker]{}, f.listErr
	}
	out := make([]*ateapipb.Worker, len(f.workers))
	copy(out, f.workers)
	return store.ListResponse[*ateapipb.Worker]{Items: out}, nil
}

// setBlockList arms a gate that the next ListWorkers call (i.e. the one
// resync() issues) blocks on until it is closed. Must be set after Start()
// has completed its own initial ListWorkers call.
func (f *fakeStore) setBlockList(ch chan struct{}) {
	f.mu.Lock()
	f.blockList = ch
	f.mu.Unlock()
}

func (f *fakeStore) getListCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listCalls
}

func (f *fakeStore) send(event store.WorkerEvent) {
	f.mu.Lock()
	ch := f.watchCh
	f.mu.Unlock()
	ch <- event
}

func (f *fakeStore) setWorkers(workers ...*ateapipb.Worker) {
	f.mu.Lock()
	f.workers = workers
	f.mu.Unlock()
}

func (f *fakeStore) disconnect() {
	f.mu.Lock()
	old := f.watchCh
	f.watchCh = make(chan store.WorkerEvent, 16)
	f.mu.Unlock()
	close(old)
}

// workerName stands in for the pod UID that names a real Worker. The tests only
// need it to be stable and unique per pod.
func workerName(namespace, pod string) string {
	return "uid-" + namespace + "-" + pod
}

func makeWorker(namespace, pod string, version int64) *ateapipb.Worker {
	return &ateapipb.Worker{
		Metadata: &ateapipb.ResourceMetadata{
			Name:    workerName(namespace, pod),
			Version: version,
		},
		WorkerNamespace: namespace,
		WorkerPod:       pod,
		WorkerPodUid:    workerName(namespace, pod),
		Status:          &ateapipb.WorkerStatus{},
	}
}

// workerSortOpt compares workers ignoring ordering.
var workerSortOpt = cmpopts.SortSlices(func(a, b *ateapipb.Worker) bool {
	if a.GetWorkerNamespace() != b.GetWorkerNamespace() {
		return a.GetWorkerNamespace() < b.GetWorkerNamespace()
	}
	return a.GetWorkerPod() < b.GetWorkerPod()
})

// eventually polls condition every 10ms until it returns true or timeout elapses.
func eventually(t *testing.T, condition func() bool, timeout time.Duration) {
	t.Helper()
	err := wait.PollUntilContextTimeout(t.Context(), 10*time.Millisecond, timeout, true, func(context.Context) (bool, error) {
		return condition(), nil
	})
	if err != nil {
		t.Fatal("condition not met within timeout")
	}
}
