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

// Tests for rendezvous hashing over Kubernetes leases.
//
// Two things are worth testing here that a coverage number does not capture.
// The first is the *property* the package exists for: which replica an item
// lands on must not depend on the order the replicas are listed in, and losing
// one replica out of n must move only that replica's items.  Both are asserted
// over generated inputs rather than over a hand-picked example.  The second is
// liveness: a lease counts a replica as live, and every field the liveness
// decision reads is optional in the API, so each missing-field case gets its
// own test.
//
// Leases are placed directly in the informer's indexer, which is what the
// lister underneath AssignedToThisReplica reads.
//
// Three behaviours here are deliberately not asserted, because no test can
// distinguish them from their absence:
//   - Hash's equal-weight tiebreak.  Reaching it needs two replica names whose
//     FNV-64a weights collide for the same item, which is ~2^32 work to find.
//     The branch is unreachable in practice, so both its direction and its
//     existence are untestable.
//   - AssignedToThisReplica's lister-error path.  The lister reads a cache
//     indexer with labels.Everything(), which has no failure mode to inject.
//   - Run's early return on a failed cache sync.  WaitForCacheSync only
//     returns false once the stop channel closes, so on that path the
//     fall-through would immediately hit <-ctx.Done() and return anyway.
package rendezvous

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	coordinationv1 "k8s.io/api/coordination/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"
)

const (
	testNamespace = "ate-system"
	testApp       = "podcertcontroller"
	testReplica   = "replica-a"
)

var testNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// fakeClock pins Now.  vendor/ does not carry k8s.io/utils/clock/testing, and
// only the passive half of the interface is exercised here, so the ticker and
// timer methods come from the real clock.
type fakeClock struct {
	clock.Clock
	now time.Time
}

func (c fakeClock) Now() time.Time                  { return c.now }
func (c fakeClock) Since(t time.Time) time.Duration { return c.now.Sub(t) }

var _ clock.Clock = fakeClock{}

func newTestHasher(t *testing.T, objs ...runtime.Object) (*Hasher, *fake.Clientset) {
	t.Helper()

	kc := fake.NewSimpleClientset(objs...)
	h := New(kc, testNamespace, testApp, testReplica, types.UID("replica-a-uid"),
		fakeClock{Clock: clock.RealClock{}, now: testNow})
	return h, kc
}

// liveLease builds a lease that counts as live at testNow.
func liveLease(name, holder string) *coordinationv1.Lease {
	return &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace, Name: name},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       ptr.To(holder),
			LeaseDurationSeconds: ptr.To[int32](15),
			RenewTime:            ptr.To(metav1.NewMicroTime(testNow.Add(-1 * time.Second))),
		},
	}
}

// addLeases puts leases where the lister behind AssignedToThisReplica reads
// them.
func addLeases(t *testing.T, h *Hasher, leases ...*coordinationv1.Lease) {
	t.Helper()
	for _, l := range leases {
		if err := h.leaseInformer.GetIndexer().Add(l); err != nil {
			t.Fatalf("adding lease %q to the indexer: %v", l.Name, err)
		}
	}
}

// --- Hash: the properties the package exists for -----------------------------

func TestHashWithNoLiveReplicasPicksNobody(t *testing.T) {
	if got := Hash("ns1/pcr1", nil); got != "" {
		t.Errorf("Hash with no replicas = %q, want the empty string", got)
	}
}

func TestHashWithOneReplicaPicksIt(t *testing.T) {
	if got := Hash("ns1/pcr1", []string{"only"}); got != "only" {
		t.Errorf("Hash = %q, want %q", got, "only")
	}
}

// TestHashDoesNotDependOnReplicaOrder is the property that makes the
// assignment safe to compute independently on every replica: two replicas that
// agree on the *set* of live peers must agree on the owner, even though each
// one lists them in whatever order its informer happens to hold.
func TestHashDoesNotDependOnReplicaOrder(t *testing.T) {
	replicas := []string{"replica-a", "replica-b", "replica-c", "replica-d", "replica-e"}

	for i := 0; i < 200; i++ {
		item := fmt.Sprintf("ns%d/pcr%d", i%7, i)
		want := Hash(item, replicas)

		// Every rotation of the list is the same set in a different order.
		for r := 1; r < len(replicas); r++ {
			rotated := append(append([]string{}, replicas[r:]...), replicas[:r]...)
			if got := Hash(item, rotated); got != want {
				t.Fatalf("Hash(%q) = %q with replicas in one order and %q in another (%v)", item, want, got, rotated)
			}
		}

		// ... and so is the exact reverse.
		reversed := make([]string, 0, len(replicas))
		for j := len(replicas) - 1; j >= 0; j-- {
			reversed = append(reversed, replicas[j])
		}
		if got := Hash(item, reversed); got != want {
			t.Fatalf("Hash(%q) = %q forwards but %q reversed", item, want, got)
		}
	}
}

// TestHashMovesOnlyTheDepartedReplicasItems is the rebalancing guarantee in the
// package doc: when one of n replicas goes away, its items are redistributed
// and *nothing else moves*.  A hash that fails this (modulo-of-index, say)
// would reshuffle nearly every item on every membership change.
func TestHashMovesOnlyTheDepartedReplicasItems(t *testing.T) {
	all := []string{"replica-a", "replica-b", "replica-c", "replica-d", "replica-e"}
	survivors := all[:4] // replica-e leaves

	movedFromSurvivor := 0
	ownedByDeparted := 0
	for i := 0; i < 1000; i++ {
		item := fmt.Sprintf("ns%d/pcr%d", i%13, i)
		before, after := Hash(item, all), Hash(item, survivors)

		if before == "replica-e" {
			ownedByDeparted++
			continue
		}
		if before != after {
			movedFromSurvivor++
		}
	}

	if movedFromSurvivor != 0 {
		t.Errorf("%d items moved between surviving replicas; only the departed replica's items should move", movedFromSurvivor)
	}
	if ownedByDeparted == 0 {
		t.Fatal("the departed replica owned no items, so this test proved nothing")
	}
}

// TestHashSpreadsItemsAcrossReplicas guards against the degenerate
// implementations that would satisfy every other test here: always returning
// the first replica, or always the lexicographic maximum.
func TestHashSpreadsItemsAcrossReplicas(t *testing.T) {
	replicas := []string{"replica-a", "replica-b", "replica-c", "replica-d", "replica-e"}

	const items = 2000
	counts := map[string]int{}
	for i := 0; i < items; i++ {
		counts[Hash(fmt.Sprintf("ns%d/pcr%d", i%13, i), replicas)]++
	}

	// Perfectly even would be 20% each.  A loose floor still rules out every
	// constant-answer implementation without making the test flaky-by-arithmetic.
	floor := items / len(replicas) / 2
	for _, r := range replicas {
		if counts[r] < floor {
			t.Errorf("replica %q got %d of %d items, want at least %d; distribution: %v", r, counts[r], items, floor, counts)
		}
	}
}

// TestHashMatchesAGoldenAssignment pins the concrete item-to-replica mapping,
// which every other Hash test here leaves free.  The properties those tests
// check -- order independence, stability, minimal rebalancing, even spread --
// all survive changes to what is actually fed to the hash, so a build that
// hashed replica+item instead of item+replica would pass all of them while
// assigning every item somewhere else.
//
// That matters because the assignment is a cross-replica agreement, not a
// local choice: two replicas on different builds must land on the same answer
// or they will both process, or both skip, the same request.  A change here is
// a fleet-wide reshuffle and has to be a deliberate edit to this table.
func TestHashMatchesAGoldenAssignment(t *testing.T) {
	replicas := []string{"replica-a", "replica-b", "replica-c", "replica-d", "replica-e"}

	for _, tc := range []struct{ item, want string }{
		{"ns1/pcr0", "replica-e"},
		{"ns1/pcr1", "replica-d"},
		{"ns1/pcr2", "replica-c"},
		{"ns1/pcr3", "replica-d"},
		{"ns1/pcr4", "replica-a"},
		{"ns1/pcr5", "replica-b"},
		{"ns1/pcr6", "replica-e"},
		{"ns1/pcr7", "replica-a"},
	} {
		if got := Hash(tc.item, replicas); got != tc.want {
			t.Errorf("Hash(%q) = %q, want %q", tc.item, got, tc.want)
		}
	}
}

func TestHashIsStableAcrossCalls(t *testing.T) {
	replicas := []string{"replica-a", "replica-b", "replica-c"}
	first := Hash("ns1/pcr1", replicas)
	for i := 0; i < 10; i++ {
		if got := Hash("ns1/pcr1", replicas); got != first {
			t.Fatalf("call %d returned %q, first call returned %q", i, got, first)
		}
	}
}

// TestHashTreatsAnEmptyReplicaNameAsNoReplicaYet pins a sharp edge in the
// exported function.  The loop uses maxReplica == "" as its "nothing chosen
// yet" sentinel, so a replica legitimately *named* the empty string is
// indistinguishable from the initial state: whatever comes after it is taken
// unconditionally, weight comparison skipped.  The result depends on list
// order, which is exactly what the rest of this file establishes must never
// happen.
//
// Pinned, not fixed, because the exported signature makes "" a caller-supplied
// value and I can't tell whether callers rely on the current shape.  The
// cluster-reachable path into it -- a Lease whose holderIdentity is set but
// empty -- is closed at the AssignedToThisReplica end instead, where skipping
// it matches the nil check already there.
func TestHashTreatsAnEmptyReplicaNameAsNoReplicaYet(t *testing.T) {
	// Find an item the empty-named replica would win outright on weight.
	item := ""
	for i := 0; i < 10000; i++ {
		candidate := fmt.Sprintf("ns1/pcr%d", i)
		if fnvhash(candidate+"") > fnvhash(candidate+"z") {
			item = candidate
			break
		}
	}
	if item == "" {
		t.Fatal("no item found where the empty-named replica outweighs the other; cannot set up the case")
	}

	if got := Hash(item, []string{"", "z"}); got != "z" {
		t.Errorf(`Hash(item, ["", "z"]) = %q, want "z": the empty name is read as the sentinel, so "z" is taken unconditionally`, got)
	}
	if got := Hash(item, []string{"z", ""}); got != "" {
		t.Errorf(`Hash(item, ["z", ""]) = %q, want "": listed second, the empty name wins on weight`, got)
	}
}

// TestHashWithDuplicateReplicaNamesIsStable exercises the equal-weight arm of
// the tiebreak.  Its strictly-less arm is unreachable from a test: it needs two
// *different* replica names whose FNV-64 weights collide for the same item, and
// finding one is a birthday search over a 64-bit space.  Order-independence,
// which is what the tiebreak exists to guarantee, is covered above.
func TestHashWithDuplicateReplicaNamesIsStable(t *testing.T) {
	if got := Hash("ns1/pcr1", []string{"replica-a", "replica-a"}); got != "replica-a" {
		t.Errorf("Hash = %q, want %q", got, "replica-a")
	}
}

func TestFnvHashIsNotTheZeroFunction(t *testing.T) {
	if fnvhash("a") == fnvhash("b") {
		t.Error("fnvhash returned the same value for different keys")
	}
	if fnvhash("a") != fnvhash("a") {
		t.Error("fnvhash is not deterministic")
	}
}

// --- AssignedToThisReplica: liveness ----------------------------------------

func TestAssignedToThisReplicaWithNoLeasesAssignsNothing(t *testing.T) {
	h, _ := newTestHasher(t)

	if h.AssignedToThisReplica(context.Background(), "ns1/pcr1") {
		t.Error("item assigned with no live replicas at all; a replica that cannot see its own lease should not claim work")
	}
}

// TestAssignedToThisReplicaAgreesWithHash checks the wiring rather than the
// arithmetic: whatever Hash says about the live set is what the method returns,
// in both directions.
func TestAssignedToThisReplicaAgreesWithHash(t *testing.T) {
	replicas := []string{testReplica, "replica-b", "replica-c"}

	mine, theirs := "", ""
	for i := 0; i < 1000 && (mine == "" || theirs == ""); i++ {
		item := fmt.Sprintf("ns1/pcr%d", i)
		if Hash(item, replicas) == testReplica {
			mine = item
		} else {
			theirs = item
		}
	}
	if mine == "" || theirs == "" {
		t.Fatal("could not find both an owned and an unowned item")
	}

	h, _ := newTestHasher(t)
	addLeases(t, h, liveLease(testReplica, testReplica), liveLease("replica-b", "replica-b"), liveLease("replica-c", "replica-c"))

	if !h.AssignedToThisReplica(context.Background(), mine) {
		t.Errorf("item %q hashes to this replica but was not assigned to it", mine)
	}
	if h.AssignedToThisReplica(context.Background(), theirs) {
		t.Errorf("item %q hashes to %q but was assigned to this replica", theirs, Hash(theirs, replicas))
	}
}

// TestAssignedToThisReplicaIgnoresDeadReplicas is the load-bearing case: a
// replica whose lease has gone stale must drop out of the live set, otherwise
// its share of the work is never picked up by anyone.
func TestAssignedToThisReplicaIgnoresDeadReplicas(t *testing.T) {
	// An item owned by replica-b while replica-b is alive.
	replicas := []string{testReplica, "replica-b"}
	item := ""
	for i := 0; i < 1000; i++ {
		candidate := fmt.Sprintf("ns1/pcr%d", i)
		if Hash(candidate, replicas) == "replica-b" {
			item = candidate
			break
		}
	}
	if item == "" {
		t.Fatal("no item owned by replica-b")
	}

	dead := liveLease("replica-b", "replica-b")
	dead.Spec.RenewTime = ptr.To(metav1.NewMicroTime(testNow.Add(-16 * time.Second))) // 15s duration

	h, _ := newTestHasher(t)
	addLeases(t, h, liveLease(testReplica, testReplica), dead)

	if !h.AssignedToThisReplica(context.Background(), item) {
		t.Error("work owned by a replica whose lease expired was not picked up by the surviving replica")
	}
}

// TestAssignedToThisReplicaLivenessBoundary pins where the expiry cut falls.
// now.After(deadline) means a lease is live right up to and including its
// deadline, and dead one instant later.
func TestAssignedToThisReplicaLivenessBoundary(t *testing.T) {
	// An item replica-b owns while it is alive, so "assigned to us" is exactly
	// "replica-b dropped out".  Both leases are present throughout: with an
	// empty live set the method returns false for its own reasons, which would
	// read as "the peer is alive" and invert the test.
	replicas := []string{testReplica, "replica-b"}
	item := ""
	for i := 0; i < 1000; i++ {
		candidate := fmt.Sprintf("ns1/pcr%d", i)
		if Hash(candidate, replicas) == "replica-b" {
			item = candidate
			break
		}
	}
	if item == "" {
		t.Fatal("no item owned by replica-b")
	}

	for _, tc := range []struct {
		name     string
		renew    time.Time
		wantLive bool
	}{
		{name: "a microsecond before the deadline", renew: testNow.Add(-15*time.Second + time.Microsecond), wantLive: true},
		{name: "exactly at the deadline", renew: testNow.Add(-15 * time.Second), wantLive: true},
		{name: "a microsecond past the deadline", renew: testNow.Add(-15*time.Second - time.Microsecond), wantLive: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other := liveLease("replica-b", "replica-b")
			other.Spec.RenewTime = ptr.To(metav1.NewMicroTime(tc.renew))

			h, _ := newTestHasher(t)
			addLeases(t, h, liveLease(testReplica, testReplica), other)

			gotLive := !h.AssignedToThisReplica(context.Background(), item)
			if gotLive != tc.wantLive {
				t.Errorf("replica-b live = %v, want %v", gotLive, tc.wantLive)
			}
		})
	}
}

// TestAssignedToThisReplicaSkipsLeasesMissingTheFieldsItReads walks the
// optional spec fields the liveness check dereferences.  Every one of them is
// omittable in the API, so each is reachable from an ordinary cluster -- a
// half-written lease, a hand-created one, a different client's idea of the
// object.  None of them may take the controller down or silently inflate the
// live set.
func TestAssignedToThisReplicaSkipsLeasesMissingTheFieldsItReads(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mutis func(*coordinationv1.Lease)
	}{
		{
			name:  "no renew time",
			mutis: func(l *coordinationv1.Lease) { l.Spec.RenewTime = nil },
		},
		{
			name:  "no holder identity",
			mutis: func(l *coordinationv1.Lease) { l.Spec.HolderIdentity = nil },
		},
		{
			name:  "empty holder identity",
			mutis: func(l *coordinationv1.Lease) { l.Spec.HolderIdentity = ptr.To("") },
		},
		{
			// Duration defaults to zero, so the deadline collapses onto the renew
			// time and any lease renewed in the past is already expired.
			name:  "no lease duration",
			mutis: func(l *coordinationv1.Lease) { l.Spec.LeaseDurationSeconds = nil },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			broken := liveLease("replica-b", "replica-b")
			tc.mutis(broken)

			h, _ := newTestHasher(t)
			addLeases(t, h, liveLease(testReplica, testReplica), broken)

			// This replica's own lease is the only sound one, so every item is
			// its own.  A panic here is the real failure mode; a broken lease
			// counted as live is the quieter one.
			//
			// Many items rather than one, because the indexer hands leases back
			// in map order: an empty holder identity that slips through is the
			// sentinel Hash treats as "nothing chosen yet", so it only changes
			// the answer for some items and only in one of the two orders.  One
			// item would make this test a coin flip.
			for i := 0; i < 50; i++ {
				item := fmt.Sprintf("ns1/pcr%d", i)
				if !h.AssignedToThisReplica(context.Background(), item) {
					t.Fatalf("item %q was assigned away: a lease missing a field the liveness check reads was counted as a live replica", item)
				}
			}
		})
	}
}

func TestAssignedToThisReplicaIgnoresLeasesInOtherNamespaces(t *testing.T) {
	elsewhere := liveLease("replica-b", "replica-b")
	elsewhere.Namespace = "somewhere-else"

	h, _ := newTestHasher(t)
	addLeases(t, h, liveLease(testReplica, testReplica), elsewhere)

	// If the out-of-namespace lease were counted, some items would hash to
	// replica-b; with it correctly ignored, this replica owns everything.
	for i := 0; i < 50; i++ {
		item := fmt.Sprintf("ns1/pcr%d", i)
		if !h.AssignedToThisReplica(context.Background(), item) {
			t.Fatalf("item %q was assigned elsewhere; a lease from another namespace leaked into the live set", item)
		}
	}
}

// --- New: the informer's filter ---------------------------------------------

// TestNewFiltersLeasesByApplicationLabel pins the label selector.  Without it
// the hasher would count every other application's replicas as its own peers
// and hand most of its work to replicas that will never do it.
func TestNewFiltersLeasesByApplicationLabel(t *testing.T) {
	h, kc := newTestHasher(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.leaseInformer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), h.leaseInformer.HasSynced) {
		t.Fatal("informer cache never synced")
	}

	want := labelKey + "=" + testApp
	var seen []string
	for _, a := range kc.Actions() {
		la, ok := a.(k8stesting.ListActionImpl)
		if !ok {
			continue
		}
		got := la.GetListRestrictions().Labels.String()
		seen = append(seen, got)
		if got == want {
			return
		}
	}
	t.Errorf("no List used the selector %q; selectors seen: %v", want, seen)
}

// --- ensureLease -------------------------------------------------------------

func TestEnsureLeaseCreatesTheLeaseWhenItIsMissing(t *testing.T) {
	h, kc := newTestHasher(t)

	if err := h.ensureLease(context.Background()); err != nil {
		t.Fatalf("ensureLease: %v", err)
	}

	got, err := kc.CoordinationV1().Leases(testNamespace).Get(context.Background(), testReplica, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("lease was not created: %v", err)
	}

	if got.Labels[labelKey] != testApp {
		t.Errorf("lease label %q = %q, want %q -- without it the lease is invisible to every peer's informer", labelKey, got.Labels[labelKey], testApp)
	}
	if n := len(got.OwnerReferences); n != 1 {
		t.Fatalf("lease has %d owner references, want 1 (the pod, so the lease is garbage-collected with it)", n)
	}
	ref := got.OwnerReferences[0]
	if ref.Kind != "Pod" || ref.APIVersion != "v1" || ref.Name != testReplica || ref.UID != types.UID("replica-a-uid") {
		t.Errorf("owner reference = %+v, want the v1/Pod named %q with this replica's UID", ref, testReplica)
	}
	if ref.Controller == nil || !*ref.Controller {
		t.Errorf("owner reference Controller = %v, want true", ref.Controller)
	}
	if got.Spec.HolderIdentity == nil || *got.Spec.HolderIdentity != testReplica {
		t.Errorf("holder identity = %v, want %q -- peers read this, not the object name", got.Spec.HolderIdentity, testReplica)
	}
	if got.Spec.LeaseDurationSeconds == nil || *got.Spec.LeaseDurationSeconds != 15 {
		t.Errorf("lease duration = %v seconds, want 15 (leaseDuration, in whole seconds)", got.Spec.LeaseDurationSeconds)
	}
	if got.Spec.RenewTime == nil || !got.Spec.RenewTime.Time.Equal(testNow) {
		t.Errorf("renew time = %v, want the clock's now (%v)", got.Spec.RenewTime, testNow)
	}
	if got.Spec.AcquireTime == nil || !got.Spec.AcquireTime.Time.Equal(testNow) {
		t.Errorf("acquire time = %v, want the clock's now (%v)", got.Spec.AcquireTime, testNow)
	}
}

// TestEnsureLeaseIsVisibleToTheLivenessCheckItFeeds closes the loop between the
// two halves of the package: the lease ensureLease writes must be one that
// AssignedToThisReplica would count as live.  A duration or renew time in the
// wrong unit would pass the field-by-field test above and still leave the
// replica permanently dead in its own eyes.
func TestEnsureLeaseIsVisibleToTheLivenessCheckItFeeds(t *testing.T) {
	h, kc := newTestHasher(t)

	if err := h.ensureLease(context.Background()); err != nil {
		t.Fatalf("ensureLease: %v", err)
	}
	written, err := kc.CoordinationV1().Leases(testNamespace).Get(context.Background(), testReplica, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("lease was not created: %v", err)
	}
	addLeases(t, h, written)

	if !h.AssignedToThisReplica(context.Background(), "ns1/pcr1") {
		t.Error("the replica does not consider itself live from the lease it just wrote")
	}
}

func TestEnsureLeaseRenewsAnExistingLease(t *testing.T) {
	existing := &coordinationv1.Lease{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testReplica,
			Labels:    map[string]string{"stale": "label"},
		},
		Spec: coordinationv1.LeaseSpec{
			HolderIdentity:       ptr.To("someone-else"),
			LeaseDurationSeconds: ptr.To[int32](3),
			AcquireTime:          ptr.To(metav1.NewMicroTime(testNow.Add(-time.Hour))),
			RenewTime:            ptr.To(metav1.NewMicroTime(testNow.Add(-time.Hour))),
			LeaseTransitions:     ptr.To[int32](7),
		},
	}

	h, kc := newTestHasher(t, existing)

	if err := h.ensureLease(context.Background()); err != nil {
		t.Fatalf("ensureLease: %v", err)
	}

	got, err := kc.CoordinationV1().Leases(testNamespace).Get(context.Background(), testReplica, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("getting the lease: %v", err)
	}

	if got.Spec.RenewTime == nil || !got.Spec.RenewTime.Time.Equal(testNow) {
		t.Errorf("renew time = %v, want it advanced to now (%v)", got.Spec.RenewTime, testNow)
	}
	if got.Spec.HolderIdentity == nil || *got.Spec.HolderIdentity != testReplica {
		t.Errorf("holder identity = %v, want it reclaimed as %q", got.Spec.HolderIdentity, testReplica)
	}
	if got.Spec.LeaseDurationSeconds == nil || *got.Spec.LeaseDurationSeconds != 15 {
		t.Errorf("lease duration = %v, want it corrected to 15", got.Spec.LeaseDurationSeconds)
	}
	if got.Labels[labelKey] != testApp {
		t.Errorf("label %q = %q, want the selector label restored", labelKey, got.Labels[labelKey])
	}
	if _, ok := got.Labels["stale"]; ok {
		t.Error("labels were merged rather than replaced; the whole map is overwritten by design")
	}
	if n := len(got.OwnerReferences); n != 1 || got.OwnerReferences[0].UID != types.UID("replica-a-uid") {
		t.Errorf("owner references = %+v, want them restored to this replica's pod", got.OwnerReferences)
	}

	// Pinned: the renewal path deliberately leaves the acquisition history
	// alone, so AcquireTime and LeaseTransitions keep whatever the create path
	// (or another writer) left there.
	if got.Spec.AcquireTime == nil || !got.Spec.AcquireTime.Time.Equal(testNow.Add(-time.Hour)) {
		t.Errorf("acquire time = %v, want the original acquisition preserved", got.Spec.AcquireTime)
	}
	if got.Spec.LeaseTransitions == nil || *got.Spec.LeaseTransitions != 7 {
		t.Errorf("lease transitions = %v, want it left at 7", got.Spec.LeaseTransitions)
	}
}

func TestEnsureLeaseReportsWhichCallFailed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		verb     string
		existing []runtime.Object
		wantIn   string
	}{
		{name: "get fails", verb: "get", wantIn: "while getting lease"},
		{name: "create fails", verb: "create", wantIn: "while creating lease"},
		{
			name:     "update fails",
			verb:     "update",
			existing: []runtime.Object{liveLease(testReplica, testReplica)},
			wantIn:   "while updating lease",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, kc := newTestHasher(t, tc.existing...)
			kc.PrependReactor(tc.verb, "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, fmt.Errorf("injected %s failure", tc.verb)
			})

			err := h.ensureLease(context.Background())
			if err == nil {
				t.Fatalf("ensureLease returned nil, want an error mentioning %q", tc.wantIn)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("ensureLease error = %q, want it to say %q so the log names the failing call", err, tc.wantIn)
			}
			if !strings.Contains(err.Error(), "injected "+tc.verb+" failure") {
				t.Errorf("ensureLease error = %q, want the underlying cause wrapped in", err)
			}
		})
	}
}

// --- runOnce / Run ------------------------------------------------------------

// TestRunOnceSwallowsLeaseErrors: the renewal loop must survive a failed write
// and try again on the next tick rather than propagate the error up into
// wait.UntilWithContext, which would crash the process.
func TestRunOnceSwallowsLeaseErrors(t *testing.T) {
	h, kc := newTestHasher(t)
	kc.PrependReactor("get", "leases", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("injected get failure")
	})

	h.runOnce(context.Background()) // must not panic

	if err := h.ensureLease(context.Background()); err == nil {
		t.Fatal("the injected failure stopped firing, so runOnce was not exercised against it")
	}
}

func TestRunOnceWritesTheLease(t *testing.T) {
	h, kc := newTestHasher(t)

	h.runOnce(context.Background())

	if _, err := kc.CoordinationV1().Leases(testNamespace).Get(context.Background(), testReplica, metav1.GetOptions{}); err != nil {
		t.Fatalf("runOnce did not write the lease: %v", err)
	}
}

func TestRunReturnsWhenTheContextIsAlreadyCancelled(t *testing.T) {
	h, _ := newTestHasher(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		h.Run(ctx)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return on a cancelled context")
	}
}
