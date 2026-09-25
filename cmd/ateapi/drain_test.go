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

package main

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/agent-substrate/substrate/internal/serverboot"
)

// withDrainTimings sets the drain flags for the duration of a test. They are
// package-level pflag pointers, so a test has to write through them; the
// cleanup restores the production defaults for whatever runs next.
func withDrainTimings(t *testing.T, delay, timeout time.Duration) {
	t.Helper()
	prevDelay, prevTimeout := *drainDelay, *drainTimeout
	t.Cleanup(func() { *drainDelay, *drainTimeout = prevDelay, prevTimeout })
	*drainDelay, *drainTimeout = delay, timeout
}

// servingGRPC returns a started gRPC server on loopback, and a function that
// blocks until the server has actually stopped serving.
func servingGRPC(t *testing.T) (*grpc.Server, func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	served := make(chan struct{})
	go func() {
		defer close(served)
		// Serve returns when the server is stopped, which is the signal the
		// caller waits on. An error here means it stopped for another reason,
		// and the test will report that as a timeout rather than mask it.
		_ = srv.Serve(lis)
	}()
	t.Cleanup(srv.Stop)
	return srv, func() { <-served }
}

// TestDrainMarksNotReadyBeforeSleeping is the ordering this function exists to
// get right. Kubernetes keeps routing to a pod until its readiness probe fails,
// so readiness has to drop first and the delay has to come after -- that window
// is what lets in-flight work finish and lets the endpoint removal propagate.
// Marking not-ready after the delay, or after GracefulStop, would leave the pod
// advertising itself as ready while it is refusing new streams, which is the
// classic dropped-request bug on a rolling update.
func TestDrainMarksNotReadyBeforeSleeping(t *testing.T) {
	// A delay long enough that observing not-ready inside it is unambiguous,
	// but short enough not to slow the suite if something regresses.
	withDrainTimings(t, 2*time.Second, time.Second)

	srv, _ := servingGRPC(t)
	readiness := &serverboot.Readiness{}
	if !readiness.Ready() {
		t.Fatal("readiness is not ready before the drain starts")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := drainOnShutdown(ctx, srv, readiness)
	cancel()

	deadline := time.Now().Add(time.Second)
	for readiness.Ready() {
		if time.Now().After(deadline) {
			t.Fatal("readiness still reports ready a second into the drain delay, want not-ready before the delay begins")
		}
		time.Sleep(time.Millisecond)
	}

	// The drain must still be in its delay: proving not-ready came first means
	// showing it happened while the server was still up, not after everything
	// finished.
	select {
	case <-done:
		t.Fatal("drain completed during the delay window, so this says nothing about ordering")
	default:
	}
}

// TestDrainStopsTheServerAndSignalsDone covers the ordinary path: nothing is
// in flight, so GracefulStop returns promptly and the returned channel closes.
// main blocks on that channel before exiting, so a drain that never closed it
// would hang shutdown until the kubelet's SIGKILL.
func TestDrainStopsTheServerAndSignalsDone(t *testing.T) {
	withDrainTimings(t, time.Millisecond, 5*time.Second)

	srv, waitStopped := servingGRPC(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := drainOnShutdown(ctx, srv, &serverboot.Readiness{})
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("drain did not signal done, want main unblocked after a graceful stop")
	}

	waitStopped()
}

// TestDrainForcesStopPastTheDeadline pins the escape hatch. GracefulStop blocks
// on in-flight RPCs with no deadline of its own, so one stuck handler would
// hold the process open until the kubelet's SIGKILL and cost every other
// connection its clean shutdown. The timeout converts that into a bounded
// forced stop.
//
// The stuck RPC has to be a real handler. An idle TCP connection does not
// reproduce it: the server's preface read is tracked by the same wait group
// that a *forced* stop also waits on, so it would stall both paths for the
// full connection timeout and the test would pass for the wrong reason.
// Blocking inside a handler is the case the deadline is actually for, because
// a forced stop does not wait for handlers and a graceful one does.
func TestDrainForcesStopPastTheDeadline(t *testing.T) {
	const timeout = 300 * time.Millisecond
	withDrainTimings(t, 0, timeout)

	srv, stream, entered := serverWithAStuckHandler(t)

	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the handler never ran, so nothing is holding the graceful drain open")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := drainOnShutdown(ctx, srv, &serverboot.Readiness{})
	start := time.Now()
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("drain never completed, want a forced stop once the deadline passed")
	}

	// Bounded on both sides: finishing early would mean the graceful path
	// returned despite the stuck handler, which is not what is being tested;
	// the upper bound is what distinguishes a forced stop from simply waiting.
	if elapsed := time.Since(start); elapsed < timeout {
		t.Errorf("drain finished in %v, before the %v deadline", elapsed, timeout)
	} else if elapsed > 5*time.Second {
		t.Errorf("drain took %v, want a forced stop shortly after the %v deadline", elapsed, timeout)
	}

	// Timing alone does not show the server was stopped -- the drain returns
	// once its deadline fires whether or not it did anything about it. Dropping
	// the srv.Stop() call leaves this the only failing assertion: the client's
	// stream survives, because the parked graceful stop holds the connection
	// open instead of tearing it down.
	streamBroken := make(chan error, 1)
	go func() { streamBroken <- stream.RecvMsg(&emptypb.Empty{}) }()
	select {
	case err := <-streamBroken:
		if err == nil {
			t.Error("the in-flight stream completed normally, want it cancelled by the forced stop")
		}
	case <-time.After(5 * time.Second):
		t.Error("the in-flight stream is still open after the drain returned, so nothing forced the server to stop")
	}
}

// serverWithAStuckHandler starts a gRPC server with one streaming method whose
// handler blocks until the test ends, and opens a client stream against it. It
// returns the server, the client connection, and a channel closed once the
// handler is running -- a graceful stop is only held open from that point.
//
// The service is described by hand rather than generated: the test needs a
// method that blocks, not a particular API.
func serverWithAStuckHandler(t *testing.T) (*grpc.Server, grpc.ClientStream, <-chan struct{}) {
	t.Helper()

	release := make(chan struct{})
	entered := make(chan struct{})

	desc := grpc.ServiceDesc{
		ServiceName: "draintest.Stuck",
		HandlerType: (*any)(nil),
		Streams: []grpc.StreamDesc{{
			StreamName: "Hang",
			Handler: func(_ any, _ grpc.ServerStream) error {
				close(entered)
				<-release
				return nil
			},
			ServerStreams: true,
			ClientStreams: true,
		}},
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	srv.RegisterService(&desc, nil)
	go func() { _ = srv.Serve(lis) }()

	cc, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	// Registered last so it runs first, and it is the only teardown here. The
	// handler outlives the forced stop by design, which leaves the drain's own
	// GracefulStop parked on it holding the server lock -- so releasing the
	// handler has to come before anything else, and a second srv.Stop from a
	// cleanup would deadlock against that parked call rather than tidy up.
	t.Cleanup(func() {
		close(release)
		cc.Close()
	})
	stream, err := cc.NewStream(context.Background(), &desc.Streams[0], "/draintest.Stuck/Hang")
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	return srv, stream, entered
}
