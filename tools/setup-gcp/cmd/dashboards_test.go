// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/monitoring/dashboard/apiv1/dashboardpb"
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeDashboardClient records the etag each UpdateDashboard was called with
// and replays a scripted error per attempt.
type fakeDashboardClient struct {
	updateErrs []error  // updateErrs[i] is returned by the i-th update
	sentEtags  []string // etag carried by each update, in order
	getEtags   []string // getEtags[i] is returned by the i-th get
	getErr     error    // if non-nil, every get fails with this
	gets       int
}

func (f *fakeDashboardClient) UpdateDashboard(_ context.Context, req *dashboardpb.UpdateDashboardRequest, _ ...gax.CallOption) (*dashboardpb.Dashboard, error) {
	f.sentEtags = append(f.sentEtags, req.GetDashboard().GetEtag())
	i := len(f.sentEtags) - 1
	if i < len(f.updateErrs) && f.updateErrs[i] != nil {
		return nil, f.updateErrs[i]
	}
	return req.GetDashboard(), nil
}

func (f *fakeDashboardClient) GetDashboard(_ context.Context, req *dashboardpb.GetDashboardRequest, _ ...gax.CallOption) (*dashboardpb.Dashboard, error) {
	f.gets++
	if f.getErr != nil {
		return nil, f.getErr
	}
	etag := "refreshed"
	if i := f.gets - 1; i < len(f.getEtags) {
		etag = f.getEtags[i]
	}
	return &dashboardpb.Dashboard{Name: req.GetName(), Etag: etag}, nil
}

func aborted() error {
	return status.Error(codes.Aborted, "The supplied etag is not up to date.")
}

// noRetryDelay collapses the backoff so the retry tests do not sleep.
func noRetryDelay(t *testing.T) {
	t.Helper()
	orig := dashboardRetryBackoff
	t.Cleanup(func() { dashboardRetryBackoff = orig })
	dashboardRetryBackoff = func(int) time.Duration { return 0 }
}

func TestUpdateDashboardWithRetryRetriesOnStaleEtag(t *testing.T) {
	noRetryDelay(t)

	f := &fakeDashboardClient{
		updateErrs: []error{aborted(), nil},
		getEtags:   []string{"fresh-etag"},
	}
	d := &dashboardpb.Dashboard{
		Name:        "projects/p/dashboards/abc",
		DisplayName: "Substrate gRPC Server",
		Etag:        "stale-etag",
	}

	if err := updateDashboardWithRetry(context.Background(), f, d); err != nil {
		t.Fatalf("expected the retry to succeed, got %v", err)
	}
	if len(f.sentEtags) != 2 {
		t.Fatalf("expected 2 update attempts, got %d", len(f.sentEtags))
	}
	// The point of the retry: the second attempt must carry the etag the
	// re-read returned. Resending the stale one would abort forever.
	if f.sentEtags[0] != "stale-etag" {
		t.Errorf("first attempt should send the original etag, sent %q", f.sentEtags[0])
	}
	if f.sentEtags[1] != "fresh-etag" {
		t.Errorf("retry must send the re-read etag, sent %q", f.sentEtags[1])
	}
	if f.gets != 1 {
		t.Errorf("expected exactly 1 re-read, got %d", f.gets)
	}
}

func TestUpdateDashboardWithRetrySucceedsWithoutReReading(t *testing.T) {
	noRetryDelay(t)

	f := &fakeDashboardClient{}
	d := &dashboardpb.Dashboard{Name: "projects/p/dashboards/abc", Etag: "e0"}

	if err := updateDashboardWithRetry(context.Background(), f, d); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if len(f.sentEtags) != 1 {
		t.Errorf("expected 1 update, got %d", len(f.sentEtags))
	}
	if f.gets != 0 {
		t.Errorf("a clean update must not re-read, got %d gets", f.gets)
	}
}

func TestUpdateDashboardWithRetryDoesNotRetryOtherCodes(t *testing.T) {
	noRetryDelay(t)

	denied := status.Error(codes.PermissionDenied, "nope")
	f := &fakeDashboardClient{updateErrs: []error{denied}}
	d := &dashboardpb.Dashboard{Name: "projects/p/dashboards/abc", Etag: "e0"}

	err := updateDashboardWithRetry(context.Background(), f, d)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected the PermissionDenied to be returned as-is, got %v", err)
	}
	if len(f.sentEtags) != 1 {
		t.Errorf("a non-ABORTED error must fail fast, got %d attempts", len(f.sentEtags))
	}
	if f.gets != 0 {
		t.Errorf("a non-ABORTED error must not re-read, got %d gets", f.gets)
	}
}

func TestUpdateDashboardWithRetryGivesUpAfterAttemptCap(t *testing.T) {
	noRetryDelay(t)

	errs := make([]error, dashboardUpdateAttempts)
	for i := range errs {
		errs[i] = aborted()
	}
	f := &fakeDashboardClient{updateErrs: errs}
	d := &dashboardpb.Dashboard{Name: "projects/p/dashboards/abc", Etag: "e0"}

	err := updateDashboardWithRetry(context.Background(), f, d)
	if status.Code(err) != codes.Aborted {
		t.Fatalf("expected the final ABORTED to surface, got %v", err)
	}
	if len(f.sentEtags) != dashboardUpdateAttempts {
		t.Errorf("expected exactly %d attempts, got %d", dashboardUpdateAttempts, len(f.sentEtags))
	}
}

func TestUpdateDashboardWithRetryReportsReReadFailure(t *testing.T) {
	noRetryDelay(t)

	f := &fakeDashboardClient{
		updateErrs: []error{aborted()},
		getErr:     errors.New("backend down"),
	}
	d := &dashboardpb.Dashboard{
		Name:        "projects/p/dashboards/abc",
		DisplayName: "Substrate gRPC Server",
		Etag:        "e0",
	}

	err := updateDashboardWithRetry(context.Background(), f, d)
	if err == nil {
		t.Fatal("expected the re-read failure to surface")
	}
	if !strings.Contains(err.Error(), "re-read dashboard") {
		t.Errorf("error should name the re-read, got %q", err)
	}
	if !strings.Contains(err.Error(), "backend down") {
		t.Errorf("error should wrap the cause, got %q", err)
	}
}

func TestUpdateDashboardWithRetryHonoursContextCancellation(t *testing.T) {
	orig := dashboardRetryBackoff
	t.Cleanup(func() { dashboardRetryBackoff = orig })
	dashboardRetryBackoff = func(int) time.Duration { return time.Hour }

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	f := &fakeDashboardClient{updateErrs: []error{aborted()}}
	d := &dashboardpb.Dashboard{Name: "projects/p/dashboards/abc", Etag: "e0"}

	if err := updateDashboardWithRetry(ctx, f, d); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if f.gets != 0 {
		t.Errorf("a cancelled backoff must not re-read, got %d gets", f.gets)
	}
}
