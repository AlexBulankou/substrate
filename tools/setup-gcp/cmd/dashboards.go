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
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	dashboard "cloud.google.com/go/monitoring/dashboard/apiv1"
	"cloud.google.com/go/monitoring/dashboard/apiv1/dashboardpb"
	gax "github.com/googleapis/gax-go/v2"
	"github.com/spf13/cobra"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

var dashboardFiles = []string{
	"ate-grpc-dashboard.json",
	"ate-e2e-latency-dashboard.json",
	"ate-snapshot-dashboard.json",
}

// dashboardUpdater is the subset of *dashboard.DashboardsClient that
// updateDashboardWithRetry calls. Narrowing it here lets the retry be
// exercised without a live Monitoring backend.
type dashboardUpdater interface {
	UpdateDashboard(context.Context, *dashboardpb.UpdateDashboardRequest, ...gax.CallOption) (*dashboardpb.Dashboard, error)
	GetDashboard(context.Context, *dashboardpb.GetDashboardRequest, ...gax.CallOption) (*dashboardpb.Dashboard, error)
}

// dashboardUpdateAttempts bounds the etag-conflict retry below.
const dashboardUpdateAttempts = 6

// dashboardRetryBackoff is a variable so tests can collapse the wait.
//
// Etag contention clears as soon as the competing write commits, so this
// backs off in fractions of a second rather than the tens of seconds
// grantCloudSQLPermissions waits on service-account propagation.
var dashboardRetryBackoff = func(attempt int) time.Duration {
	return time.Duration(attempt) * 500 * time.Millisecond
}

// updateDashboardWithRetry applies d, re-reading its etag whenever the
// update loses an optimistic-concurrency check.
//
// The etag carried by d comes from the ListDashboards pass in
// createMonitoringDashboards, which runs once before any dashboard is
// written, so the snapshot only grows staler as that loop proceeds. An
// UpdateDashboard can therefore be rejected with ABORTED ("the supplied
// etag is not up to date") through no fault of the caller. Dashboards are
// applied at the end of bootstrap, so an unretried abort discards an
// already-created cluster and fails a documented install. Re-read and
// retry instead, the same way grantCloudSQLPermissions re-reads the IAM
// policy on a conflict.
//
// Only ABORTED is retried: every other status is returned to the caller
// untouched, so a genuine permission or validation error still fails fast.
func updateDashboardWithRetry(ctx context.Context, client dashboardUpdater, d *dashboardpb.Dashboard) error {
	for attempt := 1; ; attempt++ {
		_, err := client.UpdateDashboard(ctx, &dashboardpb.UpdateDashboardRequest{Dashboard: d})
		if err == nil {
			return nil
		}
		if status.Code(err) != codes.Aborted || attempt >= dashboardUpdateAttempts {
			return err
		}
		slog.Warn("Updating dashboard hit a stale etag, retrying...",
			slog.String("displayName", d.GetDisplayName()),
			slog.Int("attempt", attempt),
			slog.Any("err", err))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(dashboardRetryBackoff(attempt)):
		}
		cur, err := client.GetDashboard(ctx, &dashboardpb.GetDashboardRequest{Name: d.GetName()})
		if err != nil {
			return fmt.Errorf("re-read dashboard %q after an aborted update: %w", d.GetDisplayName(), err)
		}
		d.Etag = cur.GetEtag()
	}
}

// createMonitoringDashboards creates or updates each dashboard in
// dashboardFiles. It is idempotent: dashboards are matched by displayName and
// updated in place, because CreateDashboard always creates a new dashboard (so
// calling it repeatedly would produce duplicates).
func createMonitoringDashboards(ctx context.Context, cfg *Config) error {
	client, err := dashboard.NewDashboardsClient(ctx)
	if err != nil {
		return fmt.Errorf("create dashboards client: %w", err)
	}
	defer client.Close()

	parent := "projects/" + cfg.ProjectID

	// Index existing dashboards by displayName to decide create vs update.
	existing := map[string]*dashboardpb.Dashboard{}
	it := client.ListDashboards(ctx, &dashboardpb.ListDashboardsRequest{Parent: parent})
	for {
		d, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return fmt.Errorf("list dashboards: %w", err)
		}
		existing[d.GetDisplayName()] = d
	}

	dir := cfg.DashboardDir
	if dir == "" {
		dir = "tools/setup-gcp/dashboards"
	}

	for _, file := range dashboardFiles {
		path := filepath.Join(dir, file)
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		d := &dashboardpb.Dashboard{}
		if err := protojson.Unmarshal(data, d); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}

		if cur, ok := existing[d.GetDisplayName()]; ok {
			// Update in place: reuse the existing resource name and etag.
			d.Name = cur.GetName()
			d.Etag = cur.GetEtag()
			slog.Info("Updating dashboard",
				slog.String("displayName", d.GetDisplayName()),
				slog.String("name", d.GetName()),
				slog.String("file", filepath.Base(path)))
			if err := updateDashboardWithRetry(ctx, client, d); err != nil {
				return fmt.Errorf("update dashboard %q: %w", d.GetDisplayName(), err)
			}
		} else {
			slog.Info("Creating dashboard",
				slog.String("displayName", d.GetDisplayName()),
				slog.String("file", filepath.Base(path)))
			if _, err := client.CreateDashboard(ctx, &dashboardpb.CreateDashboardRequest{Parent: parent, Dashboard: d}); err != nil {
				return fmt.Errorf("create dashboard %q: %w", d.GetDisplayName(), err)
			}
		}
	}
	return nil
}

var dashboardsCmd = &cobra.Command{
	Use:   "dashboards",
	Short: "Create Cloud Monitoring dashboards",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		if err := resolveProjectID(ctx, &cfg); err != nil {
			return err
		}
		return createMonitoringDashboards(ctx, &cfg)
	},
}

func init() {
	createCmd.AddCommand(dashboardsCmd)
	dashboardsCmd.Flags().StringVar(&cfg.DashboardDir, "dir", getEnv("DASHBOARD_DIR", "tools/setup-gcp/dashboards"), "Directory containing dashboard JSON files [env: DASHBOARD_DIR]")
}
