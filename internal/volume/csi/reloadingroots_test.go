//  Copyright 2026 Google LLC
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package csi

import (
	"crypto/tls"
	"path/filepath"
	"testing"

	"github.com/agent-substrate/substrate/internal/credbundle"
)

const testServerName = "server.test"

// writeCAFile writes a trust bundle to a temp file and returns its path.
func writeCAFile(t *testing.T, ca *testCA) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	writeFile(t, path, ca.certPEM())
	return path
}

// TestReloadingRootsSurfaceRoundTrip covers the parts of the
// TransportCredentials contract that are not exercised by a handshake.
//
// Info().ServerName in particular is load-bearing and easy to drop: grpc-go
// derives a channel's authority from it, and the authority is what the
// handshake verifies the peer certificate against.
func TestReloadingRootsSurfaceRoundTrip(t *testing.T) {
	caFile := writeCAFile(t, newTestCA(t))

	creds := newReloadingRootCredentials(
		&tls.Config{MinVersion: tls.VersionTLS13, ServerName: testServerName},
		credbundle.PoolLoader(caFile),
	)

	if got := creds.Info().ServerName; got != testServerName {
		t.Errorf("Info().ServerName = %q, want %q", got, testServerName)
	}
	if got := creds.Info().SecurityProtocol; got != "tls" {
		t.Errorf("Info().SecurityProtocol = %q, want %q", got, "tls")
	}

	if err := creds.OverrideServerName("override.test"); err != nil {
		t.Fatalf("OverrideServerName() error = %v", err)
	}
	if got := creds.Info().ServerName; got != "override.test" {
		t.Errorf("after OverrideServerName, Info().ServerName = %q, want %q", got, "override.test")
	}

	// A clone carries the template forward but is independent of it, so an
	// override on one channel does not retarget another.
	clone := creds.Clone()
	if err := clone.OverrideServerName("clone.test"); err != nil {
		t.Fatalf("clone OverrideServerName() error = %v", err)
	}
	if got := creds.Info().ServerName; got != "override.test" {
		t.Errorf("after cloning and overriding the clone, Info().ServerName = %q, want %q", got, "override.test")
	}

	// Serving is refused rather than quietly accepting unauthenticated peers.
	if _, _, err := creds.ServerHandshake(nil); err == nil {
		t.Error("ServerHandshake() error = nil, want these dial-only credentials to refuse")
	}
}

// TestReloadingRootsIgnoreATemplateRootCAs guards the contract that the pool
// comes from the loader: a caller that also sets RootCAs on the template must
// not end up pinned to it.
func TestReloadingRootsIgnoreATemplateRootCAs(t *testing.T) {
	pinned := newTestCA(t)
	loaded := newTestCA(t)
	caFile := writeCAFile(t, loaded)

	creds := newReloadingRootCredentials(
		&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pinned.pool()},
		credbundle.PoolLoader(caFile),
	).(*reloadingRoots)

	if creds.template.RootCAs != nil {
		t.Error("template.RootCAs is set, want the loader to be the only source of trust anchors")
	}
}
