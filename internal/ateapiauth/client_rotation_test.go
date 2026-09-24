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

package ateapiauth

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/testca"
	"google.golang.org/grpc/credentials"
)

const (
	testServerName = "ateapi.test"
	testAuthority  = testServerName + ":443"
)

// mustCreds builds the credentials DialOptions installs, against a CA file the
// caller controls. The client credential bundle is incidental here -- the test
// server never asks for one -- but it is required, so every case needs one.
func mustCreds(t *testing.T, caPath string) credentials.TransportCredentials {
	t.Helper()
	clientCA := testca.New(t, "client-ca")
	bundle := testca.WriteCredBundle(t, clientCA.Issue(t, testca.LeafOpts{}))

	creds, err := transportCredentials(ClientConfig{
		CAFile:           caPath,
		ClientCredBundle: bundle,
		ServerName:       testServerName,
	})
	if err != nil {
		t.Fatalf("transportCredentials() error = %v", err)
	}
	return creds
}

// TestDialOptionsReloadsRootCAs is the regression test for a startup-frozen
// root pool on the dialing side. atecontroller, atenet and atelet all reach
// ateapi through these credentials, so a pool fixed at process start means a
// control-plane CA rotation cuts every one of them off until it restarts --
// even though the client certificate in the same config rotates correctly.
func TestDialOptionsReloadsRootCAs(t *testing.T) {
	ca1 := testca.New(t, "server-ca-1")
	ca2 := testca.New(t, "server-ca-2")
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	testca.WriteBundle(t, caPath, ca1.PEM, time.Now())

	creds := mustCreds(t, caPath)
	serverOn := func(ca *testca.CA) error {
		return testca.ClientHandshake(t, creds, ca.Issue(t, testca.LeafOpts{DNSNames: []string{testServerName}}), testAuthority)
	}

	if err := serverOn(ca1); err != nil {
		t.Fatalf("a CA1-signed server was refused before the rotation: %v", err)
	}
	if err := serverOn(ca2); err == nil {
		t.Fatal("a CA2-signed server was trusted before the rotation, want a chain failure")
	}

	// Publishing CA2 is the rotation. The mtime bump makes the change visible
	// where the filesystem's timestamp granularity is coarser than the test.
	testca.WriteBundle(t, caPath, ca2.PEM, time.Now().Add(time.Second))

	if err := serverOn(ca2); err != nil {
		t.Fatalf("a CA2-signed server was refused after the rotation: %v", err)
	}
	if err := serverOn(ca1); err == nil {
		t.Fatal("a CA1-signed server was trusted after the rotation, want the retired CA to be dropped")
	}
}

// TestDialOptionsRejectsAnUnreadableCAFile pins the startup read. Without it a
// daemon with a misprojected trust volume comes up healthy and fails every RPC
// at dial time, which reports a mount problem as the control plane being down.
func TestDialOptionsRejectsAnUnreadableCAFile(t *testing.T) {
	clientCA := testca.New(t, "client-ca")
	bundle := testca.WriteCredBundle(t, clientCA.Issue(t, testca.LeafOpts{}))

	_, err := DialOptions(ClientConfig{
		CAFile:           filepath.Join(t.TempDir(), "absent.pem"),
		ClientCredBundle: bundle,
	})
	if err == nil {
		t.Fatal("DialOptions() error = nil for a CA file that does not exist, want a refusal")
	}
}

// TestRotatingRootCredsRefuseToServe pins the direction of these credentials.
// They carry no ClientCAs, so serving with them would verify peers against the
// host system trust store rather than the configured pool -- a fail-open that
// looks like working mTLS from the outside.
//
// The nil connection is the assertion, not a shortcut: the refusal has to come
// before anything touches the wire, so that mistakenly serving with these is a
// startup error rather than a listener that accepts unverified peers. The error
// is matched on text for the same reason -- a delegating implementation also
// fails here, but by crashing on the nil, which is not the contract.
func TestRotatingRootCredsRefuseToServe(t *testing.T) {
	ca := testca.New(t, "server-ca")
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	testca.WriteBundle(t, caPath, ca.PEM, time.Now())

	_, _, err := mustCreds(t, caPath).ServerHandshake(nil)
	if err == nil {
		t.Fatal("ServerHandshake() error = nil, want client credentials to refuse to serve")
	}
	if !strings.Contains(err.Error(), "cannot serve") {
		t.Errorf("ServerHandshake() error = %v, want a deliberate refusal", err)
	}
}
