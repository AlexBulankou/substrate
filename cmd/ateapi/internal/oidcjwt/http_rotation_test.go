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

package oidcjwt

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/testca"
)

// issuerServedBy starts an HTTPS server on loopback with a leaf from ca, and
// reports the error of fetching it with client.
func issuerServedBy(t *testing.T, client *http.Client, ca *testca.CA) error {
	t.Helper()
	leaf := ca.Issue(t, testca.LeafOpts{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}})

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{}`))
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.DER}, PrivateKey: leaf.Key}},
	}
	srv.StartTLS()
	defer srv.Close()

	// Each phase gets a fresh listener, so nothing is served from an idle
	// connection established under the previous trust bundle.
	client.CloseIdleConnections()
	resp, err := client.Get(srv.URL)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// TestNewHTTPClientReloadsRootCAs is the regression test for a startup-frozen
// root pool on ateapi's OIDC client. ateapi validates every caller token
// against keys it fetches from the issuer over this client, so a pool fixed at
// process start means a rotation of the cluster trust bundle stops ateapi
// authenticating anyone at all until it restarts.
//
// The bearer token this same client sends is already re-read per request for
// exactly that reason. Only the trust anchors were frozen, which is what made
// the gap easy to read past.
func TestNewHTTPClientReloadsRootCAs(t *testing.T) {
	ca1 := testca.New(t, "issuer-ca-1")
	ca2 := testca.New(t, "issuer-ca-2")
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	testca.WriteBundle(t, caPath, ca1.PEM, time.Now())

	client, err := NewHTTPClient("https://issuer.test", caPath, "")
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}

	if err := issuerServedBy(t, client, ca1); err != nil {
		t.Fatalf("a CA1-signed issuer was refused before the rotation: %v", err)
	}
	if err := issuerServedBy(t, client, ca2); err == nil {
		t.Fatal("a CA2-signed issuer was trusted before the rotation, want a chain failure")
	}

	// Publishing CA2 is the rotation. The mtime bump makes the change visible
	// where the filesystem's timestamp granularity is coarser than the test.
	testca.WriteBundle(t, caPath, ca2.PEM, time.Now().Add(time.Second))

	if err := issuerServedBy(t, client, ca2); err != nil {
		t.Fatalf("a CA2-signed issuer was refused after the rotation: %v", err)
	}
	if err := issuerServedBy(t, client, ca1); err == nil {
		t.Fatal("a CA1-signed issuer was trusted after the rotation, want the retired CA to be dropped")
	}
}

// TestNewHTTPClientRejectsAnUnreadableCAFile pins the startup read that the
// per-dial loader could otherwise be thought to make redundant. Without it
// ateapi comes up healthy with a misprojected trust volume and fails every
// token validation, which reports a mount problem as an unreachable issuer.
func TestNewHTTPClientRejectsAnUnreadableCAFile(t *testing.T) {
	if _, err := NewHTTPClient("https://issuer.test", filepath.Join(t.TempDir(), "absent.pem"), ""); err == nil {
		t.Fatal("NewHTTPClient() error = nil for a CA file that does not exist, want a refusal")
	}
}

// TestNewHTTPClientKeepsHTTP2 guards the cost of dialing TLS by hand: net/http
// adds the ALPN protocols when it builds the TLS connection itself, and a
// custom dialer that omits them downgrades every discovery request to HTTP/1.1
// without failing anything.
func TestNewHTTPClientKeepsHTTP2(t *testing.T) {
	ca := testca.New(t, "issuer-ca")
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	testca.WriteBundle(t, caPath, ca.PEM, time.Now())

	client, err := NewHTTPClient("https://issuer.test", caPath, "")
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}

	leaf := ca.Issue(t, testca.LeafOpts{IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{}`))
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.DER}, PrivateKey: leaf.Key}},
	}
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.Proto != "HTTP/2.0" {
		t.Errorf("resp.Proto = %q, want HTTP/2.0", resp.Proto)
	}
}
