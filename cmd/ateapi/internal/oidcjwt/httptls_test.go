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
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/agent-substrate/substrate/internal/testca"
)

// TestNewHTTPClientFollowsACARotation fetches from an issuer serving a CA-1
// certificate, republishes the trust bundle as CA-2, and fetches from an issuer
// serving a CA-2 certificate — same client, no restart.
//
// This is the defect the per-connection reload fixes: a pool set on the
// transport's TLSClientConfig is frozen for the lifetime of that transport, so
// once the issuer's serving certificate is reissued under a new CA, OIDC
// discovery and JWKS fetches fail and keep failing until ateapi restarts —
// which takes JWT authentication down with them.
func TestNewHTTPClientFollowsACARotation(t *testing.T) {
	ca1 := testca.New(t, "issuer-ca-1")
	ca2 := testca.New(t, "issuer-ca-2")
	caFile := testca.WriteFile(t, "ca.pem", ca1.CertPEM)

	underCA1 := startIssuer(t, ca1)
	underCA2 := startIssuer(t, ca2)

	client, err := NewHTTPClient(underCA1.URL, caFile, "")
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}

	if err := fetch(client, underCA1.URL); err != nil {
		t.Fatalf("before rotation, fetch from the CA1 issuer failed: %v", err)
	}
	if err := fetch(client, underCA2.URL); err == nil {
		t.Fatal("before rotation, fetch from the CA2 issuer succeeded, want a chain failure")
	}

	// Publish CA2 as the projected trust bundle.
	testca.Republish(t, caFile, ca2.CertPEM)

	if err := fetch(client, underCA2.URL); err != nil {
		t.Fatalf("after rotation, fetch from the CA2 issuer failed: %v", err)
	}

	// The reload applies to new connections, so the pooled connection to the
	// CA1 issuer keeps working until it is dropped. Drop it, then confirm the
	// retired CA no longer verifies — without which the assertion above would
	// also pass against a pool that simply trusts everything.
	client.CloseIdleConnections()
	if err := fetch(client, underCA1.URL); err == nil {
		t.Fatal("after rotation, fetch from the CA1 issuer succeeded on a fresh connection, want a chain failure")
	}
}

// TestNewHTTPClientStillNegotiatesHTTP2 guards the side effect of owning the
// dial: net/http upgrades to HTTP/2 over ALPN, which it can only arrange for
// itself when it also owns the dial, so taking that over means advertising the
// protocols by hand. Getting it wrong silently downgrades every issuer that
// speaks HTTP/2.
func TestNewHTTPClientStillNegotiatesHTTP2(t *testing.T) {
	ca := testca.New(t, "issuer-ca")
	caFile := testca.WriteFile(t, "ca.pem", ca.CertPEM)

	issued := ca.Issue(t, testca.Opts{IPs: []string{"127.0.0.1"}})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{issued.CertDER}, PrivateKey: issued.Key}},
	}
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	client, err := NewHTTPClient(srv.URL, caFile, "")
	if err != nil {
		t.Fatalf("NewHTTPClient() error = %v", err)
	}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	defer resp.Body.Close()
	if resp.Proto != "HTTP/2.0" {
		t.Errorf("response protocol = %q, want %q", resp.Proto, "HTTP/2.0")
	}
}

// TestNewHTTPClientFailsFastOnABadCAFile keeps the construction-time read: a
// missing or malformed CA file has to fail ateapi as it builds the provider,
// not on the first discovery request.
func TestNewHTTPClientFailsFastOnABadCAFile(t *testing.T) {
	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.pem")
	testca.Republish(t, garbage, []byte("not a certificate\n"))

	for _, tc := range []struct {
		name   string
		caFile string
	}{
		{name: "missing", caFile: filepath.Join(dir, "absent.pem")},
		{name: "unparseable", caFile: garbage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewHTTPClient("https://issuer.test", tc.caFile, ""); err == nil {
				t.Fatal("NewHTTPClient() error = nil, want an error at construction")
			}
		})
	}
}

// startIssuer runs a TLS server holding a certificate issued by ca.
func startIssuer(t *testing.T, ca *testca.CA) *httptest.Server {
	t.Helper()

	issued := ca.Issue(t, testca.Opts{IPs: []string{"127.0.0.1"}})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{issued.CertDER}, PrivateKey: issued.Key}},
	}
	// The negative cases deliberately fail the handshake; leaving the default
	// logger in place prints those refusals as if the test had gone wrong.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func fetch(client *http.Client, url string) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}
