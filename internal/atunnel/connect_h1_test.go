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

package atunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/atenet"
)

// The CONNECT endpoint has two relay implementations, chosen by the client's
// protocol version, and ServeConnect advertises both in its ALPN list so
// either can arrive. Only the HTTP/2 one was covered: it writes through an
// ordinary ResponseWriter, so an httptest recorder reaches it. The HTTP/1.1
// one hijacks the socket and writes its own status line, which a recorder
// cannot support -- so the tests here go through a real TLS listener instead.

// echoBackend stands in for the actor on the far side of the tunnel. It echoes
// rather than returning a canned greeting because that is what shows bytes
// moving in both directions, and it closes when its read ends so a half-close
// is observable from the client.
func echoBackend(t *testing.T) net.Listener {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { lis.Close() })
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return lis
}

// dialBackend is an activation dialer that ignores the address the handler
// composed and connects to the test backend. What that address should be is
// already pinned by TestServeConnectHTTPDialsTheSandbox; the concern here is
// the relay on top of it.
func dialBackend(backend net.Listener) DialFunc {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, backend.Addr().String())
	}
}

// connectListener starts a CONNECT listener with one active actor, and returns
// its address plus a client certificate that satisfies AllowedClientID.
func connectListener(t *testing.T, backend net.Listener) (addr string, ca *testCA, clientCert tls.Certificate) {
	t.Helper()

	dir := t.TempDir()
	ca = newTestCA(t)
	bundlePath := filepath.Join(dir, "bundle.pem")
	trustPath := filepath.Join(dir, "trust.pem")
	writeCredentialBundle(t, bundlePath, ca.issue(t, "", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}))
	if err := os.WriteFile(trustPath, ca.certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	clientCert = ca.issue(t, routerSPIFFEID, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	upstream, err := url.Parse("http://actor.internal:80")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewServer(Config{
		CredentialBundlePath: bundlePath,
		TrustBundlePath:      trustPath,
		AllowedClientID:      routerSPIFFEID,
		Upstream:             upstream,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Activate("team-a", "actor-1", "uid-actor-1", dialBackend(backend)); err != nil {
		t.Fatal(err)
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- s.ServeConnect(t.Context(), lis) }()
	t.Cleanup(func() {
		select {
		case err := <-served:
			if err != nil {
				t.Errorf("ServeConnect: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("ServeConnect did not stop after cancellation")
		}
	})
	return lis.Addr().String(), ca, clientCert
}

// TestServeConnectRelaysAnHTTP11Tunnel drives the HTTP/1.1 path end to end
// over a real TLS connection. The status line is written by hand onto a
// hijacked socket, and a client that does not recognise it waits rather than
// failing, so the bytes are asserted as a client would parse them.
func TestServeConnectRelaysAnHTTP11Tunnel(t *testing.T) {
	backend := echoBackend(t)
	addr, ca, clientCert := connectListener(t, backend)

	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      roots,
		Certificates: []tls.Certificate{clientCert},
		// Offering only http/1.1 is what selects the path under test; the
		// listener also advertises h2, and a client that offered both would
		// land on the already-covered HTTP/2 relay.
		NextProtos: []string{"http/1.1"},
		// The test server certificate carries no name for a loopback address.
		// Certificate verification is TestMutualTLSClientAuthentication's
		// subject; this test is about what happens after the handshake.
		InsecureSkipVerify: true, //nolint:gosec // see above
	})
	if err != nil {
		t.Fatalf("dialing the CONNECT listener: %v", err)
	}
	defer conn.Close()
	// A deadline rather than an assertion on timing: every way this path can
	// break short of a wrong status line -- an unflushed status line, a relay
	// that never starts, a half-close that does not propagate -- presents to
	// the client as a read that never returns.
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := conn.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("negotiated protocol = %q, want http/1.1; the HTTP/1.1 relay is not what ran", got)
	}

	// Authority-form CONNECT, written out rather than composed through
	// http.Request, because the request line is part of what the server has to
	// accept from the router.
	const authority = "actor-1.team-a.actors.resources.substrate.ate.dev:9090"
	request := "CONNECT " + authority + " HTTP/1.1\r\n" +
		"Host: " + authority + "\r\n" +
		atenet.TargetActorHeader + ": team-a/actor-1\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("writing the CONNECT request: %v", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("reading the CONNECT response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want %d: the tunnel was never established", resp.StatusCode, http.StatusOK)
	}

	if _, err := io.WriteString(conn, "ping"); err != nil {
		t.Fatalf("writing into the tunnel: %v", err)
	}
	got := make([]byte, len("ping"))
	if _, err := io.ReadFull(br, got); err != nil {
		t.Fatalf("reading back through the tunnel: %v", err)
	}
	if string(got) != "ping" {
		t.Errorf("tunnel returned %q, want %q", got, "ping")
	}

	// Half-close. Ending the client's write side has to reach the actor as an
	// EOF; an actor that reads to end-of-input before replying would otherwise
	// hang for the life of the connection. The echo backend closes once its
	// read ends, so the EOF arriving back here is the evidence it propagated.
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("half-closing the tunnel: %v", err)
	}
	if _, err := io.ReadAll(br); err != nil {
		t.Errorf("reading to EOF after the half-close: %v", err)
	}
}

// TestServeConnectHTTPRefusesAnUnhijackableWriter covers the guard the
// HTTP/1.1 relay opens with. It cannot establish a tunnel without taking over
// the socket, and the alternative to saying so is a 200 on a tunnel that
// carries nothing. The recover is what makes the guard's absence readable:
// without it the type assertion yields a nil Hijacker and the handler panics,
// which net/http turns into a dropped connection on a live listener rather
// than the 500 the caller is owed.
func TestServeConnectHTTPRefusesAnUnhijackableWriter(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ServeConnectHTTP panicked on a ResponseWriter that cannot be hijacked (%v), want a %d response", r, http.StatusInternalServerError)
		}
	}()

	backend := echoBackend(t)
	upstream, err := url.Parse("http://actor.internal:80")
	if err != nil {
		t.Fatal(err)
	}
	s := newTestServer(t, upstream)
	if err := s.Activate("team-a", "actor-1", "uid-actor-1", dialBackend(backend)); err != nil {
		t.Fatal(err)
	}

	// An httptest recorder is not an http.Hijacker, which is the case the
	// guard exists for.
	req := httptest.NewRequest(http.MethodConnect, "https://worker/", http.NoBody)
	req.Host = "actor-1.team-a.actors.resources.substrate.ate.dev:9090"
	req.Header.Set(atenet.TargetActorHeader, "team-a/actor-1")
	if req.ProtoMajor != 1 {
		t.Fatalf("request ProtoMajor = %d, want 1 so the HTTP/1.1 path is taken", req.ProtoMajor)
	}
	rec := httptest.NewRecorder()

	s.ServeConnectHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d when the connection cannot be hijacked", rec.Code, http.StatusInternalServerError)
	}
}
