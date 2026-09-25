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

package ateapiauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/testca"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"k8s.io/client-go/kubernetes/fake"
)

// ateapiServerName is the SAN the test servers are issued for. Leaving the
// addresses out of the certificates means the dial only verifies if the
// ServerName from ClientConfig reached the handshake, which it does through
// the credentials' Info — grpc-go derives the channel authority from it.
const ateapiServerName = "ateapi.test"

// TestDialOptionsFollowsACARotation dials a server holding a CA-1 certificate,
// republishes the trust bundle as CA-2, and dials a server holding a CA-2
// certificate — same process, same dial options, no restart.
//
// This is the defect the per-handshake reload fixes: a pool captured when
// DialOptions ran keeps trusting only the retired CA, so once the ateapi
// serving certificate is reissued under the new CA every client — atecontroller,
// atenet, atelet — fails every dial until its pod restarts.
func TestDialOptionsFollowsACARotation(t *testing.T) {
	clientCA := testca.New(t, "pod-identity-ca")
	clientBundle := testca.WriteCredBundle(t, clientCA.Issue(t, testca.Opts{
		URIs: []string{"spiffe://cluster.local/ns/ate-system/sa/ate-controller"},
	}))

	serverCA1 := testca.New(t, "ateapi-serving-ca-1")
	serverCA2 := testca.New(t, "ateapi-serving-ca-2")
	caFile := testca.WriteFile(t, "ca.pem", serverCA1.CertPEM)

	underCA1 := startHealthServer(t, serverCA1, clientCA.Pool())
	underCA2 := startHealthServer(t, serverCA2, clientCA.Pool())

	opts, err := DialOptions(ClientConfig{
		K8sClient:        fake.NewSimpleClientset(),
		CAFile:           caFile,
		ClientCredBundle: clientBundle,
		ServerName:       ateapiServerName,
	})
	if err != nil {
		t.Fatalf("DialOptions() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if code := healthCheckCode(ctx, t, underCA1, opts); code != codes.OK {
		t.Fatalf("before rotation, health check against the CA1 server = %v, want %v", code, codes.OK)
	}
	if code := healthCheckCode(ctx, t, underCA2, opts); code == codes.OK {
		t.Fatal("before rotation, health check against the CA2 server succeeded, want a chain failure")
	}

	// Publish CA2 as the projected trust bundle.
	testca.Republish(t, caFile, serverCA2.CertPEM)

	if code := healthCheckCode(ctx, t, underCA2, opts); code != codes.OK {
		t.Fatalf("after rotation, health check against the CA2 server = %v, want %v", code, codes.OK)
	}
	if code := healthCheckCode(ctx, t, underCA1, opts); code == codes.OK {
		t.Fatal("after rotation, health check against the CA1 server succeeded, want a chain failure")
	}
}

// TestDialOptionsFailsFastOnABadCAFile keeps the construction-time read: a
// missing or malformed CA file has to fail the caller where it builds its dial
// options, not on some later RPC.
func TestDialOptionsFailsFastOnABadCAFile(t *testing.T) {
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
			_, err := DialOptions(ClientConfig{CAFile: tc.caFile, ClientCredBundle: "bundle.pem"})
			if err == nil {
				t.Fatal("DialOptions() error = nil, want an error at construction")
			}
		})
	}
}

// startHealthServer runs a gRPC health server whose serving certificate is
// issued by ca and which requires a client certificate from clientCAs. It
// returns the address to dial.
func startHealthServer(t *testing.T, ca *testca.CA, clientCAs *x509.CertPool) string {
	t.Helper()

	issued := ca.Issue(t, testca.Opts{DNSNames: []string{ateapiServerName}})
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{issued.CertDER}, PrivateKey: issued.Key}},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		MinVersion:   tls.VersionTLS13,
	})))
	healthpb.RegisterHealthServer(srv, health.NewServer())

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}
