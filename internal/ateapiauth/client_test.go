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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"k8s.io/client-go/kubernetes/fake"
	"github.com/agent-substrate/substrate/internal/testca"
)

func TestDialOptionsRequiresCAFile(t *testing.T) {
	_, err := DialOptions(ClientConfig{ClientCredBundle: "bundle.pem"})
	if err == nil {
		t.Fatalf("DialOptions() error = nil, want error")
	}
}

func TestDialOptionsRequiresClientCredential(t *testing.T) {
	_, err := DialOptions(ClientConfig{K8sClient: fake.NewSimpleClientset(), CAFile: "ca.pem"})
	if err == nil {
		t.Fatalf("DialOptions() error = nil, want error")
	}
}

// TestDialOptionsMTLSHandshake dials a server that requires and verifies
// client certificates — the configuration ateapi will move to — and checks
// that DialOptions with a client credential bundle completes the handshake,
// while a certificate-less client is rejected.
func TestDialOptionsMTLSHandshake(t *testing.T) {
	ca := testca.New(t, "test-ca")
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	writeFile(t, caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.CertPEM}))

	clientBundle := filepath.Join(dir, "client-bundle.pem")
	writeFile(t, clientBundle, issueClientBundle(t, ca, "spiffe://cluster.local/ns/ate-system/sa/ate-controller"))

	serverCert := issueServerCert(t, ca)
	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Cert)
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	})))
	healthpb.RegisterHealthServer(srv, health.NewServer())
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go srv.Serve(lis)
	defer srv.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("with client cert", func(t *testing.T) {
		opts, err := DialOptions(ClientConfig{
			K8sClient:        fake.NewSimpleClientset(),
			CAFile:           caFile,
			ClientCredBundle: clientBundle,
		})
		if err != nil {
			t.Fatalf("DialOptions() error = %v", err)
		}
		if code := healthCheckCode(ctx, t, lis.Addr().String(), opts); code != codes.OK {
			t.Fatalf("health check code = %v, want %v", code, codes.OK)
		}
	})

	t.Run("without client cert is rejected", func(t *testing.T) {
		opts := []grpc.DialOption{grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			RootCAs:    caPool,
			MinVersion: tls.VersionTLS13,
		}))}
		if code := healthCheckCode(ctx, t, lis.Addr().String(), opts); code == codes.OK {
			t.Fatalf("health check code = %v, want handshake failure", code)
		}
	})
}

func healthCheckCode(ctx context.Context, t *testing.T, target string, opts []grpc.DialOption) codes.Code {
	t.Helper()
	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		t.Fatalf("grpc.NewClient() error = %v", err)
	}
	defer conn.Close()
	_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	return status.Code(err)
}



// issueClientBundle returns a PEM credential bundle (leaf certificate + PKCS8
// private key) for a client certificate carrying the given SPIFFE URI SAN.



func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func issueClientBundle(t *testing.T, ca *testca.CA, spiffeID string) []byte {
	t.Helper()
	leaf := ca.Issue(t, testca.Opts{
		URIs:        []string{spiffeID},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leaf.Key)
	return append(
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.CertDER})...,
	)
}

func issueServerCert(t *testing.T, ca *testca.CA) tls.Certificate {
	t.Helper()
	leaf := ca.Issue(t, testca.Opts{
		IPs:         []string{"127.0.0.1"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return tls.Certificate{Certificate: [][]byte{leaf.CertDER}, PrivateKey: leaf.Key}
}