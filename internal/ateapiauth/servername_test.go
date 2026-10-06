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
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"k8s.io/client-go/kubernetes/fake"
)

// TestDialOptionsVerifiesServerName pins the one property that a hand-rolled
// VerifyConnection drops for free: the server's certificate has to be issued
// for the peer we dialled, not merely signed by a CA we trust.
//
// ClientConfig.ServerName is documented optional and two binaries ship it
// empty (cmd/atecontroller, cmd/atenet's router). Forwarding it straight into
// x509.VerifyOptions.DNSName therefore reduces to no name check at all --
// crypto/x509 only calls VerifyHostname when DNSName is non-empty -- so any
// holder of a cluster-CA-signed certificate can impersonate the ateapi
// server. Every workload in the mesh holds one.
//
// The server below is issued for "other.invalid" and nothing else. Dialling
// it on 127.0.0.1 must fail, and must keep failing for the default empty
// ServerName specifically.
func TestDialOptionsVerifiesServerName(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	writeFile(t, caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.certDER}))

	clientBundle := filepath.Join(dir, "client-bundle.pem")
	writeFile(t, clientBundle, ca.issueClientBundle(t, "spiffe://cluster.local/ns/ate-system/sa/ate-controller"))

	caPool := x509.NewCertPool()
	caPool.AddCert(ca.cert)
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{ca.issueServerCertForDNS(t, "other.invalid")},
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

	// Both polarities, because "reject everything" would also pass the first
	// half: the name has to be checked, not the handshake refused outright.
	t.Run("unset ServerName still verifies against the dialled address", func(t *testing.T) {
		opts, err := DialOptions(ClientConfig{
			K8sClient:        fake.NewSimpleClientset(),
			CAFile:           caFile,
			ClientCredBundle: clientBundle,
		})
		if err != nil {
			t.Fatalf("DialOptions() error = %v", err)
		}
		if code := healthCheckCode(ctx, t, lis.Addr().String(), opts); code == codes.OK {
			t.Fatal("health check succeeded against a certificate issued for other.invalid; " +
				"an unset ServerName must not disable hostname verification")
		}
	})

	t.Run("an explicit ServerName the cert carries is accepted", func(t *testing.T) {
		opts, err := DialOptions(ClientConfig{
			K8sClient:        fake.NewSimpleClientset(),
			CAFile:           caFile,
			ClientCredBundle: clientBundle,
			ServerName:       "other.invalid",
		})
		if err != nil {
			t.Fatalf("DialOptions() error = %v", err)
		}
		if code := healthCheckCode(ctx, t, lis.Addr().String(), opts); code != codes.OK {
			t.Fatalf("health check code = %v, want %v", code, codes.OK)
		}
	})
}

// issueServerCertForDNS issues a server certificate valid for exactly one DNS
// name and no IP address, so dialling it by address fails the name check.
func (ca *testCA) issueServerCertForDNS(t *testing.T, dnsName string) tls.Certificate {
	t.Helper()
	key := generateKey(t)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: dnsName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{dnsName},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("create server certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
