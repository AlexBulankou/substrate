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

package ateclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	"go.ate.dev/substrate/internal/testca"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

// fakeClock advances only when a test advances it, so a TTL can expire without
// the test sleeping.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }

// liveServiceDNSBundle is a live ClusterTrustBundle for the servicedns signer
// carrying the given CA, in the shape serverTrustPool selects on.
func liveServiceDNSBundle(ca *testca.CA) *certsv1beta1.ClusterTrustBundle {
	return &certsv1beta1.ClusterTrustBundle{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "servicedns.podcert.ate.dev:identity:primary-bundle",
			Labels: map[string]string{"podcert.ate.dev/canarying": "live"},
		},
		Spec: certsv1beta1.ClusterTrustBundleSpec{
			SignerName:  serviceDNSSignerName,
			TrustBundle: string(ca.CertPEM),
		},
	}
}

// fakeClientset is fake.NewSimpleClientset plus the discovery entry that
// clustertrustbundle.NewClient looks for. A bare fake serves no API resources,
// so without this every trust-pool read fails at discovery rather than
// exercising the rotation behaviour these tests are about.
func fakeClientset(objs ...runtime.Object) *fake.Clientset {
	kc := fake.NewSimpleClientset(objs...)
	kc.Resources = []*metav1.APIResourceList{{
		GroupVersion: certsv1beta1.SchemeGroupVersion.String(),
		APIResources: []metav1.APIResource{{Name: "clustertrustbundles"}},
	}}
	return kc
}

// rotateTo rewrites the live bundle in place, the way a CA rotation does.
func rotateTo(t *testing.T, clientset kubernetes.Interface, ca *testca.CA) {
	t.Helper()
	if _, err := clientset.CertificatesV1beta1().ClusterTrustBundles().Update(
		context.Background(), liveServiceDNSBundle(ca), metav1.UpdateOptions{},
	); err != nil {
		t.Fatalf("rotating the live ClusterTrustBundle: %v", err)
	}
}

// cacheFor returns a cache over clientset driven by clk, warmed as the dial
// paths warm it.
func cacheFor(t *testing.T, clientset kubernetes.Interface, clk *fakeClock, ttl time.Duration) *trustPoolCache {
	t.Helper()
	cache := newTrustPoolCache(clientset)
	cache.ttl = ttl
	cache.now = clk.now
	if err := cache.warm(context.Background()); err != nil {
		t.Fatalf("warm: %v", err)
	}
	return cache
}

// countListsOn counts ClusterTrustBundle LISTs against the fake clientset.
func countListsOn(clientset *fake.Clientset) func() int {
	return func() int {
		n := 0
		for _, a := range clientset.Actions() {
			if a.Matches("list", "clustertrustbundles") {
				n++
			}
		}
		return n
	}
}

// TestNewTrustPoolCacheUsesTheDeclaredTTL pins the defaults the dial paths get,
// since the rotation tests below drive an injected clock and TTL instead.
func TestNewTrustPoolCacheUsesTheDeclaredTTL(t *testing.T) {
	cache := newTrustPoolCache(fakeClientset())
	if cache.ttl != trustPoolTTL {
		t.Errorf("ttl = %v, want %v", cache.ttl, trustPoolTTL)
	}
	if cache.now == nil {
		t.Error("now is nil, want a clock")
	}
}

// TestTrustPoolCacheServesTheCachedPoolWithinTTL is the reason the cache
// exists: a LIST on every handshake is not acceptable.
func TestTrustPoolCacheServesTheCachedPoolWithinTTL(t *testing.T) {
	ca := testca.New(t, "servicedns-ca-1")
	clientset := fakeClientset(liveServiceDNSBundle(ca))
	lists := countListsOn(clientset)
	clk := &fakeClock{t: time.Now()}

	cache := cacheFor(t, clientset, clk, time.Minute)
	warmLists := lists()

	for i := 0; i < 5; i++ {
		clk.add(10 * time.Second) // 50s total, inside the TTL
		if _, err := cache.roots(); err != nil {
			t.Fatalf("roots() #%d: %v", i, err)
		}
	}
	if got := lists(); got != warmLists {
		t.Errorf("LISTs = %d after five in-TTL handshakes, want %d — the cache is not being served", got, warmLists)
	}
}

// TestTrustPoolCacheFollowsARotationAfterTTL is the defect in #9518: before
// this, the pool was fixed for the life of the process.
func TestTrustPoolCacheFollowsARotationAfterTTL(t *testing.T) {
	before := testca.New(t, "servicedns-ca-before")
	after := testca.New(t, "servicedns-ca-after")
	clientset := fakeClientset(liveServiceDNSBundle(before))
	clk := &fakeClock{t: time.Now()}

	cache := cacheFor(t, clientset, clk, time.Minute)
	rotateTo(t, clientset, after)

	// Still inside the TTL: the rotation is not visible yet, by design.
	pool, err := cache.roots()
	if err != nil {
		t.Fatalf("roots() inside the TTL: %v", err)
	}
	if !pool.Equal(before.Pool()) {
		t.Error("the pool changed inside the TTL, want the cached anchors")
	}

	clk.add(trustPoolTTL + time.Second)
	pool, err = cache.roots()
	if err != nil {
		t.Fatalf("roots() past the TTL: %v", err)
	}
	if !pool.Equal(after.Pool()) {
		t.Error("the pool did not follow the rotation past the TTL — this is the frozen-pool defect")
	}
}

// TestTrustPoolCacheFrozenTTLNeverFollowsARotation is the negative control for
// the test above: with a TTL longer than the process lives — which is what a
// pool read once at construction amounts to — the rotation is never picked up.
// Without this, a roots() that simply re-LISTed every call would also pass.
func TestTrustPoolCacheFrozenTTLNeverFollowsARotation(t *testing.T) {
	before := testca.New(t, "servicedns-ca-before")
	after := testca.New(t, "servicedns-ca-after")
	clientset := fakeClientset(liveServiceDNSBundle(before))
	clk := &fakeClock{t: time.Now()}

	cache := cacheFor(t, clientset, clk, 24*time.Hour)
	rotateTo(t, clientset, after)
	clk.add(time.Hour)

	pool, err := cache.roots()
	if err != nil {
		t.Fatalf("roots(): %v", err)
	}
	if !pool.Equal(before.Pool()) {
		t.Error("the pool followed a rotation the TTL should have hidden — roots() is re-reading unconditionally")
	}
}

// TestTrustPoolCacheRefreshFailureFailsClosed: a refresh that errors must not
// fall back to the last good pool. Serving a known-stale anchor set is the
// frozen-pool defect on a slower clock.
func TestTrustPoolCacheRefreshFailureFailsClosed(t *testing.T) {
	ca := testca.New(t, "servicedns-ca")
	clientset := fakeClientset(liveServiceDNSBundle(ca))
	clk := &fakeClock{t: time.Now()}
	cache := cacheFor(t, clientset, clk, time.Minute)

	wantErr := errors.New("api server unreachable")
	cache.load = func(context.Context) (*x509.CertPool, error) { return nil, wantErr }

	clk.add(trustPoolTTL + time.Second)
	pool, err := cache.roots()
	if !errors.Is(err, wantErr) {
		t.Errorf("roots() error = %v, want it to wrap %v", err, wantErr)
	}
	if pool != nil {
		t.Error("roots() returned a pool alongside the error, want the handshake to fail rather than use stale anchors")
	}
}

// TestTrustPoolCacheRefreshesOnceForConcurrentHandshakes: the reload is under a
// lock, so N handshakes arriving together past the TTL produce one LIST.
func TestTrustPoolCacheRefreshesOnceForConcurrentHandshakes(t *testing.T) {
	ca := testca.New(t, "servicedns-ca")
	clientset := fakeClientset(liveServiceDNSBundle(ca))
	lists := countListsOn(clientset)
	clk := &fakeClock{t: time.Now()}
	cache := cacheFor(t, clientset, clk, time.Minute)
	warmLists := lists()

	clk.add(trustPoolTTL + time.Second)
	const handshakes = 8
	errs := make(chan error, handshakes)
	for i := 0; i < handshakes; i++ {
		go func() {
			_, err := cache.roots()
			errs <- err
		}()
	}
	for i := 0; i < handshakes; i++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent roots(): %v", err)
		}
	}

	if got := lists() - warmLists; got != 1 {
		t.Errorf("LISTs = %d for %d concurrent past-TTL handshakes, want 1", got, handshakes)
	}
}

// TestServerCredentialsWarmFailsAtConstruction keeps the fail-fast the dial
// paths had before: a missing bundle is reported by NewClient, not by the
// first RPC.
func TestServerCredentialsWarmFailsAtConstruction(t *testing.T) {
	if _, err := serverCredentials(context.Background(), fakeClientset(), apiServerName()); err == nil {
		t.Error("serverCredentials() error = nil, want a failure with no live bundle present")
	}
}

// TestServerCredentialsHandshakeFollowsARotation drives the whole wiring —
// cache, rotatingtls, gRPC — against a server that re-keys onto a new CA.
func TestServerCredentialsHandshakeFollowsARotation(t *testing.T) {
	before := testca.New(t, "servicedns-ca-before")
	after := testca.New(t, "servicedns-ca-after")
	clientset := fakeClientset(liveServiceDNSBundle(before))
	clk := &fakeClock{t: time.Now()}
	cache := cacheFor(t, clientset, clk, time.Minute)
	creds := cache.credentials(apiServerName())

	// The server re-keys onto the post-rotation CA, as ateapi does once its
	// serving cert is reissued.
	addr := serveHealth(t, after)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Before the TTL expires the client still trusts only the old anchors, so
	// the handshake fails — the state a frozen pool would stay in forever.
	if code := healthCode(ctx, t, addr, creds); code == codes.OK {
		t.Fatal("handshake succeeded against the post-rotation CA before the TTL expired, want a failure")
	}

	rotateTo(t, clientset, after)
	clk.add(trustPoolTTL + time.Second)
	if code := healthCode(ctx, t, addr, creds); code != codes.OK {
		t.Errorf("handshake code = %v after the rotation was picked up, want %v", code, codes.OK)
	}
}

// TestFrozenPoolCredentialsDoNotFollowARotation pins the defect this change
// fixes, so that both halves of the before/after are executable here.
//
// The rotation test above exercises a construction that does not exist on the
// pre-fix tree, so it cannot be run against that tree to demonstrate the bug.
// This one builds credentials the way the dial path built them before -- one
// pool read, assigned to RootCAs, handed to credentials.NewTLS -- and shows
// that neither elapsed time nor a rotation published to the API server ever
// reaches them. It is a characterization test, not a guard.
//
// It used to build that comparison by CALLING serverTLSConfig, which was the
// frozen-pool path at the time. #14357 moved serverTLSConfig onto the cache,
// so the frozen construction is no longer reachable through any production
// function and is spelled out inline here instead. Keeping it is what makes
// the claim "RootCAs is read once and never again" executable rather than
// asserted in a comment -- if a future Go release ever made RootCAs reload,
// this test, not a review, is what would notice.
func TestFrozenPoolCredentialsDoNotFollowARotation(t *testing.T) {
	before := testca.New(t, "servicedns-ca-before")
	after := testca.New(t, "servicedns-ca-after")
	clientset := fakeClientset(liveServiceDNSBundle(before))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := serverTrustPool(ctx, clientset)
	if err != nil {
		t.Fatalf("serverTrustPool(): %v", err)
	}
	cfg := serverTLSTemplate(apiServerName())
	cfg.RootCAs = pool
	frozen := credentials.NewTLS(cfg)

	// The server re-keys and the API server publishes the new anchors, which
	// is everything a client would need to recover.
	addr := serveHealth(t, after)
	rotateTo(t, clientset, after)

	if code := healthCode(ctx, t, addr, frozen); code == codes.OK {
		t.Fatal("the pre-fix construction followed the rotation, so this test no longer pins the defect it names")
	}
}

// TestTLSConfigHandshakeFollowsARotation is the credentials test above for the
// other half of the dial surface: NewRouterDialer needs a *tls.Config it can
// hang GetClientCertificate off, so it cannot go through rotatingtls, and
// #14357 was that config freezing RootCAs while the client cert kept rotating.
func TestTLSConfigHandshakeFollowsARotation(t *testing.T) {
	before := testca.New(t, "servicedns-ca-before")
	after := testca.New(t, "servicedns-ca-after")
	clientset := fakeClientset(liveServiceDNSBundle(before))
	clk := &fakeClock{t: time.Now()}
	cache := cacheFor(t, clientset, clk, time.Minute)
	creds := credentials.NewTLS(cache.tlsConfig(apiServerName()))

	addr := serveHealth(t, after)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Within the TTL the client still trusts only the pre-rotation anchors.
	// This half is also what shows InsecureSkipVerify did not become a bypass:
	// the chain is checked, just by VerifyConnection rather than by the stdlib.
	if code := healthCode(ctx, t, addr, creds); code == codes.OK {
		t.Fatal("handshake succeeded against the post-rotation CA before the TTL expired, want a failure")
	}

	rotateTo(t, clientset, after)
	clk.add(trustPoolTTL + time.Second)
	if code := healthCode(ctx, t, addr, creds); code != codes.OK {
		t.Errorf("handshake code = %v after the rotation was picked up, want %v", code, codes.OK)
	}
}

// TestTLSConfigRejectsAnUnexpectedServerName pins the one property that moving
// the chain check into VerifyConnection could silently drop: with
// InsecureSkipVerify set, the stdlib no longer checks the name, so the
// hostname match holds only because VerifyOptions.DNSName re-states it. A
// trusted leaf for the wrong name must still be refused.
func TestTLSConfigRejectsAnUnexpectedServerName(t *testing.T) {
	ca := testca.New(t, "servicedns-ca")
	clientset := fakeClientset(liveServiceDNSBundle(ca))
	clk := &fakeClock{t: time.Now()}
	cache := cacheFor(t, clientset, clk, time.Minute)
	// The anchors are the right ones; only the expected name differs.
	creds := credentials.NewTLS(cache.tlsConfig("ateapi.wrong-namespace.svc.cluster.local"))

	addr := serveHealth(t, ca)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if code := healthCode(ctx, t, addr, creds); code == codes.OK {
		t.Error("handshake succeeded against a leaf issued for a different name, want a failure")
	}
}

// TestServerTLSConfigWarmFailsAtConstruction keeps the fail-fast NewRouterDialer
// had before: a missing bundle is reported by the constructor, not by the first
// dial.
func TestServerTLSConfigWarmFailsAtConstruction(t *testing.T) {
	if _, err := serverTLSConfig(context.Background(), fakeClientset(), apiServerName()); err == nil {
		t.Error("serverTLSConfig() error = nil, want a failure with no live bundle present")
	}
}

// serveHealth starts a gRPC health server presenting a leaf signed by ca for
// the ateapi Service DNS name, and returns its address.
func serveHealth(t *testing.T, ca *testca.CA) string {
	t.Helper()
	leaf := ca.Issue(t, testca.Opts{
		CommonName: apiServerName(),
		DNSNames:   []string{apiServerName()},
		IPs:        []string{"127.0.0.1"},
	})
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{leaf.CertDER}, PrivateKey: leaf.Key}},
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

// healthCode dials addr with creds and reports the status code of one health
// check, which is codes.Unavailable when the handshake is refused.
func healthCode(ctx context.Context, t *testing.T, addr string, creds credentials.TransportCredentials) codes.Code {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatalf("grpc.NewClient(): %v", err)
	}
	defer conn.Close()
	_, err = healthpb.NewHealthClient(conn).Check(ctx, &healthpb.HealthCheckRequest{})
	return status.Code(err)
}
