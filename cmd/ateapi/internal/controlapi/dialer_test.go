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

package controlapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agent-substrate/substrate/internal/installdefaults"
	"github.com/agent-substrate/substrate/internal/substratex509"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
)

const testAteletSPIFFEID = "spiffe://cluster.local/ns/ate-system/sa/atelet"

// makeTestCA mints a self-signed CA and returns it along with an X.509 bundle
// containing it as the sole authority for the cluster.local trust domain.
func makeTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, *x509bundle.Bundle) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}
	td := spiffeid.RequireTrustDomainFromString("cluster.local")
	bundle := x509bundle.FromX509Authorities(td, []*x509.Certificate{cert})
	return cert, key, bundle
}

// leafOpts controls the contents of a test leaf certificate.
type leafOpts struct {
	// podUID, if non-empty, is embedded in a PodIdentity extension.
	podUID string
	// spiffeID, if non-empty, is added as a URI SAN.
	spiffeID string
	// noServerAuth omits the serverAuth EKU.
	noServerAuth bool
}

// makeLeafCert mints a server leaf certificate signed by the given CA.
func makeLeafCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, opts leafOpts) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if opts.noServerAuth {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	if opts.spiffeID != "" {
		uri, err := url.Parse(opts.spiffeID)
		if err != nil {
			t.Fatalf("parsing SPIFFE ID %q: %v", opts.spiffeID, err)
		}
		template.URIs = []*url.URL{uri}
	}
	if opts.podUID != "" {
		// AddPodIdentityToCertificate requires all fields to be non-empty;
		// only PodUID matters to these tests.
		err := substratex509.AddPodIdentityToCertificate(&substratex509.PodIdentity{
			Namespace:          "ate-system",
			ServiceAccountName: "atelet",
			ServiceAccountUID:  "sa-uid",
			PodName:            "atelet-abc",
			PodUID:             opts.podUID,
			NodeName:           "node-1",
			NodeUID:            "node-uid",
		}, template)
		if err != nil {
			t.Fatalf("adding PodIdentity extension: %v", err)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("creating leaf certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing leaf certificate: %v", err)
	}
	return cert
}

// dialerWithAtelets builds an AteletDialer over the given atelet pods, dialing
// with insecure test credentials.
func dialerWithAtelets(t *testing.T, pods ...*corev1.Pod) *AteletDialer {
	t.Helper()
	return NewAteletDialer(newTestAteletIndexer(t, pods...), installdefaults.SystemNamespace, "", "",
		WithDialCredentials(func(string) (credentials.TransportCredentials, error) {
			return insecure.NewCredentials(), nil
		}))
}

func TestDialForAteletOnNodeTarget(t *testing.T) {
	tests := []struct {
		name       string
		ateletIP   string
		wantTarget string
	}{
		{
			name:       "IPv4 atelet",
			ateletIP:   "10.244.1.7",
			wantTarget: "10.244.1.7:8085",
		},
		{
			name:       "IPv6 atelet is bracketed",
			ateletIP:   "fd00:10:244::7",
			wantTarget: "[fd00:10:244::7]:8085",
		},
		{
			name:       "IPv6 loopback is bracketed",
			ateletIP:   "::1",
			wantTarget: "[::1]:8085",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ateletPod := &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{Namespace: installdefaults.SystemNamespace, Name: "atelet-abc", UID: "atelet-uid"},
				Spec:       corev1.PodSpec{NodeName: "node-1"},
				Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: tc.ateletIP}}},
			}

			d := dialerWithAtelets(t, ateletPod)
			conn, err := d.DialForAteletOnNode("node-1")
			if err != nil {
				t.Fatalf("DialForAteletOnNode returned error: %v", err)
			}
			t.Cleanup(func() { conn.Close() })

			if got := conn.Target(); got != tc.wantTarget {
				t.Errorf("dial target = %q, want %q", got, tc.wantTarget)
			}
		})
	}
}

// Concurrent RPCs against actors on the same node all miss the cold cache. Without
// the dial being collapsed they all dial, only one connection ends up cached, and the
// rest have no owner: lru.Add displaces its predecessor without invoking the eviction
// func, and callers do not close what they take to be cache-owned. Every displaced
// connection then outlives the process -- the exact cost newAteletConnCache's comment
// describes for evictions, incurred silently on the dial path instead.
//
// The property asserted is the one that makes the leak unreachable rather than merely
// cleaned up: exactly one dial happens, so there is never a second connection to
// account for. Holding the dialing caller inside the credentials hook makes that
// deterministic rather than a hope about the scheduler.
func TestDialForAteletOnNodeCollapsesConcurrentDialsOfOneAtelet(t *testing.T) {
	const callers = 8
	ateletPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: installdefaults.SystemNamespace, Name: "atelet-abc", UID: "atelet-uid"},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.1.7"}}},
	}

	var dials atomic.Int64
	var firstDial sync.Once
	dialing := make(chan struct{})
	release := make(chan struct{})
	d := NewAteletDialer(newTestAteletIndexer(t, ateletPod), installdefaults.SystemNamespace, "", "",
		WithDialCredentials(func(string) (credentials.TransportCredentials, error) {
			dials.Add(1)
			firstDial.Do(func() { close(dialing) })
			// Hold whoever dials here, so any caller that is going to dial too has
			// every opportunity to arrive before the count is read.
			<-release
			return insecure.NewCredentials(), nil
		}))

	conns := make([]*grpc.ClientConn, callers)
	var entered, done sync.WaitGroup
	entered.Add(callers)
	done.Add(callers)
	for i := range callers {
		go func() {
			defer done.Done()
			entered.Done()
			conn, err := d.DialForAteletOnNode("node-1")
			if err != nil {
				t.Errorf("DialForAteletOnNode returned error: %v", err)
				return
			}
			conns[i] = conn
		}()
	}

	// Every caller is in the call and one of them is parked in the hook. The others
	// are now either parked in the hook too (a second dial -- the defect) or waiting
	// on the first caller's result. Only elapsed time separates those, so settle
	// before reading the count: generous, and only paid once.
	entered.Wait()
	<-dialing
	time.Sleep(250 * time.Millisecond)
	got := dials.Load()
	close(release)
	done.Wait()

	if got != 1 {
		t.Errorf("%d concurrent callers for one atelet produced %d dials, want 1: every dial beyond the first yields a connection nothing owns and nothing closes", callers, got)
	}

	cached, ok := d.ateletConns.Get(string(ateletPod.UID))
	if !ok {
		t.Fatal("no connection cached for the atelet after the race")
	}
	cachedConn := cached.(*grpc.ClientConn)
	t.Cleanup(func() { cachedConn.Close() })

	// Every caller must come away holding the one cached connection -- not a private
	// one, and not a closed one.
	for i, conn := range conns {
		if conn == nil {
			continue // the error is already reported above
		}
		if conn != cachedConn {
			t.Errorf("caller %d got a connection that is not the cached one; it has no owner and leaks", i)
			continue
		}
		if state := conn.GetState(); state == connectivity.Shutdown {
			t.Errorf("caller %d got a closed connection", i)
		}
	}
}

// Collapsing concurrent dials must not collapse dials of *different* atelets. The
// flight is keyed the same way the cache is -- on the atelet's pod UID -- so a
// caller waiting on another atelet's in-flight dial would otherwise be handed a
// connection to the wrong pod, which the per-atelet UID-pinned credentials exist
// to make impossible.
func TestDialForAteletOnNodeDoesNotCollapseDialsOfDifferentAtelets(t *testing.T) {
	atelet1 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: installdefaults.SystemNamespace, Name: "atelet-one", UID: "atelet-uid-1"},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.1.7"}}},
	}
	atelet2 := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: installdefaults.SystemNamespace, Name: "atelet-two", UID: "atelet-uid-2"},
		Spec:       corev1.PodSpec{NodeName: "node-2"},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.2.9"}}},
	}

	var firstDial sync.Once
	dialing := make(chan struct{})
	release := make(chan struct{})
	d := NewAteletDialer(newTestAteletIndexer(t, atelet1, atelet2), installdefaults.SystemNamespace, "", "",
		WithDialCredentials(func(podUID string) (credentials.TransportCredentials, error) {
			if podUID == string(atelet1.UID) {
				// Keep node-1's dial in flight for the whole of node-2's call.
				firstDial.Do(func() { close(dialing) })
				<-release
			}
			return insecure.NewCredentials(), nil
		}))

	var wg sync.WaitGroup
	wg.Add(1)
	var conn1 *grpc.ClientConn
	go func() {
		defer wg.Done()
		var err error
		if conn1, err = d.DialForAteletOnNode("node-1"); err != nil {
			t.Errorf("DialForAteletOnNode(node-1) returned error: %v", err)
		}
	}()

	<-dialing
	conn2, err := d.DialForAteletOnNode("node-2")
	if err != nil {
		t.Fatalf("DialForAteletOnNode(node-2) returned error: %v", err)
	}
	t.Cleanup(func() { conn2.Close() })
	close(release)
	wg.Wait()
	if conn1 != nil {
		t.Cleanup(func() { conn1.Close() })
	}

	if got, want := conn2.Target(), "10.244.2.9:8085"; got != want {
		t.Errorf("node-2 dial target = %q, want %q: it was served another atelet's in-flight dial", got, want)
	}
	if conn1 != nil && conn1 == conn2 {
		t.Error("both atelets were served the same connection")
	}
}

// A dial that cannot build credentials must surface the error and cache nothing --
// a failed flight that left an entry behind would pin the failure for every later
// caller.
func TestDialForAteletOnNodeReportsACredentialsFailure(t *testing.T) {
	ateletPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: installdefaults.SystemNamespace, Name: "atelet-abc", UID: "atelet-uid"},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.244.1.7"}}},
	}
	wantErr := errors.New("no client bundle on disk")
	d := NewAteletDialer(newTestAteletIndexer(t, ateletPod), installdefaults.SystemNamespace, "", "",
		WithDialCredentials(func(string) (credentials.TransportCredentials, error) {
			return nil, wantErr
		}))

	conn, err := d.DialForAteletOnNode("node-1")
	if err == nil {
		t.Fatal("DialForAteletOnNode succeeded, want the credentials error")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want it to wrap %v", err, wantErr)
	}
	if conn != nil {
		t.Error("a connection was returned alongside the error")
	}
	if _, ok := d.ateletConns.Get(string(ateletPod.UID)); ok {
		t.Error("a failed dial left an entry in the connection cache")
	}
}

func TestDialForAteletOnNodeNoIPs(t *testing.T) {
	ateletPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: installdefaults.SystemNamespace, Name: "atelet-abc", UID: "atelet-uid"},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
	}
	d := dialerWithAtelets(t, ateletPod)
	if _, err := d.DialForAteletOnNode("node-1"); err == nil {
		t.Fatal("DialForAteletOnNode succeeded, want error for atelet with no IPs")
	}
}

func TestVerifyAteletServerCert(t *testing.T) {
	ca, caKey, bundle := makeTestCA(t)
	otherCA, otherCAKey, _ := makeTestCA(t)

	expectedID := spiffeid.RequireFromString(testAteletSPIFFEID)

	const uid = "5a2e1c9f-0b57-4a52-9f6e-2f6d3a1b8c4d"

	tests := []struct {
		name        string
		leaf        *x509.Certificate
		expectedUID string
		wantErr     bool
	}{
		{
			name:        "matching UID succeeds",
			leaf:        makeLeafCert(t, ca, caKey, leafOpts{podUID: uid, spiffeID: testAteletSPIFFEID}),
			expectedUID: uid,
		},
		{
			name:        "mismatched UID fails",
			leaf:        makeLeafCert(t, ca, caKey, leafOpts{podUID: "some-other-uid", spiffeID: testAteletSPIFFEID}),
			expectedUID: uid,
			wantErr:     true,
		},
		{
			name:        "missing pod UID extension fails",
			leaf:        makeLeafCert(t, ca, caKey, leafOpts{spiffeID: testAteletSPIFFEID}),
			expectedUID: uid,
			wantErr:     true,
		},
		{
			name:        "cert from untrusted CA fails",
			leaf:        makeLeafCert(t, otherCA, otherCAKey, leafOpts{podUID: uid, spiffeID: testAteletSPIFFEID}),
			expectedUID: uid,
			wantErr:     true,
		},
		{
			name:        "wrong SPIFFE ID fails",
			leaf:        makeLeafCert(t, ca, caKey, leafOpts{podUID: uid, spiffeID: "spiffe://cluster.local/ns/other/sa/other"}),
			expectedUID: uid,
			wantErr:     true,
		},
		{
			name:        "missing URI SAN fails",
			leaf:        makeLeafCert(t, ca, caKey, leafOpts{podUID: uid}),
			expectedUID: uid,
			wantErr:     true,
		},
		{
			name:        "missing serverAuth EKU fails",
			leaf:        makeLeafCert(t, ca, caKey, leafOpts{podUID: uid, spiffeID: testAteletSPIFFEID, noServerAuth: true}),
			expectedUID: uid,
			wantErr:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verify, err := verifyAteletServerCert(bundle, expectedID, tc.expectedUID)
			if err != nil {
				t.Fatalf("constructing verifier: %v", err)
			}
			err = verify(tls.ConnectionState{
				PeerCertificates: []*x509.Certificate{tc.leaf},
			})
			if gotErr := err != nil; gotErr != tc.wantErr {
				t.Fatalf("verify returned error %v, wantErr=%v", err, tc.wantErr)
			}
		})
	}

	t.Run("no peer certificate fails", func(t *testing.T) {
		verify, err := verifyAteletServerCert(bundle, expectedID, uid)
		if err != nil {
			t.Fatalf("constructing verifier: %v", err)
		}
		if err := verify(tls.ConnectionState{}); err == nil {
			t.Fatal("verify succeeded, want error")
		}
	})

	t.Run("empty expected UID fails at construction", func(t *testing.T) {
		if _, err := verifyAteletServerCert(bundle, expectedID, ""); err == nil {
			t.Fatal("verifyAteletServerCert succeeded, want error")
		}
	})
}

// newTestAteletIndexer builds an indexer with the production byNode index
// shape, holding the given atelet pods.
func newTestAteletIndexer(t *testing.T, pods ...*corev1.Pod) cache.Indexer {
	t.Helper()
	idx := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{
		byNode: func(obj any) ([]string, error) {
			return []string{obj.(*corev1.Pod).Spec.NodeName}, nil
		},
	})
	for _, p := range pods {
		if err := idx.Add(p); err != nil {
			t.Fatalf("adding pod to indexer: %v", err)
		}
	}
	return idx
}

func TestDialForAteletOnNode(t *testing.T) {
	ateletPod := func(name, uid, node, ip string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ate-system", Name: name, UID: types.UID(uid)},
			Spec:       corev1.PodSpec{NodeName: node},
			Status:     corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: ip}}},
		}
	}

	t.Run("no atelet on node", func(t *testing.T) {
		d := NewAteletDialer(newTestAteletIndexer(t), installdefaults.AteletSPIFFEID(installdefaults.SystemNamespace), "", "")
		if _, err := d.DialForAteletOnNode("node1"); !errors.Is(err, ErrNoAteletOnNode) {
			t.Fatalf("DialForAteletOnNode = %v, want ErrNoAteletOnNode", err)
		}
	})

	t.Run("more than one atelet on node", func(t *testing.T) {
		d := NewAteletDialer(newTestAteletIndexer(t,
			ateletPod("atelet-1", "uid-1", "node1", "10.0.0.1"),
			ateletPod("atelet-2", "uid-2", "node1", "10.0.0.2"),
		), installdefaults.AteletSPIFFEID(installdefaults.SystemNamespace), "", "")
		_, err := d.DialForAteletOnNode("node1")
		if err == nil || errors.Is(err, ErrNoAteletOnNode) {
			t.Fatalf("DialForAteletOnNode = %v, want a non-ErrNoAteletOnNode error", err)
		}
	})

	t.Run("dials and caches the node's atelet", func(t *testing.T) {
		d := NewAteletDialer(newTestAteletIndexer(t,
			ateletPod("atelet-1", "uid-1", "node1", "10.0.0.1"),
		), installdefaults.AteletSPIFFEID(installdefaults.SystemNamespace), "", "")
		var credsUID string
		d.dialCredentials = func(expectedPodUID string) (credentials.TransportCredentials, error) {
			credsUID = expectedPodUID
			return insecure.NewCredentials(), nil
		}

		conn, err := d.DialForAteletOnNode("node1")
		if err != nil {
			t.Fatalf("DialForAteletOnNode: %v", err)
		}
		if credsUID != "uid-1" {
			t.Errorf("credentials pinned to pod UID %q, want %q", credsUID, "uid-1")
		}
		again, err := d.DialForAteletOnNode("node1")
		if err != nil {
			t.Fatalf("DialForAteletOnNode (cached): %v", err)
		}
		if again != conn {
			t.Error("second DialForAteletOnNode returned a different connection, want the cached one")
		}
	})

	t.Run("closes conns evicted from the cache", func(t *testing.T) {
		d := NewAteletDialer(newTestAteletIndexer(t,
			ateletPod("atelet-1", "uid-1", "node1", "10.0.0.1"),
			ateletPod("atelet-2", "uid-2", "node2", "10.0.0.2"),
		), installdefaults.AteletSPIFFEID(installdefaults.SystemNamespace), "", "", WithDialCredentials(func(string) (credentials.TransportCredentials, error) {
			return insecure.NewCredentials(), nil
		}))
		d.ateletConns = newAteletConnCache(1)

		first, err := d.DialForAteletOnNode("node1")
		if err != nil {
			t.Fatalf("DialForAteletOnNode(node1): %v", err)
		}
		if _, err := d.DialForAteletOnNode("node2"); err != nil {
			t.Fatalf("DialForAteletOnNode(node2): %v", err)
		}

		if got := first.GetState(); got != connectivity.Shutdown {
			t.Errorf("evicted conn state = %v, want %v (closed on eviction)", got, connectivity.Shutdown)
		}
	})
}
