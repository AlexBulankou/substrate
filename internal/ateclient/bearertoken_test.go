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
	"fmt"
	"strings"
	"testing"

	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// capturedTokenRequest is what the fake clientset saw, so a test can assert on
// the request rather than only on the credentials that came back.
type capturedTokenRequest struct {
	namespace      string
	serviceAccount string
	request        *authv1.TokenRequest
}

// tokenMintingClientset returns a fake clientset that answers CreateToken with
// issued, and records the request. The default fake returns an empty
// TokenRequest, so a reactor is needed to exercise this path at all.
func tokenMintingClientset(t *testing.T, issued string, failWith error) (*fake.Clientset, *capturedTokenRequest) {
	t.Helper()
	cs := fake.NewSimpleClientset()
	captured := &capturedTokenRequest{}
	cs.PrependReactor("create", "serviceaccounts", func(action k8stesting.Action) (bool, runtime.Object, error) {
		create, ok := action.(k8stesting.CreateActionImpl)
		if !ok || action.GetSubresource() != "token" {
			return false, nil, nil
		}
		req, ok := create.Object.(*authv1.TokenRequest)
		if !ok {
			t.Errorf("CreateToken object is %T, want *authv1.TokenRequest", create.Object)
			return true, nil, fmt.Errorf("unexpected object")
		}
		captured.namespace = create.GetNamespace()
		captured.serviceAccount = create.Name
		captured.request = req
		if failWith != nil {
			return true, nil, failWith
		}
		return true, &authv1.TokenRequest{Status: authv1.TokenRequestStatus{Token: issued}}, nil
	})
	return cs, captured
}

// TestBearerTokenDialOptionMintsForTheAPIServerAudience is the reason this path
// is worth reaching: the audience and the TLS ServerName both come from
// apiServerName, and ateapi rejects a token minted for anything else. A token
// minted for the wrong audience fails at the first RPC with an authentication
// error that looks like a credential problem rather than a namespace one.
func TestBearerTokenDialOptionMintsForTheAPIServerAudience(t *testing.T) {
	t.Setenv(NamespaceEnv, "team-a-substrate")
	t.Setenv(APIServiceEnv, "ate-api")
	t.Setenv(ClientServiceAccountEnv, "ate-client-sa")

	cs, captured := tokenMintingClientset(t, "minted-token", nil)
	opt, err := bearerTokenDialOption(context.Background(), cs, "")
	if err != nil {
		t.Fatalf("bearerTokenDialOption() error = %v", err)
	}
	if opt == nil {
		t.Fatal("bearerTokenDialOption() returned a nil dial option")
	}

	if captured.request == nil {
		t.Fatal("CreateToken was never called")
	}
	if got, want := captured.namespace, "team-a-substrate"; got != want {
		t.Errorf("minted in namespace %q, want %q", got, want)
	}
	if got, want := captured.serviceAccount, "ate-client-sa"; got != want {
		t.Errorf("minted for ServiceAccount %q, want %q", got, want)
	}
	// The audience has to track the namespace ateapi actually runs in, not the
	// default: an override of one and not the other is the failure this pins.
	want := []string{"ate-api.team-a-substrate.svc"}
	if got := captured.request.Spec.Audiences; len(got) != 1 || got[0] != want[0] {
		t.Errorf("audiences = %v, want %v", got, want)
	}
	if captured.request.Spec.ExpirationSeconds == nil {
		t.Error("ExpirationSeconds is nil, want a bounded lifetime")
	} else if got := *captured.request.Spec.ExpirationSeconds; got != 3600 {
		t.Errorf("ExpirationSeconds = %d, want 3600", got)
	}
}

// TestBearerTokenDialOptionRejectsAnEmptyMintedToken pins the check on the
// response. A TokenRequest that comes back with no token is not an error from
// the API server's point of view, so without this the client dials with
// "Bearer " and the failure surfaces as an opaque unauthenticated RPC.
func TestBearerTokenDialOptionRejectsAnEmptyMintedToken(t *testing.T) {
	cs, _ := tokenMintingClientset(t, "", nil)
	if _, err := bearerTokenDialOption(context.Background(), cs, ""); err == nil {
		t.Fatal("bearerTokenDialOption() error = nil for an empty token, want a refusal")
	}
}

// TestBearerTokenDialOptionPropagatesAMintingFailure covers the path where the
// caller lacks permission to mint, which is the common misconfiguration.
func TestBearerTokenDialOptionPropagatesAMintingFailure(t *testing.T) {
	cs, _ := tokenMintingClientset(t, "", fmt.Errorf("forbidden"))
	_, err := bearerTokenDialOption(context.Background(), cs, "")
	if err == nil {
		t.Fatal("bearerTokenDialOption() error = nil, want the minting failure")
	}
	if !strings.Contains(err.Error(), "forbidden") {
		t.Errorf("error = %v, want it to carry the cause", err)
	}
}

// TestBearerTokenDialOptionDefersReadingATokenFile pins that a token file is
// read per RPC rather than once here: the file is a projected ServiceAccount
// token, so reading it eagerly would pin a kubectl-ate session to the token
// that existed when it started.
func TestBearerTokenDialOptionDefersReadingATokenFile(t *testing.T) {
	// A path that does not exist: constructing the option must not touch it.
	if _, err := bearerTokenDialOption(context.Background(), fake.NewSimpleClientset(), "/nonexistent/token"); err != nil {
		t.Fatalf("bearerTokenDialOption() error = %v, want the read deferred to the first RPC", err)
	}
}

// TestBearerTokenDialOptionReadsStdin covers the "-" branch, which is how a
// caller passes a token it does not want on disk.
func TestBearerTokenDialOptionReadsStdin(t *testing.T) {
	prev := stdin
	t.Cleanup(func() { stdin = prev })
	stdin = strings.NewReader("  piped-token\n")

	if _, err := bearerTokenDialOption(context.Background(), fake.NewSimpleClientset(), "-"); err != nil {
		t.Fatalf("bearerTokenDialOption() error = %v", err)
	}

	stdin = strings.NewReader("   \n")
	if _, err := bearerTokenDialOption(context.Background(), fake.NewSimpleClientset(), "-"); err == nil {
		t.Fatal("bearerTokenDialOption() error = nil for a blank stdin token, want a refusal")
	}
}

// TestCredentialsRequireTransportSecurity is the one that matters most in this
// file. Both credential types carry a bearer token, and gRPC only refuses to
// send PerRPCCredentials over an insecure connection when the credentials say
// they require it. If either returned false, a misconfigured endpoint would
// leak an ateapi-audience token in cleartext.
func TestCredentialsRequireTransportSecurity(t *testing.T) {
	if !bearerTokenCreds("t").RequireTransportSecurity() {
		t.Error("bearerTokenCreds does not require transport security")
	}
	if !fileBearerTokenCreds("/path").RequireTransportSecurity() {
		t.Error("fileBearerTokenCreds does not require transport security")
	}
}
