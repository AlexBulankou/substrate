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

package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/openfga/openfga/pkg/storage"
)

// The transaction contract in this file is the one documented on
// transactionalDatastore: ReadPage and Write require a caller-supplied pgx.Tx
// and fail closed without one. It is exercised end-to-end by
// TestTransactionalDatastore_RollbackAndCommit, but that test needs a container
// and skips wherever Docker is absent -- which is every environment that runs
// the unit suite. These cover the refusal itself with no database at all, so
// the fail-closed half of the contract is checked on every run.
//
// The nil embedded *postgres.Datastore is the assertion, not a shortcut: the
// refusal has to come from the missing transaction, before anything reaches the
// pool. A version of these methods that checked the context after delegating --
// or that fell back to the pool the way ReadAuthorizationModel deliberately
// does -- would nil-panic here instead of returning the error.

func TestReadPageRequiresATransaction(t *testing.T) {
	d := &transactionalDatastore{}

	_, _, err := d.ReadPage(context.Background(), "store", storage.ReadFilter{}, storage.ReadPageOptions{})
	if !errors.Is(err, ErrNoTransactionInContext) {
		t.Fatalf("ReadPage() error = %v, want ErrNoTransactionInContext", err)
	}
}

// TestWriteRequiresATransaction is the one with teeth. ReadPage falling back to
// the pool would return tuples outside the caller's transaction; Write doing so
// would commit authorization tuples that the caller's transaction then rolls
// back, leaving granted permissions behind for work that did not happen.
func TestWriteRequiresATransaction(t *testing.T) {
	d := &transactionalDatastore{}

	err := d.Write(context.Background(), "store", nil, nil)
	if !errors.Is(err, ErrNoTransactionInContext) {
		t.Fatalf("Write() error = %v, want ErrNoTransactionInContext", err)
	}
}

// TestCloseDoesNotCloseTheSharedPool pins the empty body of Close. The pool is
// owned by ateapi's main, and OpenFGA's server.Close calls through to the
// datastore -- so a Close that delegated to the embedded datastore would let
// any shutdown of the authorization server take ateapi's connection pool with
// it. The nil embedded datastore is again the assertion: delegating panics,
// and the recover turns that crash into a statement of which contract broke.
func TestCloseDoesNotCloseTheSharedPool(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Close() reached the embedded datastore (%v), want a no-op: the pool belongs to the caller", r)
		}
	}()

	(&transactionalDatastore{}).Close()
}

func TestContextWithTxRoundTrips(t *testing.T) {
	want := stubTx{}
	got, ok := TxFromContext(ContextWithTx(context.Background(), want))
	if !ok {
		t.Fatal("TxFromContext() ok = false for a context carrying a transaction")
	}
	if got != pgx.Tx(want) {
		t.Errorf("TxFromContext() returned %v, want the transaction that was injected", got)
	}
}

// TestTxFromContextReportsAbsence covers the two ways a context can fail to
// carry a usable transaction. The nil case is the one worth pinning: a caller
// that passes a nil tx must not end up with a context that claims to have one,
// because every consumer of TxFromContext treats ok as permission to use the
// value without a further check.
//
// Worth knowing about what this does and does not pin: the nil case passes even
// with both nil guards deleted, because a type assertion on a nil interface
// already reports false. The guards are belt-and-braces over that. What none of
// the three catches is a *typed* nil -- a non-nil pgx.Tx interface holding a nil
// pointer -- which reports ok=true and nil-panics at first use. Nothing
// constructs one today, and this test deliberately does not assert the panicking
// behaviour as if it were the contract.
func TestTxFromContextReportsAbsence(t *testing.T) {
	t.Run("empty context", func(t *testing.T) {
		if _, ok := TxFromContext(context.Background()); ok {
			t.Error("TxFromContext() ok = true for a context with no transaction")
		}
	})

	t.Run("nil transaction", func(t *testing.T) {
		if _, ok := TxFromContext(ContextWithTx(context.Background(), nil)); ok {
			t.Error("TxFromContext() ok = true after injecting a nil transaction")
		}
	})
}

// stubTx satisfies pgx.Tx so a context can carry a distinguishable value. No
// method is called: these tests are about what reaches the transaction, not
// what it does.
type stubTx struct{ pgx.Tx }
