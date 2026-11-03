// Copyright 2026 GoSQLX Authors
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

package gosqlx

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

type countedWrapError struct {
	calls int
	text  string
}

func (e *countedWrapError) Error() string { e.calls++; return e.text }

func TestWrapErrDefersFormatting(t *testing.T) {
	outer := &countedWrapError{text: "outer"}
	inner := &countedWrapError{text: "inner"}
	w := newWrap(outer, inner)
	if !errors.Is(w, outer) || !errors.Is(w, inner) {
		t.Fatal("wrapper lost an error")
	}
	var found *countedWrapError
	if !errors.As(w, &found) || found != outer {
		t.Fatal("wrapper changed errors.As traversal order")
	}
	if outer.calls != 0 || inner.calls != 0 {
		t.Fatal("constructing or inspecting the wrapper formatted its errors")
	}
	got := w.Error()
	if outer.calls == 0 || inner.calls == 0 {
		t.Fatal("Error did not format both errors")
	}
	want := fmt.Errorf("%w: %w", outer, inner).Error()
	if got != want || w.Error() != want {
		t.Fatalf("error text: got %q, want %q", got, want)
	}
}

func TestWrapErrDialectSpecificCompatibility(t *testing.T) {
	for _, tc := range []struct {
		dialect keywords.SQLDialect
		sql     string
	}{
		{keywords.DialectPostgreSQL, "SELECT $tag$unterminated"},
		{keywords.DialectMySQL, "SELECT `unterminated"},
		{keywords.DialectSQLServer, "SELECT [unterminated"},
	} {
		t.Run(string(tc.dialect), func(t *testing.T) {
			want := legacyDialectError(tc.sql, tc.dialect)
			if want == nil {
				t.Fatalf("dialect fixture must be invalid: %q", tc.sql)
			}
			_, got := ParseWithDialect(tc.sql, tc.dialect)
			assertLegacyError(t, got, want)
			_, treeWant := legacyParseError(tc.sql, tc.dialect, "context")
			_, got = ParseTree(context.Background(), tc.sql, WithDialect(string(tc.dialect)))
			assertLegacyError(t, got, treeWant)
			_, formatWant := legacyParseError(tc.sql, tc.dialect, "")
			_, got = FormatWithDialect(tc.sql, DefaultFormatOptions(), tc.dialect)
			assertLegacyError(t, got, fmt.Errorf("cannot format invalid SQL: %w", formatWant))
			_, got = LintWithDialect(tc.sql, tc.dialect)
			assertLegacyError(t, got, legacyLintError(tc.sql, tc.dialect))
		})
	}
}
