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

// Package gosqlx - error_context_size_test.go
// End-to-end regression tests for GitHub issue #615: the rendered SQL context
// in a parse/tokenize error must not scale with the size of the input. A
// single 100 KB line used to produce a ~205 KB error string.

package gosqlx

import (
	stderrors "errors"
	"strings"
	"testing"

	sqlerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
)

func TestParse_ErrorStringBoundedForLongLines(t *testing.T) {
	const limit = 1024
	prefix := func(size int) string {
		return "SELECT " + strings.Repeat("c, ", size/3) + "x FROM t WHERE "
	}

	q1 := prefix(100*1024) + "a = 'unterminated"
	q2 := prefix(100*1024) + ") ;"

	cases := []struct {
		name     string
		sql      string
		wantCode sqlerrors.ErrorCode
	}{
		{"E1002 unterminated string at end of 100KB line", q1, sqlerrors.ErrCodeUnterminatedString},
		{"E2002 at end of 100KB line", q2, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse(c.sql)
			if err == nil {
				t.Fatalf("expected an error for %q...", c.sql[:40])
			}
			if got := len(err.Error()); got >= limit {
				t.Errorf("len(err.Error()) = %d, want < %d", got, limit)
			}
			if c.wantCode != "" {
				var se *sqlerrors.Error
				if !stderrors.As(err, &se) {
					t.Fatalf("expected *errors.Error, got %T", err)
				}
				if se.Code != c.wantCode {
					t.Errorf("code = %s, want %s", se.Code, c.wantCode)
				}
			}
		})
	}

	t.Run("E2002 error size independent of input size (100KB vs 1MiB)", func(t *testing.T) {
		if testing.Short() {
			t.Skip("skipping 1 MiB input in -short mode")
		}
		_, err100 := Parse(q2)
		_, err1m := Parse(prefix(1<<20) + ") ;")
		if err100 == nil || err1m == nil {
			t.Fatalf("expected errors, got %v / %v", err100, err1m)
		}
		l100, l1m := len(err100.Error()), len(err1m.Error())
		if l100 >= limit || l1m >= limit {
			t.Errorf("error lengths %d / %d, want both < %d", l100, l1m, limit)
		}
		// Only the digits of the line/column numbers may differ.
		if diff := l1m - l100; diff < -8 || diff > 8 {
			t.Errorf("error length depends on input size: 100KB=%d 1MiB=%d", l100, l1m)
		}
	})
}
