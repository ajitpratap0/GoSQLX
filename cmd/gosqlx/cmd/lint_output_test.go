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

package cmd

import (
	"strings"
	"testing"
)

func TestLintSyntaxErrorReportedOnce(t *testing.T) {
	bad := writeTemp(t, "invalid.sql", "SELECT FROM WHERE (\n")
	for _, tc := range []struct {
		name  string
		stdin *string
		args  []string
	}{
		{"inline", nil, []string{"lint", "SELECT FROM WHERE ("}},
		{"stdin", str("SELECT FROM WHERE ("), []string{"lint"}},
		{"file", nil, []string{"lint", bad}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := runCLI(t, tc.stdin, tc.args...)
			if res.err == nil {
				t.Fatal("invalid SQL must return an error for exit code 1")
			}
			if !IsSilentError(res.err) {
				t.Fatalf("main would print an extra error after the lint report: %v", res.err)
			}
			if count := strings.Count(strings.ToLower(res.stdout), "syntax error:"); count != 1 {
				t.Fatalf("expected one syntax error, got %d:\n%s", count, res.stdout)
			}
			if res.stderr != "" {
				t.Fatalf("unexpected duplicate error output: %s", res.stderr)
			}
		})
	}
}
