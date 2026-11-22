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

package lsp

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// Format-on-save must not delete comments or optimizer hints, in the default
// pipeline or in a dialect.
func TestFormatForDialect_KeepsComments(t *testing.T) {
	opts := gosqlx.DefaultFormatOptions()
	opts.UppercaseKeywords = true
	const sql = "-- report\nselect /*+ FULL(t) */ a from t -- trailing\n"
	for _, d := range []keywords.SQLDialect{"", keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectOracle} {
		got, err := formatForDialect(sql, opts, d)
		if err != nil {
			t.Fatalf("dialect %q: %v", d, err)
		}
		for _, want := range []string{"-- report", "/*+ FULL(t) */", "-- trailing"} {
			if !strings.Contains(got, want) {
				t.Errorf("dialect %q: output %q lost %q", d, got, want)
			}
		}
	}
}
