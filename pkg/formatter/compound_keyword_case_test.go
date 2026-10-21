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

package formatter_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestFormatAST_LowerCaseCompoundKeywordsReparse_Issue842 checks that output
// written with KeywordLower (for example "cross join") parses again and is a
// formatting fixpoint.
func TestFormatAST_LowerCaseCompoundKeywordsReparse_Issue842(t *testing.T) {
	lower := ast.CompactStyle()
	lower.KeywordCase = ast.KeywordLower
	for _, in := range []string{
		"SELECT * FROM t CROSS JOIN t2",
		"SELECT * FROM t FULL JOIN t2 ON t.a = t2.a",
		"SELECT * FROM t FULL OUTER JOIN t2 ON t.a = t2.a",
		"SELECT a, b FROM t GROUP BY GROUPING SETS ((a), (b), ())",
	} {
		t.Run(in, func(t *testing.T) {
			got := formatWithDialect(t, in, keywords.DialectPostgreSQL, lower)
			if again := formatWithDialect(t, got, keywords.DialectPostgreSQL, lower); again != got {
				t.Fatalf("re-format of %q = %q", got, again)
			}
		})
	}
}
