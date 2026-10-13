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

package keywords_test

import (
	"reflect"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// TestConflicts_NotAffectedByTokenizer pins the documented Conflicts()
// semantics (#550): only direct keywords.New calls record or reset
// conflicts. Constructing dialect tokenizers, switching dialects on pooled
// tokenizers and dialect-aware parsing must leave the buffer untouched.
func TestConflicts_NotAffectedByTokenizer(t *testing.T) {
	sentinel := []keywords.KeywordConflict{{
		Word:    "SENTINEL_550",
		Dialect: keywords.DialectMySQL,
	}}
	keywords.SetConflictsForTest(sentinel)
	t.Cleanup(keywords.ResetConflicts)

	if _, err := tokenizer.NewWithDialect(keywords.DialectMySQL); err != nil {
		t.Fatalf("NewWithDialect: %v", err)
	}
	if _, err := tokenizer.New(); err != nil {
		t.Fatalf("New: %v", err)
	}

	tkz := tokenizer.GetTokenizer()
	tkz.SetDialect(keywords.DialectClickHouse)
	if _, err := tkz.Tokenize([]byte("SELECT a FROM t PREWHERE b = 1")); err != nil {
		t.Fatalf("Tokenize: %v", err)
	}
	tokenizer.PutTokenizer(tkz)

	tree, err := parser.ParseWithDialect("SELECT `a` FROM `t` LIMIT 1", keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("ParseWithDialect: %v", err)
	}
	ast.ReleaseAST(tree)

	if err := parser.ValidateWithDialect("SELECT TOP 10 [a] FROM [t]", keywords.DialectSQLServer); err != nil {
		t.Fatalf("ValidateWithDialect: %v", err)
	}

	if got := keywords.Conflicts(); !reflect.DeepEqual(got, sentinel) {
		t.Fatalf("Conflicts() clobbered by tokenizer/parser: got %v, want %v", got, sentinel)
	}
}
