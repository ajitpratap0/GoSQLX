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

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/dialect"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// TestParser_ZeroValueMatchesConstructors guards #784: a literal &Parser{}
// must agree with NewParser() and GetParser() on Capabilities and DialectTyped.
func TestParser_ZeroValueMatchesConstructors(t *testing.T) {
	zero := &Parser{}
	pooled := GetParser()
	defer PutParser(pooled)

	cases := map[string]*Parser{"NewParser": NewParser(), "GetParser": pooled}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if zero.Capabilities() != p.Capabilities() {
				t.Errorf("zero-value Capabilities() = %+v, want %+v", zero.Capabilities(), p.Capabilities())
			}
			if zero.DialectTyped() != p.DialectTyped() {
				t.Errorf("zero-value DialectTyped() = %q, want %q", zero.DialectTyped(), p.DialectTyped())
			}
		})
	}
	if zero.Capabilities() != dialect.Unknown.Capabilities() {
		t.Error("zero-value Capabilities() != dialect.Unknown.Capabilities()")
	}
}

func TestParser_ZeroValueParses(t *testing.T) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	toks, err := tkz.Tokenize([]byte("SELECT id FROM users WHERE id = 1"))
	if err != nil {
		t.Fatalf("tokenize: %v", err)
	}
	p := &Parser{}
	tree, err := p.ParseFromModelTokens(toks)
	if err != nil {
		t.Fatalf("zero-value parse: %v", err)
	}
	defer ast.ReleaseAST(tree)
	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}
	if _, ok := tree.Statements[0].(*ast.SelectStatement); !ok {
		t.Fatalf("expected SelectStatement, got %T", tree.Statements[0])
	}
}

func TestParser_ZeroValueCapabilitiesNoAlloc(t *testing.T) {
	p := &Parser{}
	var sink bool
	if n := testing.AllocsPerRun(100, func() { sink = p.Capabilities().SupportsMerge }); n != 0 {
		t.Errorf("Capabilities() allocated %v times", n)
	}
	_ = sink
}
