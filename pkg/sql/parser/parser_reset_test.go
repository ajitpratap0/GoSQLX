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
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// TestParser_ResetDropsTokens checks that Reset (and so PutParser) drops the
// token slice. Token values are substrings of the caller's SQL (#546), so a
// pooled parser that kept them would keep the previous input alive.
// Not parallel: it inspects a parser after returning it to the pool.
func TestParser_ResetDropsTokens(t *testing.T) {
	parse := func(p *Parser) {
		t.Helper()
		tkz := tokenizer.GetTokenizer()
		defer tokenizer.PutTokenizer(tkz)
		tokens, err := tkz.TokenizeString("SELECT a, b FROM t WHERE c = 'x'")
		if err != nil {
			t.Fatalf("tokenize: %v", err)
		}
		tree, err := p.ParseFromModelTokens(tokens)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		ast.ReleaseAST(tree)
		if p.tokens == nil {
			t.Fatal("test setup: parser holds no tokens after parsing")
		}
	}

	t.Run("Reset", func(t *testing.T) {
		p := NewParser()
		parse(p)
		p.Reset()
		if p.tokens != nil {
			t.Fatalf("tokens retained after Reset: len %d cap %d", len(p.tokens), cap(p.tokens))
		}
	})

	t.Run("PutParser", func(t *testing.T) {
		p := GetParser()
		parse(p)
		PutParser(p)
		if p.tokens != nil {
			t.Fatalf("tokens retained after PutParser: len %d cap %d", len(p.tokens), cap(p.tokens))
		}
	})
}
