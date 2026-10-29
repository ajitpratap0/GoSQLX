// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestUnicodeIdentifierTokenOnlySpelling(t *testing.T) {
	tk := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tk)
	tokens, err := tk.TokenizeString(`SELECT U&"d\0061t\+000061" FROM t`)
	if err != nil {
		t.Fatal(err)
	}
	if tokens[1].Token.Value != "data" || tokens[1].Token.Word == nil || tokens[1].Token.Word.Value != `U&"d\0061t\+000061"` {
		t.Fatalf("token metadata: %#v", tokens[1].Token)
	}
	p := GetParser()
	defer PutParser(p)
	WithDialect(string(keywords.DialectPostgreSQL))(p)
	tree, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	names := tree.UnicodeIdentifiers[0]
	if len(names) != 2 || names[0].Name != "data" || names[0].Spelling != `U&"d\0061t\+000061"` {
		t.Fatalf("spellings: %#v", names)
	}
}

func TestOrdinaryIdentifiersHaveNoUnicodeMetadata(t *testing.T) {
	p := GetParser()
	defer PutParser(p)
	tk := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tk)
	tokens, err := tk.TokenizeString(`SELECT "A" FROM t`)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatal(err)
	}
	defer ast.ReleaseAST(tree)
	if tree.UnicodeIdentifiers != nil {
		t.Fatalf("ordinary names allocated Unicode metadata: %#v", tree.UnicodeIdentifiers)
	}
}
