package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// parseSQL is a test helper that tokenizes and parses SQL in one step.
func parseSQL(t *testing.T, sql string) *ast.AST {
	t.Helper()
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("tokenize: %v", err)
	}
	p := NewParser()
	defer p.Release()
	result, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return result
}

