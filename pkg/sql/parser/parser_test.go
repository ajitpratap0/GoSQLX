package parser

import (
	"testing"

	"github.com/ajitpratapsingh/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratapsingh/GoSQLX/pkg/sql/token"
)

func TestParserSimpleSelect(t *testing.T) {
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "IDENT", Literal: "id"},
		{Type: ",", Literal: ","},
		{Type: "IDENT", Literal: "name"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree == nil {
		t.Fatal("expected AST, got nil")
	}
	if len(tree.Statements) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(tree.Statements))
	}

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatal("expected SelectStatement")
	}
	if len(stmt.Columns) != 2 {
		t.Fatalf("expected 2 columns, got %d", len(stmt.Columns))
	}
	if stmt.TableName != "users" {
		t.Fatalf("expected table name 'users', got %q", stmt.TableName)
	}
}

func TestParserComplexSelect(t *testing.T) {
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "IDENT", Literal: "u"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "id"},
		{Type: ",", Literal: ","},
		{Type: "IDENT", Literal: "u"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "name"},
		{Type: ",", Literal: ","},
		{Type: "IDENT", Literal: "o"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "order_date"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
		{Type: "IDENT", Literal: "u"},
		{Type: "JOIN", Literal: "JOIN"},
		{Type: "IDENT", Literal: "orders"},
		{Type: "IDENT", Literal: "o"},
		{Type: "ON", Literal: "ON"},
		{Type: "IDENT", Literal: "u"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "id"},
		{Type: "=", Literal: "="},
		{Type: "IDENT", Literal: "o"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "user_id"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "u"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "active"},
		{Type: "=", Literal: "="},
		{Type: "TRUE", Literal: "TRUE"},
		{Type: "ORDER", Literal: "ORDER"},
		{Type: "BY", Literal: "BY"},
		{Type: "IDENT", Literal: "o"},
		{Type: ".", Literal: "."},
		{Type: "IDENT", Literal: "order_date"},
		{Type: "DESC", Literal: "DESC"},
		{Type: "LIMIT", Literal: "LIMIT"},
		{Type: "INT", Literal: "10"},
		{Type: "OFFSET", Literal: "OFFSET"},
		{Type: "INT", Literal: "20"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree == nil {
		t.Fatal("expected AST, got nil")
	}

	stmt, ok := tree.Statements[0].(*ast.SelectStatement)
	if !ok {
		t.Fatal("expected SelectStatement")
	}
	if len(stmt.Columns) != 3 {
		t.Fatalf("expected 3 columns, got %d", len(stmt.Columns))
	}
	if stmt.Where == nil {
		t.Fatal("expected WHERE clause, got nil")
	}
	if stmt.OrderBy == nil || len(stmt.OrderBy) == 0 {
		t.Fatal("expected ORDER BY clause, got nil or empty")
	}
	if stmt.Limit == nil {
		t.Fatal("expected LIMIT clause, got nil")
	}
	if stmt.Offset == nil {
		t.Fatal("expected OFFSET clause, got nil")
	}
}

func TestParserInsert(t *testing.T) {
	tokens := []token.Token{
		{Type: "INSERT", Literal: "INSERT"},
		{Type: "INTO", Literal: "INTO"},
		{Type: "IDENT", Literal: "users"},
		{Type: "(", Literal: "("},
		{Type: "IDENT", Literal: "name"},
		{Type: ",", Literal: ","},
		{Type: "IDENT", Literal: "email"},
		{Type: ")", Literal: ")"},
		{Type: "VALUES", Literal: "VALUES"},
		{Type: "(", Literal: "("},
		{Type: "STRING", Literal: "John"},
		{Type: ",", Literal: ","},
		{Type: "STRING", Literal: "john@example.com"},
		{Type: ")", Literal: ")"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree == nil {
		t.Fatal("expected AST, got nil")
	}

	stmt, ok := tree.Statements[0].(*ast.InsertStatement)
	if !ok {
		t.Fatal("expected InsertStatement")
	}
	if stmt.TableName != "users" {
		t.Fatalf("expected table name 'users', got %q", stmt.TableName)
	}
	if len(stmt.Columns) != 2 {
		t.Fatalf("expected 2 columns, got %d", len(stmt.Columns))
	}
	if len(stmt.Values) != 2 {
		t.Fatalf("expected 2 values, got %d", len(stmt.Values))
	}
}

func TestParserUpdate(t *testing.T) {
	tokens := []token.Token{
		{Type: "UPDATE", Literal: "UPDATE"},
		{Type: "IDENT", Literal: "users"},
		{Type: "SET", Literal: "SET"},
		{Type: "IDENT", Literal: "active"},
		{Type: "=", Literal: "="},
		{Type: "FALSE", Literal: "FALSE"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "last_login"},
		{Type: "<", Literal: "<"},
		{Type: "STRING", Literal: "2024-01-01"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree == nil {
		t.Fatal("expected AST, got nil")
	}

	stmt, ok := tree.Statements[0].(*ast.UpdateStatement)
	if !ok {
		t.Fatal("expected UpdateStatement")
	}
	if stmt.TableName != "users" {
		t.Fatalf("expected table name 'users', got %q", stmt.TableName)
	}
	if len(stmt.Updates) != 1 {
		t.Fatalf("expected 1 update, got %d", len(stmt.Updates))
	}
	if stmt.Where == nil {
		t.Fatal("expected WHERE clause, got nil")
	}
}

func TestParserDelete(t *testing.T) {
	tokens := []token.Token{
		{Type: "DELETE", Literal: "DELETE"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
		{Type: "WHERE", Literal: "WHERE"},
		{Type: "IDENT", Literal: "active"},
		{Type: "=", Literal: "="},
		{Type: "FALSE", Literal: "FALSE"},
	}

	parser := NewParser()
	defer parser.Release()

	tree, err := parser.Parse(tokens)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tree == nil {
		t.Fatal("expected AST, got nil")
	}

	stmt, ok := tree.Statements[0].(*ast.DeleteStatement)
	if !ok {
		t.Fatal("expected DeleteStatement")
	}
	if stmt.TableName != "users" {
		t.Fatalf("expected table name 'users', got %q", stmt.TableName)
	}
	if stmt.Where == nil {
		t.Fatal("expected WHERE clause, got nil")
	}
}

func TestParserParallel(t *testing.T) {
	tokens := []token.Token{
		{Type: "SELECT", Literal: "SELECT"},
		{Type: "IDENT", Literal: "id"},
		{Type: "FROM", Literal: "FROM"},
		{Type: "IDENT", Literal: "users"},
	}

	t.Run("Parallel", func(t *testing.T) {
		t.Parallel()
		for i := 0; i < 100; i++ {
			parser := NewParser()
			tree, err := parser.Parse(tokens)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tree == nil {
				t.Fatal("expected AST, got nil")
			}
			parser.Release()
		}
	})
}

func TestParserReuse(t *testing.T) {
	parser := NewParser()
	defer parser.Release()

	queries := [][]token.Token{
		{ // Simple SELECT
			{Type: "SELECT", Literal: "SELECT"},
			{Type: "IDENT", Literal: "id"},
			{Type: "FROM", Literal: "FROM"},
			{Type: "IDENT", Literal: "users"},
		},
		{ // INSERT
			{Type: "INSERT", Literal: "INSERT"},
			{Type: "INTO", Literal: "INTO"},
			{Type: "IDENT", Literal: "users"},
			{Type: "VALUES", Literal: "VALUES"},
			{Type: "(", Literal: "("},
			{Type: "STRING", Literal: "test"},
			{Type: ")", Literal: ")"},
		},
		{ // UPDATE
			{Type: "UPDATE", Literal: "UPDATE"},
			{Type: "IDENT", Literal: "users"},
			{Type: "SET", Literal: "SET"},
			{Type: "IDENT", Literal: "name"},
			{Type: "=", Literal: "="},
			{Type: "STRING", Literal: "test"},
		},
	}

	for i, tokens := range queries {
		tree, err := parser.Parse(tokens)
		if err != nil {
			t.Fatalf("query %d: unexpected error: %v", i, err)
		}
		if tree == nil {
			t.Fatalf("query %d: expected AST, got nil", i)
		}
		if len(tree.Statements) != 1 {
			t.Fatalf("query %d: expected 1 statement, got %d", i, len(tree.Statements))
		}
	}
}
