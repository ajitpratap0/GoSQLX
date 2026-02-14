// Package parser - on_conflict_test.go
// Tests for INSERT ON CONFLICT (UPSERT) parsing (PostgreSQL)

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestParser_InsertOnConflict(t *testing.T) {
	tests := []struct {
		name            string
		input           string
		wantTableName   string
		wantDoNothing   bool
		wantTargetCols  int
		wantConstraint  string
		wantUpdateCount int
		wantHasWhere    bool
		wantErr         bool
	}{
		{
			name:          "ON CONFLICT DO NOTHING",
			input:         "INSERT INTO users (id, name) VALUES (1, 'test') ON CONFLICT DO NOTHING",
			wantTableName: "users",
			wantDoNothing: true,
		},
		{
			name:           "ON CONFLICT (column) DO NOTHING",
			input:          "INSERT INTO users (id, name) VALUES (1, 'test') ON CONFLICT (id) DO NOTHING",
			wantTableName:  "users",
			wantDoNothing:  true,
			wantTargetCols: 1,
		},
		{
			name:           "ON CONFLICT (multiple columns) DO NOTHING",
			input:          "INSERT INTO users (id, email, name) VALUES (1, 'test@test.com', 'test') ON CONFLICT (id, email) DO NOTHING",
			wantTableName:  "users",
			wantDoNothing:  true,
			wantTargetCols: 2,
		},
		{
			name:            "ON CONFLICT DO UPDATE SET single column",
			input:           "INSERT INTO users (id, name) VALUES (1, 'test') ON CONFLICT (id) DO UPDATE SET name = 'updated'",
			wantTableName:   "users",
			wantTargetCols:  1,
			wantUpdateCount: 1,
		},
		{
			name:            "ON CONFLICT DO UPDATE SET multiple columns",
			input:           "INSERT INTO users (id, name, email) VALUES (1, 'test', 'test@test.com') ON CONFLICT (id) DO UPDATE SET name = 'updated', email = 'new@test.com'",
			wantTableName:   "users",
			wantTargetCols:  1,
			wantUpdateCount: 2,
		},
		{
			name:            "ON CONFLICT DO UPDATE with EXCLUDED reference",
			input:           "INSERT INTO users (id, name) VALUES (1, 'test') ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name",
			wantTableName:   "users",
			wantTargetCols:  1,
			wantUpdateCount: 1,
		},
		{
			name:            "ON CONFLICT DO UPDATE with WHERE clause",
			input:           "INSERT INTO users (id, name, active) VALUES (1, 'test', true) ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name WHERE users.active = true",
			wantTableName:   "users",
			wantTargetCols:  1,
			wantUpdateCount: 1,
			wantHasWhere:    true,
		},
		{
			name:           "ON CONFLICT ON CONSTRAINT",
			input:          "INSERT INTO users (id, name) VALUES (1, 'test') ON CONFLICT ON CONSTRAINT users_pkey DO NOTHING",
			wantTableName:  "users",
			wantDoNothing:  true,
			wantConstraint: "users_pkey",
		},
		{
			name:            "ON CONFLICT ON CONSTRAINT DO UPDATE",
			input:           "INSERT INTO users (id, name) VALUES (1, 'test') ON CONFLICT ON CONSTRAINT users_pkey DO UPDATE SET name = 'updated'",
			wantTableName:   "users",
			wantConstraint:  "users_pkey",
			wantUpdateCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.input))
			if err != nil {
				t.Fatalf("Tokenize() error = %v", err)
			}

			p := NewParser()
			defer p.Release()
			result, err := p.ParseFromModelTokens(tokens)

			if (err != nil) != tt.wantErr {
				t.Fatalf("Parse() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantErr {
				return
			}

			if len(result.Statements) != 1 {
				t.Fatalf("Expected 1 statement, got %d", len(result.Statements))
			}

			insertStmt, ok := result.Statements[0].(*ast.InsertStatement)
			if !ok {
				t.Fatalf("Expected InsertStatement, got %T", result.Statements[0])
			}

			if insertStmt.TableName != tt.wantTableName {
				t.Errorf("TableName = %v, want %v", insertStmt.TableName, tt.wantTableName)
			}

			if insertStmt.OnConflict == nil {
				t.Fatal("OnConflict is nil, expected non-nil")
			}

			oc := insertStmt.OnConflict

			if oc.Action.DoNothing != tt.wantDoNothing {
				t.Errorf("DoNothing = %v, want %v", oc.Action.DoNothing, tt.wantDoNothing)
			}

			if len(oc.Target) != tt.wantTargetCols {
				t.Errorf("Target columns count = %d, want %d", len(oc.Target), tt.wantTargetCols)
			}

			if oc.Constraint != tt.wantConstraint {
				t.Errorf("Constraint = %v, want %v", oc.Constraint, tt.wantConstraint)
			}

			if len(oc.Action.DoUpdate) != tt.wantUpdateCount {
				t.Errorf("Update expressions count = %d, want %d", len(oc.Action.DoUpdate), tt.wantUpdateCount)
			}

			if (oc.Action.Where != nil) != tt.wantHasWhere {
				t.Errorf("Has WHERE = %v, want %v", oc.Action.Where != nil, tt.wantHasWhere)
			}
		})
	}
}

func TestParser_InsertOnConflictWithReturning(t *testing.T) {
	input := "INSERT INTO users (id, name) VALUES (1, 'test') ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name RETURNING id, name"

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(input))
	if err != nil {
		t.Fatalf("Tokenize() error = %v", err)
	}

	p := NewParser()
	defer p.Release()
	result, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if len(result.Statements) != 1 {
		t.Fatalf("Expected 1 statement, got %d", len(result.Statements))
	}

	insertStmt, ok := result.Statements[0].(*ast.InsertStatement)
	if !ok {
		t.Fatalf("Expected InsertStatement, got %T", result.Statements[0])
	}

	if insertStmt.OnConflict == nil {
		t.Fatal("OnConflict is nil")
	}

	if insertStmt.OnConflict.Action.DoNothing {
		t.Error("Expected DoUpdate, got DoNothing")
	}

	if len(insertStmt.OnConflict.Action.DoUpdate) != 1 {
		t.Errorf("Expected 1 update expression, got %d", len(insertStmt.OnConflict.Action.DoUpdate))
	}

	if len(insertStmt.Returning) != 2 {
		t.Errorf("Expected 2 RETURNING columns, got %d", len(insertStmt.Returning))
	}
}

func TestParser_InsertOnConflictErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Missing DO keyword",
			input: "INSERT INTO users (id) VALUES (1) ON CONFLICT (id) NOTHING",
		},
		{
			name:  "Invalid action",
			input: "INSERT INTO users (id) VALUES (1) ON CONFLICT (id) DO DELETE",
		},
		{
			name:  "Missing SET after DO UPDATE",
			input: "INSERT INTO users (id) VALUES (1) ON CONFLICT (id) DO UPDATE name = 'test'",
		},
		{
			name:  "Missing = in SET clause",
			input: "INSERT INTO users (id) VALUES (1) ON CONFLICT (id) DO UPDATE SET name 'test'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.input))
			if err != nil {
				t.Fatalf("Tokenize() error = %v", err)
			}

			p := NewParser()
			defer p.Release()
			_, err = p.ParseFromModelTokens(tokens)
			if err == nil {
				t.Error("Parse() expected error, got nil")
			}
		})
	}
}

func TestParser_InsertOnConflictComplexExpressions(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Concat with EXCLUDED",
			input: "INSERT INTO users (id, name) VALUES (1, 'test') ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name || ' (updated)'",
		},
		{
			name:  "COALESCE with EXCLUDED",
			input: "INSERT INTO users (id, name) VALUES (1, 'test') ON CONFLICT (id) DO UPDATE SET name = COALESCE(EXCLUDED.name, users.name)",
		},
		{
			name:  "Arithmetic expression",
			input: "INSERT INTO products (id, quantity) VALUES (1, 10) ON CONFLICT (id) DO UPDATE SET quantity = products.quantity + EXCLUDED.quantity",
		},
		{
			name:  "CASE expression in update",
			input: "INSERT INTO users (id, status) VALUES (1, 'active') ON CONFLICT (id) DO UPDATE SET status = CASE WHEN EXCLUDED.status = 'active' THEN 'updated' ELSE users.status END",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.input))
			if err != nil {
				t.Fatalf("Tokenize() error = %v", err)
			}

			p := NewParser()
			defer p.Release()
			result, err := p.ParseFromModelTokens(tokens)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}

			if len(result.Statements) != 1 {
				t.Fatalf("Expected 1 statement, got %d", len(result.Statements))
			}

			insertStmt, ok := result.Statements[0].(*ast.InsertStatement)
			if !ok {
				t.Fatalf("Expected InsertStatement, got %T", result.Statements[0])
			}

			if insertStmt.OnConflict == nil {
				t.Fatal("OnConflict is nil")
			}

			if len(insertStmt.OnConflict.Action.DoUpdate) == 0 {
				t.Error("Expected update expressions")
			}
		})
	}
}
