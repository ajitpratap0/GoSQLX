// Package parser - on_conflict_extended_test.go
// Extended test coverage for INSERT ON CONFLICT (UPSERT) edge cases (#299)

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestParser_InsertOnConflict_Extended(t *testing.T) {
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
			name:           "ON CONFLICT ON CONSTRAINT with DO UPDATE and WHERE",
			input:          "INSERT INTO users (id, name) VALUES (1, 'test') ON CONFLICT ON CONSTRAINT users_pkey DO UPDATE SET name = EXCLUDED.name WHERE users.active = true",
			wantTableName:  "users",
			wantConstraint: "users_pkey",
			wantUpdateCount: 1,
			wantHasWhere:   true,
		},
		{
			name:           "ON CONFLICT with multiple target columns DO UPDATE",
			input:          "INSERT INTO orders (user_id, product_id, qty) VALUES (1, 2, 5) ON CONFLICT (user_id, product_id) DO UPDATE SET qty = orders.qty + EXCLUDED.qty",
			wantTableName:  "orders",
			wantTargetCols: 2,
			wantUpdateCount: 1,
		},
		{
			name:           "ON CONFLICT with multiple target columns and WHERE",
			input:          "INSERT INTO orders (user_id, product_id, qty) VALUES (1, 2, 5) ON CONFLICT (user_id, product_id) DO UPDATE SET qty = EXCLUDED.qty WHERE orders.qty < EXCLUDED.qty",
			wantTableName:  "orders",
			wantTargetCols: 2,
			wantUpdateCount: 1,
			wantHasWhere:   true,
		},
		{
			name:          "ON CONFLICT DO NOTHING without target",
			input:         "INSERT INTO logs (msg) VALUES ('hello') ON CONFLICT DO NOTHING",
			wantTableName: "logs",
			wantDoNothing: true,
			wantTargetCols: 0,
		},
		{
			name:            "ON CONFLICT DO UPDATE SET multiple columns with EXCLUDED",
			input:           "INSERT INTO users (id, name, email, age) VALUES (1, 'a', 'a@b.com', 30) ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, email = EXCLUDED.email, age = EXCLUDED.age",
			wantTableName:   "users",
			wantTargetCols:  1,
			wantUpdateCount: 3,
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
				t.Errorf("Target columns = %d, want %d", len(oc.Target), tt.wantTargetCols)
			}
			if oc.Constraint != tt.wantConstraint {
				t.Errorf("Constraint = %v, want %v", oc.Constraint, tt.wantConstraint)
			}
			if len(oc.Action.DoUpdate) != tt.wantUpdateCount {
				t.Errorf("Update count = %d, want %d", len(oc.Action.DoUpdate), tt.wantUpdateCount)
			}
			if (oc.Action.Where != nil) != tt.wantHasWhere {
				t.Errorf("Has WHERE = %v, want %v", oc.Action.Where != nil, tt.wantHasWhere)
			}
		})
	}
}

func TestParser_InsertSelectOnConflict(t *testing.T) {
	tests := []struct {
		name  string
		input string
		wantDoNothing bool
		wantUpdateCount int
	}{
		{
			name:  "INSERT SELECT ON CONFLICT DO NOTHING",
			input: "INSERT INTO archive (id, name) SELECT id, name FROM users ON CONFLICT DO NOTHING",
			wantDoNothing: true,
		},
		{
			name:  "INSERT SELECT ON CONFLICT DO UPDATE",
			input: "INSERT INTO archive (id, name) SELECT id, name FROM users ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name",
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

			if insertStmt.Query == nil {
				t.Fatal("Expected SELECT query in INSERT, got nil")
			}

			if insertStmt.OnConflict == nil {
				t.Fatal("OnConflict is nil")
			}

			if insertStmt.OnConflict.Action.DoNothing != tt.wantDoNothing {
				t.Errorf("DoNothing = %v, want %v", insertStmt.OnConflict.Action.DoNothing, tt.wantDoNothing)
			}
			if len(insertStmt.OnConflict.Action.DoUpdate) != tt.wantUpdateCount {
				t.Errorf("Update count = %d, want %d", len(insertStmt.OnConflict.Action.DoUpdate), tt.wantUpdateCount)
			}
		})
	}
}

func TestParser_InsertOnConflict_ExcludedComplexExpressions(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "EXCLUDED in concatenation",
			input: "INSERT INTO users (id, name) VALUES (1, 'test') ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name || ' (dup)'",
		},
		{
			name:  "EXCLUDED in arithmetic with table ref",
			input: "INSERT INTO inventory (sku, qty) VALUES ('A', 10) ON CONFLICT (sku) DO UPDATE SET qty = inventory.qty + EXCLUDED.qty",
		},
		{
			name:  "Multiple EXCLUDED refs in SET",
			input: "INSERT INTO users (id, fname, lname) VALUES (1, 'A', 'B') ON CONFLICT (id) DO UPDATE SET fname = EXCLUDED.fname, lname = EXCLUDED.lname",
		},
		{
			name:  "COALESCE wrapping EXCLUDED",
			input: "INSERT INTO users (id, bio) VALUES (1, 'x') ON CONFLICT (id) DO UPDATE SET bio = COALESCE(EXCLUDED.bio, users.bio)",
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
				t.Fatalf("Parse() error = %v for input: %s", err, tt.input)
			}

			insertStmt := result.Statements[0].(*ast.InsertStatement)
			if insertStmt.OnConflict == nil {
				t.Fatal("OnConflict is nil")
			}
			if len(insertStmt.OnConflict.Action.DoUpdate) == 0 {
				t.Error("Expected DO UPDATE expressions")
			}
		})
	}
}
