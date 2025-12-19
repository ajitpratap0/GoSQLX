// Package parser - double_quoted_identifier_test.go
// Tests for double-quoted identifier support in DML and DDL statements.
// Double-quoted identifiers are part of the ANSI SQL standard and are used by
// PostgreSQL, Oracle, SQLite, and other databases.

package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// parseSQLWithQuotedIdentifiers is a helper to tokenize and parse SQL for testing quoted identifiers
// (double-quoted for ANSI SQL/PostgreSQL, backticks for MySQL, etc.)
func parseSQLWithQuotedIdentifiers(t *testing.T, sql string) error {
	t.Helper()

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return err
	}

	convertedTokens := convertTokensWithQuotedIdentifiers(tokens)

	parser := &Parser{}
	_, err = parser.Parse(convertedTokens)
	return err
}

// convertTokensWithQuotedIdentifiers converts tokenizer tokens to parser tokens,
// including proper handling of quoted strings (double-quoted, backticks) as identifiers
func convertTokensWithQuotedIdentifiers(tokens []models.TokenWithSpan) []token.Token {
	result := make([]token.Token, 0, len(tokens))
	for _, t := range tokens {
		var tokenType token.Type
		var modelType models.TokenType = t.Token.Type // Preserve the original ModelType

		switch t.Token.Type {
		case models.TokenTypeIdentifier:
			tokenType = "IDENT"
		case models.TokenTypeDoubleQuotedString:
			// Double-quoted strings should be treated as identifiers in SQL
			tokenType = "DOUBLE_QUOTED_STRING"
		case models.TokenTypeKeyword:
			tokenType = token.Type(t.Token.Value)
		case models.TokenTypeString:
			tokenType = "STRING"
		case models.TokenTypeNumber:
			tokenType = "INT"
		case models.TokenTypeOperator:
			tokenType = token.Type(t.Token.Value)
		case models.TokenTypeLParen:
			tokenType = "("
		case models.TokenTypeRParen:
			tokenType = ")"
		case models.TokenTypeComma:
			tokenType = ","
		case models.TokenTypePeriod:
			tokenType = "."
		case models.TokenTypeEq:
			tokenType = "="
		case models.TokenTypeSemicolon:
			tokenType = ";"
		default:
			if t.Token.Value != "" {
				tokenType = token.Type(t.Token.Value)
			}
		}

		if tokenType != "" && t.Token.Value != "" {
			result = append(result, token.Token{
				Type:      tokenType,
				ModelType: modelType,
				Literal:   t.Token.Value,
			})
		}
	}
	return result
}

func TestDoubleQuotedIdentifiers_SELECT(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "double-quoted column in SELECT",
			sql:  `SELECT "id" FROM users`,
		},
		{
			name: "double-quoted table in SELECT",
			sql:  `SELECT id FROM "users"`,
		},
		{
			name: "double-quoted column and table in SELECT",
			sql:  `SELECT "id", "name" FROM "users"`,
		},
		{
			name: "double-quoted in WHERE clause",
			sql:  `SELECT id FROM users WHERE "id" = 1`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseSQLWithQuotedIdentifiers(t, tt.sql)
			if err != nil {
				t.Errorf("Failed to parse %q: %v", tt.sql, err)
			}
		})
	}
}

func TestDoubleQuotedIdentifiers_INSERT(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "double-quoted table in INSERT",
			sql:  `INSERT INTO "users" (name) VALUES (1)`,
		},
		{
			name: "double-quoted columns in INSERT",
			sql:  `INSERT INTO users ("id", "name") VALUES (1, 2)`,
		},
		{
			name: "double-quoted table and columns in INSERT",
			sql:  `INSERT INTO "users" ("id", "name") VALUES (1, 2)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseSQLWithQuotedIdentifiers(t, tt.sql)
			if err != nil {
				t.Errorf("Failed to parse %q: %v", tt.sql, err)
			}
		})
	}
}

func TestDoubleQuotedIdentifiers_UPDATE(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "double-quoted table in UPDATE",
			sql:  `UPDATE "users" SET name = 1`,
		},
		{
			name: "double-quoted column in UPDATE SET",
			sql:  `UPDATE users SET "name" = 1`,
		},
		{
			name: "double-quoted table and column in UPDATE",
			sql:  `UPDATE "users" SET "name" = 1 WHERE "id" = 1`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseSQLWithQuotedIdentifiers(t, tt.sql)
			if err != nil {
				t.Errorf("Failed to parse %q: %v", tt.sql, err)
			}
		})
	}
}

func TestDoubleQuotedIdentifiers_DELETE(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "double-quoted table in DELETE",
			sql:  `DELETE FROM "users"`,
		},
		{
			name: "double-quoted table with WHERE in DELETE",
			sql:  `DELETE FROM "users" WHERE "id" = 1`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseSQLWithQuotedIdentifiers(t, tt.sql)
			if err != nil {
				t.Errorf("Failed to parse %q: %v", tt.sql, err)
			}
		})
	}
}

func TestDoubleQuotedIdentifiers_DROP(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "double-quoted table in DROP TABLE",
			sql:  `DROP TABLE "users"`,
		},
		{
			name: "double-quoted table with IF EXISTS in DROP",
			sql:  `DROP TABLE IF EXISTS "users"`,
		},
		{
			name: "double-quoted view in DROP VIEW",
			sql:  `DROP VIEW "user_summary"`,
		},
		{
			name: "double-quoted index in DROP INDEX",
			sql:  `DROP INDEX "idx_users_name"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseSQLWithQuotedIdentifiers(t, tt.sql)
			if err != nil {
				t.Errorf("Failed to parse %q: %v", tt.sql, err)
			}
		})
	}
}

func TestDoubleQuotedIdentifiers_CREATE(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "double-quoted table in CREATE TABLE",
			sql:  `CREATE TABLE "users" (id INT)`,
		},
		{
			name: "double-quoted view in CREATE VIEW",
			sql:  `CREATE VIEW "user_summary" AS SELECT id FROM users`,
		},
		{
			name: "double-quoted index in CREATE INDEX",
			sql:  `CREATE INDEX "idx_users_name" ON users (name)`,
		},
		{
			name: "double-quoted table in CREATE INDEX ON",
			sql:  `CREATE INDEX idx_users_name ON "users" (name)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseSQLWithQuotedIdentifiers(t, tt.sql)
			if err != nil {
				t.Errorf("Failed to parse %q: %v", tt.sql, err)
			}
		})
	}
}

func TestDoubleQuotedIdentifiers_TRUNCATE(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "double-quoted table in TRUNCATE",
			sql:  `TRUNCATE TABLE "users"`,
		},
		{
			name: "double-quoted table without TABLE keyword",
			sql:  `TRUNCATE "users"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseSQLWithQuotedIdentifiers(t, tt.sql)
			if err != nil {
				t.Errorf("Failed to parse %q: %v", tt.sql, err)
			}
		})
	}
}

// TestDoubleQuotedIdentifiers_Mixed tests mixing quoted and unquoted identifiers
func TestDoubleQuotedIdentifiers_Mixed(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "mixed identifiers in SELECT",
			sql:  `SELECT "id", name FROM "users" WHERE status = 1`,
		},
		{
			name: "mixed identifiers in INSERT",
			sql:  `INSERT INTO "users" (id, "name") VALUES (1, 2)`,
		},
		{
			name: "mixed identifiers in UPDATE",
			sql:  `UPDATE "users" SET name = 1, "status" = 2`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := parseSQLWithQuotedIdentifiers(t, tt.sql)
			if err != nil {
				t.Errorf("Failed to parse %q: %v", tt.sql, err)
			}
		})
	}
}
