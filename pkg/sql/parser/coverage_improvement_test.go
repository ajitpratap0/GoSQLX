package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// parseSQLHelper tokenizes and parses SQL, returning the AST tree.
func parseSQLHelper(t *testing.T, sql string) *ast.AST {
	t.Helper()
	tokens := tokenizeSQL(t, sql)
	p := NewParser()
	defer p.Release()

	tree, err := p.Parse(tokens)
	if err != nil {
		t.Fatalf("Failed to parse %q: %v", sql, err)
	}
	return tree
}

// parseTokensHelper parses manually-constructed tokens, returning the AST tree.
func parseTokensHelper(t *testing.T, tokens []token.Token) *ast.AST {
	t.Helper()
	p := NewParser()
	defer p.Release()

	tree, err := p.Parse(tokens)
	if err != nil {
		t.Fatalf("Failed to parse tokens: %v", err)
	}
	return tree
}

// TestParsePartitionDefinition targets parsePartitionDefinition (26.5% coverage)
func TestParsePartitionDefinition(t *testing.T) {
	t.Run("RANGE partition with LESS THAN value", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE TABLE orders (id INT, created DATE) PARTITION BY RANGE (created) (PARTITION p0 VALUES LESS THAN ('2024-01-01'), PARTITION p1 VALUES LESS THAN ('2025-01-01'))`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateTableStatement)
		if !ok {
			t.Fatalf("expected CreateTableStatement, got %T", tree.Statements[0])
		}
		if stmt.PartitionBy == nil {
			t.Fatal("expected PartitionBy to be set")
		}
		if len(stmt.Partitions) < 2 {
			t.Fatalf("expected at least 2 partition definitions, got %d", len(stmt.Partitions))
		}
		if stmt.Partitions[0].Name != "p0" {
			t.Errorf("expected partition name p0, got %s", stmt.Partitions[0].Name)
		}
		if stmt.Partitions[0].Type != "LESS THAN" {
			t.Errorf("expected type LESS THAN, got %s", stmt.Partitions[0].Type)
		}
	})

	t.Run("RANGE partition with MAXVALUE in parens", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE TABLE orders (id INT) PARTITION BY RANGE (id) (PARTITION p0 VALUES LESS THAN (100), PARTITION pmax VALUES LESS THAN (MAXVALUE))`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateTableStatement)
		if !ok {
			t.Fatalf("expected CreateTableStatement, got %T", tree.Statements[0])
		}
		if len(stmt.Partitions) < 2 {
			t.Fatal("expected at least 2 partition definitions")
		}
		def := stmt.Partitions[1]
		if def.Name != "pmax" {
			t.Errorf("expected partition name pmax, got %s", def.Name)
		}
		ident, ok := def.LessThan.(*ast.Identifier)
		if !ok {
			t.Fatalf("expected Identifier for MAXVALUE, got %T", def.LessThan)
		}
		if ident.Name != "MAXVALUE" {
			t.Errorf("expected MAXVALUE, got %s", ident.Name)
		}
	})

	t.Run("RANGE partition with MAXVALUE without parens", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE TABLE orders (id INT) PARTITION BY RANGE (id) (PARTITION pmax VALUES LESS THAN MAXVALUE)`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateTableStatement)
		if !ok {
			t.Fatalf("expected CreateTableStatement, got %T", tree.Statements[0])
		}
		if len(stmt.Partitions) < 1 {
			t.Fatal("expected at least 1 partition definition")
		}
	})

	t.Run("LIST partition with IN values", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE TABLE regions (id INT, region VARCHAR(50)) PARTITION BY LIST (region) (PARTITION p_east VALUES IN ('east', 'northeast'), PARTITION p_west VALUES IN ('west', 'northwest'))`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateTableStatement)
		if !ok {
			t.Fatalf("expected CreateTableStatement, got %T", tree.Statements[0])
		}
		if len(stmt.Partitions) < 2 {
			t.Fatal("expected 2 partition definitions")
		}
		def := stmt.Partitions[0]
		if def.Type != "IN" {
			t.Errorf("expected type IN, got %s", def.Type)
		}
		if len(def.InValues) != 2 {
			t.Errorf("expected 2 IN values, got %d", len(def.InValues))
		}
	})

	t.Run("multiple LESS THAN partitions", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE TABLE sales (id INT, amount DECIMAL(10,2)) PARTITION BY RANGE (amount) (PARTITION p_small VALUES LESS THAN (100), PARTITION p_medium VALUES LESS THAN (1000), PARTITION p_large VALUES LESS THAN (10000), PARTITION p_max VALUES LESS THAN MAXVALUE)`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateTableStatement)
		if !ok {
			t.Fatalf("expected CreateTableStatement, got %T", tree.Statements[0])
		}
		if len(stmt.Partitions) != 4 {
			t.Fatalf("expected 4 partitions, got %d", len(stmt.Partitions))
		}
	})

	t.Run("LIST partition with single value", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE TABLE regions (id INT, status VARCHAR(20)) PARTITION BY LIST (status) (PARTITION p_active VALUES IN ('active'), PARTITION p_inactive VALUES IN ('inactive', 'deleted'))`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateTableStatement)
		if !ok {
			t.Fatalf("expected CreateTableStatement, got %T", tree.Statements[0])
		}
		if len(stmt.Partitions) < 2 {
			t.Fatal("expected 2 partitions")
		}
		if len(stmt.Partitions[0].InValues) != 1 {
			t.Errorf("expected 1 IN value in first partition, got %d", len(stmt.Partitions[0].InValues))
		}
	})

	t.Run("partition with tablespace", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE TABLE orders (id INT) PARTITION BY RANGE (id) (PARTITION p0 VALUES LESS THAN (100) TABLESPACE ts1)`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateTableStatement)
		if !ok {
			t.Fatalf("expected CreateTableStatement, got %T", tree.Statements[0])
		}
		if len(stmt.Partitions) < 1 {
			t.Fatal("expected at least 1 partition")
		}
		if stmt.Partitions[0].Tablespace != "ts1" {
			t.Errorf("expected tablespace ts1, got %s", stmt.Partitions[0].Tablespace)
		}
	})
}

// TestParseAlterRole targets parseAlterRoleStatement (40.5%) and parseRoleOption (18.8%)
// Uses manual token construction since ROLE is not a tokenizer keyword.
func TestParseAlterRole(t *testing.T) {
	t.Run("RENAME TO", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "ROLE", Literal: "ROLE"},
			{Type: "IDENT", Literal: "admin"},
			{Type: "RENAME", Literal: "RENAME"},
			{Type: "TO", Literal: "TO"},
			{Type: "IDENT", Literal: "superadmin"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.AlterStatement)
		if !ok {
			t.Fatalf("expected AlterStatement, got %T", tree.Statements[0])
		}
		if stmt.Name != "admin" {
			t.Errorf("expected name admin, got %s", stmt.Name)
		}
		op, ok := stmt.Operation.(*ast.AlterRoleOperation)
		if !ok {
			t.Fatalf("expected AlterRoleOperation, got %T", stmt.Operation)
		}
		if op.Type != ast.RenameRole {
			t.Errorf("expected RenameRole, got %v", op.Type)
		}
		if op.NewName != "superadmin" {
			t.Errorf("expected new name superadmin, got %s", op.NewName)
		}
	})

	t.Run("ADD MEMBER", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "ROLE", Literal: "ROLE"},
			{Type: "IDENT", Literal: "admins"},
			{Type: "ADD", Literal: "ADD"},
			{Type: "MEMBER", Literal: "MEMBER"},
			{Type: "IDENT", Literal: "john"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)

		stmt := tree.Statements[0].(*ast.AlterStatement)
		op := stmt.Operation.(*ast.AlterRoleOperation)
		if op.Type != ast.AddMember {
			t.Errorf("expected AddMember, got %v", op.Type)
		}
		if op.MemberName != "john" {
			t.Errorf("expected member john, got %s", op.MemberName)
		}
	})

	t.Run("DROP MEMBER", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "ROLE", Literal: "ROLE"},
			{Type: "IDENT", Literal: "admins"},
			{Type: "DROP", Literal: "DROP"},
			{Type: "MEMBER", Literal: "MEMBER"},
			{Type: "IDENT", Literal: "john"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)

		stmt := tree.Statements[0].(*ast.AlterStatement)
		op := stmt.Operation.(*ast.AlterRoleOperation)
		if op.Type != ast.DropMember {
			t.Errorf("expected DropMember, got %v", op.Type)
		}
	})

	t.Run("SET config TO", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "ROLE", Literal: "ROLE"},
			{Type: "IDENT", Literal: "admin"},
			{Type: "SET", Literal: "SET"},
			{Type: "IDENT", Literal: "search_path"},
			{Type: "TO", Literal: "TO"},
			{Type: "IDENT", Literal: "public"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)

		stmt := tree.Statements[0].(*ast.AlterStatement)
		op := stmt.Operation.(*ast.AlterRoleOperation)
		if op.Type != ast.SetConfig {
			t.Errorf("expected SetConfig, got %v", op.Type)
		}
		if op.ConfigName != "search_path" {
			t.Errorf("expected config name search_path, got %s", op.ConfigName)
		}
	})

	t.Run("SET config equals", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "ROLE", Literal: "ROLE"},
			{Type: "IDENT", Literal: "admin"},
			{Type: "SET", Literal: "SET"},
			{Type: "IDENT", Literal: "search_path"},
			{Type: "=", Literal: "="},
			{Type: "IDENT", Literal: "public"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)

		stmt := tree.Statements[0].(*ast.AlterStatement)
		op := stmt.Operation.(*ast.AlterRoleOperation)
		if op.Type != ast.SetConfig {
			t.Errorf("expected SetConfig, got %v", op.Type)
		}
	})

	t.Run("RESET config", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "ROLE", Literal: "ROLE"},
			{Type: "IDENT", Literal: "admin"},
			{Type: "RESET", Literal: "RESET"},
			{Type: "IDENT", Literal: "search_path"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)

		stmt := tree.Statements[0].(*ast.AlterStatement)
		op := stmt.Operation.(*ast.AlterRoleOperation)
		if op.Type != ast.ResetConfig {
			t.Errorf("expected ResetConfig, got %v", op.Type)
		}
		if op.ConfigName != "search_path" {
			t.Errorf("expected config name search_path, got %s", op.ConfigName)
		}
	})

	t.Run("RESET ALL", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "ROLE", Literal: "ROLE"},
			{Type: "IDENT", Literal: "admin"},
			{Type: "RESET", Literal: "RESET"},
			{Type: "ALL", Literal: "ALL"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)

		stmt := tree.Statements[0].(*ast.AlterStatement)
		op := stmt.Operation.(*ast.AlterRoleOperation)
		if op.ConfigName != "ALL" {
			t.Errorf("expected config ALL, got %s", op.ConfigName)
		}
	})

	t.Run("WITH SUPERUSER", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "ROLE", Literal: "ROLE"},
			{Type: "IDENT", Literal: "admin"},
			{Type: "WITH", Literal: "WITH"},
			{Type: "SUPERUSER", Literal: "SUPERUSER"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)

		stmt := tree.Statements[0].(*ast.AlterStatement)
		op := stmt.Operation.(*ast.AlterRoleOperation)
		if op.Type != ast.WithOptions {
			t.Errorf("expected WithOptions, got %v", op.Type)
		}
		if len(op.Options) == 0 {
			t.Fatal("expected at least 1 option")
		}
	})

	t.Run("WITH NOSUPERUSER", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "ROLE", Literal: "ROLE"},
			{Type: "IDENT", Literal: "admin"},
			{Type: "WITH", Literal: "WITH"},
			{Type: "NOSUPERUSER", Literal: "NOSUPERUSER"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)
	})

	t.Run("WITH CREATEDB", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "ROLE", Literal: "ROLE"},
			{Type: "IDENT", Literal: "admin"},
			{Type: "WITH", Literal: "WITH"},
			{Type: "CREATEDB", Literal: "CREATEDB"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)
	})

	t.Run("WITH NOCREATEDB", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "ROLE", Literal: "ROLE"},
			{Type: "IDENT", Literal: "admin"},
			{Type: "WITH", Literal: "WITH"},
			{Type: "NOCREATEDB", Literal: "NOCREATEDB"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)
	})

	t.Run("WITH CREATEROLE", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "ROLE", Literal: "ROLE"},
			{Type: "IDENT", Literal: "admin"},
			{Type: "WITH", Literal: "WITH"},
			{Type: "CREATEROLE", Literal: "CREATEROLE"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)
	})

	t.Run("WITH NOCREATEROLE", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "ROLE", Literal: "ROLE"},
			{Type: "IDENT", Literal: "admin"},
			{Type: "WITH", Literal: "WITH"},
			{Type: "NOCREATEROLE", Literal: "NOCREATEROLE"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)
	})

	t.Run("WITH LOGIN", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "ROLE", Literal: "ROLE"},
			{Type: "IDENT", Literal: "admin"},
			{Type: "WITH", Literal: "WITH"},
			{Type: "LOGIN", Literal: "LOGIN"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)
	})

	t.Run("WITH NOLOGIN", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "ROLE", Literal: "ROLE"},
			{Type: "IDENT", Literal: "admin"},
			{Type: "WITH", Literal: "WITH"},
			{Type: "NOLOGIN", Literal: "NOLOGIN"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)
	})

	t.Run("WITH PASSWORD", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "ROLE", Literal: "ROLE"},
			{Type: "IDENT", Literal: "admin"},
			{Type: "WITH", Literal: "WITH"},
			{Type: "PASSWORD", Literal: "PASSWORD"},
			{Type: "STRING", Literal: "secret123"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)
	})

	t.Run("WITH PASSWORD NULL", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "ROLE", Literal: "ROLE"},
			{Type: "IDENT", Literal: "admin"},
			{Type: "WITH", Literal: "WITH"},
			{Type: "PASSWORD", Literal: "PASSWORD"},
			{Type: "NULL", Literal: "NULL"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)
	})

	t.Run("WITH VALID UNTIL", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "ROLE", Literal: "ROLE"},
			{Type: "IDENT", Literal: "admin"},
			{Type: "WITH", Literal: "WITH"},
			{Type: "VALID", Literal: "VALID"},
			{Type: "UNTIL", Literal: "UNTIL"},
			{Type: "STRING", Literal: "2026-12-31"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)
	})
}

// TestParseAlterPolicy targets parseAlterPolicyStatement (50.0%)
// Uses manual token construction since POLICY is not a tokenizer keyword.
func TestParseAlterPolicy(t *testing.T) {
	t.Run("RENAME TO", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "POLICY", Literal: "POLICY"},
			{Type: "IDENT", Literal: "user_policy"},
			{Type: "ON", Literal: "ON"},
			{Type: "IDENT", Literal: "users"},
			{Type: "RENAME", Literal: "RENAME"},
			{Type: "TO", Literal: "TO"},
			{Type: "IDENT", Literal: "new_policy"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)

		stmt := tree.Statements[0].(*ast.AlterStatement)
		op := stmt.Operation.(*ast.AlterPolicyOperation)
		if op.Type != ast.RenamePolicy {
			t.Errorf("expected RenamePolicy, got %v", op.Type)
		}
		if op.NewName != "new_policy" {
			t.Errorf("expected new_policy, got %s", op.NewName)
		}
	})

	t.Run("with TO roles", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "POLICY", Literal: "POLICY"},
			{Type: "IDENT", Literal: "user_policy"},
			{Type: "ON", Literal: "ON"},
			{Type: "IDENT", Literal: "users"},
			{Type: "TO", Literal: "TO"},
			{Type: "IDENT", Literal: "admin"},
			{Type: ",", Literal: ","},
			{Type: "IDENT", Literal: "manager"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)

		stmt := tree.Statements[0].(*ast.AlterStatement)
		op := stmt.Operation.(*ast.AlterPolicyOperation)
		if op.Type != ast.ModifyPolicy {
			t.Errorf("expected ModifyPolicy, got %v", op.Type)
		}
		if len(op.To) != 2 {
			t.Fatalf("expected 2 TO roles, got %d", len(op.To))
		}
	})

	t.Run("with USING", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "POLICY", Literal: "POLICY"},
			{Type: "IDENT", Literal: "user_policy"},
			{Type: "ON", Literal: "ON"},
			{Type: "IDENT", Literal: "users"},
			{Type: "USING", Literal: "USING"},
			{Type: "(", Literal: "("},
			{Type: "IDENT", Literal: "user_id"},
			{Type: "=", Literal: "="},
			{Type: "IDENT", Literal: "current_user"},
			{Type: ")", Literal: ")"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)

		stmt := tree.Statements[0].(*ast.AlterStatement)
		op := stmt.Operation.(*ast.AlterPolicyOperation)
		if op.Using == nil {
			t.Error("expected Using expression to be set")
		}
	})

	t.Run("with WITH CHECK", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "POLICY", Literal: "POLICY"},
			{Type: "IDENT", Literal: "user_policy"},
			{Type: "ON", Literal: "ON"},
			{Type: "IDENT", Literal: "users"},
			{Type: "WITH", Literal: "WITH"},
			{Type: "CHECK", Literal: "CHECK"},
			{Type: "(", Literal: "("},
			{Type: "IDENT", Literal: "status"},
			{Type: "=", Literal: "="},
			{Type: "STRING", Literal: "active"},
			{Type: ")", Literal: ")"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)

		stmt := tree.Statements[0].(*ast.AlterStatement)
		op := stmt.Operation.(*ast.AlterPolicyOperation)
		if op.WithCheck == nil {
			t.Error("expected WithCheck expression to be set")
		}
	})

	t.Run("with TO and USING", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "POLICY", Literal: "POLICY"},
			{Type: "IDENT", Literal: "user_policy"},
			{Type: "ON", Literal: "ON"},
			{Type: "IDENT", Literal: "users"},
			{Type: "TO", Literal: "TO"},
			{Type: "IDENT", Literal: "admin"},
			{Type: "USING", Literal: "USING"},
			{Type: "(", Literal: "("},
			{Type: "IDENT", Literal: "department"},
			{Type: "=", Literal: "="},
			{Type: "STRING", Literal: "IT"},
			{Type: ")", Literal: ")"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)

		stmt := tree.Statements[0].(*ast.AlterStatement)
		op := stmt.Operation.(*ast.AlterPolicyOperation)
		if len(op.To) != 1 {
			t.Errorf("expected 1 TO role, got %d", len(op.To))
		}
		if op.Using == nil {
			t.Error("expected Using expression to be set")
		}
	})
}

// TestParseCreateViewCoverage targets parseCreateView (53.3%)
func TestParseCreateViewCoverage(t *testing.T) {
	t.Run("IF NOT EXISTS", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE VIEW IF NOT EXISTS my_view AS SELECT 1`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateViewStatement)
		if !ok {
			t.Fatalf("expected CreateViewStatement, got %T", tree.Statements[0])
		}
		if !stmt.IfNotExists {
			t.Error("expected IfNotExists to be true")
		}
	})

	t.Run("with column list", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE VIEW emp_summary (emp_id, emp_name, dept) AS SELECT id, name, department FROM employees`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateViewStatement)
		if !ok {
			t.Fatalf("expected CreateViewStatement, got %T", tree.Statements[0])
		}
		if len(stmt.Columns) != 3 {
			t.Fatalf("expected 3 columns, got %d", len(stmt.Columns))
		}
		if stmt.Columns[0] != "emp_id" || stmt.Columns[1] != "emp_name" || stmt.Columns[2] != "dept" {
			t.Errorf("unexpected columns: %v", stmt.Columns)
		}
	})

	t.Run("WITH CHECK OPTION", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE VIEW active_users AS SELECT id FROM users WHERE active = true WITH CHECK OPTION`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateViewStatement)
		if !ok {
			t.Fatalf("expected CreateViewStatement, got %T", tree.Statements[0])
		}
		if stmt.WithOption != "CHECK OPTION" {
			t.Errorf("expected CHECK OPTION, got %s", stmt.WithOption)
		}
	})

	t.Run("WITH CASCADED CHECK OPTION", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE VIEW active_users AS SELECT id FROM users WHERE active = true WITH CASCADED CHECK OPTION`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateViewStatement)
		if !ok {
			t.Fatalf("expected CreateViewStatement, got %T", tree.Statements[0])
		}
		if stmt.WithOption != "CASCADED CHECK OPTION" {
			t.Errorf("expected CASCADED CHECK OPTION, got %s", stmt.WithOption)
		}
	})

	t.Run("WITH LOCAL CHECK OPTION", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE VIEW active_users AS SELECT id FROM users WHERE active = true WITH LOCAL CHECK OPTION`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateViewStatement)
		if !ok {
			t.Fatalf("expected CreateViewStatement, got %T", tree.Statements[0])
		}
		if stmt.WithOption != "LOCAL CHECK OPTION" {
			t.Errorf("expected LOCAL CHECK OPTION, got %s", stmt.WithOption)
		}
	})

	t.Run("CREATE OR REPLACE VIEW", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE OR REPLACE VIEW active_users AS SELECT id FROM users`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateViewStatement)
		if !ok {
			t.Fatalf("expected CreateViewStatement, got %T", tree.Statements[0])
		}
		if !stmt.OrReplace {
			t.Error("expected OrReplace to be true")
		}
	})

	t.Run("schema-qualified view name", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE VIEW myschema.active_users AS SELECT id FROM users`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateViewStatement)
		if !ok {
			t.Fatalf("expected CreateViewStatement, got %T", tree.Statements[0])
		}
		if stmt.Name != "myschema.active_users" {
			t.Errorf("expected myschema.active_users, got %s", stmt.Name)
		}
	})
}

// TestParseCreateIndexCoverage targets parseCreateIndex (56.2%)
func TestParseCreateIndexCoverage(t *testing.T) {
	t.Run("UNIQUE INDEX", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE UNIQUE INDEX idx_email ON users (email)`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateIndexStatement)
		if !ok {
			t.Fatalf("expected CreateIndexStatement, got %T", tree.Statements[0])
		}
		if !stmt.Unique {
			t.Error("expected Unique to be true")
		}
	})

	t.Run("IF NOT EXISTS", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE INDEX IF NOT EXISTS idx_name ON users (name)`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateIndexStatement)
		if !ok {
			t.Fatalf("expected CreateIndexStatement, got %T", tree.Statements[0])
		}
		if !stmt.IfNotExists {
			t.Error("expected IfNotExists to be true")
		}
	})

	t.Run("USING btree", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE INDEX idx_name ON users USING btree (name)`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateIndexStatement)
		if !ok {
			t.Fatalf("expected CreateIndexStatement, got %T", tree.Statements[0])
		}
		if stmt.Using != "btree" {
			t.Errorf("expected USING btree, got %s", stmt.Using)
		}
	})

	t.Run("USING gin", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE INDEX idx_data ON docs USING gin (data)`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateIndexStatement)
		if !ok {
			t.Fatalf("expected CreateIndexStatement, got %T", tree.Statements[0])
		}
		if stmt.Using != "gin" {
			t.Errorf("expected USING gin, got %s", stmt.Using)
		}
	})

	t.Run("multiple columns with directions", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE INDEX idx_multi ON orders (created_at DESC, amount ASC)`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateIndexStatement)
		if !ok {
			t.Fatalf("expected CreateIndexStatement, got %T", tree.Statements[0])
		}
		if len(stmt.Columns) != 2 {
			t.Fatalf("expected 2 columns, got %d", len(stmt.Columns))
		}
		if stmt.Columns[0].Direction != "DESC" {
			t.Errorf("expected DESC, got %s", stmt.Columns[0].Direction)
		}
		if stmt.Columns[1].Direction != "ASC" {
			t.Errorf("expected ASC, got %s", stmt.Columns[1].Direction)
		}
	})

	t.Run("NULLS LAST", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE INDEX idx_null ON users (last_login DESC NULLS LAST)`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateIndexStatement)
		if !ok {
			t.Fatalf("expected CreateIndexStatement, got %T", tree.Statements[0])
		}
		if !stmt.Columns[0].NullsLast {
			t.Error("expected NullsLast to be true")
		}
	})

	t.Run("NULLS FIRST", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE INDEX idx_null ON users (priority ASC NULLS FIRST)`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateIndexStatement)
		if !ok {
			t.Fatalf("expected CreateIndexStatement, got %T", tree.Statements[0])
		}
		if stmt.Columns[0].NullsLast {
			t.Error("expected NullsLast to be false for NULLS FIRST")
		}
	})

	t.Run("partial index with WHERE", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE INDEX idx_active ON users (name) WHERE active = true`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateIndexStatement)
		if !ok {
			t.Fatalf("expected CreateIndexStatement, got %T", tree.Statements[0])
		}
		if stmt.Where == nil {
			t.Error("expected WHERE clause to be set")
		}
	})

	t.Run("schema-qualified names", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE INDEX myschema.idx_name ON myschema.users (name)`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateIndexStatement)
		if !ok {
			t.Fatalf("expected CreateIndexStatement, got %T", tree.Statements[0])
		}
		if stmt.Name != "myschema.idx_name" {
			t.Errorf("expected myschema.idx_name, got %s", stmt.Name)
		}
		if stmt.Table != "myschema.users" {
			t.Errorf("expected myschema.users, got %s", stmt.Table)
		}
	})

	t.Run("UNIQUE IF NOT EXISTS with USING and WHERE", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE UNIQUE INDEX IF NOT EXISTS idx_composite ON myschema.orders USING btree (user_id ASC, created_at DESC NULLS LAST) WHERE status = 'active'`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateIndexStatement)
		if !ok {
			t.Fatalf("expected CreateIndexStatement, got %T", tree.Statements[0])
		}
		if !stmt.Unique {
			t.Error("expected Unique to be true")
		}
		if !stmt.IfNotExists {
			t.Error("expected IfNotExists to be true")
		}
		if stmt.Using != "btree" {
			t.Errorf("expected btree, got %s", stmt.Using)
		}
		if stmt.Where == nil {
			t.Error("expected WHERE clause")
		}
	})
}

// TestParseGroupingSetsExtended targets parseGroupingSets (67.5%)
func TestParseGroupingSetsExtended(t *testing.T) {
	sqls := []struct {
		name string
		sql  string
	}{
		{"single column without parens", `SELECT region, SUM(sales) FROM orders GROUP BY GROUPING SETS (region, product)`},
		{"multi-column sets", `SELECT a, b, c, SUM(x) FROM t GROUP BY GROUPING SETS ((a, b), (b, c), (a))`},
		{"ROLLUP", `SELECT year, quarter, SUM(revenue) FROM sales GROUP BY ROLLUP (year, quarter)`},
		{"CUBE", `SELECT region, product, SUM(amount) FROM sales GROUP BY CUBE (region, product)`},
		{"combined GROUP BY with ROLLUP", `SELECT dept, year, SUM(salary) FROM emp GROUP BY dept, ROLLUP (year)`},
		{"GROUPING SETS with parenthesized sets", `SELECT region, product, SUM(sales) FROM orders GROUP BY GROUPING SETS ((region), (product))`},
	}

	for _, tt := range sqls {
		t.Run(tt.name, func(t *testing.T) {
			tree := parseSQLHelper(t, tt.sql)
			defer ast.ReleaseAST(tree)
		})
	}
}

// TestParseReferentialActions targets parseReferentialAction (70.0%)
func TestParseReferentialActions(t *testing.T) {
	sqls := []struct {
		name string
		sql  string
	}{
		{"ON DELETE CASCADE", `CREATE TABLE orders (id INT, user_id INT REFERENCES users(id) ON DELETE CASCADE)`},
		{"ON DELETE RESTRICT", `CREATE TABLE orders (id INT, user_id INT REFERENCES users(id) ON DELETE RESTRICT)`},
		{"ON DELETE SET NULL", `CREATE TABLE orders (id INT, user_id INT REFERENCES users(id) ON DELETE SET NULL)`},
		{"ON DELETE SET DEFAULT", `CREATE TABLE orders (id INT, user_id INT REFERENCES users(id) ON DELETE SET DEFAULT)`},
		{"ON DELETE NO ACTION", `CREATE TABLE orders (id INT, user_id INT REFERENCES users(id) ON DELETE NO ACTION)`},
		{"ON UPDATE CASCADE", `CREATE TABLE orders (id INT, user_id INT REFERENCES users(id) ON UPDATE CASCADE)`},
		{"both ON DELETE and ON UPDATE", `CREATE TABLE orders (id INT, user_id INT REFERENCES users(id) ON DELETE CASCADE ON UPDATE SET NULL)`},
	}

	for _, tt := range sqls {
		t.Run(tt.name, func(t *testing.T) {
			tree := parseSQLHelper(t, tt.sql)
			defer ast.ReleaseAST(tree)
		})
	}
}

// TestParseCreateTableConstraints targets parseCreateTable (70.1%) and parseTableConstraint (83.1%)
func TestParseCreateTableConstraints(t *testing.T) {
	sqls := []struct {
		name string
		sql  string
	}{
		{"CHECK constraint", `CREATE TABLE employees (id INT, age INT, CONSTRAINT chk_age CHECK (age >= 18))`},
		{"UNIQUE multi-column", `CREATE TABLE users (id INT, email VARCHAR(255), name VARCHAR(100), CONSTRAINT uq_email_name UNIQUE (email, name))`},
		{"composite PRIMARY KEY", `CREATE TABLE order_items (order_id INT, product_id INT, qty INT, PRIMARY KEY (order_id, product_id))`},
		{"FOREIGN KEY constraint", `CREATE TABLE orders (id INT, user_id INT, FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE)`},
		{"multiple constraints", `CREATE TABLE products (id INT PRIMARY KEY, name VARCHAR(100) NOT NULL, sku VARCHAR(50) UNIQUE, price DECIMAL(10,2) CHECK (price > 0), category_id INT REFERENCES categories(id))`},
		{"DEFAULT values", `CREATE TABLE logs (id INT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, status VARCHAR(20) DEFAULT 'pending')`},
		{"IF NOT EXISTS", `CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, name VARCHAR(100))`},
		{"schema-qualified", `CREATE TABLE myschema.users (id INT PRIMARY KEY, name VARCHAR(100))`},
	}

	for _, tt := range sqls {
		t.Run(tt.name, func(t *testing.T) {
			tree := parseSQLHelper(t, tt.sql)
			defer ast.ReleaseAST(tree)
		})
	}
}

// TestParseMergeExtended targets parseMergeStatement (85.1%) and parseMergeWhenClause (84.4%)
func TestParseMergeExtended(t *testing.T) {
	sqls := []struct {
		name string
		sql  string
	}{
		{"MERGE with DELETE", `MERGE INTO target t USING source s ON t.id = s.id WHEN MATCHED AND s.deleted = true THEN DELETE WHEN MATCHED THEN UPDATE SET t.name = s.name WHEN NOT MATCHED THEN INSERT (id, name) VALUES (s.id, s.name)`},
		{"MERGE multiple MATCHED", `MERGE INTO inventory t USING updates s ON t.product_id = s.product_id WHEN MATCHED AND s.qty = 0 THEN DELETE WHEN MATCHED THEN UPDATE SET t.qty = s.qty WHEN NOT MATCHED THEN INSERT (product_id, qty) VALUES (s.product_id, s.qty)`},
	}

	for _, tt := range sqls {
		t.Run(tt.name, func(t *testing.T) {
			tree := parseSQLHelper(t, tt.sql)
			defer ast.ReleaseAST(tree)
		})
	}
}

// TestParseComparisonExpressionEdgeCases targets parseComparisonExpression (76.4%)
func TestParseComparisonExpressionEdgeCases(t *testing.T) {
	sqls := []struct {
		name string
		sql  string
	}{
		{"NOT BETWEEN", `SELECT * FROM orders WHERE amount NOT BETWEEN 100 AND 500`},
		{"NOT LIKE", `SELECT * FROM users WHERE name NOT LIKE '%admin%'`},
		{"NOT IN with list", `SELECT * FROM users WHERE id NOT IN (1, 2, 3)`},
		{"NOT IN with subquery", `SELECT * FROM users WHERE id NOT IN (SELECT user_id FROM banned)`},
		{"BETWEEN with complex exprs", `SELECT * FROM products WHERE price BETWEEN 10 AND 1000`},
		{"IS NULL", `SELECT * FROM users WHERE email IS NULL`},
		{"IS NOT NULL", `SELECT * FROM users WHERE email IS NOT NULL`},
		{"LIKE with pattern", `SELECT * FROM users WHERE name LIKE 'test%'`},
		{"IN with single value", `SELECT * FROM users WHERE status IN ('active')`},
		{"nested NOT BETWEEN", `SELECT * FROM orders WHERE amount NOT BETWEEN 10 AND 100`},
	}

	for _, tt := range sqls {
		t.Run(tt.name, func(t *testing.T) {
			tree := parseSQLHelper(t, tt.sql)
			defer ast.ReleaseAST(tree)
		})
	}
}

// TestParseWithPositionsCoverage targets ParseWithPositions (68.0%)
func TestParseWithPositionsCoverage(t *testing.T) {
	sqls := []struct {
		name string
		sql  string
	}{
		{"simple SELECT", `SELECT id, name FROM users WHERE active = true`},
		{"INSERT", `INSERT INTO users (name, email) VALUES ('John', 'john@example.com')`},
		{"multiple statements", `SELECT 1; SELECT 2`},
		{"complex SELECT", `SELECT u.id, u.name, COUNT(o.id) FROM users u LEFT JOIN orders o ON u.id = o.user_id WHERE u.active = true GROUP BY u.id, u.name HAVING COUNT(o.id) > 0 ORDER BY u.name LIMIT 10`},
		{"UPDATE", `UPDATE users SET name = 'Jane', email = 'jane@test.com' WHERE id = 1`},
		{"DELETE", `DELETE FROM sessions WHERE expired_at < '2024-01-01'`},
		{"CREATE TABLE", `CREATE TABLE test (id INT PRIMARY KEY, name VARCHAR(100))`},
	}

	for _, tt := range sqls {
		t.Run(tt.name, func(t *testing.T) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.sql))
			if err != nil {
				t.Fatalf("tokenize error: %v", err)
			}

			p := NewParser()
			defer p.Release()

			astResult, err := p.ParseFromModelTokensWithPositions(tokens)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if astResult == nil {
				t.Fatal("expected non-nil result")
			}
			if len(astResult.Statements) == 0 {
				t.Fatal("expected at least 1 statement")
			}
		})
	}
}

// TestParseMaterializedViewExtended targets parseCreateMaterializedView (75.9%)
func TestParseMaterializedViewExtended(t *testing.T) {
	t.Run("IF NOT EXISTS", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE MATERIALIZED VIEW IF NOT EXISTS sales_summary AS SELECT region, SUM(amount) FROM sales GROUP BY region`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateMaterializedViewStatement)
		if !ok {
			t.Fatalf("expected CreateMaterializedViewStatement, got %T", tree.Statements[0])
		}
		if !stmt.IfNotExists {
			t.Error("expected IfNotExists to be true")
		}
	})

	t.Run("schema-qualified", func(t *testing.T) {
		tree := parseSQLHelper(t, `CREATE MATERIALIZED VIEW analytics.sales_summary AS SELECT region, SUM(amount) FROM sales GROUP BY region`)
		defer ast.ReleaseAST(tree)

		stmt, ok := tree.Statements[0].(*ast.CreateMaterializedViewStatement)
		if !ok {
			t.Fatalf("expected CreateMaterializedViewStatement, got %T", tree.Statements[0])
		}
		if !strings.Contains(stmt.Name, "analytics") {
			t.Errorf("expected schema-qualified name, got %s", stmt.Name)
		}
	})

	t.Run("REFRESH MATERIALIZED VIEW", func(t *testing.T) {
		tree := parseSQLHelper(t, `REFRESH MATERIALIZED VIEW sales_summary`)
		defer ast.ReleaseAST(tree)
		if len(tree.Statements) == 0 {
			t.Fatal("expected at least 1 statement")
		}
	})

	t.Run("REFRESH MATERIALIZED VIEW CONCURRENTLY", func(t *testing.T) {
		tree := parseSQLHelper(t, `REFRESH MATERIALIZED VIEW CONCURRENTLY sales_summary`)
		defer ast.ReleaseAST(tree)
		if len(tree.Statements) == 0 {
			t.Fatal("expected at least 1 statement")
		}
	})
}

// TestParseReturningClauseCoverage targets parseReturningColumns (76.9%)
func TestParseReturningClauseCoverage(t *testing.T) {
	sqls := []struct {
		name string
		sql  string
	}{
		{"INSERT RETURNING star", `INSERT INTO users (name) VALUES ('John') RETURNING *`},
		{"INSERT RETURNING columns", `INSERT INTO users (name, email) VALUES ('John', 'john@test.com') RETURNING id, created_at`},
		{"UPDATE RETURNING", `UPDATE users SET status = 'active' WHERE id = 1 RETURNING id, status`},
		{"DELETE RETURNING", `DELETE FROM sessions WHERE expired_at < '2024-01-01' RETURNING user_id, session_id`},
	}

	for _, tt := range sqls {
		t.Run(tt.name, func(t *testing.T) {
			tree := parseSQLHelper(t, tt.sql)
			defer ast.ReleaseAST(tree)
		})
	}
}

// TestParseAlterConnectorCoverage targets parseAlterConnectorStatement
func TestParseAlterConnectorCoverage(t *testing.T) {
	t.Run("SET DCPROPERTIES", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "CONNECTOR", Literal: "CONNECTOR"},
			{Type: "IDENT", Literal: "my_connector"},
			{Type: "SET", Literal: "SET"},
			{Type: "DCPROPERTIES", Literal: "DCPROPERTIES"},
			{Type: "(", Literal: "("},
			{Type: "IDENT", Literal: "host"},
			{Type: "=", Literal: "="},
			{Type: "STRING", Literal: "localhost"},
			{Type: ",", Literal: ","},
			{Type: "IDENT", Literal: "port"},
			{Type: "=", Literal: "="},
			{Type: "STRING", Literal: "5432"},
			{Type: ")", Literal: ")"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)
	})

	t.Run("SET URL", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "CONNECTOR", Literal: "CONNECTOR"},
			{Type: "IDENT", Literal: "my_connector"},
			{Type: "SET", Literal: "SET"},
			{Type: "URL", Literal: "URL"},
			{Type: "STRING", Literal: "jdbc:postgresql://localhost:5432/db"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)
	})

	t.Run("SET OWNER USER", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "CONNECTOR", Literal: "CONNECTOR"},
			{Type: "IDENT", Literal: "my_connector"},
			{Type: "SET", Literal: "SET"},
			{Type: "OWNER", Literal: "OWNER"},
			{Type: "USER", Literal: "USER"},
			{Type: "IDENT", Literal: "admin"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)
	})

	t.Run("SET OWNER ROLE", func(t *testing.T) {
		tokens := []token.Token{
			{Type: "ALTER",
				ModelType: models.TokenTypeAlter, Literal: "ALTER"},
			{Type: "CONNECTOR", Literal: "CONNECTOR"},
			{Type: "IDENT", Literal: "my_connector"},
			{Type: "SET", Literal: "SET"},
			{Type: "OWNER", Literal: "OWNER"},
			{Type: "ROLE", Literal: "ROLE"},
			{Type: "IDENT", Literal: "admin_role"},
		}
		tree := parseTokensHelper(t, tokens)
		defer ast.ReleaseAST(tree)
	})
}

// TestParsePartitionByClauseCoverage targets parsePartitionByClause (70.4%)
func TestParsePartitionByClauseCoverage(t *testing.T) {
	sqls := []struct {
		name string
		sql  string
	}{
		{"PARTITION BY RANGE", `CREATE TABLE t (id INT) PARTITION BY RANGE (id)`},
		{"PARTITION BY LIST", `CREATE TABLE t (status VARCHAR(20)) PARTITION BY LIST (status)`},
		{"PARTITION BY HASH", `CREATE TABLE t (id INT) PARTITION BY HASH (id)`},
		{"PARTITION BY multi-column", `CREATE TABLE t (a INT, b INT) PARTITION BY RANGE (a, b)`},
	}

	for _, tt := range sqls {
		t.Run(tt.name, func(t *testing.T) {
			tree := parseSQLHelper(t, tt.sql)
			defer ast.ReleaseAST(tree)

			stmt, ok := tree.Statements[0].(*ast.CreateTableStatement)
			if !ok {
				t.Fatalf("expected CreateTableStatement, got %T", tree.Statements[0])
			}
			if stmt.PartitionBy == nil {
				t.Fatal("expected PartitionBy to be set")
			}
		})
	}
}

// TestParseCreateTableAdvanced targets more parseCreateTable paths
func TestParseCreateTableAdvanced(t *testing.T) {
	sqls := []struct {
		name string
		sql  string
	}{
		{"column with NOT NULL and DEFAULT", `CREATE TABLE t (id INT NOT NULL DEFAULT 0, name VARCHAR(100) NOT NULL)`},
		{"multiple column constraints", `CREATE TABLE t (id INT PRIMARY KEY NOT NULL, email VARCHAR(255) UNIQUE NOT NULL)`},
		{"DECIMAL precision", `CREATE TABLE t (price DECIMAL(10,2), tax NUMERIC(5,3))`},
		{"VARCHAR and CHAR types", `CREATE TABLE t (name VARCHAR(100), code CHAR(10), bio TEXT)`},
		{"table with schema and many columns", `CREATE TABLE mydb.myschema.users (id INT, name VARCHAR(100), email VARCHAR(255), created_at TIMESTAMP)`},
	}

	for _, tt := range sqls {
		t.Run(tt.name, func(t *testing.T) {
			tree := parseSQLHelper(t, tt.sql)
			defer ast.ReleaseAST(tree)
		})
	}
}
