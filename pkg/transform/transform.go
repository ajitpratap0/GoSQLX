package transform

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Rule represents a rewrite rule that can be applied to a statement.
type Rule interface {
	Apply(stmt ast.Statement) error
}

// RuleFunc adapts a function to the Rule interface.
type RuleFunc func(stmt ast.Statement) error

// Apply implements Rule.
func (f RuleFunc) Apply(stmt ast.Statement) error {
	return f(stmt)
}

// Apply applies multiple rules to a statement in order.
// If any rule returns an error, Apply stops and returns that error.
func Apply(stmt ast.Statement, rules ...Rule) error {
	for _, rule := range rules {
		if err := rule.Apply(stmt); err != nil {
			return err
		}
	}
	return nil
}

// ErrUnsupportedStatement is returned when a transform is applied to an unsupported statement type.
type ErrUnsupportedStatement struct {
	Transform string
	Got       string
}

func (e *ErrUnsupportedStatement) Error() string {
	return fmt.Sprintf("transform %s: unsupported statement type %s", e.Transform, e.Got)
}

// parseSQL parses a full SQL statement and returns the first statement's AST.
func parseSQL(sql string) (ast.Statement, error) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return nil, fmt.Errorf("tokenize: %w", err)
	}

	p := parser.NewParser()
	defer p.Release()

	tree, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	if tree == nil || len(tree.Statements) == 0 {
		return nil, fmt.Errorf("no statements parsed")
	}

	return tree.Statements[0], nil
}

// parseCondition parses a SQL condition expression by wrapping it in a SELECT.
func parseCondition(sql string) (ast.Expression, error) {
	stmt, err := parseSQL("SELECT * FROM _t WHERE " + sql)
	if err != nil {
		return nil, fmt.Errorf("parse condition %q: %w", sql, err)
	}

	sel, ok := stmt.(*ast.SelectStatement)
	if !ok || sel.Where == nil {
		return nil, fmt.Errorf("parse condition %q: failed to extract WHERE", sql)
	}

	return sel.Where, nil
}

// parseJoinClause parses a JOIN clause from SQL by wrapping it in a SELECT.
func parseJoinClause(sql string) (*ast.JoinClause, error) {
	stmt, err := parseSQL("SELECT * FROM _t " + sql)
	if err != nil {
		return nil, fmt.Errorf("parse join %q: %w", sql, err)
	}

	sel, ok := stmt.(*ast.SelectStatement)
	if !ok || len(sel.Joins) == 0 {
		return nil, fmt.Errorf("parse join %q: no join found", sql)
	}

	return &sel.Joins[0], nil
}

// stmtTypeName returns a human-readable name for a statement type.
func stmtTypeName(stmt ast.Statement) string {
	switch stmt.(type) {
	case *ast.SelectStatement:
		return "SELECT"
	case *ast.UpdateStatement:
		return "UPDATE"
	case *ast.DeleteStatement:
		return "DELETE"
	case *ast.InsertStatement:
		return "INSERT"
	default:
		return fmt.Sprintf("%T", stmt)
	}
}

// ParseSQL parses a SQL string into an AST. This is a convenience function
// for use with transform functions.
func ParseSQL(sql string) (*ast.AST, error) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return nil, fmt.Errorf("tokenize: %w", err)
	}

	p := parser.NewParser()
	defer p.Release()

	tree, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	return tree, nil
}

// FormatSQL formats an AST statement back to SQL using compact style.
func FormatSQL(stmt ast.Statement) string {
	type formattable interface {
		Format(ast.FormatOptions) string
	}
	if f, ok := stmt.(formattable); ok {
		return f.Format(ast.CompactStyle())
	}
	type sqlable interface {
		SQL() string
	}
	if s, ok := stmt.(sqlable); ok {
		return s.SQL()
	}
	return ""
}

