// Package formatter provides a public API for formatting SQL strings.
//
// Usage:
//
//	f := formatter.New(formatter.Options{IndentSize: 2, Uppercase: true})
//	formatted, err := f.Format("select id,name from users where id=1")
package formatter

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Options configures SQL formatting behaviour.
type Options struct {
	IndentSize int  // spaces per indent level (default 2)
	Uppercase  bool // uppercase SQL keywords
	Compact    bool // single-line output
}

// Formatter formats SQL strings.
type Formatter struct {
	opts Options
}

// New creates a Formatter with the given options.
func New(opts Options) *Formatter {
	if opts.IndentSize <= 0 {
		opts.IndentSize = 2
	}
	return &Formatter{opts: opts}
}

// Format parses and re-formats a SQL string.
func (f *Formatter) Format(sql string) (string, error) {
	if strings.TrimSpace(sql) == "" {
		return "", nil
	}

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return "", fmt.Errorf("tokenization failed: %w", err)
	}

	if len(tokens) == 0 {
		return "", nil
	}

	p := parser.NewParser()
	parsedAST, err := p.ParseFromModelTokens(tokens)
	if err != nil {
		return "", fmt.Errorf("parsing failed: %w", err)
	}
	defer ast.ReleaseAST(parsedAST)

	// Use AST's built-in Format method
	style := ast.ReadableStyle()
	if f.opts.Compact {
		style = ast.CompactStyle()
	}
	if f.opts.IndentSize > 0 {
		style.IndentWidth = f.opts.IndentSize
	}
	if f.opts.Uppercase {
		style.KeywordCase = ast.KeywordUpper
	}

	return parsedAST.Format(style), nil
}

// FormatString is a convenience function that formats SQL with default options.
func FormatString(sql string) (string, error) {
	return New(Options{}).Format(sql)
}
