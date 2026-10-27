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

// Validate() implements a fast path for SQL validation without full AST construction.
// See issue #274.
package parser

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/internal/tokscratch"
	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Validate checks whether the given SQL string is syntactically valid without
// building a full AST. It tokenizes the input and runs the parser, but the
// returned AST is immediately released. This is significantly faster than
// Parse() when you only need to know if the SQL is valid.
func Validate(sql string) error {
	return validateSQL(sqlText{s: sql, isString: true})
}

// ValidateBytes is like Validate but accepts []byte to avoid a string copy.
// Empty or whitespace-only input is rejected as invalid SQL.
func ValidateBytes(input []byte) error {
	return validateSQL(sqlText{b: input})
}

func validateSQL(in sqlText) error {
	if in.blank() {
		return goerrors.IncompleteStatementError(models.Location{}, "")
	}

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := in.tokenize(tkz)
	if err != nil {
		return wrapTokenizeError(in, err)
	}

	if len(tokens) == 0 {
		return nil
	}

	p := GetParser()
	defer PutParser(p)

	astResult, parseErr := p.ParseFromModelTokens(tokens)
	if parseErr != nil {
		return parseErr
	}
	ast.ReleaseAST(astResult)
	return nil
}

// sqlText is SQL passed to a package-level entry point either as []byte or
// as a string. String entry points tokenize the caller's string in place
// instead of converting it to []byte and having the tokenizer copy it back.
type sqlText struct {
	b        []byte
	s        string
	isString bool
}

// blank reports whether the SQL is empty or only ASCII spaces, tabs, CRs and
// LFs (the trimBytes set).
func (in sqlText) blank() bool {
	if in.isString {
		return strings.Trim(in.s, " \t\n\r") == ""
	}
	return len(trimBytes(in.b)) == 0
}

// source returns the SQL as a string for error context.
func (in sqlText) source() string {
	if in.isString {
		return in.s
	}
	return string(in.b)
}

// tokenize tokenizes the SQL into tkz's scratch buffer. The tokens are valid
// only until tkz is reused or returned to the pool, so callers must hand
// them straight to a parse method that preprocesses (copies) them and must
// never return them.
func (in sqlText) tokenize(tkz *tokenizer.Tokenizer) ([]models.TokenWithSpan, error) {
	if in.isString {
		return tokscratch.String(tkz, in.s)
	}
	return tokscratch.Bytes(tkz, in.b)
}

// wrapTokenizeError wraps a tokenizer error the way every package-level
// entry point reports it.
func wrapTokenizeError(in sqlText, err error) error {
	return goerrors.WrapError(
		goerrors.ErrCodeInvalidSyntax,
		fmt.Sprintf("tokenization error: %v", err),
		models.Location{},
		in.source(),
		err,
	)
}

// trimBytes returns input with leading/trailing whitespace removed.
func trimBytes(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\t' || b[start] == '\n' || b[start] == '\r') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\t' || b[end-1] == '\n' || b[end-1] == '\r') {
		end--
	}
	return b[start:end]
}

// validDialectList returns a human-readable comma-separated list of all valid
// dialect names for use in error messages.
func validDialectList() string {
	return strings.Join(keywords.DialectNames(), ", ")
}

// ParseBytes parses SQL from a []byte input without requiring a string conversion.
// This is especially useful when reading SQL from files via os.ReadFile.
// See issue #277.
func ParseBytes(input []byte) (*ast.AST, error) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	in := sqlText{b: input}
	tokens, err := in.tokenize(tkz)
	if err != nil {
		return nil, wrapTokenizeError(in, err)
	}

	if len(tokens) == 0 {
		return nil, goerrors.IncompleteStatementError(models.Location{}, "")
	}

	p := GetParser()
	defer PutParser(p)

	return p.ParseFromModelTokens(tokens)
}

// ParseBytesWithTokens is like ParseBytes but also returns the preprocessed
// token slice ([]models.TokenWithSpan) for callers that need both.
func ParseBytesWithTokens(input []byte) (*ast.AST, []models.TokenWithSpan, error) {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize(input)
	if err != nil {
		return nil, nil, goerrors.WrapError(
			goerrors.ErrCodeInvalidSyntax,
			fmt.Sprintf("tokenization error: %v", err),
			models.Location{},
			string(input),
			err,
		)
	}

	if len(tokens) == 0 {
		return nil, nil, goerrors.IncompleteStatementError(models.Location{}, "")
	}

	p := GetParser()
	defer PutParser(p)

	// Not p.preprocess: the slice is returned to the caller, so it must be a
	// fresh allocation rather than the pooled parser's reusable buffer.
	preprocessed := preprocessTokens(tokens)
	astResult, parseErr := p.parseTokens(preprocessed)
	if parseErr != nil {
		return nil, nil, parseErr
	}

	return astResult, preprocessed, nil
}

// ValidateWithDialect checks whether the given SQL string is syntactically valid
// using the specified SQL dialect for keyword recognition.
func ValidateWithDialect(sql string, dialect keywords.SQLDialect) error {
	return validateWithDialect(sqlText{s: sql, isString: true}, dialect)
}

// ValidateBytesWithDialect is like ValidateWithDialect but accepts []byte.
func ValidateBytesWithDialect(input []byte, dialect keywords.SQLDialect) error {
	return validateWithDialect(sqlText{b: input}, dialect)
}

func validateWithDialect(in sqlText, dialect keywords.SQLDialect) error {
	if in.blank() {
		return nil
	}

	if !keywords.IsValidDialect(string(dialect)) {
		return goerrors.InvalidSyntaxError(
			fmt.Sprintf("unknown SQL dialect %q; valid dialects: %s", dialect, validDialectList()),
			models.Location{},
			"",
		)
	}

	// Pooled tokenizer: PutTokenizer restores the default dialect, so the
	// configured dialect never leaks to a later pool user.
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tkz.SetDialect(dialect)

	tokens, err := in.tokenize(tkz)
	if err != nil {
		return wrapTokenizeError(in, err)
	}

	if len(tokens) == 0 {
		return nil
	}

	// Pooled parser: PutParser -> Reset clears dialect, typed dialect,
	// capabilities and strict mode.
	p := GetParser()
	defer PutParser(p)
	p.ApplyOptions(WithDialect(string(dialect)))

	astResult, parseErr := p.ParseFromModelTokens(tokens)
	if parseErr != nil {
		return parseErr
	}
	ast.ReleaseAST(astResult)
	return nil
}

// ParseWithDialect parses SQL using the specified dialect for keyword recognition.
// This is a convenience function combining dialect-aware tokenization and parsing.
func ParseWithDialect(sql string, dialect keywords.SQLDialect) (*ast.AST, error) {
	return parseWithDialect(sqlText{s: sql, isString: true}, dialect)
}

// ParseBytesWithDialect is like ParseWithDialect but accepts []byte.
func ParseBytesWithDialect(input []byte, dialect keywords.SQLDialect) (*ast.AST, error) {
	return parseWithDialect(sqlText{b: input}, dialect)
}

func parseWithDialect(in sqlText, dialect keywords.SQLDialect) (*ast.AST, error) {
	if !keywords.IsValidDialect(string(dialect)) {
		return nil, goerrors.InvalidSyntaxError(
			fmt.Sprintf("unknown SQL dialect %q; valid dialects: %s", dialect, validDialectList()),
			models.Location{},
			"",
		)
	}

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	tkz.SetDialect(dialect)

	tokens, err := in.tokenize(tkz)
	if err != nil {
		return nil, wrapTokenizeError(in, err)
	}

	if len(tokens) == 0 {
		return nil, goerrors.IncompleteStatementError(models.Location{}, "")
	}

	// The returned AST does not alias parser or tokenizer pooled state, so it
	// is owned by the caller exactly as with the pooled default ParseBytes.
	p := GetParser()
	defer PutParser(p)
	p.ApplyOptions(WithDialect(string(dialect)))

	return p.parseWithSource(tokens, in)
}
