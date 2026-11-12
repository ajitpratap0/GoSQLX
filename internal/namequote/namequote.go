// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

// Package namequote is the single quoting predicate for parser rendering and
// fingerprint normal form version 2 rule N3.
package namequote

import (
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/dialect"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Fold returns how the dialect matches the case of unquoted identifiers.
// Generic SQL folds to lower case like PostgreSQL.
func Fold(d keywords.SQLDialect) ast.IdentifierCaseFolding {
	switch d {
	case keywords.DialectOracle, keywords.DialectSnowflake:
		return ast.FoldUpper
	case keywords.DialectMySQL, keywords.DialectMariaDB, keywords.DialectSQLServer,
		keywords.DialectSQLite, keywords.DialectClickHouse, keywords.DialectBigQuery:
		return ast.FoldNone
	}
	return ast.FoldLower
}

// MustStayQuoted reports whether a delimited name must retain its delimiters.
func MustStayQuoted(name string, d keywords.SQLDialect) bool {
	// TOP is a dialect keyword, absent from the tokenizer's global keyword map.
	return (dialect.Parse(string(d)) == dialect.SQLServer && isTOP(name)) ||
		ast.DelimitedNameMustStayQuoted(name, Fold(d)) || tokenizer.IsKeyword(name) ||
		isContextualKeywordName(name)
}

// contextualKeywordNames lists, in upper case, words the tokenizer reads as
// plain identifiers but that the databases (or the parser, in context) treat
// as niladic functions, pseudo-columns or operators when written bare:
// "user" is a column, user is the current user; "PRIOR" is a column, PRIOR
// in CONNECT BY is the operator. A delimited name equal to one of them keeps
// its delimiters.
var contextualKeywordNames = map[string]bool{
	"PRIOR": true, "CONNECT_BY_ROOT": true,
	"USER": true, "CURRENT_USER": true, "SESSION_USER": true, "SYSTEM_USER": true,
	"CURRENT_ROLE": true, "CURRENT_CATALOG": true, "CURRENT_SCHEMA": true,
	"CURRENT_DATE": true, "CURRENT_TIME": true, "CURRENT_TIMESTAMP": true,
	"LOCALTIME": true, "LOCALTIMESTAMP": true,
	"SYSDATE": true, "SYSTIMESTAMP": true, "ROWNUM": true, "ROWID": true, "LEVEL": true,
}

// maxContextualKeywordLen is the length of the longest
// contextualKeywordNames word.
const maxContextualKeywordLen = len("CURRENT_TIMESTAMP")

// isContextualKeywordName reports whether name is in contextualKeywordNames,
// ignoring ASCII case, without allocating.
func isContextualKeywordName(name string) bool {
	if len(name) < 4 || len(name) > maxContextualKeywordLen {
		return false
	}
	var up [maxContextualKeywordLen]byte
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'a' && c <= 'z' {
			c -= 'a' - 'A'
		}
		up[i] = c
	}
	return contextualKeywordNames[string(up[:len(name)])]
}

// isTOP compares ASCII case-insensitively. No non-ASCII rune upper-cases to
// T, O or P: unicode.ToUpper maps only U+0131 to I and U+017F to S into ASCII,
// so this is identical to the parser's Unicode comparison for this word.
func isTOP(s string) bool {
	return len(s) == 3 && (s[0] == 'T' || s[0] == 't') &&
		(s[1] == 'O' || s[1] == 'o') && (s[2] == 'P' || s[2] == 'p')
}
