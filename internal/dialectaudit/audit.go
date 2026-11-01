// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

// Package dialectaudit implements the shared per-statement corpus audit.
package dialectaudit

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/ajitpratap0/GoSQLX/internal/dropcheck"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// Result identifies the failed pipeline stage, or ok/empty for passing input.
type Result struct {
	Stage  string
	Error  string
	Format string
}

// Check parses, formats, reparses and reformats one statement, then checks for
// dropped words. Callbacks let in-package gosqlx tests use the same pipeline
// as the command without creating an import cycle.
func Check(stmt string, d keywords.SQLDialect, parse func(string, keywords.SQLDialect) (*ast.AST, error), format func(*ast.AST) string) (r Result) {
	defer func() {
		if p := recover(); p != nil {
			r.Stage, r.Error = "panic", fmt.Sprint(p)
		}
	}()
	if Empty(stmt) {
		return Result{Stage: "empty"}
	}
	tree, err := parse(stmt, d)
	if err != nil {
		return Result{Stage: "parse", Error: err.Error()}
	}
	defer ast.ReleaseAST(tree)
	f1 := format(tree)
	r.Format = f1
	tree2, err := parse(f1, d)
	if err != nil {
		r.Stage, r.Error = "reparse", err.Error()
		return r
	}
	defer ast.ReleaseAST(tree2)
	if f2 := format(tree2); f2 != f1 {
		r.Stage, r.Error = "idempotent", "format(parse(format(x))) != format(x): "+Compact(f2)
		return r
	}
	if lost := dropcheck.DroppedWords(stmt, f1, string(d)); len(lost) > 0 {
		r.Stage, r.Error = "drop", "formatter output lost words: "+strings.Join(lost, " ")
		return r
	}
	return Result{Stage: "ok"}
}

// Empty reports whether s consists only of whitespace and complete comments.
// Unterminated block comments remain input so the parser can reject them.
func Empty(s string) bool {
	for i := 0; i < len(s); {
		switch {
		case strings.ContainsRune(" \t\r\n\f\v", rune(s[i])):
			i++
		case strings.HasPrefix(s[i:], "--"):
			if end := strings.IndexByte(s[i:], '\n'); end >= 0 {
				i += end + 1
			} else {
				return true
			}
		case strings.HasPrefix(s[i:], "/*"):
			depth := 1
			i += 2
			for i < len(s) && depth > 0 {
				switch {
				case strings.HasPrefix(s[i:], "*/"):
					depth--
					i += 2
				default:
					i++
				}
			}
			if depth > 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// Compact produces a bounded single-line diagnostic.
func Compact(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 300 {
		s = string(r[:300]) + "…"
	}
	return s
}

// ParseKnownFailures parses the testdata/realworld/known_failures.txt format,
// "dialect/file.sql#N stage  # reason". Lines starting with '#' and lines that
// are empty once a trailing " #..." comment is cut are skipped; every other
// line must have exactly two fields, and a key may appear only once.
func ParseKnownFailures(r io.Reader) (map[string]string, error) {
	known := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		raw := sc.Text()
		line := raw
		if strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 {
			return nil, fmt.Errorf("known_failures.txt: malformed entry %q (want \"file.sql#N stage\")", raw)
		}
		if _, dup := known[fields[0]]; dup {
			return nil, fmt.Errorf("known_failures.txt: duplicate entry %s", fields[0])
		}
		known[fields[0]] = fields[1]
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("known_failures.txt: scan: %w", err)
	}
	return known, nil
}
