// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package formatter

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// TestCompactFastDifferential retains the visitor renderer as an independent
// oracle. Whole files exercise batches; chunks recover statements from files
// containing unsupported syntax. Parse failures are counted rather than treated
// as formatter failures, since this corpus also contains intentionally invalid SQL.
func TestCompactFastDifferential(t *testing.T) {
	root := filepath.Join("..", "..", "testdata")
	var files []string
	groups := map[string]int{"realworld": 0, "corpus": 0}
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			return nil
		}
		files = append(files, path)
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		group := strings.SplitN(rel, string(filepath.Separator), 2)[0]
		if _, ok := groups[group]; ok {
			groups[group]++
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for group, count := range groups {
		if count == 0 {
			t.Fatalf("no SQL fixtures found in testdata/%s", group)
		}
	}

	dialects := []keywords.SQLDialect{
		keywords.DialectGeneric, keywords.DialectPostgreSQL, keywords.DialectMySQL,
		keywords.DialectSQLServer, keywords.DialectOracle, keywords.DialectSQLite,
		keywords.DialectSnowflake, keywords.DialectClickHouse, keywords.DialectMariaDB,
	}
	parsed, skipped, statements, comparisons, mismatches, fastEligible := 0, 0, 0, 0, 0, 0
	statementTypes := make(map[string]int)
	for _, file := range files {
		contents, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		chunks := append([]string{string(contents)}, strings.Split(string(contents), ";\n")...)
		for chunkIndex, chunk := range chunks {
			if strings.TrimSpace(chunk) == "" {
				continue
			}
			for _, dialect := range dialects {
				tree, err := parser.ParseBytesWithDialect([]byte(chunk), dialect)
				if err != nil {
					skipped++
					continue
				}
				parsed++
				for _, statement := range tree.Statements {
					statements++
					statementTypes[fmt.Sprintf("%T", statement)]++
					for _, keywordCase := range []ast.KeywordCase{ast.KeywordPreserve, ast.KeywordUpper, ast.KeywordLower} {
						for _, target := range []string{"", string(dialect)} {
							for _, indent := range []struct {
								style ast.IndentStyle
								width int
							}{{ast.IndentSpaces, 0}, {ast.IndentSpaces, 4}, {ast.IndentTabs, 2}} {
								opts := ast.CompactStyle()
								opts.KeywordCase = keywordCase
								opts.Dialect = target
								opts.IndentStyle, opts.IndentWidth = indent.style, indent.width
								fast := formatStatement(statement, opts)
								// The visitor ignores LineWidth. A nonzero width also
								// disables the fast path for descendants, keeping this
								// oracle independent when nested statements recurse.
								slowOpts := opts
								slowOpts.LineWidth = 80
								slow := formatStatementSlow(statement, slowOpts)
								comparisons++
								if opts.Dialect == "" && opts.KeywordCase != ast.KeywordLower {
									switch statement.(type) {
									case *ast.SelectStatement, *ast.InsertStatement, *ast.UpdateStatement, *ast.DeleteStatement:
										fastEligible++
									}
								}
								if fast != slow {
									mismatches++
									if mismatches <= 12 {
										t.Logf("%s chunk=%d parseDialect=%s statement=%T options=%+v\nslow: %q\nfast: %q", file, chunkIndex, dialect, statement, opts, slow, fast)
									}
								}
							}
						}
					}
				}
				ast.ReleaseAST(tree)
			}
		}
	}
	t.Logf("files=%d realworld=%d corpus=%d parsed(file/chunk,dialect)=%d parse_skips=%d statements=%d comparisons=%d fast_eligible=%d mismatches=%d types=%v", len(files), groups["realworld"], groups["corpus"], parsed, skipped, statements, comparisons, fastEligible, mismatches, statementTypes)
	if statements == 0 {
		t.Fatal("no statements parsed from differential fixtures")
	}
	if fastEligible == 0 {
		t.Fatal("no comparison was eligible for the compact fast path; the differential is vacuous")
	}
	if mismatches != 0 {
		t.Fatalf("compact rendering differs from visitor output in %d/%d comparisons (first 12 logged)", mismatches, comparisons)
	}
}
