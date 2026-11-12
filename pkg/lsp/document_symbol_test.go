// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package lsp

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestDocumentSymbolExactRanges(t *testing.T) {
	cases := []struct {
		name, dialect, sql string
		ranges, selections []Range
	}{
		{"positionless", "", "SELECT a FROM t1;\nDROP TABLE t2;\nTRUNCATE TABLE t4;", []Range{{Position{0, 0}, Position{0, 17}}, {Position{1, 0}, Position{1, 14}}, {Position{2, 0}, Position{2, 18}}}, []Range{{Position{0, 0}, Position{0, 14}}, {Position{1, 0}, Position{1, 13}}, {Position{2, 0}, Position{2, 11}}}},
		{"same line unicode", "", "SELECT 'é' AS a FROM t1; DROP TABLE t2;", []Range{{Position{0, 0}, Position{0, 25}}, {Position{0, 26}, Position{0, 40}}}, []Range{{Position{0, 0}, Position{0, 14}}, {Position{0, 26}, Position{0, 39}}}},
		{"comments multiline", "", "-- lead\nSELECT a\nFROM t;\n-- gap\nDROP TABLE t", []Range{{Position{1, 0}, Position{2, 7}}, {Position{4, 0}, Position{4, 12}}}, []Range{{Position{1, 0}, Position{1, 8}}, {Position{4, 0}, Position{4, 12}}}},
		{"crlf trailing blanks", "", "DROP TABLE t;\r\n\r\n", []Range{{Position{0, 0}, Position{0, 13}}}, []Range{{Position{0, 0}, Position{0, 12}}}},
		{"ddl and dml", "", "CREATE TABLE t (id INT);\nINSERT INTO t VALUES (1);\nALTER TABLE t ADD c INT;\nUPDATE t SET c = 1;\nCREATE INDEX ix ON t (id);", []Range{{Position{0, 0}, Position{0, 24}}, {Position{1, 0}, Position{1, 25}}, {Position{2, 0}, Position{2, 24}}, {Position{3, 0}, Position{3, 19}}, {Position{4, 0}, Position{4, 26}}}, []Range{{Position{0, 0}, Position{0, 14}}, {Position{1, 0}, Position{1, 13}}, {Position{2, 0}, Position{2, 7}}, {Position{3, 0}, Position{3, 8}}, {Position{4, 0}, Position{4, 15}}}},
		{"empty document", "", "", nil, nil},
		{"empty", "", " \n\n", nil, nil},
		{"parse error", "", "SELECT FROM ;", nil, nil},
		{"go", "sqlserver", "DROP TABLE t;\nGO\nDROP TABLE u\nGO\n", []Range{{Position{0, 0}, Position{0, 13}}, {Position{2, 0}, Position{2, 12}}}, []Range{{Position{0, 0}, Position{0, 12}}, {Position{2, 0}, Position{2, 12}}}},
		{"oracle slash", "oracle", "SELECT 1 FROM dual;\n/\nDROP TABLE t;", []Range{{Position{0, 0}, Position{0, 19}}, {Position{2, 0}, Position{2, 13}}}, []Range{{Position{0, 0}, Position{0, 16}}, {Position{2, 0}, Position{2, 12}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _, _ := lspBenchHandler(t, tc.dialect, tc.sql)
			got, err := h.handleDocumentSymbol(mustMarshal(t, DocumentSymbolParams{TextDocument: TextDocumentIdentifier{URI: benchURI}}))
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.ranges) {
				t.Fatalf("got %d symbols, want %d: %+v", len(got), len(tc.ranges), got)
			}
			for i := range got {
				if got[i].Range != tc.ranges[i] || got[i].SelectionRange != tc.selections[i] {
					t.Errorf("symbol %d %q: range %+v selection %+v; want %+v %+v", i, got[i].Name, got[i].Range, got[i].SelectionRange, tc.ranges[i], tc.selections[i])
				}
			}
		})
	}
}

func TestDocumentSymbolSpanInvariant(t *testing.T) {
	dialects := append([]keywords.SQLDialect{""}, keywords.AllDialects()...)
	for _, d := range dialects {
		t.Run(string(d), func(t *testing.T) {
			sql := "SELECT 1; DROP TABLE t;"
			if d == keywords.DialectSQLServer {
				sql = "SELECT 1\nGO\nDROP TABLE t;"
			}
			if d == keywords.DialectOracle {
				sql = "SELECT 1 FROM dual;\n/\nDROP TABLE t;"
			}
			parsed, err := parseForDialect(sql, d)
			if err != nil {
				t.Fatal(err)
			}
			if len(parsed.Statements) != len(parsed.StatementStarts) || len(parsed.Statements) != len(parsed.StatementEnds) {
				t.Fatalf("statements %d starts %d ends %d", len(parsed.Statements), len(parsed.StatementStarts), len(parsed.StatementEnds))
			}
		})
	}
}

// tokenRanges uses parser first-token positions only as boundaries, and derives
// each end independently from the tokenizer. It never reads StatementEnds.
func tokenRanges(t *testing.T, sql string, dialect keywords.SQLDialect) ([]Range, error) {
	t.Helper()
	parsed, err := parseForDialect(sql, dialect)
	if err != nil {
		return nil, err
	}
	tk := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tk)
	if !usesDefaultPipeline(dialect) {
		tk.SetDialect(dialect)
	}
	toks, err := tk.TokenizeString(sql)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(sql, "\n")
	var out []Range
	ti := 0
	for i, stmt := range parsed.Statements {
		start := parsed.StatementStarts[i]
		for ti < len(toks) && toks[ti].Start != start {
			ti++
		}
		if ti == len(toks) {
			t.Fatalf("statement %d starts at %v, not a token", i, start)
		}
		begin := ti
		ti++
		if i+1 < len(parsed.Statements) {
			next := parsed.StatementStarts[i+1]
			for ti < len(toks) && toks[ti].Start != next && toks[ti].Token.Type != models.TokenTypeEOF {
				ti++
			}
		} else {
			for ti < len(toks) && toks[ti].Token.Type != models.TokenTypeEOF {
				ti++
			}
		}
		if _, ok := stmt.(*ast.BatchSeparator); ok {
			continue
		}
		end := ti - 1
		// SQL*Plus slash is a client directive, not part of the preceding SQL.
		for j := begin; j <= end; j++ {
			line := toks[j].Start.Line - 1
			if dialect == keywords.DialectOracle && line >= 0 && line < len(lines) && strings.TrimSpace(lines[line]) == "/" {
				end = j - 1
				break
			}
		}
		if end < begin {
			t.Fatalf("statement %d has no tokens", i)
		}
		out = append(out, Range{Position{start.Line - 1, start.Column - 1}, Position{toks[end].End.Line - 1, toks[end].End.Column - 1}})
	}
	return out, nil
}

func checkDocumentSymbolOracle(t *testing.T, sql string, d keywords.SQLDialect) {
	t.Helper()
	want, parseErr := tokenRanges(t, sql, d)
	h, _, _ := lspBenchHandler(t, string(d), sql)
	got, err := h.handleDocumentSymbol(mustMarshal(t, DocumentSymbolParams{TextDocument: TextDocumentIdentifier{URI: benchURI}}))
	if err != nil {
		t.Fatal(err)
	}
	if parseErr != nil {
		if len(got) != 0 {
			t.Fatalf("parse error %v: got %d symbols", parseErr, len(got))
		}
		return
	}
	if len(got) != len(want) {
		t.Fatalf("got %d symbols, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Range != want[i] {
			t.Errorf("symbol %d: got %+v want %+v", i, got[i].Range, want[i])
			if i > 10 {
				break
			}
		}
	}
}

func TestDocumentSymbolTokenOracleBenchCorpus(t *testing.T) {
	for _, d := range lspBenchDialects {
		for _, size := range lspBenchSizes {
			t.Run(d+"/"+size.name, func(t *testing.T) {
				checkDocumentSymbolOracle(t, lspBenchDoc(t, d, size.bytes), keywords.SQLDialect(d))
			})
		}
	}
}

// This mirrors the fixed document/dialect matrix in lsp_golden_test.go.
func TestDocumentSymbolTokenOracleGoldenCorpus(t *testing.T) {
	set, err := benchcorpus.Default()
	if err != nil {
		t.Fatal(err)
	}
	type doc struct {
		name, sql string
		dialects  []string
	}
	var docs []doc
	var generic []benchcorpus.Statement
	for _, c := range benchcorpus.Corpora {
		switch c.Kind {
		case benchcorpus.KindRealWorld:
			docs = append(docs, doc{"rw-" + c.Dialect, benchcorpus.Script(set.ByCorpus(c.Name), 30<<10).SQL, []string{c.Dialect, benchcorpus.GenericDialect}})
		case benchcorpus.KindGeneric:
			generic = append(generic, set.ByCorpus(c.Name)...)
		case benchcorpus.KindFeature:
			var b strings.Builder
			for _, st := range set.ByCorpus(c.Name) {
				b.WriteString(strings.TrimRight(st.SQL, " \t\r\n"))
				b.WriteString("\n;\n")
			}
			docs = append(docs, doc{strings.ReplaceAll(c.Name, "/", "-"), b.String(), []string{c.Dialect}})
		}
	}
	docs = append(docs, doc{"generic", benchcorpus.Script(generic, 30<<10).SQL, []string{"generic", "bigquery", "redshift"}})
	docs = append(docs, doc{"errors", "-- naïve “quotes” before errors\r\nSELECT * FROM 表 WHERE x = 'é' AND;\r\n" + "SELECT\tname, FROM users;\n" + "INSERT INTO t (a, b VALUES (1, 2);\n" + "UPDATE t SET a = WHERE id = 1;\n" + "SELECT 'ünïcödé' AS s, ) FROM dual;\n" + "CREATE TABLE x (id INT PRIMARY KEY, name VARCHAR(10)\n" + "WITH c AS (SELECT 1) SELECT * FROM c;\n", []string{"generic", "postgresql", "sqlserver"}})
	for _, doc := range docs {
		for _, d := range doc.dialects {
			t.Run(doc.name+"@"+d, func(t *testing.T) { checkDocumentSymbolOracle(t, doc.sql, keywords.SQLDialect(d)) })
		}
	}
}
