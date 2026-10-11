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

package gosqlx

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// qualifiedKeys renders qualified names as sorted "%q/%q/%q" keys for set comparison.
func qualifiedKeys(in []QualifiedName) []string {
	out := make([]string, 0, len(in))
	for _, q := range in {
		out = append(out, fmt.Sprintf("%q/%q/%q", q.Schema, q.Table, q.Name))
	}
	sort.Strings(out)
	return out
}

func hasDuplicates(in []string) bool {
	seen := make(map[string]struct{}, len(in))
	for _, s := range in {
		if _, dup := seen[s]; dup {
			return true
		}
		seen[s] = struct{}{}
	}
	return false
}

// assertMetadataMatchesExtractors checks ExtractMetadata against the individual
// extractors (as sets) and that no slice contains duplicates.
func assertMetadataMatchesExtractors(t *testing.T, tree *ast.AST) {
	t.Helper()

	md := ExtractMetadata(tree)
	if md == nil {
		t.Fatal("ExtractMetadata returned nil")
	}

	stringChecks := []struct {
		name      string
		got, want []string
	}{
		{"Tables", md.Tables, ExtractTables(tree)},
		{"Columns", md.Columns, ExtractColumns(tree)},
		{"Functions", md.Functions, ExtractFunctions(tree)},
	}
	for _, c := range stringChecks {
		if !stringSlicesEqual(c.got, c.want) {
			t.Errorf("%s mismatch: metadata=%v individual=%v", c.name, c.got, c.want)
		}
		if hasDuplicates(c.got) {
			t.Errorf("%s contains duplicates: %v", c.name, c.got)
		}
	}

	qualifiedChecks := []struct {
		name      string
		got, want []QualifiedName
	}{
		{"TablesQualified", md.TablesQualified, ExtractTablesQualified(tree)},
		{"ColumnsQualified", md.ColumnsQualified, ExtractColumnsQualified(tree)},
	}
	for _, c := range qualifiedChecks {
		gotKeys, wantKeys := qualifiedKeys(c.got), qualifiedKeys(c.want)
		if strings.Join(gotKeys, "|") != strings.Join(wantKeys, "|") {
			t.Errorf("%s mismatch: metadata=%v individual=%v", c.name, gotKeys, wantKeys)
		}
		if hasDuplicates(gotKeys) {
			t.Errorf("%s contains duplicates: %v", c.name, gotKeys)
		}
	}
}

func TestExtractMetadata_MatchesIndividualExtractors(t *testing.T) {
	inline := []string{
		`SELECT u.name, COUNT(o.id) as order_count, UPPER(u.email)
		 FROM users u LEFT JOIN orders o ON u.id = o.user_id
		 WHERE u.active = true GROUP BY u.name, u.email
		 HAVING COUNT(o.id) > 5 ORDER BY order_count DESC`,
		`INSERT INTO t (a, b) VALUES (UPPER(c), 1)`,
		`UPDATE t SET a = LOWER(b) WHERE t.id = 1`,
		`DELETE FROM t WHERE t.id = 1 AND LENGTH(x) > 1`,
		`SELECT * FROM public.users u JOIN db.public.orders o ON u.id = o.user_id`,
		`SELECT u.id, u.id, id FROM users u`,
		`WITH c AS (SELECT id FROM a) SELECT COUNT(*) FROM c UNION SELECT 1 FROM b`,
		`INSERT INTO t SELECT id, MAX(v) FROM s GROUP BY id`,
	}

	for _, sql := range inline {
		sql := sql
		t.Run(sql, func(t *testing.T) {
			tree, err := Parse(sql)
			if err != nil {
				t.Fatalf("Parse(%q) failed: %v", sql, err)
			}
			assertMetadataMatchesExtractors(t, tree)
		})
	}

	root := filepath.Join("..", "..", "testdata")
	if _, err := os.Stat(root); err != nil {
		t.Logf("testdata directory not available: %v", err)
		return
	}

	parsed := 0
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".sql") {
			return nil
		}
		content, err := os.ReadFile(path) // #nosec G304 -- repository testdata
		if err != nil {
			return err
		}
		for i, stmt := range SplitStatements(string(content), "") {
			tree, perr := Parse(stmt)
			if perr != nil {
				continue
			}
			parsed++
			t.Run(fmt.Sprintf("%s#%d", filepath.ToSlash(path), i), func(t *testing.T) {
				assertMetadataMatchesExtractors(t, tree)
			})
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walking testdata: %v", walkErr)
	}
	t.Logf("compared %d parsed testdata statements", parsed)
}

// The parser does not accept UPDATE ... FROM or DELETE ... USING, so build
// those trees by hand to cover the From/Using table paths.
func TestExtractMetadata_HandBuiltDML(t *testing.T) {
	where := &ast.BinaryExpression{
		Left:     &ast.Identifier{Table: "t", Name: "id"},
		Operator: "=",
		Right: &ast.FunctionCall{
			Name:      "LENGTH",
			Arguments: []ast.Expression{&ast.Identifier{Table: "s", Name: "x"}},
		},
	}
	update := &ast.UpdateStatement{
		TableName: "app.t",
		From:      []ast.TableReference{{Name: "s"}},
		Assignments: []ast.UpdateExpression{{
			Column: &ast.Identifier{Name: "a"},
			Value:  &ast.FunctionCall{Name: "LOWER", Arguments: []ast.Expression{&ast.Identifier{Name: "b"}}},
		}},
		Where: where,
	}
	del := &ast.DeleteStatement{
		TableName: "t",
		Using:     []ast.TableReference{{Name: "db.s.u"}},
		Where:     where,
	}
	tree := &ast.AST{Statements: []ast.Statement{update, del}}

	assertMetadataMatchesExtractors(t, tree)

	if got, want := ExtractTables(tree), []string{"app.t", "s", "t", "db.s.u"}; !stringSlicesEqual(got, want) {
		t.Errorf("ExtractTables = %v, want %v", got, want)
	}
	if got, want := ExtractFunctions(tree), []string{"LOWER", "LENGTH"}; !stringSlicesEqual(got, want) {
		t.Errorf("ExtractFunctions = %v, want %v", got, want)
	}
	if got, want := ExtractColumns(tree), []string{"a", "b", "id", "x"}; !stringSlicesEqual(got, want) {
		t.Errorf("ExtractColumns = %v, want %v", got, want)
	}
}

func TestParseQualifiedTableName(t *testing.T) {
	tests := []struct {
		in   string
		want QualifiedName
	}{
		{"users", QualifiedName{Name: "users"}},
		{"public.users", QualifiedName{Schema: "public", Name: "users"}},
		{"db.public.users", QualifiedName{Schema: "db", Table: "public", Name: "users"}},
		{"a.b.c.d", QualifiedName{Name: "a.b.c.d"}},
		{"a..b", QualifiedName{Schema: "a", Table: "", Name: "b"}},
		{".users", QualifiedName{Schema: "", Name: "users"}},
		{"users.", QualifiedName{Schema: "users", Name: ""}},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := parseQualifiedTableName(tt.in); got != tt.want {
				t.Errorf("parseQualifiedTableName(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestExtractTablesQualified_HandBuiltNames(t *testing.T) {
	tree := &ast.AST{Statements: []ast.Statement{
		&ast.InsertStatement{TableName: "users"},
		&ast.InsertStatement{TableName: "public.users"},
		&ast.InsertStatement{TableName: "db.public.users"},
		&ast.InsertStatement{TableName: "a.b.c.d"},
		&ast.InsertStatement{TableName: "a..b"},
		&ast.DeleteStatement{TableName: "public.users"}, // duplicate
	}}

	got := qualifiedKeys(ExtractTablesQualified(tree))
	want := qualifiedKeys([]QualifiedName{
		{Name: "users"},
		{Schema: "public", Name: "users"},
		{Schema: "db", Table: "public", Name: "users"},
		{Name: "a.b.c.d"},
		{Schema: "a", Table: "", Name: "b"},
	})
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("ExtractTablesQualified = %v, want %v", got, want)
	}

	tables := ExtractTables(tree)
	wantRaw := []string{"users", "public.users", "db.public.users", "a.b.c.d", "a..b"}
	if !stringSlicesEqual(tables, wantRaw) {
		t.Errorf("ExtractTables = %v, want %v", tables, wantRaw)
	}
}

func TestExtract_ModeGating(t *testing.T) {
	tests := []struct {
		name          string
		sql           string
		wantFunctions []string
		wantColumns   []string
	}{
		{
			name:          "insert values hold functions, columns hold names",
			sql:           `INSERT INTO t (a, b) VALUES (UPPER(c), 1)`,
			wantFunctions: []string{"UPPER"},
			wantColumns:   []string{"a", "b"},
		},
		{
			name:          "update value function, column and where identifiers",
			sql:           `UPDATE t SET a = LOWER(b) WHERE id = 1`,
			wantFunctions: []string{"LOWER"},
			wantColumns:   []string{"a", "b", "id"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree, err := Parse(tt.sql)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}
			if got := ExtractFunctions(tree); !stringSlicesEqual(got, tt.wantFunctions) {
				t.Errorf("ExtractFunctions = %v, want %v", got, tt.wantFunctions)
			}
			cols := ExtractColumns(tree)
			for _, want := range tt.wantColumns {
				if !contains(cols, want) {
					t.Errorf("ExtractColumns = %v, missing %q", cols, want)
				}
			}
			assertMetadataMatchesExtractors(t, tree)
		})
	}
}

func TestExtractColumnsQualified_Dedup(t *testing.T) {
	tree, err := Parse(`SELECT u.id, u.id, id FROM users u`)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	got := qualifiedKeys(ExtractColumnsQualified(tree))
	want := qualifiedKeys([]QualifiedName{{Table: "u", Name: "id"}, {Name: "id"}})
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("ExtractColumnsQualified = %v, want %v", got, want)
	}
	if cols := ExtractColumns(tree); len(cols) != 1 || cols[0] != "id" {
		t.Errorf("ExtractColumns = %v, want [id]", cols)
	}

	tree, err = Parse(`SELECT * FROM public.users u JOIN public.users v ON u.id = v.id`)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	if tq := ExtractTablesQualified(tree); len(tq) != 1 {
		t.Errorf("ExtractTablesQualified = %v, want exactly 1 entry", tq)
	}
}

func TestExtract_NilAndEmpty(t *testing.T) {
	if ExtractTables(nil) != nil || ExtractTablesQualified(nil) != nil ||
		ExtractColumns(nil) != nil || ExtractColumnsQualified(nil) != nil ||
		ExtractFunctions(nil) != nil {
		t.Error("Extract*(nil) must return nil")
	}

	md := ExtractMetadata(nil)
	if md == nil {
		t.Fatal("ExtractMetadata(nil) must return a non-nil Metadata")
	}
	if len(md.Tables)+len(md.TablesQualified)+len(md.Columns)+len(md.ColumnsQualified)+len(md.Functions) != 0 {
		t.Errorf("ExtractMetadata(nil) must be empty, got %+v", md)
	}

	empty := &ast.AST{Statements: []ast.Statement{}}
	if r := ExtractTables(empty); r == nil || len(r) != 0 {
		t.Errorf("ExtractTables(empty) = %#v, want non-nil empty", r)
	}
	if r := ExtractTablesQualified(empty); r == nil || len(r) != 0 {
		t.Errorf("ExtractTablesQualified(empty) = %#v, want non-nil empty", r)
	}
	if r := ExtractColumns(empty); r == nil || len(r) != 0 {
		t.Errorf("ExtractColumns(empty) = %#v, want non-nil empty", r)
	}
	if r := ExtractColumnsQualified(empty); r == nil || len(r) != 0 {
		t.Errorf("ExtractColumnsQualified(empty) = %#v, want non-nil empty", r)
	}
	if r := ExtractFunctions(empty); r == nil || len(r) != 0 {
		t.Errorf("ExtractFunctions(empty) = %#v, want non-nil empty", r)
	}
}

func TestExtractMetadata_ConcurrentSameAST(t *testing.T) {
	tree, err := Parse(`SELECT u.name, COUNT(o.id), UPPER(u.email)
		FROM public.users u JOIN orders o ON u.id = o.user_id
		WHERE u.active = true GROUP BY u.name, u.email`)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	serial := ExtractMetadata(tree)
	serialCols := qualifiedKeys(ExtractColumnsQualified(tree))

	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan string, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			md := ExtractMetadata(tree)
			if !stringSlicesEqual(md.Tables, serial.Tables) ||
				!stringSlicesEqual(md.Columns, serial.Columns) ||
				!stringSlicesEqual(md.Functions, serial.Functions) ||
				strings.Join(qualifiedKeys(md.TablesQualified), "|") != strings.Join(qualifiedKeys(serial.TablesQualified), "|") ||
				strings.Join(qualifiedKeys(md.ColumnsQualified), "|") != strings.Join(qualifiedKeys(serial.ColumnsQualified), "|") {
				errs <- "ExtractMetadata result differs from serial run"
			}
			if got := qualifiedKeys(ExtractColumnsQualified(tree)); strings.Join(got, "|") != strings.Join(serialCols, "|") {
				errs <- "ExtractColumnsQualified result differs from serial run"
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

func BenchmarkExtractMetadataLarge(b *testing.B) {
	path := filepath.Join("..", "..", "testdata", "real_world", "19_geo_location_radius_search.sql")
	content, err := os.ReadFile(path) // #nosec G304 -- repository testdata
	if err != nil {
		b.Skipf("cannot read %s: %v", path, err)
	}
	tree, err := Parse(string(content))
	if err != nil {
		b.Skipf("cannot parse %s: %v", path, err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractMetadata(tree)
	}
}
