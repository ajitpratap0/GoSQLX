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

package sqlite_test

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	dbschema "github.com/ajitpratap0/GoSQLX/pkg/schema/db"
	sqschema "github.com/ajitpratap0/GoSQLX/pkg/schema/sqlite"
)

func openSQLite(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.Exec(`
		CREATE TABLE items (
			id   INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			qty  INTEGER DEFAULT 0
		);
		CREATE TABLE tags (
			item_id INTEGER NOT NULL REFERENCES items(id),
			tag     TEXT NOT NULL
		);
		CREATE INDEX idx_tags_item ON tags(item_id);
	`)
	if err != nil {
		t.Fatalf("create tables: %v", err)
	}
	return db
}

func TestSQLiteLoader_Load(t *testing.T) {
	db := openSQLite(t)
	loader := sqschema.NewLoader()
	s, err := loader.Load(db, "main")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	names := make(map[string]bool)
	for _, tbl := range s.Tables {
		names[tbl.Name] = true
	}
	if !names["items"] || !names["tags"] {
		t.Errorf("missing tables: %v", names)
	}
}

func TestSQLiteLoader_LoadTable_Columns(t *testing.T) {
	db := openSQLite(t)
	loader := sqschema.NewLoader()
	tbl, err := loader.LoadTable(db, "main", "items")
	if err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	if len(tbl.Columns) != 3 {
		t.Errorf("columns: got %d want 3", len(tbl.Columns))
	}
	var found bool
	for i := range tbl.Columns {
		if tbl.Columns[i].Name == "id" {
			if !tbl.Columns[i].IsPrimary {
				t.Error("expected id to be primary key")
			}
			found = true
		}
	}
	if !found {
		t.Error("id column not found")
	}
}

func TestSQLiteLoader_LoadTable_Indexes(t *testing.T) {
	db := openSQLite(t)
	loader := sqschema.NewLoader()
	tbl, err := loader.LoadTable(db, "main", "tags")
	if err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	if len(tbl.Indexes) == 0 {
		t.Error("expected at least one index on tags")
	}
	var found bool
	for _, idx := range tbl.Indexes {
		if idx.Name == "idx_tags_item" {
			found = true
		}
	}
	if !found {
		t.Error("idx_tags_item index not found")
	}
}

func TestSQLiteLoader_LoadTable_ForeignKeys(t *testing.T) {
	db := openSQLite(t)
	loader := sqschema.NewLoader()
	tbl, err := loader.LoadTable(db, "main", "tags")
	if err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	if len(tbl.ForeignKeys) != 1 {
		t.Fatalf("foreign keys: got %d want 1", len(tbl.ForeignKeys))
	}
	if tbl.ForeignKeys[0].RefTable != "items" {
		t.Errorf("fk ref table: got %q want items", tbl.ForeignKeys[0].RefTable)
	}
}

// richSchemaDDL creates a fixture with multiple indexes per table, multi-column
// indexes, and single and composite foreign keys.
const richSchemaDDL = `
	CREATE TABLE items (
		id   INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		qty  INTEGER DEFAULT 0
	);
	CREATE TABLE cats (
		id    INTEGER PRIMARY KEY,
		label TEXT
	);
	CREATE TABLE tags (
		item_id INTEGER NOT NULL REFERENCES items(id),
		cat_id  INTEGER REFERENCES cats(id) ON DELETE CASCADE,
		tag     TEXT NOT NULL,
		UNIQUE(item_id, tag)
	);
	CREATE INDEX idx_tags_item ON tags(item_id);
	CREATE INDEX idx_tags_cat_tag ON tags(cat_id, tag);
	CREATE TABLE pairs (
		a INTEGER,
		b TEXT,
		FOREIGN KEY(a, b) REFERENCES tags(item_id, tag)
	);
`

// openSQLiteRich opens dsn and creates the rich fixture on it.
func openSQLiteRich(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(richSchemaDDL); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	return db
}

func findTable(s *dbschema.DatabaseSchema, name string) *dbschema.Table {
	for i := range s.Tables {
		if s.Tables[i].Name == name {
			return &s.Tables[i]
		}
	}
	return nil
}

func findIndex(tbl *dbschema.Table, name string) *dbschema.Index {
	for i := range tbl.Indexes {
		if tbl.Indexes[i].Name == name {
			return &tbl.Indexes[i]
		}
	}
	return nil
}

// assertRichDetail checks that the rich fixture was loaded with full column,
// index and foreign-key detail.
func assertRichDetail(t *testing.T, s *dbschema.DatabaseSchema) {
	t.Helper()
	tests := []struct {
		name                      string
		wantCols, wantIdx, wantFK int
	}{
		{"cats", 2, 0, 0},
		{"items", 3, 0, 0},
		{"pairs", 2, 0, 1},
		{"tags", 3, 3, 2},
	}
	if len(s.Tables) != len(tests) {
		t.Errorf("tables: got %d want %d", len(s.Tables), len(tests))
	}
	for _, tc := range tests {
		tbl := findTable(s, tc.name)
		if tbl == nil {
			t.Errorf("table %q not found", tc.name)
			continue
		}
		if len(tbl.Columns) != tc.wantCols {
			t.Errorf("%s columns: got %d want %d", tc.name, len(tbl.Columns), tc.wantCols)
		}
		if len(tbl.Indexes) != tc.wantIdx {
			t.Errorf("%s indexes: got %d want %d", tc.name, len(tbl.Indexes), tc.wantIdx)
		}
		if len(tbl.ForeignKeys) != tc.wantFK {
			t.Errorf("%s foreign keys: got %d want %d", tc.name, len(tbl.ForeignKeys), tc.wantFK)
		}
	}

	tags := findTable(s, "tags")
	if tags == nil {
		return
	}
	assertTagsDetail(t, tags)

	pairs := findTable(s, "pairs")
	if pairs != nil && len(pairs.ForeignKeys) == 1 {
		fk := pairs.ForeignKeys[0]
		if fk.RefTable != "tags" ||
			!reflect.DeepEqual(fk.Columns, []string{"a", "b"}) ||
			!reflect.DeepEqual(fk.RefColumns, []string{"item_id", "tag"}) {
			t.Errorf("pairs composite fk: got %+v", fk)
		}
	}
}

// assertTagsDetail checks the indexes and foreign keys of the tags table.
func assertTagsDetail(t *testing.T, tags *dbschema.Table) {
	t.Helper()
	wantIdx := []struct {
		name   string
		cols   []string
		unique bool
	}{
		{"idx_tags_cat_tag", []string{"cat_id", "tag"}, false},
		{"idx_tags_item", []string{"item_id"}, false},
		{"sqlite_autoindex_tags_1", []string{"item_id", "tag"}, true},
	}
	for _, w := range wantIdx {
		idx := findIndex(tags, w.name)
		if idx == nil {
			t.Errorf("index %q not found", w.name)
			continue
		}
		if !reflect.DeepEqual(idx.Columns, w.cols) {
			t.Errorf("index %q columns: got %v want %v", w.name, idx.Columns, w.cols)
		}
		if idx.IsUnique != w.unique {
			t.Errorf("index %q unique: got %v want %v", w.name, idx.IsUnique, w.unique)
		}
		if idx.TableName != "tags" {
			t.Errorf("index %q table: got %q want tags", w.name, idx.TableName)
		}
	}

	if len(tags.ForeignKeys) != 2 {
		return
	}
	fk0, fk1 := tags.ForeignKeys[0], tags.ForeignKeys[1]
	if fk0.Name != "fk_tags_0" || fk0.RefTable != "cats" || fk0.OnDelete != "CASCADE" ||
		!reflect.DeepEqual(fk0.Columns, []string{"cat_id"}) ||
		!reflect.DeepEqual(fk0.RefColumns, []string{"id"}) {
		t.Errorf("tags fk[0]: got %+v", fk0)
	}
	if fk1.Name != "fk_tags_1" || fk1.RefTable != "items" ||
		!reflect.DeepEqual(fk1.Columns, []string{"item_id"}) ||
		!reflect.DeepEqual(fk1.RefColumns, []string{"id"}) {
		t.Errorf("tags fk[1]: got %+v", fk1)
	}
}

// loadWithTimeout runs Load in a goroutine and fails the test if it does not
// return within d (a deadlock on a single-connection pool).
func loadWithTimeout(t *testing.T, db *sql.DB, d time.Duration) *dbschema.DatabaseSchema {
	t.Helper()
	type result struct {
		s   *dbschema.DatabaseSchema
		err error
	}
	done := make(chan result, 1)
	go func() {
		s, err := sqschema.NewLoader().Load(db, "main")
		done <- result{s, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Load: %v", r.err)
		}
		return r.s
	case <-time.After(d):
		t.Fatal("Load deadlocked with MaxOpenConns=1")
	}
	return nil
}

// TestSQLiteLoader_Load_InMemoryFullDetail guards against nested queries
// landing on a second pooled connection, which for ":memory:" is a different,
// empty database.
func TestSQLiteLoader_Load_InMemoryFullDetail(t *testing.T) {
	db := openSQLiteRich(t, ":memory:")
	s, err := sqschema.NewLoader().Load(db, "main")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	assertRichDetail(t, s)
}

func TestSQLiteLoader_Load_MaxOpenConns1(t *testing.T) {
	db := openSQLiteRich(t, filepath.Join(t.TempDir(), "rich.db"))
	db.SetMaxOpenConns(1)
	s := loadWithTimeout(t, db, 10*time.Second)
	assertRichDetail(t, s)
}

func TestSQLiteLoader_LoadTable_MaxOpenConns1(t *testing.T) {
	db := openSQLiteRich(t, filepath.Join(t.TempDir(), "rich.db"))
	db.SetMaxOpenConns(1)
	type result struct {
		tbl *dbschema.Table
		err error
	}
	done := make(chan result, 1)
	go func() {
		tbl, err := sqschema.NewLoader().LoadTable(db, "main", "tags")
		done <- result{tbl, err}
	}()
	var r result
	select {
	case r = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("LoadTable deadlocked with MaxOpenConns=1")
	}
	if r.err != nil {
		t.Fatalf("LoadTable: %v", r.err)
	}
	if len(r.tbl.Indexes) != 3 {
		t.Fatalf("indexes: got %d want 3", len(r.tbl.Indexes))
	}
	for _, idx := range r.tbl.Indexes {
		if len(idx.Columns) == 0 {
			t.Errorf("index %q has no columns", idx.Name)
		}
	}
	assertTagsDetail(t, r.tbl)
}

func TestSQLiteLoader_LoadMatchesLoadTable(t *testing.T) {
	db := openSQLiteRich(t, filepath.Join(t.TempDir(), "rich.db"))
	loader := sqschema.NewLoader()
	s, err := loader.Load(db, "main")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(s.Tables) == 0 {
		t.Fatal("Load returned no tables")
	}
	for i := range s.Tables {
		want := s.Tables[i]
		got, err := loader.LoadTable(db, "main", want.Name)
		if err != nil {
			t.Fatalf("LoadTable(%q): %v", want.Name, err)
		}
		if !reflect.DeepEqual(*got, want) {
			t.Errorf("LoadTable(%q) differs from Load:\n got: %+v\nwant: %+v", want.Name, *got, want)
		}
	}
}

func TestSQLiteLoader_IndexColumns_Multiple(t *testing.T) {
	db := openSQLiteRich(t, ":memory:")
	tbl, err := sqschema.NewLoader().LoadTable(db, "main", "tags")
	if err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	if len(tbl.Indexes) != 3 {
		t.Fatalf("indexes: got %d want 3 (%+v)", len(tbl.Indexes), tbl.Indexes)
	}
	assertTagsDetail(t, tbl)
}

func TestSQLiteLoader_ForeignKeys_Composite(t *testing.T) {
	db := openSQLiteRich(t, ":memory:")
	loader := sqschema.NewLoader()

	pairs, err := loader.LoadTable(db, "main", "pairs")
	if err != nil {
		t.Fatalf("LoadTable(pairs): %v", err)
	}
	if len(pairs.ForeignKeys) != 1 {
		t.Fatalf("pairs foreign keys: got %d want 1", len(pairs.ForeignKeys))
	}
	fk := pairs.ForeignKeys[0]
	if fk.Name != "fk_pairs_0" || fk.TableName != "pairs" || fk.RefTable != "tags" {
		t.Errorf("pairs fk: got %+v", fk)
	}
	if !reflect.DeepEqual(fk.Columns, []string{"a", "b"}) {
		t.Errorf("pairs fk columns: got %v want [a b]", fk.Columns)
	}
	if !reflect.DeepEqual(fk.RefColumns, []string{"item_id", "tag"}) {
		t.Errorf("pairs fk ref columns: got %v want [item_id tag]", fk.RefColumns)
	}

	tags, err := loader.LoadTable(db, "main", "tags")
	if err != nil {
		t.Fatalf("LoadTable(tags): %v", err)
	}
	if len(tags.ForeignKeys) != 2 {
		t.Fatalf("tags foreign keys: got %d want 2", len(tags.ForeignKeys))
	}
	assertTagsDetail(t, tags)
}

func TestSQLiteLoader_QuotedTableName(t *testing.T) {
	db := openSQLiteRich(t, ":memory:")
	if _, err := db.Exec(`CREATE TABLE "we""ird" (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	loader := sqschema.NewLoader()
	const name = `we"ird`

	tbl, err := loader.LoadTable(db, "main", name)
	if err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	if len(tbl.Columns) != 1 || tbl.Columns[0].Name != "id" || !tbl.Columns[0].IsPrimary {
		t.Errorf("LoadTable columns: got %+v", tbl.Columns)
	}

	s, err := loader.Load(db, "main")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	fromLoad := findTable(s, name)
	if fromLoad == nil {
		t.Fatalf("table %q missing from Load", name)
	}
	if len(fromLoad.Columns) != 1 {
		t.Errorf("Load columns: got %d want 1", len(fromLoad.Columns))
	}
}

func TestSQLiteLoader_LoadTable_Missing(t *testing.T) {
	db := openSQLiteRich(t, ":memory:")
	tbl, err := sqschema.NewLoader().LoadTable(db, "main", "no_such_table")
	if err != nil {
		t.Fatalf("LoadTable: %v", err)
	}
	if tbl.Name != "no_such_table" || tbl.Schema != "main" {
		t.Errorf("table identity: got %q.%q", tbl.Schema, tbl.Name)
	}
	if len(tbl.Columns) != 0 || len(tbl.Indexes) != 0 || len(tbl.ForeignKeys) != 0 {
		t.Errorf("expected no columns, indexes or foreign keys, got %+v", tbl)
	}
}

func BenchmarkSQLiteLoader_Load(b *testing.B) {
	for _, n := range []int{10, 100} {
		b.Run(fmt.Sprintf("tables=%d", n), func(b *testing.B) {
			db, err := sql.Open("sqlite", filepath.Join(b.TempDir(), "bench.db"))
			if err != nil {
				b.Fatalf("open sqlite: %v", err)
			}
			defer func() { _ = db.Close() }()

			var ddl strings.Builder
			ddl.WriteString("CREATE TABLE parent (id INTEGER PRIMARY KEY, name TEXT);\n")
			for i := 0; i < n; i++ {
				fmt.Fprintf(&ddl,
					"CREATE TABLE t%03d (id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parent(id), val TEXT NOT NULL, qty INTEGER DEFAULT 0);\n"+
						"CREATE INDEX idx_t%03d_parent ON t%03d(parent_id);\n", i, i, i)
			}
			if _, err := db.Exec(ddl.String()); err != nil {
				b.Fatalf("create tables: %v", err)
			}

			loader := sqschema.NewLoader()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				s, err := loader.Load(db, "main")
				if err != nil {
					b.Fatalf("Load: %v", err)
				}
				if len(s.Tables) != n+1 {
					b.Fatalf("tables: got %d want %d", len(s.Tables), n+1)
				}
			}
		})
	}
}
