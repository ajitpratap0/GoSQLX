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
	"testing"

	_ "modernc.org/sqlite"

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
