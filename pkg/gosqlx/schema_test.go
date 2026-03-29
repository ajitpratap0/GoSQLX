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

package gosqlx_test

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	sqschema "github.com/ajitpratap0/GoSQLX/pkg/schema/sqlite"
)

func TestGoSQLX_LoadSchema(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _ = db.Exec("CREATE TABLE t1 (id INTEGER PRIMARY KEY, val TEXT)")

	loader := sqschema.NewLoader()
	s, err := gosqlx.LoadSchema(db, loader, "main")
	if err != nil {
		t.Fatalf("LoadSchema: %v", err)
	}
	if len(s.Tables) == 0 {
		t.Error("expected at least one table")
	}
	var found bool
	for _, tbl := range s.Tables {
		if tbl.Name == "t1" {
			found = true
		}
	}
	if !found {
		t.Error("expected t1 table in schema")
	}
}
