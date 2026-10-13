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

package schema

import (
	"runtime"
	"strings"
	"testing"
	"unsafe"
	"weak"
)

// AST values are substrings of the parsed SQL (#546). A loaded Schema or
// Catalog is long-lived, so it must not keep the DDL text alive.

const retentionDDL = `
CREATE TABLE users (
	id INT PRIMARY KEY,
	name VARCHAR(100) NOT NULL DEFAULT 'anon',
	email VARCHAR(255) UNIQUE,
	org_id INT REFERENCES orgs(id)
);
CREATE TABLE orders (
	id INT,
	user_id INT,
	code VARCHAR(10),
	CONSTRAINT pk_orders PRIMARY KEY (id),
	CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id),
	CONSTRAINT uq_code UNIQUE (code)
);
ALTER TABLE users ADD COLUMN nick VARCHAR(20);
ALTER TABLE users RENAME COLUMN email TO mail;
`

// largeDDL returns a freshly allocated copy of ddl padded to over 1 MiB,
// and a weak pointer to its backing array.
func largeDDL(ddl string) (string, weak.Pointer[byte]) {
	sql := "/* " + strings.Repeat("x", 1<<20) + " */" + ddl
	return sql, weak.Make(unsafe.StringData(sql))
}

func ddlCollected(wp weak.Pointer[byte]) bool {
	runtime.GC()
	runtime.GC()
	return wp.Value() == nil
}

func TestLoadFromDDL_DoesNotRetainInput(t *testing.T) {
	var kept *Schema
	wp := func() weak.Pointer[byte] {
		sql, wp := largeDDL(retentionDDL)
		s, err := LoadFromDDL(sql)
		if err != nil {
			t.Fatalf("LoadFromDDL: %v", err)
		}
		kept = s
		return wp
	}()
	if !ddlCollected(wp) {
		t.Error("Schema returned by LoadFromDDL keeps the 1 MiB DDL text alive")
	}
	// Sanity: the schema really holds what the DDL declared.
	users, ok := kept.GetTable("users")
	if !ok {
		t.Fatal("table users missing")
	}
	if _, ok := users.GetColumn("mail"); !ok {
		t.Error("renamed column mail missing")
	}
	if c, ok := users.GetColumn("name"); !ok || c.Default == "" {
		t.Errorf("column name default not loaded: %+v", c)
	}
	orders, ok := kept.GetTable("orders")
	if !ok || len(orders.ForeignKeys) != 1 || len(orders.Indexes) != 1 || len(orders.PrimaryKey) != 1 {
		t.Errorf("orders constraints not loaded: %+v", orders)
	}
	runtime.KeepAlive(kept)
}

func TestLoadCatalogFromDDL_DoesNotRetainInput(t *testing.T) {
	var kept *Catalog
	wp := func() weak.Pointer[byte] {
		// Schema-qualified CREATEs; the unqualified ALTERs then create
		// "users" on demand in the default schema.
		ddl := strings.ReplaceAll(retentionDDL, "CREATE TABLE ", "CREATE TABLE app.")
		sql, wp := largeDDL(ddl)
		c, err := LoadCatalogFromDDL(sql)
		if err != nil {
			t.Fatalf("LoadCatalogFromDDL: %v", err)
		}
		kept = c
		return wp
	}()
	if !ddlCollected(wp) {
		t.Error("Catalog returned by LoadCatalogFromDDL keeps the 1 MiB DDL text alive")
	}
	if _, _, err := kept.ResolveTable("orders"); err != nil {
		t.Errorf("ResolveTable(orders): %v", err)
	}
	runtime.KeepAlive(kept)
}
