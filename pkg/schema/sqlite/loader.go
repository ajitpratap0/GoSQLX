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

// Package sqlite provides a live schema Loader for SQLite databases.
// It uses the pragma_table_info, pragma_index_list, pragma_index_info and
// pragma_foreign_key_list table-valued functions to retrieve tables, columns,
// indexes, and foreign keys with bound parameters. Load issues one query per
// kind for the whole database, and every cursor is drained and closed before
// the next statement runs, so a single connection is sufficient. No CGO is
// required when using modernc.org/sqlite.
package sqlite

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	dbschema "github.com/ajitpratap0/GoSQLX/pkg/schema/db"
)

// Loader implements db.Loader for SQLite.
type Loader struct{}

// NewLoader returns a new SQLite schema loader.
func NewLoader() *Loader { return &Loader{} }

// Load returns the full schema for all user tables.
// schemaName is recorded in the returned DatabaseSchema but otherwise unused
// (SQLite does not have named schemas in the PostgreSQL sense; use "main").
func (l *Loader) Load(db *sql.DB, schemaName string) (*dbschema.DatabaseSchema, error) {
	names, err := l.listTables(db)
	if err != nil {
		return nil, err
	}
	cols, err := l.loadColumns(db, "")
	if err != nil {
		return nil, err
	}
	idxs, err := l.loadIndexes(db, "")
	if err != nil {
		return nil, err
	}
	fks, err := l.loadForeignKeys(db, "")
	if err != nil {
		return nil, err
	}

	ds := &dbschema.DatabaseSchema{Name: schemaName}
	if len(names) > 0 {
		ds.Tables = make([]dbschema.Table, 0, len(names))
	}
	for _, n := range names {
		ds.Tables = append(ds.Tables, dbschema.Table{
			Schema:      schemaName,
			Name:        n,
			Columns:     cols[n],
			Indexes:     idxs[n],
			ForeignKeys: fks[n],
		})
	}
	return ds, nil
}

// LoadTable returns schema for a single named table.
func (l *Loader) LoadTable(db *sql.DB, schemaName, tableName string) (*dbschema.Table, error) {
	if tableName == "" {
		return nil, errors.New("load table: table name must not be empty")
	}
	cols, err := l.loadColumns(db, tableName)
	if err != nil {
		return nil, err
	}
	idxs, err := l.loadIndexes(db, tableName)
	if err != nil {
		return nil, err
	}
	fks, err := l.loadForeignKeys(db, tableName)
	if err != nil {
		return nil, err
	}
	return &dbschema.Table{
		Schema:      schemaName,
		Name:        tableName,
		Columns:     cols[tableName],
		Indexes:     idxs[tableName],
		ForeignKeys: fks[tableName],
	}, nil
}

// listTables returns the names of all user tables, ordered by name.
func (l *Loader) listTables(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("list tables: scan: %w", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	return names, nil
}

// tableSource returns the FROM-clause source of table names for the pragma
// table-valued functions: the single table tableName (as a bound parameter),
// or every user table when tableName is empty. The returned SQL is constant.
func tableSource(tableName string) (string, []any) {
	if tableName != "" {
		return `(SELECT ? AS name)`, []any{tableName}
	}
	return `(SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%')`, nil
}

// loadColumns returns columns grouped by table name, in ordinal order.
// An empty tableName loads every user table.
func (l *Loader) loadColumns(db *sql.DB, tableName string) (map[string][]dbschema.Column, error) {
	src, args := tableSource(tableName)
	rows, err := db.Query(`
		SELECT m.name, p.cid, p.name, p.type, p."notnull", p.dflt_value, p.pk
		FROM `+src+` m
		JOIN pragma_table_info(m.name) p
		ORDER BY m.name, p.cid`, args...)
	if err != nil {
		return nil, fmt.Errorf("load columns: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string][]dbschema.Column)
	for rows.Next() {
		var tbl, name, typ string
		var cid, notNull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&tbl, &cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return nil, fmt.Errorf("load columns: scan: %w", err)
		}
		col := dbschema.Column{
			Name:       name,
			OrdinalPos: cid + 1,
			DataType:   typ,
			IsNullable: notNull == 0,
			IsPrimary:  pk > 0,
		}
		if dflt.Valid {
			col.DefaultValue = &dflt.String
		}
		out[tbl] = append(out[tbl], col)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load columns: %w", err)
	}
	return out, nil
}

// loadIndexes returns indexes grouped by table name, in index_list order, with
// each index's columns in key order. An empty tableName loads every user table.
func (l *Loader) loadIndexes(db *sql.DB, tableName string) (map[string][]dbschema.Index, error) {
	src, args := tableSource(tableName)
	rows, err := db.Query(`
		SELECT m.name, il.name, il."unique", ii.name -- NULL for expression columns
		FROM `+src+` m
		JOIN pragma_index_list(m.name) il
		JOIN pragma_index_info(il.name) ii
		ORDER BY m.name, il.seq, ii.seqno`, args...)
	if err != nil {
		return nil, fmt.Errorf("load indexes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string][]dbschema.Index)
	for rows.Next() {
		var tbl, name string
		var colName sql.NullString
		var unique int
		if err := rows.Scan(&tbl, &name, &unique, &colName); err != nil {
			return nil, fmt.Errorf("load indexes: scan: %w", err)
		}
		idxs := out[tbl]
		if n := len(idxs); n == 0 || idxs[n-1].Name != name {
			out[tbl] = append(idxs, dbschema.Index{
				Name:      name,
				TableName: tbl,
				IsUnique:  unique == 1,
			})
			idxs = out[tbl]
		}
		// Expression index columns (e.g. lower(x)) have a NULL name; they
		// cannot be represented as a column name, so they are skipped.
		if colName.Valid {
			last := &idxs[len(idxs)-1]
			last.Columns = append(last.Columns, colName.String)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load indexes: %w", err)
	}
	return out, nil
}

// loadForeignKeys returns foreign keys grouped by table name, in id order,
// with columns in sequence order. An empty tableName loads every user table.
func (l *Loader) loadForeignKeys(db *sql.DB, tableName string) (map[string][]dbschema.ForeignKey, error) {
	src, args := tableSource(tableName)
	rows, err := db.Query(`
		SELECT m.name, f.id, f."table", f."from",
			COALESCE(f."to", (SELECT p.name FROM pragma_table_info(f."table") p WHERE p.pk = f.seq + 1)),
			f.on_update, f.on_delete
		FROM `+src+` m
		JOIN pragma_foreign_key_list(m.name) f
		ORDER BY m.name, f.id, f.seq`, args...)
	if err != nil {
		return nil, fmt.Errorf("load fks: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string][]dbschema.ForeignKey)
	lastTable, lastID := "", -1
	for rows.Next() {
		var tbl, refTable, fromCol, onUpdate, onDelete string
		var toNull sql.NullString
		var id int
		if err := rows.Scan(&tbl, &id, &refTable, &fromCol, &toNull, &onUpdate, &onDelete); err != nil {
			return nil, fmt.Errorf("load fks: scan: %w", err)
		}
		// "to" is NULL when REFERENCES omits the column list; the COALESCE
		// above resolves it to the parent's primary key column at the same
		// position. It stays empty only if the parent or its PK is missing.
		toCol := toNull.String
		fks := out[tbl]
		if n := len(fks); n > 0 && tbl == lastTable && id == lastID {
			fks[n-1].Columns = append(fks[n-1].Columns, fromCol)
			fks[n-1].RefColumns = append(fks[n-1].RefColumns, toCol)
			continue
		}
		lastTable, lastID = tbl, id
		out[tbl] = append(fks, dbschema.ForeignKey{
			Name:       fmt.Sprintf("fk_%s_%d", strings.ToLower(tbl), id),
			TableName:  tbl,
			Columns:    []string{fromCol},
			RefTable:   refTable,
			RefColumns: []string{toCol},
			OnDelete:   onDelete,
			OnUpdate:   onUpdate,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load fks: %w", err)
	}
	return out, nil
}

// ensure Loader satisfies the interface (compile-time check).
var _ dbschema.Loader = (*Loader)(nil)
