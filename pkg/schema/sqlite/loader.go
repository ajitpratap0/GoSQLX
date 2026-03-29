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
// It uses PRAGMA commands (table_info, index_list, index_info, foreign_key_list)
// to retrieve tables, columns, indexes, and foreign keys. No CGO is required
// when using modernc.org/sqlite.
package sqlite

import (
	"database/sql"
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
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	defer func() { _ = rows.Close() }()

	ds := &dbschema.DatabaseSchema{Name: schemaName}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		tbl, err := l.LoadTable(db, schemaName, name)
		if err != nil {
			return nil, err
		}
		ds.Tables = append(ds.Tables, *tbl)
	}
	return ds, rows.Err()
}

// LoadTable returns schema for a single named table.
func (l *Loader) LoadTable(db *sql.DB, schemaName, tableName string) (*dbschema.Table, error) {
	tbl := &dbschema.Table{Schema: schemaName, Name: tableName}
	var err error
	tbl.Columns, err = l.loadColumns(db, tableName)
	if err != nil {
		return nil, err
	}
	tbl.Indexes, err = l.loadIndexes(db, tableName)
	if err != nil {
		return nil, err
	}
	tbl.ForeignKeys, err = l.loadForeignKeys(db, tableName)
	if err != nil {
		return nil, err
	}
	return tbl, nil
}

func (l *Loader) loadColumns(db *sql.DB, tableName string) ([]dbschema.Column, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA table_info(%q)", tableName))
	if err != nil {
		return nil, fmt.Errorf("pragma table_info: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var cols []dbschema.Column
	for rows.Next() {
		// cid, name, type, notnull, dflt_value, pk
		var cid, notNull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			return nil, err
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
		cols = append(cols, col)
	}
	return cols, rows.Err()
}

func (l *Loader) loadIndexes(db *sql.DB, tableName string) ([]dbschema.Index, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA index_list(%q)", tableName))
	if err != nil {
		return nil, fmt.Errorf("pragma index_list: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var indexes []dbschema.Index
	for rows.Next() {
		// seq, name, unique, origin, partial
		var seq, unique, partial int
		var name, origin string
		if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			return nil, err
		}
		idx := dbschema.Index{
			Name:      name,
			TableName: tableName,
			IsUnique:  unique == 1,
		}
		// get columns in this index
		icols, err := db.Query(fmt.Sprintf("PRAGMA index_info(%q)", name))
		if err != nil {
			return nil, err
		}
		for icols.Next() {
			var seqno, cid int
			var colName string
			if err := icols.Scan(&seqno, &cid, &colName); err != nil {
				_ = icols.Close()
				return nil, err
			}
			idx.Columns = append(idx.Columns, colName)
		}
		_ = icols.Close()
		if err := icols.Err(); err != nil {
			return nil, err
		}
		indexes = append(indexes, idx)
	}
	return indexes, rows.Err()
}

func (l *Loader) loadForeignKeys(db *sql.DB, tableName string) ([]dbschema.ForeignKey, error) {
	rows, err := db.Query(fmt.Sprintf("PRAGMA foreign_key_list(%q)", tableName))
	if err != nil {
		return nil, fmt.Errorf("pragma foreign_key_list: %w", err)
	}
	defer func() { _ = rows.Close() }()

	fkMap := make(map[int]*dbschema.ForeignKey)
	var order []int
	for rows.Next() {
		// id, seq, table, from, to, on_update, on_delete, match
		var id, seq int
		var refTable, fromCol, toCol, onUpdate, onDelete, match string
		if err := rows.Scan(&id, &seq, &refTable, &fromCol, &toCol, &onUpdate, &onDelete, &match); err != nil {
			return nil, err
		}
		if _, ok := fkMap[id]; !ok {
			fkMap[id] = &dbschema.ForeignKey{
				Name:      fmt.Sprintf("fk_%s_%d", strings.ToLower(tableName), id),
				TableName: tableName,
				RefTable:  refTable,
				OnDelete:  onDelete,
				OnUpdate:  onUpdate,
			}
			order = append(order, id)
		}
		fkMap[id].Columns = append(fkMap[id].Columns, fromCol)
		fkMap[id].RefColumns = append(fkMap[id].RefColumns, toCol)
	}
	fks := make([]dbschema.ForeignKey, 0, len(order))
	for _, id := range order {
		fks = append(fks, *fkMap[id])
	}
	return fks, rows.Err()
}

// ensure Loader satisfies the interface (compile-time check).
var _ dbschema.Loader = (*Loader)(nil)
