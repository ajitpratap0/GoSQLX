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

// Package mysql provides a live schema Loader for MySQL databases.
// It queries information_schema to retrieve tables, columns, indexes,
// and foreign keys.
package mysql

import (
	"database/sql"
	"errors"
	"fmt"

	dbschema "github.com/ajitpratap0/GoSQLX/pkg/schema/db"
)

// Loader implements db.Loader for MySQL.
type Loader struct{}

// NewLoader returns a new MySQL schema loader.
func NewLoader() *Loader { return &Loader{} }

// Load returns the full schema for all user tables in the given schemaName.
//
// Load issues four statements (tables, columns, indexes, foreign keys) for the
// whole schema and drains each cursor before running the next, so it works
// with a single-connection pool.
func (l *Loader) Load(db *sql.DB, schemaName string) (*dbschema.DatabaseSchema, error) {
	names, err := l.listTables(db, schemaName)
	if err != nil {
		return nil, err
	}
	cols, err := l.loadColumns(db, schemaName, "")
	if err != nil {
		return nil, err
	}
	idxs, err := l.loadIndexes(db, schemaName, "")
	if err != nil {
		return nil, err
	}
	fks, err := l.loadForeignKeys(db, schemaName, "")
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
	cols, err := l.loadColumns(db, schemaName, tableName)
	if err != nil {
		return nil, err
	}
	idxs, err := l.loadIndexes(db, schemaName, tableName)
	if err != nil {
		return nil, err
	}
	fks, err := l.loadForeignKeys(db, schemaName, tableName)
	if err != nil {
		return nil, err
	}
	return &dbschema.Table{
		Schema:      schemaName,
		Name:        tableName,
		Columns:     forTable(cols, tableName),
		Indexes:     forTable(idxs, tableName),
		ForeignKeys: forTable(fks, tableName),
	}, nil
}

// forTable returns the entry for tableName from the result of a query filtered
// to that one table. MySQL may match table names case-insensitively (see
// lower_case_table_names), in which case the key is the stored spelling rather
// than tableName; since every row of a filtered query belongs to the same
// table, any single entry is the answer.
func forTable[T any](m map[string][]T, tableName string) []T {
	if v, ok := m[tableName]; ok {
		return v
	}
	for _, v := range m {
		return v
	}
	return nil
}

// listTables returns the base tables in schemaName, ordered by name.
func (l *Loader) listTables(db *sql.DB, schemaName string) ([]string, error) {
	rows, err := db.Query(`
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = ? AND table_type = 'BASE TABLE'
		ORDER BY table_name
	`, schemaName)
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

// loadColumns returns columns grouped by table name, in ordinal order.
// An empty tableName loads every table in schemaName.
func (l *Loader) loadColumns(db *sql.DB, schemaName, tableName string) (map[string][]dbschema.Column, error) {
	rows, err := db.Query(`
		SELECT
			c.table_name,
			c.column_name,
			c.ordinal_position,
			c.data_type,
			c.is_nullable,
			c.column_default,
			c.character_maximum_length,
			c.numeric_precision,
			c.numeric_scale,
			c.column_key
		FROM information_schema.columns c
		WHERE c.table_schema = ? AND (? = '' OR c.table_name = ?)
		ORDER BY c.table_name, c.ordinal_position
	`, schemaName, tableName, tableName)
	if err != nil {
		return nil, fmt.Errorf("load columns: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string][]dbschema.Column)
	for rows.Next() {
		var tbl string
		var col dbschema.Column
		var isNullable, columnKey string
		err := rows.Scan(
			&tbl,
			&col.Name, &col.OrdinalPos, &col.DataType, &isNullable,
			&col.DefaultValue, &col.MaxLength, &col.Precision, &col.Scale,
			&columnKey,
		)
		if err != nil {
			return nil, fmt.Errorf("load columns: scan: %w", err)
		}
		col.IsNullable = isNullable == "YES"
		col.IsPrimary = columnKey == "PRI"
		col.IsUnique = columnKey == "UNI"
		out[tbl] = append(out[tbl], col)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load columns: %w", err)
	}
	return out, nil
}

// loadIndexes returns indexes grouped by table name, ordered by index name,
// with columns in key order. An empty tableName loads every table in schemaName.
func (l *Loader) loadIndexes(db *sql.DB, schemaName, tableName string) (map[string][]dbschema.Index, error) {
	rows, err := db.Query(`
		SELECT table_name, index_name, non_unique, column_name
		FROM information_schema.statistics
		WHERE table_schema = ? AND (? = '' OR table_name = ?)
		ORDER BY table_name, index_name, seq_in_index
	`, schemaName, tableName, tableName)
	if err != nil {
		return nil, fmt.Errorf("load indexes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string][]dbschema.Index)
	for rows.Next() {
		var tbl, name, col string
		var nonUnique int
		if err := rows.Scan(&tbl, &name, &nonUnique, &col); err != nil {
			return nil, fmt.Errorf("load indexes: scan: %w", err)
		}
		// Rows are ordered by (table, index), so an index's rows are
		// contiguous and the last entry is the one to extend.
		idxs := out[tbl]
		if n := len(idxs); n > 0 && idxs[n-1].Name == name {
			idxs[n-1].Columns = append(idxs[n-1].Columns, col)
			continue
		}
		out[tbl] = append(idxs, dbschema.Index{
			Name:      name,
			TableName: tbl,
			Columns:   []string{col},
			IsUnique:  nonUnique == 0,
			IsPrimary: name == "PRIMARY",
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load indexes: %w", err)
	}
	return out, nil
}

// loadForeignKeys returns foreign keys grouped by table name, ordered by
// constraint name. An empty tableName loads every table in schemaName.
func (l *Loader) loadForeignKeys(db *sql.DB, schemaName, tableName string) (map[string][]dbschema.ForeignKey, error) {
	rows, err := db.Query(`
		SELECT
			kcu.table_name,
			kcu.constraint_name,
			kcu.column_name,
			kcu.referenced_table_name,
			kcu.referenced_column_name,
			rc.delete_rule,
			rc.update_rule
		FROM information_schema.key_column_usage kcu
		JOIN information_schema.referential_constraints rc
			ON rc.constraint_name = kcu.constraint_name
			AND rc.constraint_schema = kcu.table_schema
		WHERE kcu.table_schema = ? AND (? = '' OR kcu.table_name = ?)
		  AND kcu.referenced_table_name IS NOT NULL
		ORDER BY kcu.table_name, kcu.constraint_name, kcu.ordinal_position
	`, schemaName, tableName, tableName)
	if err != nil {
		return nil, fmt.Errorf("load fks: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string][]dbschema.ForeignKey)
	for rows.Next() {
		var tbl, name, col, refTable, refCol, onDelete, onUpdate string
		if err := rows.Scan(&tbl, &name, &col, &refTable, &refCol, &onDelete, &onUpdate); err != nil {
			return nil, fmt.Errorf("load fks: scan: %w", err)
		}
		// Rows are ordered by (table, constraint), so a constraint's rows are
		// contiguous and the last entry is the one to extend.
		fks := out[tbl]
		if n := len(fks); n > 0 && fks[n-1].Name == name {
			fks[n-1].Columns = append(fks[n-1].Columns, col)
			fks[n-1].RefColumns = append(fks[n-1].RefColumns, refCol)
			continue
		}
		out[tbl] = append(fks, dbschema.ForeignKey{
			Name:       name,
			TableName:  tbl,
			Columns:    []string{col},
			RefTable:   refTable,
			RefColumns: []string{refCol},
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
