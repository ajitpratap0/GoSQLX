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
	"fmt"

	dbschema "github.com/ajitpratap0/GoSQLX/pkg/schema/db"
)

// Loader implements db.Loader for MySQL.
type Loader struct{}

// NewLoader returns a new MySQL schema loader.
func NewLoader() *Loader { return &Loader{} }

// Load returns the full schema for all user tables in the given schemaName.
func (l *Loader) Load(db *sql.DB, schemaName string) (*dbschema.DatabaseSchema, error) {
	rows, err := db.Query(`
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = ? AND table_type = 'BASE TABLE'
		ORDER BY table_name
	`, schemaName)
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}
	defer rows.Close()

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
	tbl.Columns, err = l.loadColumns(db, schemaName, tableName)
	if err != nil {
		return nil, err
	}
	tbl.Indexes, err = l.loadIndexes(db, schemaName, tableName)
	if err != nil {
		return nil, err
	}
	tbl.ForeignKeys, err = l.loadForeignKeys(db, schemaName, tableName)
	if err != nil {
		return nil, err
	}
	return tbl, nil
}

func (l *Loader) loadColumns(db *sql.DB, schemaName, tableName string) ([]dbschema.Column, error) {
	rows, err := db.Query(`
		SELECT
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
		WHERE c.table_schema = ? AND c.table_name = ?
		ORDER BY c.ordinal_position
	`, schemaName, tableName)
	if err != nil {
		return nil, fmt.Errorf("load columns: %w", err)
	}
	defer rows.Close()

	var cols []dbschema.Column
	for rows.Next() {
		var col dbschema.Column
		var isNullable, columnKey string
		err := rows.Scan(
			&col.Name, &col.OrdinalPos, &col.DataType, &isNullable,
			&col.DefaultValue, &col.MaxLength, &col.Precision, &col.Scale,
			&columnKey,
		)
		if err != nil {
			return nil, err
		}
		col.IsNullable = isNullable == "YES"
		col.IsPrimary = columnKey == "PRI"
		col.IsUnique = columnKey == "UNI"
		cols = append(cols, col)
	}
	return cols, rows.Err()
}

func (l *Loader) loadIndexes(db *sql.DB, schemaName, tableName string) ([]dbschema.Index, error) {
	rows, err := db.Query(`
		SELECT index_name, non_unique, column_name
		FROM information_schema.statistics
		WHERE table_schema = ? AND table_name = ?
		ORDER BY index_name, seq_in_index
	`, schemaName, tableName)
	if err != nil {
		return nil, fmt.Errorf("load indexes: %w", err)
	}
	defer rows.Close()

	idxMap := make(map[string]*dbschema.Index)
	var order []string
	for rows.Next() {
		var name, col string
		var nonUnique int
		if err := rows.Scan(&name, &nonUnique, &col); err != nil {
			return nil, err
		}
		if _, ok := idxMap[name]; !ok {
			idxMap[name] = &dbschema.Index{
				Name:      name,
				TableName: tableName,
				IsUnique:  nonUnique == 0,
				IsPrimary: name == "PRIMARY",
			}
			order = append(order, name)
		}
		idxMap[name].Columns = append(idxMap[name].Columns, col)
	}
	result := make([]dbschema.Index, 0, len(order))
	for _, n := range order {
		result = append(result, *idxMap[n])
	}
	return result, rows.Err()
}

func (l *Loader) loadForeignKeys(db *sql.DB, schemaName, tableName string) ([]dbschema.ForeignKey, error) {
	rows, err := db.Query(`
		SELECT
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
		WHERE kcu.table_schema = ? AND kcu.table_name = ?
		  AND kcu.referenced_table_name IS NOT NULL
		ORDER BY kcu.constraint_name, kcu.ordinal_position
	`, schemaName, tableName)
	if err != nil {
		return nil, fmt.Errorf("load fks: %w", err)
	}
	defer rows.Close()

	fkMap := make(map[string]*dbschema.ForeignKey)
	var order []string
	for rows.Next() {
		var name, col, refTable, refCol, onDelete, onUpdate string
		if err := rows.Scan(&name, &col, &refTable, &refCol, &onDelete, &onUpdate); err != nil {
			return nil, err
		}
		if _, ok := fkMap[name]; !ok {
			fkMap[name] = &dbschema.ForeignKey{
				Name:      name,
				TableName: tableName,
				RefTable:  refTable,
				OnDelete:  onDelete,
				OnUpdate:  onUpdate,
			}
			order = append(order, name)
		}
		fkMap[name].Columns = append(fkMap[name].Columns, col)
		fkMap[name].RefColumns = append(fkMap[name].RefColumns, refCol)
	}
	fks := make([]dbschema.ForeignKey, 0, len(order))
	for _, n := range order {
		fks = append(fks, *fkMap[n])
	}
	return fks, rows.Err()
}

// ensure Loader satisfies the interface (compile-time check).
var _ dbschema.Loader = (*Loader)(nil)
