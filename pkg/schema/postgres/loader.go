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

// Package postgres provides a live schema Loader for PostgreSQL databases.
// It queries information_schema and pg_catalog to retrieve tables, columns,
// indexes, and foreign keys.
package postgres

import (
	"database/sql"
	"fmt"
	"strings"

	dbschema "github.com/ajitpratap0/GoSQLX/pkg/schema/db"
)

// Loader implements db.Loader for PostgreSQL.
type Loader struct{}

// NewLoader returns a new Postgres schema loader.
func NewLoader() *Loader { return &Loader{} }

// Load returns the full schema for all user tables in the given schemaName.
// If schemaName is empty, "public" is used.
func (l *Loader) Load(db *sql.DB, schemaName string) (*dbschema.DatabaseSchema, error) {
	if schemaName == "" {
		schemaName = "public"
	}
	rows, err := db.Query(`
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = $1
		  AND table_type = 'BASE TABLE'
		ORDER BY table_name
	`, schemaName)
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
// If schemaName is empty, "public" is used.
func (l *Loader) LoadTable(db *sql.DB, schemaName, tableName string) (*dbschema.Table, error) {
	if schemaName == "" {
		schemaName = "public"
	}
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
			COALESCE(pk.is_primary, false),
			COALESCE(uq.is_unique, false)
		FROM information_schema.columns c
		LEFT JOIN (
			SELECT kcu.column_name, true AS is_primary
			FROM information_schema.table_constraints tc
			JOIN information_schema.key_column_usage kcu
				ON tc.constraint_name = kcu.constraint_name
				AND tc.table_schema = kcu.table_schema
			WHERE tc.table_schema = $1 AND tc.table_name = $2
			  AND tc.constraint_type = 'PRIMARY KEY'
		) pk ON pk.column_name = c.column_name
		LEFT JOIN (
			SELECT kcu.column_name, true AS is_unique
			FROM information_schema.table_constraints tc
			JOIN information_schema.key_column_usage kcu
				ON tc.constraint_name = kcu.constraint_name
				AND tc.table_schema = kcu.table_schema
			WHERE tc.table_schema = $1 AND tc.table_name = $2
			  AND tc.constraint_type = 'UNIQUE'
		) uq ON uq.column_name = c.column_name
		WHERE c.table_schema = $1 AND c.table_name = $2
		ORDER BY c.ordinal_position
	`, schemaName, tableName)
	if err != nil {
		return nil, fmt.Errorf("load columns: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var cols []dbschema.Column
	for rows.Next() {
		var col dbschema.Column
		var isNullable string
		err := rows.Scan(
			&col.Name, &col.OrdinalPos, &col.DataType, &isNullable,
			&col.DefaultValue, &col.MaxLength, &col.Precision, &col.Scale,
			&col.IsPrimary, &col.IsUnique,
		)
		if err != nil {
			return nil, err
		}
		col.IsNullable = isNullable == "YES"
		cols = append(cols, col)
	}
	return cols, rows.Err()
}

func (l *Loader) loadIndexes(db *sql.DB, schemaName, tableName string) ([]dbschema.Index, error) {
	rows, err := db.Query(`
		SELECT
			i.relname AS index_name,
			ix.indisunique,
			ix.indisprimary,
			array_agg(a.attname ORDER BY a.attnum) AS columns
		FROM pg_class t
		JOIN pg_index ix ON t.oid = ix.indrelid
		JOIN pg_class i ON i.oid = ix.indexrelid
		JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = ANY(ix.indkey)
		JOIN pg_namespace n ON n.oid = t.relnamespace
		WHERE n.nspname = $1 AND t.relname = $2 AND t.relkind = 'r'
		GROUP BY i.relname, ix.indisunique, ix.indisprimary
		ORDER BY i.relname
	`, schemaName, tableName)
	if err != nil {
		return nil, fmt.Errorf("load indexes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var indexes []dbschema.Index
	for rows.Next() {
		var idx dbschema.Index
		var colArray string
		if err := rows.Scan(&idx.Name, &idx.IsUnique, &idx.IsPrimary, &colArray); err != nil {
			return nil, err
		}
		idx.TableName = tableName
		idx.Columns = parseArrayAgg(colArray)
		indexes = append(indexes, idx)
	}
	return indexes, rows.Err()
}

func (l *Loader) loadForeignKeys(db *sql.DB, schemaName, tableName string) ([]dbschema.ForeignKey, error) {
	rows, err := db.Query(`
		SELECT
			tc.constraint_name,
			kcu.column_name,
			ccu.table_name AS foreign_table_name,
			ccu.column_name AS foreign_column_name,
			rc.delete_rule,
			rc.update_rule
		FROM information_schema.table_constraints AS tc
		JOIN information_schema.key_column_usage AS kcu
			ON tc.constraint_name = kcu.constraint_name
			AND tc.table_schema = kcu.table_schema
		JOIN information_schema.constraint_column_usage AS ccu
			ON ccu.constraint_name = tc.constraint_name
			AND ccu.table_schema = tc.table_schema
		JOIN information_schema.referential_constraints AS rc
			ON rc.constraint_name = tc.constraint_name
		WHERE tc.constraint_type = 'FOREIGN KEY'
		  AND tc.table_schema = $1 AND tc.table_name = $2
		ORDER BY tc.constraint_name, kcu.ordinal_position
	`, schemaName, tableName)
	if err != nil {
		return nil, fmt.Errorf("load fks: %w", err)
	}
	defer func() { _ = rows.Close() }()

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

// parseArrayAgg parses a Postgres array literal "{a,b,c}" into []string{"a","b","c"}.
func parseArrayAgg(s string) []string {
	if len(s) < 2 {
		return nil
	}
	s = s[1 : len(s)-1] // strip braces
	if s == "" {
		return nil
	}
	var result []string
	for _, p := range strings.Split(s, ",") {
		result = append(result, strings.TrimSpace(p))
	}
	return result
}

// ensure Loader satisfies the interface (compile-time check).
var _ dbschema.Loader = (*Loader)(nil)
