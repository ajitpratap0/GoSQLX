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
// Tables and column metadata come from information_schema; key flags, indexes
// and foreign keys come from pg_catalog (pg_constraint, pg_index), so they are
// complete for roles that only have SELECT.
//
// It requires PostgreSQL 11 or later: partition clones of foreign keys are
// filtered on pg_constraint.conparentid, and index INCLUDE columns
// (pg_index.indnkeyatts) were both added in PostgreSQL 11.
package postgres

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	dbschema "github.com/ajitpratap0/GoSQLX/pkg/schema/db"
)

// Loader implements db.Loader for PostgreSQL.
type Loader struct{}

// NewLoader returns a new Postgres schema loader.
func NewLoader() *Loader { return &Loader{} }

// Load returns the full schema for all user tables in the given schemaName.
// If schemaName is empty, "public" is used.
//
// Load issues four statements (tables, columns, indexes, foreign keys) for the
// whole schema and drains each cursor before running the next, so it works
// with a single-connection pool.
func (l *Loader) Load(db *sql.DB, schemaName string) (*dbschema.DatabaseSchema, error) {
	if schemaName == "" {
		schemaName = "public"
	}
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
// If schemaName is empty, "public" is used.
func (l *Loader) LoadTable(db *sql.DB, schemaName, tableName string) (*dbschema.Table, error) {
	if tableName == "" {
		return nil, errors.New("load table: table name must not be empty")
	}
	if schemaName == "" {
		schemaName = "public"
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
		Columns:     cols[tableName],
		Indexes:     idxs[tableName],
		ForeignKeys: fks[tableName],
	}, nil
}

// listTables returns the base tables in schemaName, ordered by name.
func (l *Loader) listTables(db *sql.DB, schemaName string) ([]string, error) {
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
//
// Column metadata comes from information_schema.columns. The PRIMARY KEY and
// UNIQUE flags come from pg_constraint, which any role can read, whereas the
// information_schema constraint views hide constraints from roles that do not
// own the table. IsPrimary means the column is a member of the primary key.
// IsUnique means the column alone is a UNIQUE constraint; members of composite
// UNIQUE constraints are not flagged, matching MySQL's COLUMN_KEY = 'UNI'.
// Constraints are aggregated per column, so each column is emitted once.
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
			COALESCE(kf.is_primary, false),
			COALESCE(kf.is_unique, false)
		FROM information_schema.columns c
		LEFT JOIN (
			SELECT
				cl.relname AS table_name,
				a.attname  AS column_name,
				bool_or(con.contype = 'p') AS is_primary,
				bool_or(con.contype = 'u' AND cardinality(con.conkey) = 1) AS is_unique
			FROM pg_constraint con
			JOIN pg_class cl ON cl.oid = con.conrelid
			JOIN pg_namespace n ON n.oid = cl.relnamespace
			CROSS JOIN LATERAL unnest(con.conkey) AS k(attnum)
			JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.attnum
			WHERE n.nspname = $1 AND ($2::text = '' OR cl.relname = $2)
			  AND con.contype IN ('p', 'u')
			GROUP BY cl.relname, a.attname
		) kf ON kf.table_name = c.table_name AND kf.column_name = c.column_name
		WHERE c.table_schema = $1 AND ($2::text = '' OR c.table_name = $2)
		ORDER BY c.table_name, c.ordinal_position
	`, schemaName, tableName)
	if err != nil {
		return nil, fmt.Errorf("load columns: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string][]dbschema.Column)
	for rows.Next() {
		var tbl string
		var col dbschema.Column
		var isNullable string
		err := rows.Scan(
			&tbl,
			&col.Name, &col.OrdinalPos, &col.DataType, &isNullable,
			&col.DefaultValue, &col.MaxLength, &col.Precision, &col.Scale,
			&col.IsPrimary, &col.IsUnique,
		)
		if err != nil {
			return nil, fmt.Errorf("load columns: scan: %w", err)
		}
		col.IsNullable = isNullable == "YES"
		out[tbl] = append(out[tbl], col)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load columns: %w", err)
	}
	return out, nil
}

// loadIndexes returns indexes grouped by table name, ordered by index name.
// An empty tableName loads every table in schemaName.
//
// Index.Columns lists the key columns in index order; INCLUDE columns are
// reported separately in Index.IncludeColumns. An expression key is reported as
// the expression text from pg_get_indexdef, for example lower(email). Ordinary
// and partitioned tables (relkind 'r' and 'p') are covered.
func (l *Loader) loadIndexes(db *sql.DB, schemaName, tableName string) (map[string][]dbschema.Index, error) {
	rows, err := db.Query(`
		SELECT
			t.relname AS table_name,
			i.relname AS index_name,
			ix.indisunique,
			ix.indisprimary,
			json_agg(CASE WHEN k.attnum = 0 THEN pg_get_indexdef(ix.indexrelid, k.ord::int, true) ELSE a.attname END ORDER BY k.ord)
				FILTER (WHERE k.ord <= ix.indnkeyatts)::text AS columns,
			json_agg(a.attname ORDER BY k.ord) FILTER (WHERE k.ord > ix.indnkeyatts)::text AS include_columns
		FROM pg_class t
		JOIN pg_index ix ON t.oid = ix.indrelid
		JOIN pg_class i ON i.oid = ix.indexrelid
		JOIN pg_namespace n ON n.oid = t.relnamespace
		CROSS JOIN LATERAL unnest(ix.indkey) WITH ORDINALITY AS k(attnum, ord)
		LEFT JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum AND k.attnum <> 0
		WHERE n.nspname = $1 AND ($2::text = '' OR t.relname = $2) AND t.relkind IN ('r', 'p')
		GROUP BY t.relname, i.relname, ix.indisunique, ix.indisprimary
		ORDER BY t.relname, i.relname
	`, schemaName, tableName)
	if err != nil {
		return nil, fmt.Errorf("load indexes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string][]dbschema.Index)
	for rows.Next() {
		var idx dbschema.Index
		// Columns arrive as a JSON array (not a Postgres array literal) so that
		// quoted identifiers containing commas, quotes or braces decode exactly,
		// independent of the SQL driver in use.
		// include_columns is SQL NULL (a nil slice) when there are none.
		var colJSON, inclJSON []byte
		if err := rows.Scan(&idx.TableName, &idx.Name, &idx.IsUnique, &idx.IsPrimary, &colJSON, &inclJSON); err != nil {
			return nil, fmt.Errorf("load indexes: scan: %w", err)
		}
		if err := json.Unmarshal(colJSON, &idx.Columns); err != nil {
			return nil, fmt.Errorf("load indexes: decode columns of %s.%s: %w", idx.TableName, idx.Name, err)
		}
		if inclJSON != nil {
			if err := json.Unmarshal(inclJSON, &idx.IncludeColumns); err != nil {
				return nil, fmt.Errorf("load indexes: decode include columns of %s.%s: %w", idx.TableName, idx.Name, err)
			}
		}
		out[idx.TableName] = append(out[idx.TableName], idx)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load indexes: %w", err)
	}
	return out, nil
}

// loadForeignKeys returns foreign keys grouped by table name, ordered by
// constraint name. An empty tableName loads every table in schemaName.
//
// It reads pg_constraint directly: unnest(conkey, confkey) pairs each local
// column with its referenced column by position, so composite keys are not
// cross-multiplied, and constraints are identified by (table, name) because
// Postgres only requires constraint names to be unique per table. Constraints
// that are internal per-partition clones of a key referencing a partitioned
// table (their parent constraint lives on the same relation) are skipped.
//
// Requires PostgreSQL 11+ (pg_constraint.conparentid). Because pg_constraint is
// readable by any role, foreign keys are returned even when the connecting role
// only has SELECT on the tables (information_schema hid them from non-owners).
// ForeignKey.RefSchema carries the schema of the referenced table, so a foreign
// key into another schema is not ambiguous.
func (l *Loader) loadForeignKeys(db *sql.DB, schemaName, tableName string) (map[string][]dbschema.ForeignKey, error) {
	rows, err := db.Query(`
		SELECT
			cl.relname  AS table_name,
			con.conname AS constraint_name,
			a.attname   AS column_name,
			rn.nspname  AS foreign_table_schema,
			rcl.relname AS foreign_table_name,
			ra.attname  AS foreign_column_name,
			CASE con.confdeltype WHEN 'a' THEN 'NO ACTION' WHEN 'r' THEN 'RESTRICT' WHEN 'c' THEN 'CASCADE' WHEN 'n' THEN 'SET NULL' WHEN 'd' THEN 'SET DEFAULT' ELSE con.confdeltype::text END AS delete_rule,
			CASE con.confupdtype WHEN 'a' THEN 'NO ACTION' WHEN 'r' THEN 'RESTRICT' WHEN 'c' THEN 'CASCADE' WHEN 'n' THEN 'SET NULL' WHEN 'd' THEN 'SET DEFAULT' ELSE con.confupdtype::text END AS update_rule
		FROM pg_constraint con
		JOIN pg_class cl ON cl.oid = con.conrelid
		JOIN pg_namespace n ON n.oid = cl.relnamespace
		JOIN pg_class rcl ON rcl.oid = con.confrelid
		JOIN pg_namespace rn ON rn.oid = rcl.relnamespace
		CROSS JOIN LATERAL unnest(con.conkey, con.confkey) WITH ORDINALITY AS k(attnum, ref_attnum, ord)
		JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = k.attnum
		JOIN pg_attribute ra ON ra.attrelid = con.confrelid AND ra.attnum = k.ref_attnum
		WHERE con.contype = 'f'
		  AND n.nspname = $1 AND ($2::text = '' OR cl.relname = $2)
		  AND NOT EXISTS (
			SELECT 1 FROM pg_constraint p
			WHERE p.oid = con.conparentid AND p.conrelid = con.conrelid)
		ORDER BY cl.relname, con.conname, k.ord
	`, schemaName, tableName)
	if err != nil {
		return nil, fmt.Errorf("load fks: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make(map[string][]dbschema.ForeignKey)
	for rows.Next() {
		var tbl, name, col, refSchema, refTable, refCol, onDelete, onUpdate string
		if err := rows.Scan(&tbl, &name, &col, &refSchema, &refTable, &refCol, &onDelete, &onUpdate); err != nil {
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
			RefSchema:  refSchema,
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
