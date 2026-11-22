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

package ast

import (
	"reflect"
	"testing"
)

// TestDDLObjects_HandBuiltSQL checks the rendering of hand-built nodes that
// use the CREATE TABLE / INDEX / VIEW / DROP extensions, including values
// outside the allow-lists, which are dropped rather than written raw.
func TestDDLObjects_HandBuiltSQL(t *testing.T) {
	str := "a table"
	yes := true
	tests := []struct {
		name string
		stmt interface{ SQL() string }
		want string
	}{
		{"ctas", &CreateTableStatement{Name: "t", CreateTableExtras: CreateTableExtras{
			OrReplace: true, Kind: "TRANSIENT", AsQuery: &SelectStatement{Columns: []Expression{&Identifier{Name: "a"}}, TableName: "u", From: []TableReference{{Name: "u"}}},
		}}, "CREATE OR REPLACE TRANSIENT TABLE t AS SELECT a FROM u"},
		{"unknown kind falls back to temporary", &CreateTableStatement{Name: "t", Temporary: true,
			Columns: []ColumnDef{{Name: "a", Type: "INT"}}, CreateTableExtras: CreateTableExtras{Kind: "x; DROP"}},
			"CREATE TEMPORARY TABLE t (a INT)"},
		{"options", &CreateTableStatement{Name: "t", Columns: []ColumnDef{{Name: "a", Type: "INT"}}, Options: []TableOption{
			{Name: "ENGINE", Value: "InnoDB"},
			{Name: "COMMENT", Value: "it's", ValueKind: TableOptionString},
			{Name: "AUTO_INCREMENT", Value: "10", ValueKind: TableOptionNumber},
			{Name: "TABLESPACE", Value: "ts", Form: TableOptionSpaced},
			{Name: "WITH", Form: TableOptionList, Sub: []OptionParam{{Name: "fillfactor", HasValue: true, Value: "70", ValueKind: TableOptionNumber}, {Name: "x y; z"}}},
			{Name: "CLUSTER BY", Form: TableOptionArgs, Args: []Expression{&Identifier{Name: "a"}}},
			{Name: "STRICT", Form: TableOptionFlag},
			{Name: "WITHOUT ROWID", Form: TableOptionFlag},
			{Name: "EVIL; DROP", Form: TableOptionFlag},
		}}, "CREATE TABLE t (a INT) ENGINE=InnoDB COMMENT='it''s' AUTO_INCREMENT=10 TABLESPACE ts WITH (fillfactor = 70) CLUSTER BY (a) STRICT, WITHOUT ROWID"},
		{"engine clauses", &CreateTableStatement{Name: "t", Columns: []ColumnDef{{Name: "a", Type: "UInt8"}},
			Options: []TableOption{{Name: "ENGINE", Value: "MergeTree"}},
			CreateTableExtras: CreateTableExtras{Engine: &TableEngineClauses{
				OrderBy:  &Identifier{Name: "a"},
				TTL:      []TTLRule{{Expr: &Identifier{Name: "a"}, Action: "TO DISK", Target: "d"}, {Expr: &Identifier{Name: "a"}, Action: "bogus"}},
				Settings: []QuerySetting{{Name: "index_granularity", Value: &LiteralValue{Value: "1", Type: "INTEGER"}}},
				Comment:  &str,
			}}}, "CREATE TABLE t (a UInt8) ENGINE=MergeTree ORDER BY a TTL a TO DISK 'd', a SETTINGS index_granularity = 1 COMMENT 'a table'"},
		{"partitions", &CreateTableStatement{Name: "t", Columns: []ColumnDef{{Name: "a", Type: "INT"}},
			PartitionBy: &PartitionBy{Type: "RANGE", Columns: []string{"a"}},
			Partitions: []PartitionDefinition{
				{Name: "p1", Type: "LESS THAN", LessThan: &Identifier{Name: "MAXVALUE"}},
				{Name: "p2", Type: "VALUES", Values: []Expression{&Identifier{Name: "DEFAULT"}}},
				{Name: "p3", Type: "unknown"},
			}}, "CREATE TABLE t (a INT) PARTITION BY RANGE (a) (PARTITION p1 VALUES LESS THAN (MAXVALUE), PARTITION p2 VALUES (DEFAULT), PARTITION p3)"},
		{"like", &CreateTableStatement{Name: "t", CreateTableExtras: CreateTableExtras{Like: "u"}}, "CREATE TABLE t LIKE u"},
		{"partition of", &CreateTableStatement{Name: "t", CreateTableExtras: CreateTableExtras{PartitionOf: "p", PartitionBound: &PartitionBound{Default: true}}},
			"CREATE TABLE t PARTITION OF p DEFAULT"},
		{"index", &CreateIndexStatement{Name: "i", Table: "t", Columns: []IndexColumn{{Expr: &BinaryExpression{Left: &Identifier{Name: "a"}, Operator: "+", Right: &Identifier{Name: "b"}}, NullsFirst: true}},
			CreateIndexExtras: CreateIndexExtras{Kind: "BITMAP", Include: []string{"c"}, Options: []TableOption{{Name: "LOCAL", Form: TableOptionFlag}, {Name: "BOGUS", Form: TableOptionFlag}}}},
			"CREATE BITMAP INDEX i ON t ((a + b) NULLS FIRST) INCLUDE (c) LOCAL"},
		{"view", &CreateViewStatement{Name: "v", Query: &SelectStatement{Columns: []Expression{&Identifier{Name: "a"}}},
			ViewExtras: ViewExtras{OrAlter: true, Modifiers: "SECURE", ReadOnly: true}}, "CREATE OR ALTER SECURE VIEW v AS SELECT a WITH READ ONLY"},
		{"view bad modifier", &CreateViewStatement{Name: "v", Temporary: true, Query: &SelectStatement{Columns: []Expression{&Identifier{Name: "a"}}},
			ViewExtras: ViewExtras{Modifiers: "x;y"}}, "CREATE TEMPORARY VIEW v AS SELECT a"},
		{"mv", &CreateMaterializedViewStatement{Name: "m", OrReplace: true, Query: &SelectStatement{Columns: []Expression{&Identifier{Name: "a"}}}, WithData: &yes,
			ViewExtras: ViewExtras{To: "d", Populate: true}}, "CREATE OR REPLACE MATERIALIZED VIEW m TO d POPULATE AS SELECT a WITH DATA"},
		{"drop", &DropStatement{ObjectType: "INDEX", Names: []string{"i"}, CascadeType: "CASCADE CONSTRAINTS",
			DropExtras: DropExtras{Concurrently: true, OnTable: "t", Purge: true}}, "DROP INDEX CONCURRENTLY i ON t CASCADE CONSTRAINTS PURGE"},
		{"truncate", &TruncateStatement{Tables: []string{"t"}, Storage: "REUSE STORAGE"}, "TRUNCATE TABLE t REUSE STORAGE"},
		{"truncate bad storage", &TruncateStatement{Tables: []string{"t"}, Storage: "x"}, "TRUNCATE TABLE t"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.stmt.SQL(); got != tt.want {
				t.Fatalf("SQL()\n got: %s\nwant: %s", got, tt.want)
			}
		})
	}
}

// TestDDLObjects_PoolReset checks that the Put functions clear every field
// added by the DDL extensions.
func TestDDLObjects_PoolReset(t *testing.T) {
	no := false
	ct := GetCreateTableStatement()
	ct.Name = "t"
	ct.WithoutRowID = true
	ct.WithSystemVersioning = true
	ct.Options = append(ct.Options, TableOption{Name: "CLUSTER BY", Form: TableOptionArgs, Args: []Expression{&Identifier{Name: "a"}}},
		TableOption{Name: "WITH", Form: TableOptionList, Sub: []OptionParam{{Name: "x"}}})
	ct.PartitionBy = &PartitionBy{Type: "HASH", Expressions: []Expression{&Identifier{Name: "a"}}, Partitions: &Identifier{Name: "n"}, Linear: true}
	ct.CreateTableExtras = CreateTableExtras{
		OrReplace: true, Kind: "TEMP", OnCluster: "c", Like: "l", Clone: &TableClone{Source: "s", Point: &Identifier{Name: "p"}},
		PartitionOf: "p", PartitionBound: &PartitionBound{In: []Expression{&Identifier{Name: "x"}}},
		AsTable: "a", AsQuery: &SelectStatement{}, WithData: &no, OptionsBeforePartition: 1,
		Engine: &TableEngineClauses{OrderBy: &Identifier{Name: "a"}, TTL: []TTLRule{{Expr: &Identifier{Name: "a"}}}},
	}
	PutCreateTableStatement(ct)
	if !reflect.DeepEqual(ct.CreateTableExtras, CreateTableExtras{}) || ct.WithoutRowID || ct.WithSystemVersioning ||
		len(ct.Options) != 0 || ct.PartitionBy != nil {
		t.Fatalf("CreateTableStatement not reset: %+v", ct)
	}

	ci := GetCreateIndexStatement()
	ci.Columns = append(ci.Columns, IndexColumn{Expr: &Identifier{Name: "a"}, OpClass: "o", NullsFirst: true})
	ci.CreateIndexExtras = CreateIndexExtras{OrReplace: true, Kind: "BITMAP", Concurrently: true, Only: true,
		Include: []string{"c"}, Options: []TableOption{{Name: "LOCAL", Form: TableOptionFlag}}, OptionsBeforeWhere: 1}
	PutCreateIndexStatement(ci)
	if ci.OrReplace || ci.Kind != "" || ci.Concurrently || ci.Only || len(ci.Include) != 0 || len(ci.Options) != 0 ||
		ci.OptionsBeforeWhere != 0 || len(ci.Columns) != 0 {
		t.Fatalf("CreateIndexStatement not reset: %+v", ci)
	}

	cv := GetCreateViewStatement()
	cv.ViewExtras = ViewExtras{OrAlter: true, Modifiers: "SECURE", ReadOnly: true}
	PutCreateViewStatement(cv)
	if !reflect.DeepEqual(cv.ViewExtras, ViewExtras{}) {
		t.Fatalf("CreateViewStatement not reset: %+v", cv.ViewExtras)
	}

	mv := GetCreateMaterializedViewStatement()
	mv.OrReplace = true
	mv.ViewExtras = ViewExtras{To: "d", Populate: true, Refresh: "REFRESH FAST",
		ColumnDefs: []ColumnDef{{Name: "a", Type: "UInt8"}}, Engine: &TableEngineClauses{OrderBy: &Identifier{Name: "a"}}}
	PutCreateMaterializedViewStatement(mv)
	if mv.OrReplace || !reflect.DeepEqual(mv.ViewExtras, ViewExtras{}) {
		t.Fatalf("CreateMaterializedViewStatement not reset: %+v", mv.ViewExtras)
	}

	d := GetDropStatement()
	d.DropExtras = DropExtras{Temporary: true, Concurrently: true, OnTable: "t", OnCluster: "c", Purge: true, Sync: true}
	PutDropStatement(d)
	if d.DropExtras != (DropExtras{}) {
		t.Fatalf("DropStatement not reset: %+v", d.DropExtras)
	}

	tr := GetTruncateStatement()
	tr.Storage = "DROP STORAGE"
	PutTruncateStatement(tr)
	if tr.Storage != "" {
		t.Fatalf("TruncateStatement not reset: %q", tr.Storage)
	}
}
