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
	"strings"
	"testing"
)

func strLit(s string) *LiteralValue { return &LiteralValue{Value: s, Type: "string"} }

func TestColumnConstraintSQL_Kinds(t *testing.T) {
	paren := &ParenthesizedExpression{Expr: &Identifier{Name: "a"}}
	cases := []struct {
		name string
		c    ColumnConstraint
		want string
	}{
		{"comment", ColumnConstraint{Type: "COMMENT", Expr: strLit("it's")}, "COMMENT 'it''s'"},
		{"charset spelling", ColumnConstraint{Type: "CHARACTER SET", Keyword: "CHARSET", Value: "latin1"}, "CHARSET latin1"},
		{"character set", ColumnConstraint{Type: "CHARACTER SET", Value: "utf8mb4"}, "CHARACTER SET utf8mb4"},
		{"collate quoted", ColumnConstraint{Type: "COLLATE", Value: `"C"`}, `COLLATE "C"`},
		{"collate qualified", ColumnConstraint{Type: "COLLATE", Value: `pg_catalog."default"`}, `COLLATE pg_catalog."default"`},
		{"srid", ColumnConstraint{Type: "SRID", Value: "4326"}, "SRID 4326"},
		{"identity args", ColumnConstraint{Type: "IDENTITY", Args: "(1, 1)"}, "IDENTITY(1, 1)"},
		{"identity start", ColumnConstraint{Type: "IDENTITY", Args: "START 1 INCREMENT 2"}, "IDENTITY START 1 INCREMENT 2"},
		{"identity bare", ColumnConstraint{Type: "IDENTITY"}, "IDENTITY"},
		{"autoincrement", ColumnConstraint{Type: "AUTO_INCREMENT", AutoIncrement: true, Keyword: "autoincrement"}, "AUTOINCREMENT"},
		{"auto_increment default", ColumnConstraint{AutoIncrement: true}, "AUTO_INCREMENT"},
		{"identity always", ColumnConstraint{Type: "GENERATED ALWAYS AS IDENTITY", Args: "(START WITH 5)"}, "GENERATED ALWAYS AS IDENTITY (START WITH 5)"},
		{"generated parenthesised", ColumnConstraint{Type: "GENERATED ALWAYS AS", Expr: paren, Keyword: "STORED"}, "GENERATED ALWAYS AS (a) STORED"},
		{"generated wraps", ColumnConstraint{Type: "AS", Expr: &Identifier{Name: "a"}, Keyword: "persisted"}, "AS (a) persisted"},
		{"clickhouse materialized", ColumnConstraint{Type: "MATERIALIZED", Expr: &Identifier{Name: "a"}}, "MATERIALIZED a"},
		{"clickhouse ephemeral bare", ColumnConstraint{Type: "EPHEMERAL"}, "EPHEMERAL"},
		{"clickhouse codec", ColumnConstraint{Type: "CODEC", Args: "(Delta, ZSTD(1))"}, "CODEC(Delta, ZSTD(1))"},
		{"deferrable", ColumnConstraint{Type: "NOT DEFERRABLE"}, "NOT DEFERRABLE"},
		{"named", ColumnConstraint{Name: "pk", Type: "PRIMARY KEY", Keyword: "CLUSTERED"}, "CONSTRAINT pk PRIMARY KEY CLUSTERED"},
		{"cluster keyword only on keys", ColumnConstraint{Type: "NOT NULL", Keyword: "CLUSTERED"}, "NOT NULL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ColumnConstraintSQL(&tc.c); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestColumnConstraintSQL_HostileFieldsAreDropped checks that text a hand-built
// AST puts in the free-form fields cannot end the statement or open a comment:
// it is dropped, leaving a clause that does not parse, rather than written.
func TestColumnConstraintSQL_HostileFieldsAreDropped(t *testing.T) {
	cases := []struct {
		name string
		c    ColumnConstraint
		bad  string
	}{
		{"collation", ColumnConstraint{Type: "COLLATE", Value: "x; DROP TABLE t"}, "DROP"},
		{"charset", ColumnConstraint{Type: "CHARACTER SET", Value: "a b"}, "a b"},
		{"srid", ColumnConstraint{Type: "SRID", Value: "1; DROP"}, "DROP"},
		{"identity args", ColumnConstraint{Type: "IDENTITY", Args: "(1); DROP TABLE t"}, "DROP"},
		{"codec comment", ColumnConstraint{Type: "CODEC", Args: "(ZSTD) -- x"}, "--"},
		{"unbalanced args", ColumnConstraint{Type: "GENERATED ALWAYS AS IDENTITY", Args: "(1"}, "(1"},
		{"unclosed quote", ColumnConstraint{Type: "CODEC", Args: "('x)"}, "'x"},
		{"unknown keyword", ColumnConstraint{Type: "AUTO_INCREMENT", Keyword: "x; DROP", AutoIncrement: true}, "DROP"},
		{"storage keyword", ColumnConstraint{Type: "AS", Expr: &Identifier{Name: "a"}, Keyword: "STORED; DROP"}, "DROP"},
		{"unknown kind", ColumnConstraint{Type: "DROP TABLE t"}, "DROP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ColumnConstraintSQL(&tc.c); strings.Contains(got, tc.bad) {
				t.Errorf("got %q, which contains %q", got, tc.bad)
			}
		})
	}
}

func TestTableConstraintSQL_Kinds(t *testing.T) {
	fn := &FunctionCall{Name: "lower", Arguments: []Expression{&Identifier{Name: "b"}}}
	cases := []struct {
		name string
		c    TableConstraint
		want string
	}{
		{"primary key", TableConstraint{Type: "PRIMARY KEY", Columns: []string{"a", "b"}}, "PRIMARY KEY (a, b)"},
		{"clustered", TableConstraint{Name: "pk", Type: "PRIMARY KEY", Cluster: "CLUSTERED", Columns: []string{"a"}, ColumnSuffix: []string{"DESC"}}, "CONSTRAINT pk PRIMARY KEY CLUSTERED (a DESC)"},
		{"unique key", TableConstraint{Type: "UNIQUE", Keyword: "KEY", IndexName: "uq", Columns: []string{"a"}}, "UNIQUE KEY uq (a)"},
		{"unique plain", TableConstraint{Type: "UNIQUE", Columns: []string{"a"}, Deferrable: "DEFERRABLE INITIALLY DEFERRED"}, "UNIQUE (a) DEFERRABLE INITIALLY DEFERRED"},
		{"key with length and order", TableConstraint{Type: "KEY", IndexName: "k", Using: "BTREE", Columns: []string{"a", "b"}, ColumnSuffix: []string{"(10)", "(5) DESC"}}, "KEY k USING BTREE (a(10), b(5) DESC)"},
		{"fulltext", TableConstraint{Type: "FULLTEXT", Keyword: "INDEX", IndexName: "ft", Columns: []string{"a"}}, "FULLTEXT INDEX ft (a)"},
		{"functional", TableConstraint{Type: "KEY", IndexName: "k", Exprs: []Expression{&Identifier{Name: "a"}, fn}}, "KEY k (a, (lower(b)))"},
		{"clickhouse index", TableConstraint{Type: "INDEX", IndexName: "i", Exprs: []Expression{fn}, Text: "bloom_filter(0.01)", Granularity: "3"}, "INDEX i lower(b) TYPE bloom_filter(0.01) GRANULARITY 3"},
		{"like", TableConstraint{Type: "LIKE", LikeTable: "s.u", LikeOptions: []string{"INCLUDING ALL", "EXCLUDING INDEXES"}}, "LIKE s.u INCLUDING ALL EXCLUDING INDEXES"},
		{"like quoted", TableConstraint{Type: "LIKE", LikeTable: "u; DROP TABLE t"}, `LIKE "u; DROP TABLE t"`},
		{"projection", TableConstraint{Type: "PROJECTION", IndexName: "p", Text: "(SELECT a GROUP BY a)"}, "PROJECTION p (SELECT a GROUP BY a)"},
		{"assume", TableConstraint{Name: "c", Type: "ASSUME", Check: &Identifier{Name: "a"}}, "CONSTRAINT c ASSUME a"},
		{"foreign key deferrable", TableConstraint{Type: "FOREIGN KEY", Columns: []string{"a"}, References: &ReferenceDefinition{Table: "u", Columns: []string{"id"}}, Deferrable: "NOT DEFERRABLE"}, "FOREIGN KEY (a) REFERENCES u (id) NOT DEFERRABLE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := TableConstraintSQL(&tc.c); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestTableConstraintSQL_HostileFieldsAreDropped(t *testing.T) {
	cases := []struct {
		name string
		c    TableConstraint
		bad  string
	}{
		{"using", TableConstraint{Type: "KEY", Using: "BTREE; DROP", Columns: []string{"a"}}, "DROP"},
		{"cluster", TableConstraint{Type: "PRIMARY KEY", Cluster: "X; DROP", Columns: []string{"a"}}, "DROP"},
		{"deferrable", TableConstraint{Type: "UNIQUE", Deferrable: "DEFERRABLE; DROP", Columns: []string{"a"}}, "DROP"},
		{"suffix", TableConstraint{Type: "KEY", Columns: []string{"a"}, ColumnSuffix: []string{"; DROP"}}, "DROP"},
		{"like option", TableConstraint{Type: "LIKE", LikeTable: "u", LikeOptions: []string{"INCLUDING ALL; DROP"}}, "DROP"},
		{"clickhouse type", TableConstraint{Type: "INDEX", IndexName: "i", Text: "minmax); DROP", Granularity: "1"}, "DROP"},
		{"granularity", TableConstraint{Type: "INDEX", IndexName: "i", Text: "minmax", Granularity: "1; DROP"}, "DROP"},
		{"projection body", TableConstraint{Type: "PROJECTION", IndexName: "p", Text: "(SELECT 1); DROP"}, "DROP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := TableConstraintSQL(&tc.c); strings.Contains(got, tc.bad) {
				t.Errorf("got %q, which contains %q", got, tc.bad)
			}
		})
	}
}

func TestColumnDefSQL_OmitsEmptyType(t *testing.T) {
	c := &ColumnDef{Name: "a", Constraints: []ColumnConstraint{{Type: "NOT NULL"}}}
	if got, want := ColumnDefSQL(c), "a NOT NULL"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got, want := ColumnDefSQL(&ColumnDef{Name: "a"}), "a"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// TestColumnConstraint_ChildrenIncludeExpr checks visitors reach the new
// expression fields.
func TestColumnConstraint_ChildrenIncludeExpr(t *testing.T) {
	e := &Identifier{Name: "a"}
	if kids := (ColumnConstraint{Type: "MATERIALIZED", Expr: e}).Children(); len(kids) != 1 || kids[0] != Node(e) {
		t.Errorf("ColumnConstraint children = %v, want the expression", kids)
	}
	if kids := (TableConstraint{Type: "KEY", Exprs: []Expression{e, nil}}).Children(); len(kids) != 1 || kids[0] != Node(e) {
		t.Errorf("TableConstraint children = %v, want the one non-nil expression", kids)
	}
}

// TestCreateTablePool_ResetsColumnAndConstraintFields checks that releasing a
// CREATE TABLE clears every field of its column constraints and table
// constraints, so a slot reused for the next statement carries no state.
func TestCreateTablePool_ResetsColumnAndConstraintFields(t *testing.T) {
	stmt := GetCreateTableStatement()
	stmt.Columns = append(stmt.Columns, ColumnDef{
		Name: "a", Type: "INT",
		Constraints: []ColumnConstraint{{
			Name: "n", Type: "GENERATED ALWAYS AS", Keyword: "STORED", Value: "v", Args: "(1)",
			Expr: &Identifier{Name: "x"}, AutoIncrement: true,
		}},
	})
	stmt.Constraints = append(stmt.Constraints, TableConstraint{
		Name: "k", Type: "KEY", Columns: []string{"a"}, ColumnSuffix: []string{"DESC"},
		Keyword: "KEY", IndexName: "i", Using: "BTREE", Cluster: "CLUSTERED", Deferrable: "DEFERRABLE",
		Exprs: []Expression{&Identifier{Name: "y"}}, Text: "t", Granularity: "1",
		LikeTable: "u", LikeOptions: []string{"INCLUDING ALL"},
	})
	cons := stmt.Columns[0].Constraints
	tcons := stmt.Constraints
	PutCreateTableStatement(stmt)

	if got := cons[0]; got.Name != "" || got.Type != "" || got.Keyword != "" || got.Value != "" ||
		got.Args != "" || got.Expr != nil || got.AutoIncrement {
		t.Errorf("column constraint not cleared: %+v", got)
	}
	got := tcons[0]
	if got.Name != "" || got.Type != "" || len(got.Columns) != 0 || got.ColumnSuffix != nil ||
		got.Keyword != "" || got.IndexName != "" || got.Using != "" || got.Cluster != "" ||
		got.Deferrable != "" || got.Exprs != nil || got.Text != "" || got.Granularity != "" ||
		got.LikeTable != "" || got.LikeOptions != nil {
		t.Errorf("table constraint not cleared: %+v", got)
	}
}
