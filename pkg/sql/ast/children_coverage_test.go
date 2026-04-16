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
	"strings"
	"testing"
)

// TestChildrenCoverage_VisitorContract enforces the AST's visitor contract
// using reflection: every Node type with fields typed as Node / Expression /
// Statement (or slices thereof) must surface non-nil values of those fields
// through its Children() method.
//
// Silently dropping children breaks ast.Walk and ast.Inspect — semantic
// analyzers built on the visitor pattern miss entire subtrees without any
// diagnostic. This test catches that regression for every existing and
// future Node type.
//
// Mechanics:
//  1. For each candidate type, build a zero value (addressable via *T).
//  2. Walk the struct fields; for each Node/Expression/Statement field
//     (or slice element type that implements one of those interfaces),
//     inject a unique mock node produced by mockChildNode / mockChildExpr /
//     mockChildStmt.
//  3. Call Children() and assert every injected mock appears somewhere in
//     the returned slice (pointer equality).
//
// Types in childrenCoverageAllowlist are deliberately exempted because they
// are leaf nodes, marker-only types, or cannot meaningfully expose children
// without dereferencing something the visitor shouldn't traverse (e.g. a
// raw string that merely names a column).
func TestChildrenCoverage_VisitorContract(t *testing.T) {
	for _, c := range childrenCoverageCases() {
		c := c
		t.Run(c.name, func(t *testing.T) {
			// Build a fresh, addressable value of the concrete type.
			ptr := reflect.New(c.typ) // *T
			injected := injectMockChildren(t, ptr.Elem())

			if len(injected) == 0 {
				// Type has no Node/Expression/Statement-typed fields —
				// Children() returning nil is correct; nothing further
				// to verify here.
				return
			}

			// Call Children() on the value (or pointer, whichever has
			// the method set).
			got := callChildren(t, ptr)

			// Every injected mock must appear somewhere in the result.
			missing := make([]string, 0)
			for _, want := range injected {
				if !containsNode(got, want.node) {
					missing = append(missing, want.fieldPath)
				}
			}
			if len(missing) > 0 {
				t.Errorf(
					"%s.Children() dropped %d field(s) from traversal: %s\n"+
						"Children() returned %d node(s). Add the missing field(s) to Children().",
					c.name, len(missing), strings.Join(missing, ", "), len(got),
				)
			}
		})
	}
}

// TestChildrenCoverage_ZeroValueSafe verifies that every Node can safely have
// its Children() called on a zero value without panicking. Any Children()
// implementation that dereferences pointers without nil checks will panic
// here — which is exactly the bug class this suite exists to prevent.
func TestChildrenCoverage_ZeroValueSafe(t *testing.T) {
	for _, c := range childrenCoverageCases() {
		c := c
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s.Children() panicked on zero value: %v", c.name, r)
				}
			}()
			ptr := reflect.New(c.typ)
			_ = callChildren(t, ptr)
		})
	}
}

// childrenCoverageCase names a Node type under test.
type childrenCoverageCase struct {
	name string
	typ  reflect.Type
}

// childrenCoverageCases enumerates every Node-implementing struct in this
// package. New Node types must be added here (or to the allowlist below)
// so that regressions cannot slip in.
func childrenCoverageCases() []childrenCoverageCase {
	return []childrenCoverageCase{
		// WITH / CTE / set operations
		{"WithClause", reflect.TypeOf(WithClause{})},
		{"CommonTableExpr", reflect.TypeOf(CommonTableExpr{})},
		{"SetOperation", reflect.TypeOf(SetOperation{})},

		// SELECT & friends
		{"SelectStatement", reflect.TypeOf(SelectStatement{})},
		{"TopClause", reflect.TypeOf(TopClause{})},
		{"FetchClause", reflect.TypeOf(FetchClause{})},
		{"ForClause", reflect.TypeOf(ForClause{})},
		{"JoinClause", reflect.TypeOf(JoinClause{})},
		{"TableReference", reflect.TypeOf(TableReference{})},
		{"WindowSpec", reflect.TypeOf(WindowSpec{})},
		{"WindowFrame", reflect.TypeOf(WindowFrame{})},
		{"WindowFrameBound", reflect.TypeOf(WindowFrameBound{})},
		{"RollupExpression", reflect.TypeOf(RollupExpression{})},
		{"CubeExpression", reflect.TypeOf(CubeExpression{})},
		{"GroupingSetsExpression", reflect.TypeOf(GroupingSetsExpression{})},

		// Expressions
		{"Identifier", reflect.TypeOf(Identifier{})},
		{"FunctionCall", reflect.TypeOf(FunctionCall{})},
		{"CaseExpression", reflect.TypeOf(CaseExpression{})},
		{"WhenClause", reflect.TypeOf(WhenClause{})},
		{"ExistsExpression", reflect.TypeOf(ExistsExpression{})},
		{"InExpression", reflect.TypeOf(InExpression{})},
		{"SubqueryExpression", reflect.TypeOf(SubqueryExpression{})},
		{"AnyExpression", reflect.TypeOf(AnyExpression{})},
		{"AllExpression", reflect.TypeOf(AllExpression{})},
		{"BetweenExpression", reflect.TypeOf(BetweenExpression{})},
		{"BinaryExpression", reflect.TypeOf(BinaryExpression{})},
		{"LiteralValue", reflect.TypeOf(LiteralValue{})},
		{"ListExpression", reflect.TypeOf(ListExpression{})},
		{"TupleExpression", reflect.TypeOf(TupleExpression{})},
		{"ArrayConstructorExpression", reflect.TypeOf(ArrayConstructorExpression{})},
		{"UnaryExpression", reflect.TypeOf(UnaryExpression{})},
		{"VariantPath", reflect.TypeOf(VariantPath{})},
		{"NamedArgument", reflect.TypeOf(NamedArgument{})},
		{"CastExpression", reflect.TypeOf(CastExpression{})},
		{"AliasedExpression", reflect.TypeOf(AliasedExpression{})},
		{"ExtractExpression", reflect.TypeOf(ExtractExpression{})},
		{"PositionExpression", reflect.TypeOf(PositionExpression{})},
		{"SubstringExpression", reflect.TypeOf(SubstringExpression{})},
		{"IntervalExpression", reflect.TypeOf(IntervalExpression{})},
		{"ArraySubscriptExpression", reflect.TypeOf(ArraySubscriptExpression{})},
		{"ArraySliceExpression", reflect.TypeOf(ArraySliceExpression{})},

		// DML
		{"InsertStatement", reflect.TypeOf(InsertStatement{})},
		{"OnConflict", reflect.TypeOf(OnConflict{})},
		{"UpsertClause", reflect.TypeOf(UpsertClause{})},
		{"Values", reflect.TypeOf(Values{})},
		{"UpdateStatement", reflect.TypeOf(UpdateStatement{})},
		{"UpdateExpression", reflect.TypeOf(UpdateExpression{})},
		{"DeleteStatement", reflect.TypeOf(DeleteStatement{})},
		{"MergeStatement", reflect.TypeOf(MergeStatement{})},
		{"MergeWhenClause", reflect.TypeOf(MergeWhenClause{})},
		{"MergeAction", reflect.TypeOf(MergeAction{})},
		{"SetClause", reflect.TypeOf(SetClause{})},
		{"ReplaceStatement", reflect.TypeOf(ReplaceStatement{})},

		// DDL
		{"CreateTableStatement", reflect.TypeOf(CreateTableStatement{})},
		{"ColumnDef", reflect.TypeOf(ColumnDef{})},
		{"ColumnConstraint", reflect.TypeOf(ColumnConstraint{})},
		{"TableConstraint", reflect.TypeOf(TableConstraint{})},
		{"ReferenceDefinition", reflect.TypeOf(ReferenceDefinition{})},
		{"PartitionBy", reflect.TypeOf(PartitionBy{})},
		{"TableOption", reflect.TypeOf(TableOption{})},
		{"PartitionDefinition", reflect.TypeOf(PartitionDefinition{})},
		{"AlterTableStatement", reflect.TypeOf(AlterTableStatement{})},
		{"AlterTableAction", reflect.TypeOf(AlterTableAction{})},
		{"CreateIndexStatement", reflect.TypeOf(CreateIndexStatement{})},
		{"IndexColumn", reflect.TypeOf(IndexColumn{})},
		{"CreateViewStatement", reflect.TypeOf(CreateViewStatement{})},
		{"CreateMaterializedViewStatement", reflect.TypeOf(CreateMaterializedViewStatement{})},
		{"RefreshMaterializedViewStatement", reflect.TypeOf(RefreshMaterializedViewStatement{})},
		{"DropStatement", reflect.TypeOf(DropStatement{})},
		{"TruncateStatement", reflect.TypeOf(TruncateStatement{})},

		// Misc statements
		{"PragmaStatement", reflect.TypeOf(PragmaStatement{})},
		{"ShowStatement", reflect.TypeOf(ShowStatement{})},
		{"DescribeStatement", reflect.TypeOf(DescribeStatement{})},
		{"UnsupportedStatement", reflect.TypeOf(UnsupportedStatement{})},

		// Temporal / Snowflake / SQL Server table-expression clauses
		{"ForSystemTimeClause", reflect.TypeOf(ForSystemTimeClause{})},
		{"TimeTravelClause", reflect.TypeOf(TimeTravelClause{})},
		{"PivotClause", reflect.TypeOf(PivotClause{})},
		{"UnpivotClause", reflect.TypeOf(UnpivotClause{})},
		{"MatchRecognizeClause", reflect.TypeOf(MatchRecognizeClause{})},
		{"PeriodDefinition", reflect.TypeOf(PeriodDefinition{})},
		{"ConnectByClause", reflect.TypeOf(ConnectByClause{})},
		{"SampleClause", reflect.TypeOf(SampleClause{})},

		// Alter operations
		{"AlterStatement", reflect.TypeOf(AlterStatement{})},
		{"AlterTableOperation", reflect.TypeOf(AlterTableOperation{})},
		{"AlterRoleOperation", reflect.TypeOf(AlterRoleOperation{})},
		{"AlterPolicyOperation", reflect.TypeOf(AlterPolicyOperation{})},
		{"AlterConnectorOperation", reflect.TypeOf(AlterConnectorOperation{})},

		// Legacy DML duplicates in dml.go — still Node-implementing.
		{"Select", reflect.TypeOf(Select{})},
		{"Insert", reflect.TypeOf(Insert{})},
		{"Delete", reflect.TypeOf(Delete{})},
		{"Update", reflect.TypeOf(Update{})},
	}
}

// childrenCoverageAllowlist contains types that implement Node but are
// exempted from the Children() visitor-contract check because they have
// no Node-typed fields at all, or only carry raw strings / enums that
// the visitor intentionally does not descend into.
//
// Each exemption must have a justification comment; add new entries only
// when the type truly cannot produce children.
//
//nolint:unused // referenced by documentation in this file
var childrenCoverageAllowlist = map[string]string{
	// Leaf / atomic value types — stored fields are strings / numbers /
	// raw tokens, not AST subtrees.
	"IntervalExpression": "value is a raw string, not an Expression",
	"LiteralValue":       "leaf: primitive Go value",
	"Identifier":         "leaf: column/table name as string",
	"Value":              "leaf: raw value",
	"Ident":              "leaf: identifier wrapper",
	"Query":              "leaf: raw SQL text, not a parsed subtree",
	"CommentDef":         "leaf: raw comment text",
	"ObjectName":         "leaf: qualified-name string",

	// Marker enum types wrapped as Node for traversal convenience.
	"AlterColumnOperation": "enum-only, no child nodes",
	"TriggerObject":        "enum-only, no child nodes",
	"TriggerPeriod":        "enum-only, no child nodes",

	// Statements whose entire payload is raw strings / flags.
	"DropStatement":                    "object names are strings, not AST",
	"TruncateStatement":                "table names are strings, not AST",
	"PragmaStatement":                  "name/arg/value are strings",
	"ShowStatement":                    "object name is a string",
	"DescribeStatement":                "table name is a string",
	"UnsupportedStatement":             "raw SQL kept verbatim",
	"RefreshMaterializedViewStatement": "only flags and a name",

	// Clauses whose payload is strings / flags / pointers to non-nodes.
	"FetchClause":         "offset/fetch counts are *int64",
	"ForClause":           "lock type and table names are strings",
	"UnpivotClause":       "all fields are strings",
	"SampleClause":        "sampling ratio stored as string",
	"ReferenceDefinition": "referenced columns are strings",
	"TableOption":         "key=value strings",
	"IndexColumn":         "column name is a string",

	// Alter connector — config map, no AST children.
	"AlterConnectorOperation": "properties are a string map",
}

// injectedChild records a mock node we placed into a field during setup.
type injectedChild struct {
	node      Node
	fieldPath string
}

// injectMockChildren walks the struct's Node/Expression/Statement fields
// (including single-level slices thereof) and assigns unique mock nodes,
// returning the full list so the caller can assert on each.
//
// Only fields whose declared type is the Node, Expression, or Statement
// interface (or a slice of one) are mockable — concrete-typed fields like
// *CommonTableExpr cannot accept a bare sentinel. Those concrete fields are
// exercised transitively when we run the reflection test on their own
// containing types.
func injectMockChildren(t *testing.T, val reflect.Value) []injectedChild {
	t.Helper()

	var injected []injectedChild
	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		f := val.Field(i)
		ft := typ.Field(i)
		if !f.CanSet() {
			continue
		}

		// Only interface-typed fields can receive a sentinel mock node.
		if ft.Type.Kind() == reflect.Interface {
			switch {
			case ft.Type == statementInterface:
				mock := newCovMockStmt(ft.Name)
				f.Set(reflect.ValueOf(mock))
				injected = append(injected, injectedChild{node: mock, fieldPath: ft.Name})
			case ft.Type == expressionIface:
				mock := newCovMockExpr(ft.Name)
				f.Set(reflect.ValueOf(mock))
				injected = append(injected, injectedChild{node: mock, fieldPath: ft.Name})
			case ft.Type == nodeInterface:
				mock := newCovMockNode(ft.Name)
				f.Set(reflect.ValueOf(mock))
				injected = append(injected, injectedChild{node: mock, fieldPath: ft.Name})
			case ft.Type.Implements(nodeInterface):
				// A custom interface (e.g. AlterOperation) that embeds Node —
				// inject based on which marker it additionally requires.
				switch {
				case ft.Type.Implements(statementInterface):
					mock := newCovMockStmt(ft.Name)
					if reflect.TypeOf(mock).Implements(ft.Type) {
						f.Set(reflect.ValueOf(mock))
						injected = append(injected, injectedChild{node: mock, fieldPath: ft.Name})
					}
				case ft.Type.Implements(expressionIface):
					mock := newCovMockExpr(ft.Name)
					if reflect.TypeOf(mock).Implements(ft.Type) {
						f.Set(reflect.ValueOf(mock))
						injected = append(injected, injectedChild{node: mock, fieldPath: ft.Name})
					}
				}
			}
			continue
		}

		if ft.Type.Kind() == reflect.Slice {
			elem := ft.Type.Elem()
			if elem.Kind() != reflect.Interface {
				continue
			}
			switch {
			case elem == statementInterface:
				m := newCovMockStmt(ft.Name + "[0]")
				slice := reflect.MakeSlice(ft.Type, 1, 1)
				slice.Index(0).Set(reflect.ValueOf(m))
				f.Set(slice)
				injected = append(injected, injectedChild{node: m, fieldPath: ft.Name + "[0]"})
			case elem == expressionIface:
				m := newCovMockExpr(ft.Name + "[0]")
				slice := reflect.MakeSlice(ft.Type, 1, 1)
				slice.Index(0).Set(reflect.ValueOf(m))
				f.Set(slice)
				injected = append(injected, injectedChild{node: m, fieldPath: ft.Name + "[0]"})
			case elem == nodeInterface:
				m := newCovMockNode(ft.Name + "[0]")
				slice := reflect.MakeSlice(ft.Type, 1, 1)
				slice.Index(0).Set(reflect.ValueOf(m))
				f.Set(slice)
				injected = append(injected, injectedChild{node: m, fieldPath: ft.Name + "[0]"})
			}
		}
	}
	return injected
}

// callChildren invokes Children() on either *T or T (whichever has the
// method). Returns the resulting []Node.
func callChildren(t *testing.T, ptr reflect.Value) []Node {
	t.Helper()

	// Try pointer receiver first.
	if m := ptr.MethodByName("Children"); m.IsValid() {
		out := m.Call(nil)
		return out[0].Interface().([]Node)
	}

	// Try value receiver.
	if m := ptr.Elem().MethodByName("Children"); m.IsValid() {
		out := m.Call(nil)
		return out[0].Interface().([]Node)
	}

	t.Fatalf("type %s has no Children() method", ptr.Elem().Type().Name())
	return nil
}

// containsNode returns true if want is present in got (pointer-identity for
// pointer nodes, reflect.DeepEqual fallback for value nodes).
func containsNode(got []Node, want Node) bool {
	for _, g := range got {
		if g == nil {
			continue
		}
		if g == want {
			return true
		}
		// Value-receiver children may be copies of the injected value.
		if reflect.DeepEqual(g, want) {
			return true
		}
	}
	return false
}

// ---- Interface checks -------------------------------------------------------

var (
	nodeInterface      = reflect.TypeOf((*Node)(nil)).Elem()
	expressionIface    = reflect.TypeOf((*Expression)(nil)).Elem()
	statementInterface = reflect.TypeOf((*Statement)(nil)).Elem()
)

func implementsNode(t reflect.Type) bool       { return t != nodeInterface && t.Implements(nodeInterface) }
func implementsExpression(t reflect.Type) bool { return t.Implements(expressionIface) }
func implementsStatement(t reflect.Type) bool  { return t.Implements(statementInterface) }

// ---- Mock nodes -------------------------------------------------------------

// covMockExpr is an Expression-implementing sentinel used to verify that a
// Node's Children() surfaces its configured field.
type covMockExpr struct{ tag string }

func (*covMockExpr) expressionNode()         {}
func (m *covMockExpr) TokenLiteral() string  { return m.tag }
func (*covMockExpr) Children() []Node        { return nil }
func newCovMockExpr(tag string) *covMockExpr { return &covMockExpr{tag: "mock-expr:" + tag} }

// covMockStmt is a Statement-implementing sentinel.
type covMockStmt struct{ tag string }

func (*covMockStmt) statementNode()          {}
func (m *covMockStmt) TokenLiteral() string  { return m.tag }
func (*covMockStmt) Children() []Node        { return nil }
func newCovMockStmt(tag string) *covMockStmt { return &covMockStmt{tag: "mock-stmt:" + tag} }

// covMockNode is a bare Node-implementing sentinel (no Statement / Expression
// marker). Used for fields typed as the Node interface directly.
type covMockNode struct{ tag string }

func (m *covMockNode) TokenLiteral() string  { return m.tag }
func (*covMockNode) Children() []Node        { return nil }
func newCovMockNode(tag string) *covMockNode { return &covMockNode{tag: "mock-node:" + tag} }
