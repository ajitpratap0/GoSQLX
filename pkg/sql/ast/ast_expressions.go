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
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// RollupExpression represents ROLLUP(col1, col2, ...) in GROUP BY clause
// ROLLUP generates hierarchical grouping sets from right to left
// Example: ROLLUP(a, b, c) generates grouping sets:
//
//	(a, b, c), (a, b), (a), ()
type RollupExpression struct {
	Expressions []Expression
}

func (r *RollupExpression) expressionNode()     {}
func (r RollupExpression) TokenLiteral() string { return "ROLLUP" }
func (r RollupExpression) Children() []Node     { return nodifyExpressions(r.Expressions) }

// CubeExpression represents CUBE(col1, col2, ...) in GROUP BY clause
// CUBE generates all possible combinations of grouping sets
// Example: CUBE(a, b) generates grouping sets:
//
//	(a, b), (a), (b), ()
type CubeExpression struct {
	Expressions []Expression
}

func (c *CubeExpression) expressionNode()     {}
func (c CubeExpression) TokenLiteral() string { return "CUBE" }
func (c CubeExpression) Children() []Node     { return nodifyExpressions(c.Expressions) }

// GroupingSetsExpression represents GROUPING SETS(...) in GROUP BY clause
// Allows explicit specification of grouping sets
// Example: GROUPING SETS((a, b), (a), ())
type GroupingSetsExpression struct {
	Sets [][]Expression // Each inner slice is one grouping set
}

func (g *GroupingSetsExpression) expressionNode()     {}
func (g GroupingSetsExpression) TokenLiteral() string { return "GROUPING SETS" }
func (g GroupingSetsExpression) Children() []Node {
	children := make([]Node, 0)
	for _, set := range g.Sets {
		children = append(children, nodifyExpressions(set)...)
	}
	return children
}

// FunctionCall represents a function call expression with full SQL-99/PostgreSQL support.
//
// FunctionCall supports:
//   - Scalar functions: UPPER(), LOWER(), COALESCE(), etc.
//   - Aggregate functions: COUNT(), SUM(), AVG(), MAX(), MIN(), etc.
//   - Window functions: ROW_NUMBER(), RANK(), DENSE_RANK(), LAG(), LEAD(), etc.
//   - DISTINCT modifier: COUNT(DISTINCT column)
//   - FILTER clause: Conditional aggregation (PostgreSQL v1.6.0)
//   - ORDER BY clause: For order-sensitive aggregates like STRING_AGG, ARRAY_AGG (v1.6.0)
//   - OVER clause: Window specifications for window functions
//
// Fields:
//   - Name: Function name (e.g., "COUNT", "SUM", "ROW_NUMBER")
//   - Arguments: Function arguments (expressions)
//   - Over: Window specification for window functions (OVER clause)
//   - Distinct: DISTINCT modifier for aggregates (COUNT(DISTINCT col))
//   - Filter: FILTER clause for conditional aggregation (PostgreSQL v1.6.0)
//   - OrderBy: ORDER BY clause for order-sensitive aggregates (v1.6.0)
//
// Example - Basic aggregate:
//
//	FunctionCall{
//	    Name:      "COUNT",
//	    Arguments: []Expression{&Identifier{Name: "id"}},
//	}
//	// SQL: COUNT(id)
//
// Example - Window function:
//
//	FunctionCall{
//	    Name: "ROW_NUMBER",
//	    Over: &WindowSpec{
//	        PartitionBy: []Expression{&Identifier{Name: "dept_id"}},
//	        OrderBy:     []OrderByExpression{{Expression: &Identifier{Name: "salary"}, Ascending: false}},
//	    },
//	}
//	// SQL: ROW_NUMBER() OVER (PARTITION BY dept_id ORDER BY salary DESC)
//
// Example - FILTER clause (PostgreSQL v1.6.0):
//
//	FunctionCall{
//	    Name:      "COUNT",
//	    Arguments: []Expression{&Identifier{Name: "id"}},
//	    Filter:    &BinaryExpression{Left: &Identifier{Name: "status"}, Operator: "=", Right: &LiteralValue{Value: "active"}},
//	}
//	// SQL: COUNT(id) FILTER (WHERE status = 'active')
//
// Example - ORDER BY in aggregate (PostgreSQL v1.6.0):
//
//	FunctionCall{
//	    Name:      "STRING_AGG",
//	    Arguments: []Expression{&Identifier{Name: "name"}, &LiteralValue{Value: ", "}},
//	    OrderBy:   []OrderByExpression{{Expression: &Identifier{Name: "name"}, Ascending: true}},
//	}
//	// SQL: STRING_AGG(name, ', ' ORDER BY name)
//
// Example - Window function with frame:
//
//	FunctionCall{
//	    Name:      "AVG",
//	    Arguments: []Expression{&Identifier{Name: "amount"}},
//	    Over: &WindowSpec{
//	        OrderBy: []OrderByExpression{{Expression: &Identifier{Name: "date"}, Ascending: true}},
//	        FrameClause: &WindowFrame{
//	            Type:  "ROWS",
//	            Start: WindowFrameBound{Type: "2 PRECEDING"},
//	            End:   &WindowFrameBound{Type: "CURRENT ROW"},
//	        },
//	    },
//	}
//	// SQL: AVG(amount) OVER (ORDER BY date ROWS BETWEEN 2 PRECEDING AND CURRENT ROW)
//
// New in v1.6.0:
//   - Filter: FILTER clause for conditional aggregation
//   - OrderBy: ORDER BY clause for order-sensitive aggregates (STRING_AGG, ARRAY_AGG, etc.)
//   - WithinGroup: ORDER BY clause for ordered-set aggregates (PERCENTILE_CONT, PERCENTILE_DISC, MODE, etc.)
type FunctionCall struct {
	Name          string
	Arguments     []Expression // Renamed from Args for consistency
	Parameters    []Expression // ClickHouse parametric aggregates: quantile(0.5)(x) — params before args
	Over          *WindowSpec  // For window functions
	Distinct      bool
	Filter        Expression          // WHERE clause for aggregate functions
	OrderBy       []OrderByExpression // ORDER BY clause for aggregate functions (STRING_AGG, ARRAY_AGG, etc.)
	WithinGroup   []OrderByExpression // ORDER BY clause for ordered-set aggregates (PERCENTILE_CONT, etc.)
	NullTreatment string              // "IGNORE NULLS" or "RESPECT NULLS" on window functions (Snowflake, Oracle, BigQuery, SQL:2016)
	Pos           models.Location     // Source position of the function name (1-based line and column)
}

func (f *FunctionCall) expressionNode()     {}
func (f FunctionCall) TokenLiteral() string { return f.Name }
func (f FunctionCall) Children() []Node {
	children := nodifyExpressions(f.Arguments)
	if len(f.Parameters) > 0 {
		children = append(children, nodifyExpressions(f.Parameters)...)
	}
	if f.Over != nil {
		children = append(children, f.Over)
	}
	if f.Filter != nil {
		children = append(children, f.Filter)
	}
	for _, orderBy := range f.OrderBy {
		orderBy := orderBy // G601: Create local copy to avoid memory aliasing
		children = append(children, &orderBy)
	}
	for _, orderBy := range f.WithinGroup {
		orderBy := orderBy // G601: Create local copy to avoid memory aliasing
		children = append(children, &orderBy)
	}
	return children
}

// CaseExpression represents a CASE expression
type CaseExpression struct {
	Value       Expression // Optional CASE value
	WhenClauses []WhenClause
	ElseClause  Expression
	Pos         models.Location // Source position of the CASE keyword (1-based line and column)
}

func (c *CaseExpression) expressionNode()     {}
func (c CaseExpression) TokenLiteral() string { return "CASE" }
func (c CaseExpression) Children() []Node {
	children := make([]Node, 0)
	if c.Value != nil {
		children = append(children, c.Value)
	}
	for _, when := range c.WhenClauses {
		when := when // G601: Create local copy to avoid memory aliasing
		children = append(children, &when)
	}
	if c.ElseClause != nil {
		children = append(children, c.ElseClause)
	}
	return children
}

// WhenClause represents WHEN ... THEN ... in CASE expression
type WhenClause struct {
	Condition Expression
	Result    Expression
	Pos       models.Location // Source position of the WHEN keyword (1-based line and column)
}

func (w *WhenClause) expressionNode()     {}
func (w WhenClause) TokenLiteral() string { return "WHEN" }
func (w WhenClause) Children() []Node {
	var nodes []Node
	if w.Condition != nil {
		nodes = append(nodes, w.Condition)
	}
	if w.Result != nil {
		nodes = append(nodes, w.Result)
	}
	return nodes
}

// ExistsExpression represents EXISTS (subquery)
type ExistsExpression struct {
	Subquery Statement
}

func (e *ExistsExpression) expressionNode()     {}
func (e ExistsExpression) TokenLiteral() string { return "EXISTS" }
func (e ExistsExpression) Children() []Node {
	if e.Subquery == nil {
		return nil
	}
	return []Node{e.Subquery}
}

// InExpression represents expr IN (values) or expr IN (subquery)
type InExpression struct {
	Expr     Expression
	List     []Expression // For value list: IN (1, 2, 3)
	Subquery Statement    // For subquery: IN (SELECT ...)
	Not      bool
	Pos      models.Location // Source position of the IN keyword (1-based line and column)
}

func (i *InExpression) expressionNode()     {}
func (i InExpression) TokenLiteral() string { return "IN" }
func (i InExpression) Children() []Node {
	var children []Node
	if i.Expr != nil {
		children = append(children, i.Expr)
	}
	if i.Subquery != nil {
		children = append(children, i.Subquery)
	}
	children = append(children, nodifyExpressions(i.List)...)
	return children
}

// SubqueryExpression represents a scalar subquery (SELECT ...)
type SubqueryExpression struct {
	Subquery Statement
	Pos      models.Location // Source position of the opening parenthesis (1-based line and column)
}

func (s *SubqueryExpression) expressionNode()     {}
func (s SubqueryExpression) TokenLiteral() string { return "SUBQUERY" }
func (s SubqueryExpression) Children() []Node {
	if s.Subquery == nil {
		return nil
	}
	return []Node{s.Subquery}
}

// AnyExpression represents expr op ANY (subquery)
type AnyExpression struct {
	Expr     Expression
	Operator string
	Subquery Statement
}

func (a *AnyExpression) expressionNode()     {}
func (a AnyExpression) TokenLiteral() string { return "ANY" }
func (a AnyExpression) Children() []Node {
	var nodes []Node
	if a.Expr != nil {
		nodes = append(nodes, a.Expr)
	}
	if a.Subquery != nil {
		nodes = append(nodes, a.Subquery)
	}
	return nodes
}

// AllExpression represents expr op ALL (subquery)
type AllExpression struct {
	Expr     Expression
	Operator string
	Subquery Statement
}

func (al *AllExpression) expressionNode()     {}
func (al AllExpression) TokenLiteral() string { return "ALL" }
func (al AllExpression) Children() []Node {
	var nodes []Node
	if al.Expr != nil {
		nodes = append(nodes, al.Expr)
	}
	if al.Subquery != nil {
		nodes = append(nodes, al.Subquery)
	}
	return nodes
}

// BetweenExpression represents expr BETWEEN lower AND upper
type BetweenExpression struct {
	Expr  Expression
	Lower Expression
	Upper Expression
	Not   bool
	Pos   models.Location // Source position of the BETWEEN keyword (1-based line and column)
}

func (b *BetweenExpression) expressionNode()     {}
func (b BetweenExpression) TokenLiteral() string { return "BETWEEN" }
func (b BetweenExpression) Children() []Node {
	var nodes []Node
	if b.Expr != nil {
		nodes = append(nodes, b.Expr)
	}
	if b.Lower != nil {
		nodes = append(nodes, b.Lower)
	}
	if b.Upper != nil {
		nodes = append(nodes, b.Upper)
	}
	return nodes
}

// BinaryExpression represents binary operations between two expressions.
//
// BinaryExpression supports all standard SQL binary operators plus PostgreSQL-specific
// operators including JSON/JSONB operators added in v1.6.0.
//
// Fields:
//   - Left: Left-hand side expression
//   - Operator: Binary operator (=, <, >, +, -, *, /, AND, OR, ->, #>, etc.)
//   - Right: Right-hand side expression
//   - Not: NOT modifier for negation (NOT expr)
//   - CustomOp: PostgreSQL custom operators (OPERATOR(schema.name))
//
// Supported Operator Categories:
//   - Comparison: =, <>, <, >, <=, >=, <=> (spaceship)
//   - Arithmetic: +, -, *, /, %, DIV, // (integer division)
//   - Logical: AND, OR, XOR
//   - String: || (concatenation)
//   - Bitwise: &, |, ^, <<, >> (shifts)
//   - Pattern: LIKE, ILIKE, SIMILAR TO
//   - Range: OVERLAPS
//   - PostgreSQL JSON/JSONB (v1.6.0): ->, ->>, #>, #>>, @>, <@, ?, ?|, ?&, #-
//
// Example - Basic comparison:
//
//	BinaryExpression{
//	    Left:     &Identifier{Name: "age"},
//	    Operator: ">",
//	    Right:    &LiteralValue{Value: 18, Type: "INTEGER"},
//	}
//	// SQL: age > 18
//
// Example - Logical AND:
//
//	BinaryExpression{
//	    Left: &BinaryExpression{
//	        Left:     &Identifier{Name: "active"},
//	        Operator: "=",
//	        Right:    &LiteralValue{Value: true, Type: "BOOLEAN"},
//	    },
//	    Operator: "AND",
//	    Right: &BinaryExpression{
//	        Left:     &Identifier{Name: "status"},
//	        Operator: "=",
//	        Right:    &LiteralValue{Value: "pending", Type: "STRING"},
//	    },
//	}
//	// SQL: active = true AND status = 'pending'
//
// Example - PostgreSQL JSON operator -> (v1.6.0):
//
//	BinaryExpression{
//	    Left:     &Identifier{Name: "data"},
//	    Operator: "->",
//	    Right:    &LiteralValue{Value: "name", Type: "STRING"},
//	}
//	// SQL: data->'name'
//
// Example - PostgreSQL JSON operator ->> (v1.6.0):
//
//	BinaryExpression{
//	    Left:     &Identifier{Name: "data"},
//	    Operator: "->>",
//	    Right:    &LiteralValue{Value: "email", Type: "STRING"},
//	}
//	// SQL: data->>'email'  (returns text)
//
// Example - PostgreSQL JSON contains @> (v1.6.0):
//
//	BinaryExpression{
//	    Left:     &Identifier{Name: "attributes"},
//	    Operator: "@>",
//	    Right:    &LiteralValue{Value: `{"color": "red"}`, Type: "STRING"},
//	}
//	// SQL: attributes @> '{"color": "red"}'
//
// Example - PostgreSQL JSON key exists ? (v1.6.0):
//
//	BinaryExpression{
//	    Left:     &Identifier{Name: "profile"},
//	    Operator: "?",
//	    Right:    &LiteralValue{Value: "email", Type: "STRING"},
//	}
//	// SQL: profile ? 'email'
//
// Example - Custom PostgreSQL operator:
//
//	BinaryExpression{
//	    Left:     &Identifier{Name: "point1"},
//	    Operator: "",
//	    Right:    &Identifier{Name: "point2"},
//	    CustomOp: &CustomBinaryOperator{Parts: []string{"pg_catalog", "<->"}},
//	}
//	// SQL: point1 OPERATOR(pg_catalog.<->) point2
//
// New in v1.6.0:
//   - JSON/JSONB operators: ->, ->>, #>, #>>, @>, <@, ?, ?|, ?&, #-
//   - CustomOp field for PostgreSQL custom operators
//
// PostgreSQL JSON/JSONB Operator Reference:
//   - -> (Arrow): Extract JSON field or array element (returns JSON)
//   - ->> (LongArrow): Extract JSON field or array element as text
//   - #> (HashArrow): Extract JSON at path (returns JSON)
//   - #>> (HashLongArrow): Extract JSON at path as text
//   - @> (AtArrow): JSON contains (does left JSON contain right?)
//   - <@ (ArrowAt): JSON is contained by (is left JSON contained in right?)
//   - ? (Question): JSON key exists
//   - ?| (QuestionPipe): Any of the keys exist
//   - ?& (QuestionAnd): All of the keys exist
//   - #- (HashMinus): Delete key from JSON
type BinaryExpression struct {
	Left     Expression
	Operator string
	Right    Expression
	Not      bool                  // For NOT (expr)
	CustomOp *CustomBinaryOperator // For PostgreSQL custom operators
	Pos      models.Location       // Source position of the operator (1-based line and column)
}

func (b *BinaryExpression) expressionNode() {}

func (b *BinaryExpression) TokenLiteral() string {
	if b.CustomOp != nil {
		return b.CustomOp.String()
	}
	return b.Operator
}

func (b BinaryExpression) Children() []Node {
	var nodes []Node
	if b.Left != nil {
		nodes = append(nodes, b.Left)
	}
	if b.Right != nil {
		nodes = append(nodes, b.Right)
	}
	return nodes
}

// ListExpression represents a list of expressions (1, 2, 3)
type ListExpression struct {
	Values []Expression
}

func (l *ListExpression) expressionNode()     {}
func (l ListExpression) TokenLiteral() string { return "LIST" }
func (l ListExpression) Children() []Node     { return nodifyExpressions(l.Values) }

// TupleExpression represents a row constructor / tuple (col1, col2) for multi-column comparisons
// Used in: WHERE (user_id, status) IN ((1, 'active'), (2, 'pending'))
type TupleExpression struct {
	Expressions []Expression
}

func (t *TupleExpression) expressionNode()     {}
func (t TupleExpression) TokenLiteral() string { return "TUPLE" }
func (t TupleExpression) Children() []Node     { return nodifyExpressions(t.Expressions) }

// ArrayConstructorExpression represents PostgreSQL ARRAY constructor syntax.
// Creates an array value from a list of expressions or a subquery.
//
// Examples:
//
//	ARRAY[1, 2, 3]                    - Integer array literal
//	ARRAY['admin', 'moderator']      - Text array literal
//	ARRAY(SELECT id FROM users)      - Array from subquery
type ArrayConstructorExpression struct {
	Elements []Expression     // Elements inside ARRAY[...]
	Subquery *SelectStatement // For ARRAY(SELECT ...) syntax (optional)
}

func (a *ArrayConstructorExpression) expressionNode()     {}
func (a ArrayConstructorExpression) TokenLiteral() string { return "ARRAY" }
func (a ArrayConstructorExpression) Children() []Node {
	if a.Subquery != nil {
		return []Node{a.Subquery}
	}
	return nodifyExpressions(a.Elements)
}

// UnaryExpression represents operations like NOT expr
type UnaryExpression struct {
	Operator UnaryOperator
	Expr     Expression
	Pos      models.Location // Source position of the operator (1-based line and column)
}

func (u *UnaryExpression) expressionNode() {}

func (u *UnaryExpression) TokenLiteral() string {
	return u.Operator.String()
}

func (u UnaryExpression) Children() []Node {
	if u.Expr == nil {
		return nil
	}
	return []Node{u.Expr}
}

// VariantPath represents a Snowflake VARIANT path expression:
//
//	col:field.sub[0]::string
//
// The Root is the base expression (typically an Identifier or FunctionCall
// like PARSE_JSON(raw)). Segments is the chain of path steps that follow
// the leading `:`. Each segment is either a field name (Name set) or a
// bracketed index expression (Index set).
type VariantPath struct {
	Root     Expression
	Segments []VariantPathSegment
	Pos      models.Location
}

// VariantPathSegment is one step in a VARIANT path: either a field name
// reached via `:` or `.`, or a bracketed index expression.
type VariantPathSegment struct {
	Name  string     // field name (`:field` or `.field`), empty when Index is set
	Index Expression // bracket subscript (`[expr]`), nil when Name is set
}

func (v *VariantPath) expressionNode()     {}
func (v VariantPath) TokenLiteral() string { return ":" }
func (v VariantPath) Children() []Node {
	var nodes []Node
	if v.Root != nil {
		nodes = append(nodes, v.Root)
	}
	for _, seg := range v.Segments {
		if seg.Index != nil {
			nodes = append(nodes, seg.Index)
		}
	}
	return nodes
}

// NamedArgument represents a function argument of the form `name => expr`,
// used by Snowflake (FLATTEN(input => col), GENERATOR(rowcount => 100)),
// BigQuery, Oracle, and PostgreSQL procedural calls.
type NamedArgument struct {
	Name  string
	Value Expression
	Pos   models.Location
}

func (n *NamedArgument) expressionNode()     {}
func (n NamedArgument) TokenLiteral() string { return n.Name }
func (n NamedArgument) Children() []Node {
	if n.Value == nil {
		return nil
	}
	return []Node{n.Value}
}

// CastExpression represents CAST(expr AS type) or TRY_CAST(expr AS type).
// Try is set when the expression originated from TRY_CAST (Snowflake / SQL
// Server / BigQuery), which returns NULL on conversion failure instead of
// raising an error.
type CastExpression struct {
	Expr Expression
	Type string
	Try  bool
}

func (c *CastExpression) expressionNode() {}
func (c CastExpression) TokenLiteral() string {
	if c.Try {
		return "TRY_CAST"
	}
	return "CAST"
}
func (c CastExpression) Children() []Node {
	if c.Expr == nil {
		return nil
	}
	return []Node{c.Expr}
}

// AliasedExpression represents an expression with an alias (expr AS alias)
type AliasedExpression struct {
	Expr  Expression
	Alias string
}

func (a *AliasedExpression) expressionNode()     {}
func (a AliasedExpression) TokenLiteral() string { return a.Alias }
func (a AliasedExpression) Children() []Node {
	if a.Expr == nil {
		return nil
	}
	return []Node{a.Expr}
}

// ExtractExpression represents EXTRACT(field FROM source)
type ExtractExpression struct {
	Field  string
	Source Expression
}

func (e *ExtractExpression) expressionNode()     {}
func (e ExtractExpression) TokenLiteral() string { return "EXTRACT" }
func (e ExtractExpression) Children() []Node {
	if e.Source == nil {
		return nil
	}
	return []Node{e.Source}
}

// PositionExpression represents POSITION(substr IN str)
type PositionExpression struct {
	Substr Expression
	Str    Expression
}

func (p *PositionExpression) expressionNode()     {}
func (p PositionExpression) TokenLiteral() string { return "POSITION" }
func (p PositionExpression) Children() []Node {
	var nodes []Node
	if p.Substr != nil {
		nodes = append(nodes, p.Substr)
	}
	if p.Str != nil {
		nodes = append(nodes, p.Str)
	}
	return nodes
}

// SubstringExpression represents SUBSTRING(str FROM start [FOR length])
type SubstringExpression struct {
	Str    Expression
	Start  Expression
	Length Expression
}

func (s *SubstringExpression) expressionNode()     {}
func (s SubstringExpression) TokenLiteral() string { return "SUBSTRING" }
func (s SubstringExpression) Children() []Node {
	children := []Node{s.Str, s.Start}
	if s.Length != nil {
		children = append(children, s.Length)
	}
	return children
}

// IntervalExpression represents INTERVAL 'value' for date/time arithmetic
// Examples: INTERVAL '1 day', INTERVAL '2 hours', INTERVAL '1 year 2 months'
type IntervalExpression struct {
	Value string // The interval specification string (e.g., '1 day', '2 hours')
}

func (i *IntervalExpression) expressionNode()     {}
func (i IntervalExpression) TokenLiteral() string { return "INTERVAL" }

// Children implements Node. IntervalExpression stores its value as a raw
// string (not an Expression), so it has no child nodes. Returns nil for
// consistency with other leaf nodes.
func (i IntervalExpression) Children() []Node { return nil }

// ArraySubscriptExpression represents array element access syntax.
// Supports single and multi-dimensional array subscripting.
//
// Examples:
//
//	tags[1]              - Single subscript
//	matrix[2][3]         - Multi-dimensional subscript
//	arr[i]               - Subscript with variable
//	(SELECT arr)[1]      - Subscript on subquery result
type ArraySubscriptExpression struct {
	Array   Expression   // The array expression being subscripted
	Indices []Expression // Subscript indices (one or more for multi-dimensional arrays)
}

func (a *ArraySubscriptExpression) expressionNode()     {}
func (a ArraySubscriptExpression) TokenLiteral() string { return "[]" }
func (a ArraySubscriptExpression) Children() []Node {
	var children []Node
	if a.Array != nil {
		children = append(children, a.Array)
	}
	for _, idx := range a.Indices {
		if idx != nil {
			children = append(children, idx)
		}
	}
	return children
}

// ArraySliceExpression represents array slicing syntax for extracting subarrays.
// Supports PostgreSQL-style array slicing with optional start/end bounds.
//
// Examples:
//
//	arr[1:3]    - Slice from index 1 to 3 (inclusive)
//	arr[2:]     - Slice from index 2 to end
//	arr[:5]     - Slice from start to index 5
//	arr[:]      - Full array slice (copy)
type ArraySliceExpression struct {
	Array Expression // The array expression being sliced
	Start Expression // Start index (nil means from beginning)
	End   Expression // End index (nil means to end)
}

func (a *ArraySliceExpression) expressionNode()     {}
func (a ArraySliceExpression) TokenLiteral() string { return "[:]" }
func (a ArraySliceExpression) Children() []Node {
	var children []Node
	if a.Array != nil {
		children = append(children, a.Array)
	}
	if a.Start != nil {
		children = append(children, a.Start)
	}
	if a.End != nil {
		children = append(children, a.End)
	}
	return children
}

// UpdateExpression represents a column=value expression in UPDATE
type UpdateExpression struct {
	Column Expression
	Value  Expression
}

func (u *UpdateExpression) expressionNode()     {}
func (u UpdateExpression) TokenLiteral() string { return "=" }
func (u UpdateExpression) Children() []Node {
	var nodes []Node
	if u.Column != nil {
		nodes = append(nodes, u.Column)
	}
	if u.Value != nil {
		nodes = append(nodes, u.Value)
	}
	return nodes
}
