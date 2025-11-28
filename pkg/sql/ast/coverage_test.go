package ast

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// TestPutExpressionAllTypes tests PutExpression with all expression types
func TestPutExpressionAllTypes(t *testing.T) {
	t.Run("nil expression", func(t *testing.T) {
		// Should not panic
		PutExpression(nil)
	})

	t.Run("Identifier", func(t *testing.T) {
		id := GetIdentifier()
		id.Name = "test_col"
		PutExpression(id)
	})

	t.Run("BinaryExpression with children", func(t *testing.T) {
		left := GetIdentifier()
		left.Name = "a"
		right := GetIdentifier()
		right.Name = "b"
		expr := GetBinaryExpression()
		expr.Left = left
		expr.Right = right
		expr.Operator = "="
		PutExpression(expr)
	})

	t.Run("BinaryExpression with nil children", func(t *testing.T) {
		expr := GetBinaryExpression()
		expr.Operator = "+"
		PutExpression(expr)
	})

	t.Run("LiteralValue", func(t *testing.T) {
		lit := GetLiteralValue()
		lit.Value = "test"
		lit.Type = "string"
		PutExpression(lit)
	})

	t.Run("FunctionCall with arguments", func(t *testing.T) {
		fn := GetFunctionCall()
		fn.Name = "COUNT"
		fn.Arguments = []Expression{
			&Identifier{Name: "col1"},
			&LiteralValue{Value: 1, Type: "int"},
		}
		fn.Distinct = true
		PutExpression(fn)
	})

	t.Run("FunctionCall empty arguments", func(t *testing.T) {
		fn := GetFunctionCall()
		fn.Name = "NOW"
		PutExpression(fn)
	})

	t.Run("CaseExpression full", func(t *testing.T) {
		caseExpr := GetCaseExpression()
		caseExpr.Value = &Identifier{Name: "status"}
		caseExpr.WhenClauses = []WhenClause{
			{
				Condition: &LiteralValue{Value: 1, Type: "int"},
				Result:    &LiteralValue{Value: "one", Type: "string"},
			},
			{
				Condition: &LiteralValue{Value: 2, Type: "int"},
				Result:    &LiteralValue{Value: "two", Type: "string"},
			},
		}
		caseExpr.ElseClause = &LiteralValue{Value: "unknown", Type: "string"}
		PutExpression(caseExpr)
	})

	t.Run("CaseExpression nil value", func(t *testing.T) {
		caseExpr := GetCaseExpression()
		caseExpr.WhenClauses = []WhenClause{
			{
				Condition: &BinaryExpression{Left: &Identifier{Name: "x"}, Operator: ">", Right: &LiteralValue{Value: 0}},
				Result:    &LiteralValue{Value: "positive", Type: "string"},
			},
		}
		PutExpression(caseExpr)
	})

	t.Run("BetweenExpression", func(t *testing.T) {
		between := GetBetweenExpression()
		between.Expr = &Identifier{Name: "age"}
		between.Lower = &LiteralValue{Value: 18, Type: "int"}
		between.Upper = &LiteralValue{Value: 65, Type: "int"}
		between.Not = false
		PutExpression(between)
	})

	t.Run("BetweenExpression nil fields", func(t *testing.T) {
		between := GetBetweenExpression()
		between.Not = true
		PutExpression(between)
	})

	t.Run("InExpression with list", func(t *testing.T) {
		inExpr := GetInExpression()
		inExpr.Expr = &Identifier{Name: "status"}
		inExpr.List = []Expression{
			&LiteralValue{Value: "active", Type: "string"},
			&LiteralValue{Value: "pending", Type: "string"},
		}
		inExpr.Not = false
		PutExpression(inExpr)
	})

	t.Run("InExpression with subquery", func(t *testing.T) {
		inExpr := GetInExpression()
		inExpr.Expr = &Identifier{Name: "id"}
		inExpr.Subquery = &SelectStatement{}
		inExpr.Not = true
		PutExpression(inExpr)
	})

	t.Run("SubqueryExpression", func(t *testing.T) {
		subq := GetSubqueryExpression()
		subq.Subquery = &SelectStatement{}
		PutExpression(subq)
	})

	t.Run("CastExpression", func(t *testing.T) {
		cast := GetCastExpression()
		cast.Expr = &Identifier{Name: "price"}
		cast.Type = "DECIMAL(10,2)"
		PutExpression(cast)
	})

	t.Run("CastExpression nil expr", func(t *testing.T) {
		cast := GetCastExpression()
		cast.Type = "INTEGER"
		PutExpression(cast)
	})

	t.Run("ExistsExpression", func(t *testing.T) {
		exists := &ExistsExpression{}
		exists.Subquery = &SelectStatement{}
		PutExpression(exists)
	})

	t.Run("AnyExpression", func(t *testing.T) {
		any := &AnyExpression{}
		any.Expr = &Identifier{Name: "col"}
		any.Subquery = &SelectStatement{}
		any.Operator = "="
		PutExpression(any)
	})

	t.Run("AnyExpression nil expr", func(t *testing.T) {
		any := &AnyExpression{}
		any.Operator = ">"
		PutExpression(any)
	})

	t.Run("AllExpression", func(t *testing.T) {
		all := &AllExpression{}
		all.Expr = &Identifier{Name: "value"}
		all.Subquery = &SelectStatement{}
		all.Operator = "<"
		PutExpression(all)
	})

	t.Run("AllExpression nil expr", func(t *testing.T) {
		all := &AllExpression{}
		all.Operator = ">="
		PutExpression(all)
	})

	t.Run("ListExpression", func(t *testing.T) {
		list := &ListExpression{}
		list.Values = []Expression{
			&LiteralValue{Value: 1},
			&LiteralValue{Value: 2},
			&LiteralValue{Value: 3},
		}
		PutExpression(list)
	})

	t.Run("ListExpression empty", func(t *testing.T) {
		list := &ListExpression{}
		PutExpression(list)
	})

	t.Run("UnaryExpression", func(t *testing.T) {
		unary := &UnaryExpression{}
		unary.Operator = Minus
		unary.Expr = &Identifier{Name: "balance"}
		PutExpression(unary)
	})

	t.Run("UnaryExpression nil expr", func(t *testing.T) {
		unary := &UnaryExpression{}
		unary.Operator = Not
		PutExpression(unary)
	})

	t.Run("ExtractExpression", func(t *testing.T) {
		extract := &ExtractExpression{}
		extract.Field = "YEAR"
		extract.Source = &Identifier{Name: "created_at"}
		PutExpression(extract)
	})

	t.Run("ExtractExpression nil source", func(t *testing.T) {
		extract := &ExtractExpression{}
		extract.Field = "MONTH"
		PutExpression(extract)
	})

	t.Run("PositionExpression", func(t *testing.T) {
		pos := &PositionExpression{}
		pos.Substr = &LiteralValue{Value: "abc", Type: "string"}
		pos.Str = &Identifier{Name: "description"}
		PutExpression(pos)
	})

	t.Run("PositionExpression nil fields", func(t *testing.T) {
		pos := &PositionExpression{}
		PutExpression(pos)
	})

	t.Run("SubstringExpression", func(t *testing.T) {
		substr := &SubstringExpression{}
		substr.Str = &Identifier{Name: "name"}
		substr.Start = &LiteralValue{Value: 1, Type: "int"}
		substr.Length = &LiteralValue{Value: 10, Type: "int"}
		PutExpression(substr)
	})

	t.Run("SubstringExpression nil fields", func(t *testing.T) {
		substr := &SubstringExpression{}
		PutExpression(substr)
	})
}

// TestPutExpressionNestedDeep tests deeply nested expressions
func TestPutExpressionNestedDeep(t *testing.T) {
	// Create a moderately nested binary expression tree
	var createNested func(depth int) Expression
	createNested = func(depth int) Expression {
		if depth == 0 {
			return &Identifier{Name: "leaf"}
		}
		return &BinaryExpression{
			Left:     createNested(depth - 1),
			Right:    createNested(depth - 1),
			Operator: "+",
		}
	}

	// Test with various depths
	for _, depth := range []int{5, 10, 15} {
		t.Run("depth_"+string(rune('0'+depth/10))+string(rune('0'+depth%10)), func(t *testing.T) {
			expr := createNested(depth)
			PutExpression(expr) // Should not stack overflow
		})
	}
}

// TestSpanMethods tests Span() methods on various AST nodes
func TestSpanMethods(t *testing.T) {
	t.Run("SelectStatement span", func(t *testing.T) {
		sel := &SelectStatement{}
		span := sel.Span()
		// Without explicit span info, should return empty span
		if span.Start.Line != 0 || span.Start.Column != 0 {
			t.Errorf("expected empty span, got %+v", span)
		}
	})

	t.Run("SelectStatement with SetSpan", func(t *testing.T) {
		sel := &SelectStatement{}
		testSpan := models.Span{
			Start: models.Location{Line: 1, Column: 1},
			End:   models.Location{Line: 1, Column: 20},
		}
		SetSpan(sel, testSpan)
		span := sel.Span()
		if span.Start.Line != 1 || span.End.Column != 20 {
			t.Errorf("expected set span, got %+v", span)
		}
	})

	t.Run("InsertStatement span with columns and values", func(t *testing.T) {
		insert := &InsertStatement{
			TableName: "users",
			Columns: []Expression{
				&Identifier{Name: "id"},
				&Identifier{Name: "name"},
			},
			Values: []Expression{
				&LiteralValue{Value: 1},
				&LiteralValue{Value: "test"},
			},
		}
		span := insert.Span()
		// Should return combined span of components
		if span.Start.Line < 0 {
			t.Errorf("unexpected negative span line")
		}
	})

	t.Run("InsertStatement span with Query", func(t *testing.T) {
		insert := &InsertStatement{
			TableName: "archive",
			Query: &SelectStatement{
				Columns: []Expression{
					&Identifier{Name: "*"},
				},
			},
			Returning: []Expression{
				&Identifier{Name: "id"},
			},
		}
		span := insert.Span()
		_ = span // Should not panic
	})

	t.Run("UpdateStatement span", func(t *testing.T) {
		update := &UpdateStatement{
			TableName: "users",
		}
		span := update.Span()
		if span.Start.Line != 0 {
			t.Errorf("expected empty span without SetSpan")
		}
	})

	t.Run("DeleteStatement span", func(t *testing.T) {
		del := &DeleteStatement{
			TableName: "logs",
		}
		span := del.Span()
		if span.Start.Line != 0 {
			t.Errorf("expected empty span without SetSpan")
		}
	})

	t.Run("BinaryExpression span computes from children", func(t *testing.T) {
		// BinaryExpression.Span() computes by calling Span() on children recursively
		// Since Identifier doesn't implement Spanned, returns empty span
		left := &Identifier{Name: "a"}
		right := &Identifier{Name: "b"}

		expr := &BinaryExpression{
			Left:     left,
			Right:    right,
			Operator: "+",
		}
		span := expr.Span()
		// Should return empty span since Identifier doesn't implement Spanned
		if span.Start.Line != 0 {
			t.Errorf("expected empty span for non-Spanned children, got %+v", span)
		}
	})

	t.Run("BinaryExpression span nil children", func(t *testing.T) {
		expr := &BinaryExpression{
			Operator: "=",
		}
		span := expr.Span()
		// Should return empty span
		if span.Start.Line != 0 && span.Start.Column != 0 {
			t.Errorf("expected empty span for nil children")
		}
	})

	t.Run("UnaryExpression span computes from child", func(t *testing.T) {
		// Identifier doesn't implement Spanned, returns empty span
		child := &Identifier{Name: "x"}
		expr := &UnaryExpression{
			Operator: Minus,
			Expr:     child,
		}
		span := expr.Span()
		// Should return empty span since Identifier doesn't implement Spanned
		if span.Start.Line != 0 {
			t.Errorf("expected empty span for non-Spanned child, got %+v", span)
		}
	})

	t.Run("UnaryExpression span nil child", func(t *testing.T) {
		expr := &UnaryExpression{
			Operator: Not,
		}
		span := expr.Span()
		if span.Start.Line != 0 {
			t.Errorf("expected empty span for nil child")
		}
	})

	t.Run("CastExpression span computes from child", func(t *testing.T) {
		// LiteralValue doesn't implement Spanned, returns empty span
		child := &LiteralValue{Value: "123"}
		expr := &CastExpression{
			Expr: child,
			Type: "INT",
		}
		span := expr.Span()
		// Should return empty span since LiteralValue doesn't implement Spanned
		if span.Start.Line != 0 {
			t.Errorf("expected empty span for non-Spanned child, got %+v", span)
		}
	})

	t.Run("CastExpression span nil child", func(t *testing.T) {
		expr := &CastExpression{
			Type: "VARCHAR",
		}
		span := expr.Span()
		if span.Start.Line != 0 {
			t.Errorf("expected empty span for nil child")
		}
	})

	t.Run("FunctionCall span computes from arguments", func(t *testing.T) {
		// Identifier doesn't implement Spanned, returns empty span
		arg1 := &Identifier{Name: "col1"}
		arg2 := &LiteralValue{Value: 10}

		fn := &FunctionCall{
			Name:      "SUBSTR",
			Arguments: []Expression{arg1, arg2},
		}
		span := fn.Span()
		// Should return empty span since Identifier doesn't implement Spanned
		if span.Start.Line != 0 {
			t.Errorf("expected empty span for non-Spanned arguments, got %+v", span)
		}
	})

	t.Run("FunctionCall span no arguments", func(t *testing.T) {
		fn := &FunctionCall{
			Name: "NOW",
		}
		span := fn.Span()
		_ = span // Should not panic
	})
}

// TestGetSpanUnregistered tests GetSpan with unregistered nodes
func TestGetSpanUnregistered(t *testing.T) {
	node := &Identifier{Name: "unregistered"}
	span := GetSpan(node)

	// Should return empty span
	if span.Start.Line != 0 || span.Start.Column != 0 ||
		span.End.Line != 0 || span.End.Column != 0 {
		t.Errorf("expected empty span for unregistered node, got %+v", span)
	}
}

// TestUnionSpansEmpty tests UnionSpans with empty slice
func TestUnionSpansEmpty(t *testing.T) {
	span := UnionSpans(nil)
	if span.Start.Line != 0 {
		t.Errorf("expected empty span for nil slice")
	}

	span = UnionSpans([]models.Span{})
	if span.Start.Line != 0 {
		t.Errorf("expected empty span for empty slice")
	}
}

// TestUnionSpansSingle tests UnionSpans with single span
func TestUnionSpansSingle(t *testing.T) {
	single := models.Span{
		Start: models.Location{Line: 5, Column: 10},
		End:   models.Location{Line: 5, Column: 20},
	}
	span := UnionSpans([]models.Span{single})
	if span.Start.Line != 5 || span.Start.Column != 10 ||
		span.End.Line != 5 || span.End.Column != 20 {
		t.Errorf("expected single span returned, got %+v", span)
	}
}

// TestUnionSpansMultiple tests UnionSpans with multiple spans
func TestUnionSpansMultiple(t *testing.T) {
	spans := []models.Span{
		{Start: models.Location{Line: 1, Column: 5}, End: models.Location{Line: 1, Column: 10}},
		{Start: models.Location{Line: 1, Column: 1}, End: models.Location{Line: 1, Column: 3}},
		{Start: models.Location{Line: 2, Column: 1}, End: models.Location{Line: 2, Column: 15}},
	}
	span := UnionSpans(spans)

	// Should get min start and max end
	if span.Start.Line != 1 || span.Start.Column != 1 {
		t.Errorf("expected min start (1,1), got (%d,%d)", span.Start.Line, span.Start.Column)
	}
	if span.End.Line != 2 || span.End.Column != 15 {
		t.Errorf("expected max end (2,15), got (%d,%d)", span.End.Line, span.End.Column)
	}
}

// TestReleaseASTWithContent tests ReleaseAST with actual content
func TestReleaseASTWithContent(t *testing.T) {
	t.Run("release AST with statements", func(t *testing.T) {
		ast := NewAST()
		ast.Statements = []Statement{
			&SelectStatement{
				Columns: []Expression{
					&Identifier{Name: "id"},
				},
			},
			&InsertStatement{
				TableName: "users",
			},
		}
		ReleaseAST(ast)
	})

	t.Run("release nil AST", func(t *testing.T) {
		ReleaseAST(nil) // Should not panic
	})

	t.Run("release AST with deep SELECT", func(t *testing.T) {
		ast := NewAST()
		ast.Statements = []Statement{
			&SelectStatement{
				Columns: []Expression{
					&BinaryExpression{
						Left:     &Identifier{Name: "a"},
						Right:    &Identifier{Name: "b"},
						Operator: "+",
					},
				},
				From: []TableReference{
					{Name: "t1"},
				},
				Where: &BinaryExpression{
					Left:     &Identifier{Name: "id"},
					Right:    &LiteralValue{Value: 1},
					Operator: "=",
				},
				GroupBy: []Expression{
					&Identifier{Name: "category"},
				},
				Having: &BinaryExpression{
					Left: &FunctionCall{
						Name:      "COUNT",
						Arguments: []Expression{&Identifier{Name: "*"}},
					},
					Right:    &LiteralValue{Value: 5},
					Operator: ">",
				},
			},
		}
		ReleaseAST(ast)
	})
}

// TestPutSelectStatementWithContent tests returning SELECT statements to pool
func TestPutSelectStatementWithContent(t *testing.T) {
	sel := GetSelectStatement()
	sel.Distinct = true
	sel.Columns = []Expression{
		&Identifier{Name: "id"},
		&FunctionCall{Name: "COUNT", Arguments: []Expression{&Identifier{Name: "*"}}},
	}
	sel.From = []TableReference{
		{Name: "users"},
	}
	sel.Where = &BinaryExpression{
		Left:     &Identifier{Name: "active"},
		Right:    &LiteralValue{Value: true},
		Operator: "=",
	}
	sel.GroupBy = []Expression{&Identifier{Name: "department"}}
	sel.Having = &BinaryExpression{
		Left:     &FunctionCall{Name: "COUNT", Arguments: []Expression{&Identifier{Name: "*"}}},
		Right:    &LiteralValue{Value: 10},
		Operator: ">=",
	}
	sel.OrderBy = []OrderByExpression{
		{Expression: &Identifier{Name: "name"}, Ascending: true},
	}

	PutSelectStatement(sel)
}

// TestPutIdentifierWithContent tests returning Identifiers to pool
func TestPutIdentifierWithContent(t *testing.T) {
	t.Run("simple identifier", func(t *testing.T) {
		id := GetIdentifier()
		id.Name = "column_name"
		PutIdentifier(id)
	})

	t.Run("nil identifier", func(t *testing.T) {
		PutIdentifier(nil) // Should not panic
	})
}

// TestPutBinaryExpressionWithContent tests returning BinaryExpressions to pool
func TestPutBinaryExpressionWithContent(t *testing.T) {
	t.Run("binary expression with children", func(t *testing.T) {
		expr := GetBinaryExpression()
		expr.Left = &Identifier{Name: "x"}
		expr.Right = &LiteralValue{Value: 10}
		expr.Operator = ">"
		PutBinaryExpression(expr)
	})

	t.Run("nil binary expression", func(t *testing.T) {
		PutBinaryExpression(nil) // Should not panic
	})

	t.Run("binary expression nil children", func(t *testing.T) {
		expr := GetBinaryExpression()
		expr.Operator = "="
		PutBinaryExpression(expr)
	})
}

// TestPutExpressionSliceWithContent tests returning expression slices to pool
func TestPutExpressionSliceWithContent(t *testing.T) {
	t.Run("expression slice with content", func(t *testing.T) {
		slice := GetExpressionSlice()
		*slice = append(*slice, &Identifier{Name: "col1"})
		*slice = append(*slice, &LiteralValue{Value: 42})
		PutExpressionSlice(slice)
	})

	t.Run("nil expression slice", func(t *testing.T) {
		PutExpressionSlice(nil) // Should not panic
	})

	t.Run("empty expression slice", func(t *testing.T) {
		slice := GetExpressionSlice()
		PutExpressionSlice(slice)
	})
}

// TestLiteralValuePooling tests LiteralValue pooling
func TestLiteralValuePooling(t *testing.T) {
	t.Run("get and put literal value", func(t *testing.T) {
		lit := GetLiteralValue()
		lit.Value = "test_value"
		lit.Type = "string"
		PutLiteralValue(lit)
	})

	t.Run("nil literal value", func(t *testing.T) {
		PutLiteralValue(nil) // Should not panic
	})
}

// TestOrderByExpressionChildren tests OrderByExpression.Children()
func TestOrderByExpressionChildren(t *testing.T) {
	t.Run("with expression", func(t *testing.T) {
		orderBy := &OrderByExpression{
			Expression: &Identifier{Name: "col"},
			Ascending:  true,
		}
		children := orderBy.Children()
		if len(children) != 1 {
			t.Errorf("expected 1 child, got %d", len(children))
		}
	})

	t.Run("nil expression", func(t *testing.T) {
		orderBy := &OrderByExpression{
			Ascending: false,
		}
		children := orderBy.Children()
		if children != nil {
			t.Errorf("expected nil children, got %v", children)
		}
	})
}

// TestWindowSpecChildren tests WindowSpec.Children()
func TestWindowSpecChildren(t *testing.T) {
	t.Run("with partition and order", func(t *testing.T) {
		spec := &WindowSpec{
			PartitionBy: []Expression{&Identifier{Name: "dept"}},
			OrderBy:     []OrderByExpression{{Expression: &Identifier{Name: "salary"}}},
		}
		children := spec.Children()
		if len(children) != 2 {
			t.Errorf("expected 2 children, got %d", len(children))
		}
	})

	t.Run("with frame clause", func(t *testing.T) {
		spec := &WindowSpec{
			FrameClause: &WindowFrame{Type: "ROWS"},
		}
		children := spec.Children()
		if len(children) != 1 {
			t.Errorf("expected 1 child for frame clause, got %d", len(children))
		}
	})

	t.Run("empty", func(t *testing.T) {
		spec := &WindowSpec{}
		children := spec.Children()
		if len(children) != 0 {
			t.Errorf("expected 0 children, got %d", len(children))
		}
	})
}

// TestWindowFrameBoundChildren tests WindowFrameBound.Children()
func TestWindowFrameBoundChildren(t *testing.T) {
	t.Run("with value", func(t *testing.T) {
		bound := &WindowFrameBound{
			Type:  "PRECEDING",
			Value: &LiteralValue{Value: 5},
		}
		children := bound.Children()
		if len(children) != 1 {
			t.Errorf("expected 1 child, got %d", len(children))
		}
	})

	t.Run("nil value", func(t *testing.T) {
		bound := &WindowFrameBound{
			Type: "CURRENT ROW",
		}
		children := bound.Children()
		if children != nil {
			t.Errorf("expected nil children, got %v", children)
		}
	})
}

// TestWindowFrameBoundTokenLiteral tests WindowFrameBound.TokenLiteral()
func TestWindowFrameBoundTokenLiteral(t *testing.T) {
	t.Run("with type", func(t *testing.T) {
		bound := &WindowFrameBound{Type: "UNBOUNDED PRECEDING"}
		if bound.TokenLiteral() != "UNBOUNDED PRECEDING" {
			t.Errorf("expected 'UNBOUNDED PRECEDING', got %q", bound.TokenLiteral())
		}
	})

	t.Run("empty type", func(t *testing.T) {
		bound := &WindowFrameBound{}
		if bound.TokenLiteral() != "BOUND" {
			t.Errorf("expected 'BOUND', got %q", bound.TokenLiteral())
		}
	})
}

// TestGroupingExpressions tests grouping expressions (ROLLUP, CUBE, GROUPING SETS)
func TestGroupingExpressions(t *testing.T) {
	t.Run("RollupExpression", func(t *testing.T) {
		rollup := &RollupExpression{
			Expressions: []Expression{
				&Identifier{Name: "year"},
				&Identifier{Name: "quarter"},
			},
		}
		if rollup.TokenLiteral() != "ROLLUP" {
			t.Errorf("expected 'ROLLUP', got %q", rollup.TokenLiteral())
		}
		children := rollup.Children()
		if len(children) != 2 {
			t.Errorf("expected 2 children, got %d", len(children))
		}
	})

	t.Run("CubeExpression", func(t *testing.T) {
		cube := &CubeExpression{
			Expressions: []Expression{
				&Identifier{Name: "region"},
				&Identifier{Name: "product"},
			},
		}
		if cube.TokenLiteral() != "CUBE" {
			t.Errorf("expected 'CUBE', got %q", cube.TokenLiteral())
		}
		children := cube.Children()
		if len(children) != 2 {
			t.Errorf("expected 2 children, got %d", len(children))
		}
	})

	t.Run("GroupingSetsExpression", func(t *testing.T) {
		gs := &GroupingSetsExpression{
			Sets: [][]Expression{
				{&Identifier{Name: "a"}},
				{&Identifier{Name: "b"}, &Identifier{Name: "c"}},
			},
		}
		if gs.TokenLiteral() != "GROUPING SETS" {
			t.Errorf("expected 'GROUPING SETS', got %q", gs.TokenLiteral())
		}
		children := gs.Children()
		if len(children) != 3 {
			t.Errorf("expected 3 children (a, b, c), got %d", len(children))
		}
	})
}

// TestCommonTableExprChildren tests CommonTableExpr.Children()
func TestCommonTableExprChildren(t *testing.T) {
	cte := &CommonTableExpr{
		Name:    "cte_name",
		Columns: []string{"col1", "col2"},
		Statement: &SelectStatement{
			Columns: []Expression{&Identifier{Name: "*"}},
		},
	}
	children := cte.Children()
	// Should include the statement
	if len(children) != 1 {
		t.Errorf("expected 1 child, got %d", len(children))
	}
}

// TestInsertStatementChildrenCoverage tests InsertStatement.Children() for coverage
func TestInsertStatementChildrenCoverage(t *testing.T) {
	t.Run("full insert", func(t *testing.T) {
		insert := &InsertStatement{
			With: &WithClause{
				CTEs: []*CommonTableExpr{{Name: "temp"}},
			},
			TableName: "users",
			Columns:   []Expression{&Identifier{Name: "id"}},
			Values:    []Expression{&LiteralValue{Value: 1}},
			Query:     &SelectStatement{},
			Returning: []Expression{&Identifier{Name: "id"}},
			OnConflict: &OnConflict{
				Target: []Expression{&Identifier{Name: "id"}},
			},
		}
		children := insert.Children()
		if len(children) < 4 {
			t.Errorf("expected at least 4 children, got %d", len(children))
		}
	})

	t.Run("minimal insert", func(t *testing.T) {
		insert := &InsertStatement{
			TableName: "users",
		}
		children := insert.Children()
		if children == nil {
			t.Error("expected non-nil children slice")
		}
	})
}

// TestOnConflictChildren tests OnConflict.Children()
func TestOnConflictChildren(t *testing.T) {
	t.Run("with target and update", func(t *testing.T) {
		conflict := &OnConflict{
			Target: []Expression{&Identifier{Name: "id"}},
			Action: OnConflictAction{
				DoUpdate: []UpdateExpression{
					{Column: &Identifier{Name: "name"}, Value: &LiteralValue{Value: "updated"}},
				},
			},
		}
		children := conflict.Children()
		if len(children) < 2 {
			t.Errorf("expected at least 2 children, got %d", len(children))
		}
	})

	t.Run("do nothing", func(t *testing.T) {
		conflict := &OnConflict{
			Action: OnConflictAction{DoNothing: true},
		}
		children := conflict.Children()
		_ = children // Should not panic
	})
}
