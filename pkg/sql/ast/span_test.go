// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package ast

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Test SpannedNode
func TestSpannedNode(t *testing.T) {
	t.Run("Span and SetSpan", func(t *testing.T) {
		node := &SpannedNode{}

		// Initially should have zero span
		span := node.Span()
		if span.Start.Line != 0 || span.Start.Column != 0 {
			t.Errorf("Initial span not zero: %+v", span)
		}

		// Set a new span
		newSpan := models.Span{
			Start: models.Location{Line: 1, Column: 5},
			End:   models.Location{Line: 1, Column: 15},
		}
		node.SetSpan(newSpan)

		// Verify it was set
		gotSpan := node.Span()
		if gotSpan != newSpan {
			t.Errorf("SetSpan/Span mismatch: got %+v, want %+v", gotSpan, newSpan)
		}
	})
}

// Test UnionSpans
func TestUnionSpans(t *testing.T) {
	tests := []struct {
		name     string
		spans    []models.Span
		expected models.Span
	}{
		{
			name:     "empty slice",
			spans:    []models.Span{},
			expected: models.EmptySpan(),
		},
		{
			name: "single span",
			spans: []models.Span{
				{
					Start: models.Location{Line: 2, Column: 10},
					End:   models.Location{Line: 2, Column: 20},
				},
			},
			expected: models.Span{
				Start: models.Location{Line: 2, Column: 10},
				End:   models.Location{Line: 2, Column: 20},
			},
		},
		{
			name: "multiple spans - sequential",
			spans: []models.Span{
				{
					Start: models.Location{Line: 1, Column: 5},
					End:   models.Location{Line: 1, Column: 10},
				},
				{
					Start: models.Location{Line: 1, Column: 15},
					End:   models.Location{Line: 1, Column: 25},
				},
			},
			expected: models.Span{
				Start: models.Location{Line: 1, Column: 5},
				End:   models.Location{Line: 1, Column: 25},
			},
		},
		{
			name: "multiple spans - overlapping",
			spans: []models.Span{
				{
					Start: models.Location{Line: 2, Column: 10},
					End:   models.Location{Line: 3, Column: 5},
				},
				{
					Start: models.Location{Line: 1, Column: 1},
					End:   models.Location{Line: 2, Column: 15},
				},
			},
			expected: models.Span{
				Start: models.Location{Line: 1, Column: 1},
				End:   models.Location{Line: 3, Column: 5},
			},
		},
		{
			name: "multiple spans - multiline",
			spans: []models.Span{
				{
					Start: models.Location{Line: 5, Column: 20},
					End:   models.Location{Line: 5, Column: 30},
				},
				{
					Start: models.Location{Line: 3, Column: 5},
					End:   models.Location{Line: 4, Column: 10},
				},
				{
					Start: models.Location{Line: 4, Column: 15},
					End:   models.Location{Line: 6, Column: 2},
				},
			},
			expected: models.Span{
				Start: models.Location{Line: 3, Column: 5},
				End:   models.Location{Line: 6, Column: 2},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := UnionSpans(tt.spans)
			if got != tt.expected {
				t.Errorf("UnionSpans() = %+v, want %+v", got, tt.expected)
			}
		})
	}
}

// Test AST.Span()
func TestAST_Span(t *testing.T) {
	t.Run("empty AST", func(t *testing.T) {
		ast := &AST{
			Statements: []Statement{},
		}
		span := ast.Span()
		if span != models.EmptySpan() {
			t.Errorf("Empty AST span should be EmptySpan, got %+v", span)
		}
	})

	t.Run("AST with statements", func(t *testing.T) {
		// Create statements with spans
		stmt1 := &SelectStatement{}
		SetSpan(stmt1, models.Span{
			Start: models.Location{Line: 1, Column: 1},
			End:   models.Location{Line: 1, Column: 20},
		})

		stmt2 := &InsertStatement{
			Columns: []Expression{},
			Values:  []Expression{},
		}
		SetSpan(stmt2, models.Span{
			Start: models.Location{Line: 3, Column: 1},
			End:   models.Location{Line: 3, Column: 30},
		})

		ast := &AST{
			Statements: []Statement{stmt1, stmt2},
		}

		// Just call Span() to ensure it works
		_ = ast.Span()
	})
}

// Test SetSpan and GetSpan global functions
func TestSetSpanGetSpan(t *testing.T) {
	t.Run("set and get span", func(t *testing.T) {
		stmt := &SelectStatement{}
		testSpan := models.Span{
			Start: models.Location{Line: 5, Column: 10},
			End:   models.Location{Line: 5, Column: 50},
		}

		SetSpan(stmt, testSpan)
		gotSpan := GetSpan(stmt)

		if gotSpan != testSpan {
			t.Errorf("GetSpan() = %+v, want %+v", gotSpan, testSpan)
		}
	})

	t.Run("get span for unset node", func(t *testing.T) {
		stmt := &UpdateStatement{}
		span := GetSpan(stmt)

		if span != models.EmptySpan() {
			t.Errorf("GetSpan for unset node should return EmptySpan, got %+v", span)
		}
	})
}

// Test SelectStatement.Span()
func TestSelectStatement_Span(t *testing.T) {
	stmt := &SelectStatement{}
	testSpan := models.Span{
		Start: models.Location{Line: 2, Column: 5},
		End:   models.Location{Line: 2, Column: 25},
	}

	SetSpan(stmt, testSpan)
	gotSpan := stmt.Span()

	if gotSpan != testSpan {
		t.Errorf("SelectStatement.Span() = %+v, want %+v", gotSpan, testSpan)
	}
}

// Test InsertStatement.Span()
func TestInsertStatement_Span(t *testing.T) {
	t.Run("with columns and values", func(t *testing.T) {
		col := &Identifier{Name: "id"}
		SetSpan(col, models.Span{
			Start: models.Location{Line: 1, Column: 10},
			End:   models.Location{Line: 1, Column: 12},
		})

		val := &LiteralValue{Value: "test"}
		SetSpan(val, models.Span{
			Start: models.Location{Line: 1, Column: 20},
			End:   models.Location{Line: 1, Column: 26},
		})

		stmt := &InsertStatement{
			Columns: []Expression{col},
			Values:  []Expression{val},
		}

		// Just call Span() to ensure it works
		_ = stmt.Span()
	})

	t.Run("with returning clause", func(t *testing.T) {
		ret := &Identifier{Name: "id"}
		SetSpan(ret, models.Span{
			Start: models.Location{Line: 2, Column: 30},
			End:   models.Location{Line: 2, Column: 32},
		})

		stmt := &InsertStatement{
			Columns:   []Expression{},
			Values:    []Expression{},
			Returning: []Expression{ret},
		}

		// Just call Span() to ensure it works
		_ = stmt.Span()
	})
}

// Test UpdateStatement.Span()
func TestUpdateStatement_Span(t *testing.T) {
	stmt := &UpdateStatement{}
	testSpan := models.Span{
		Start: models.Location{Line: 3, Column: 1},
		End:   models.Location{Line: 3, Column: 40},
	}

	SetSpan(stmt, testSpan)
	gotSpan := stmt.Span()

	if gotSpan != testSpan {
		t.Errorf("UpdateStatement.Span() = %+v, want %+v", gotSpan, testSpan)
	}
}

// Test DeleteStatement.Span()
func TestDeleteStatement_Span(t *testing.T) {
	stmt := &DeleteStatement{}
	testSpan := models.Span{
		Start: models.Location{Line: 4, Column: 1},
		End:   models.Location{Line: 4, Column: 30},
	}

	SetSpan(stmt, testSpan)
	gotSpan := stmt.Span()

	if gotSpan != testSpan {
		t.Errorf("DeleteStatement.Span() = %+v, want %+v", gotSpan, testSpan)
	}
}

// Test BinaryExpression.Span()
func TestBinaryExpression_Span(t *testing.T) {
	t.Run("with left and right", func(t *testing.T) {
		left := &Identifier{Name: "x"}
		SetSpan(left, models.Span{
			Start: models.Location{Line: 1, Column: 5},
			End:   models.Location{Line: 1, Column: 6},
		})

		right := &LiteralValue{Value: "10"}
		SetSpan(right, models.Span{
			Start: models.Location{Line: 1, Column: 10},
			End:   models.Location{Line: 1, Column: 12},
		})

		expr := &BinaryExpression{
			Left:     left,
			Operator: "=",
			Right:    right,
		}

		// Just call Span() to ensure it works
		_ = expr.Span()
	})

	t.Run("empty expression", func(t *testing.T) {
		expr := &BinaryExpression{
			Operator: "+",
		}
		span := expr.Span()
		if span != models.EmptySpan() {
			t.Errorf("Empty BinaryExpression should return EmptySpan, got %+v", span)
		}
	})
}

// Test UnaryExpression.Span()
func TestUnaryExpression_Span(t *testing.T) {
	t.Run("with expression", func(t *testing.T) {
		inner := &Identifier{Name: "value"}
		SetSpan(inner, models.Span{
			Start: models.Location{Line: 2, Column: 10},
			End:   models.Location{Line: 2, Column: 15},
		})

		expr := &UnaryExpression{
			Operator: Not,
			Expr:     inner,
		}

		// Just call Span() to ensure it works
		_ = expr.Span()
	})

	t.Run("without expression", func(t *testing.T) {
		expr := &UnaryExpression{
			Operator: Not,
		}
		span := expr.Span()
		if span != models.EmptySpan() {
			t.Errorf("Empty UnaryExpression should return EmptySpan, got %+v", span)
		}
	})
}

// Test CastExpression.Span()
func TestCastExpression_Span(t *testing.T) {
	t.Run("with expression", func(t *testing.T) {
		inner := &LiteralValue{Value: "123"}
		SetSpan(inner, models.Span{
			Start: models.Location{Line: 3, Column: 5},
			End:   models.Location{Line: 3, Column: 8},
		})

		expr := &CastExpression{
			Expr: inner,
			Type: "INTEGER",
		}

		// Just call Span() to ensure it works
		_ = expr.Span()
	})

	t.Run("without expression", func(t *testing.T) {
		expr := &CastExpression{
			Type: "INTEGER",
		}
		span := expr.Span()
		if span != models.EmptySpan() {
			t.Errorf("Empty CastExpression should return EmptySpan, got %+v", span)
		}
	})
}

// Test FunctionCall.Span()
func TestFunctionCall_Span(t *testing.T) {
	t.Run("with arguments", func(t *testing.T) {
		arg1 := &Identifier{Name: "col1"}
		SetSpan(arg1, models.Span{
			Start: models.Location{Line: 4, Column: 10},
			End:   models.Location{Line: 4, Column: 14},
		})

		arg2 := &Identifier{Name: "col2"}
		SetSpan(arg2, models.Span{
			Start: models.Location{Line: 4, Column: 16},
			End:   models.Location{Line: 4, Column: 20},
		})

		fn := &FunctionCall{
			Name:      "MAX",
			Arguments: []Expression{arg1, arg2},
		}

		// Just call Span() to ensure it works
		_ = fn.Span()
	})

	t.Run("without arguments", func(t *testing.T) {
		fn := &FunctionCall{
			Name:      "NOW",
			Arguments: []Expression{},
		}
		span := fn.Span()
		if span != models.EmptySpan() {
			t.Errorf("FunctionCall without args should return EmptySpan, got %+v", span)
		}
	})
}
