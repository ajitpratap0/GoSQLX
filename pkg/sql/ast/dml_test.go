package ast

import "testing"

// Test Select node (DML)
func TestSelect(t *testing.T) {
	tests := []struct {
		name        string
		sel         *Select
		wantLiteral string
		minChildren int
	}{
		{
			name: "simple SELECT with columns",
			sel: &Select{
				Columns: []Expression{
					&Identifier{Name: "id"},
					&Identifier{Name: "name"},
				},
			},
			wantLiteral: "SELECT",
			minChildren: 2,
		},
		{
			name: "SELECT with FROM",
			sel: &Select{
				Columns: []Expression{&Identifier{Name: "*"}},
				From: []TableReference{
					{Name: "users"},
				},
			},
			wantLiteral: "SELECT",
			minChildren: 2,
		},
		{
			name: "SELECT with WHERE",
			sel: &Select{
				Columns: []Expression{&Identifier{Name: "id"}},
				From: []TableReference{
					{Name: "users"},
				},
				Where: &BinaryExpression{
					Left:     &Identifier{Name: "id"},
					Operator: "=",
					Right:    &LiteralValue{Value: "1"},
				},
			},
			wantLiteral: "SELECT",
			minChildren: 3,
		},
		{
			name: "SELECT with GROUP BY and HAVING",
			sel: &Select{
				Columns: []Expression{
					&Identifier{Name: "dept"},
					&FunctionCall{Name: "COUNT", Arguments: []Expression{&Identifier{Name: "*"}}},
				},
				From: []TableReference{
					{Name: "employees"},
				},
				GroupBy: []Expression{&Identifier{Name: "dept"}},
				Having: &BinaryExpression{
					Left:     &FunctionCall{Name: "COUNT", Arguments: []Expression{&Identifier{Name: "*"}}},
					Operator: ">",
					Right:    &LiteralValue{Value: "5"},
				},
			},
			wantLiteral: "SELECT",
			minChildren: 5,
		},
		{
			name: "SELECT with ORDER BY",
			sel: &Select{
				Columns: []Expression{&Identifier{Name: "*"}},
				From: []TableReference{
					{Name: "users"},
				},
				OrderBy: []OrderByExpression{{Expression: &Identifier{Name: "created_at"}, Ascending: true}},
			},
			wantLiteral: "SELECT",
			minChildren: 3,
		},
		{
			name: "SELECT DISTINCT",
			sel: &Select{
				Distinct: true,
				Columns:  []Expression{&Identifier{Name: "category"}},
				From: []TableReference{
					{Name: "products"},
				},
			},
			wantLiteral: "SELECT",
			minChildren: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.sel.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("Select.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.sel.Children()
			if len(children) < tt.minChildren {
				t.Errorf("Select.Children() count = %d, want at least %d", len(children), tt.minChildren)
			}

			// Test statementNode
			tt.sel.statementNode()

			// Test interface implementation
			var _ Statement = tt.sel
		})
	}
}

// Test Insert node (DML)
func TestInsert(t *testing.T) {
	tests := []struct {
		name        string
		ins         *Insert
		wantLiteral string
		minChildren int
	}{
		{
			name: "simple INSERT with values",
			ins: &Insert{
				Table: TableReference{Name: "users"},
				Columns: []Expression{
					&Identifier{Name: "name"},
					&Identifier{Name: "email"},
				},
				Values: [][]Expression{
					{
						&LiteralValue{Value: "John"},
						&LiteralValue{Value: "john@example.com"},
					},
				},
			},
			wantLiteral: "INSERT",
			minChildren: 5,
		},
		{
			name: "INSERT with multiple rows",
			ins: &Insert{
				Table: TableReference{Name: "products"},
				Columns: []Expression{
					&Identifier{Name: "name"},
					&Identifier{Name: "price"},
				},
				Values: [][]Expression{
					{
						&LiteralValue{Value: "Widget"},
						&LiteralValue{Value: "9.99"},
					},
					{
						&LiteralValue{Value: "Gadget"},
						&LiteralValue{Value: "19.99"},
					},
				},
			},
			wantLiteral: "INSERT",
			minChildren: 7,
		},
		{
			name: "INSERT with RETURNING",
			ins: &Insert{
				Table: TableReference{Name: "users"},
				Columns: []Expression{
					&Identifier{Name: "name"},
				},
				Values: [][]Expression{
					{
						&LiteralValue{Value: "Jane"},
					},
				},
				ReturningClause: []Expression{&Identifier{Name: "id"}},
			},
			wantLiteral: "INSERT",
			minChildren: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.ins.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("Insert.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.ins.Children()
			if len(children) < tt.minChildren {
				t.Errorf("Insert.Children() count = %d, want at least %d", len(children), tt.minChildren)
			}

			// Test statementNode
			tt.ins.statementNode()

			// Test interface implementation
			var _ Statement = tt.ins
		})
	}
}

// Test Delete node (DML)
func TestDelete(t *testing.T) {
	tests := []struct {
		name        string
		del         *Delete
		wantLiteral string
		minChildren int
	}{
		{
			name: "simple DELETE",
			del: &Delete{
				Table: TableReference{Name: "users"},
			},
			wantLiteral: "DELETE",
			minChildren: 1,
		},
		{
			name: "DELETE with WHERE",
			del: &Delete{
				Table: TableReference{Name: "users"},
				Where: &BinaryExpression{
					Left:     &Identifier{Name: "id"},
					Operator: "=",
					Right:    &LiteralValue{Value: "5"},
				},
			},
			wantLiteral: "DELETE",
			minChildren: 2,
		},
		{
			name: "DELETE with RETURNING",
			del: &Delete{
				Table:           TableReference{Name: "users"},
				ReturningClause: []Expression{&Identifier{Name: "id"}, &Identifier{Name: "name"}},
			},
			wantLiteral: "DELETE",
			minChildren: 3,
		},
		{
			name: "DELETE with WHERE and RETURNING",
			del: &Delete{
				Table: TableReference{Name: "users"},
				Where: &BinaryExpression{
					Left:     &Identifier{Name: "active"},
					Operator: "=",
					Right:    &LiteralValue{Value: "false"},
				},
				ReturningClause: []Expression{&Identifier{Name: "*"}},
			},
			wantLiteral: "DELETE",
			minChildren: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.del.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("Delete.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.del.Children()
			if len(children) < tt.minChildren {
				t.Errorf("Delete.Children() count = %d, want at least %d", len(children), tt.minChildren)
			}

			// Test statementNode
			tt.del.statementNode()

			// Test interface implementation
			var _ Statement = tt.del
		})
	}
}

// Test Update node (DML)
func TestUpdate(t *testing.T) {
	tests := []struct {
		name        string
		upd         *Update
		wantLiteral string
		minChildren int
	}{
		{
			name: "simple UPDATE",
			upd: &Update{
				Table: TableReference{Name: "users"},
				Updates: []UpdateExpression{
					{
						Column: &Identifier{Name: "email"},
						Value:  &LiteralValue{Value: "new@example.com"},
					},
				},
			},
			wantLiteral: "UPDATE",
			minChildren: 2,
		},
		{
			name: "UPDATE with multiple columns",
			upd: &Update{
				Table: TableReference{Name: "users"},
				Updates: []UpdateExpression{
					{
						Column: &Identifier{Name: "name"},
						Value:  &LiteralValue{Value: "John"},
					},
					{
						Column: &Identifier{Name: "age"},
						Value:  &LiteralValue{Value: "30"},
					},
				},
			},
			wantLiteral: "UPDATE",
			minChildren: 3,
		},
		{
			name: "UPDATE with WHERE",
			upd: &Update{
				Table: TableReference{Name: "users"},
				Updates: []UpdateExpression{
					{
						Column: &Identifier{Name: "status"},
						Value:  &LiteralValue{Value: "inactive"},
					},
				},
				Where: &BinaryExpression{
					Left:     &Identifier{Name: "id"},
					Operator: "=",
					Right:    &LiteralValue{Value: "10"},
				},
			},
			wantLiteral: "UPDATE",
			minChildren: 3,
		},
		{
			name: "UPDATE with RETURNING",
			upd: &Update{
				Table: TableReference{Name: "users"},
				Updates: []UpdateExpression{
					{
						Column: &Identifier{Name: "updated_at"},
						Value:  &FunctionCall{Name: "NOW", Arguments: []Expression{}},
					},
				},
				ReturningClause: []Expression{&Identifier{Name: "id"}},
			},
			wantLiteral: "UPDATE",
			minChildren: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.upd.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("Update.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.upd.Children()
			if len(children) < tt.minChildren {
				t.Errorf("Update.Children() count = %d, want at least %d", len(children), tt.minChildren)
			}

			// Test statementNode
			tt.upd.statementNode()

			// Test interface implementation
			var _ Statement = tt.upd
		})
	}
}

// Test ObjectName
func TestObjectName(t *testing.T) {
	tests := []struct {
		name       string
		objName    ObjectName
		wantString string
	}{
		{
			name:       "simple object name",
			objName:    ObjectName{Name: "users"},
			wantString: "users",
		},
		{
			name:       "object name with schema",
			objName:    ObjectName{Name: "public.employees"},
			wantString: "public.employees",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test String
			if got := tt.objName.String(); got != tt.wantString {
				t.Errorf("ObjectName.String() = %v, want %v", got, tt.wantString)
			}

			// Test TokenLiteral
			if got := tt.objName.TokenLiteral(); got != tt.wantString {
				t.Errorf("ObjectName.TokenLiteral() = %v, want %v", got, tt.wantString)
			}

			// Test Children (should be nil)
			if children := tt.objName.Children(); children != nil {
				t.Errorf("ObjectName.Children() = %v, want nil", children)
			}
		})
	}
}

// Test FunctionDesc
func TestFunctionDesc(t *testing.T) {
	tests := []struct {
		name       string
		funcDesc   FunctionDesc
		wantString string
	}{
		{
			name: "simple function no args",
			funcDesc: FunctionDesc{
				Name: ObjectName{Name: "COUNT"},
			},
			wantString: "COUNT",
		},
		{
			name: "function with schema no args",
			funcDesc: FunctionDesc{
				Name:   ObjectName{Name: "myfunction"},
				Schema: "myschema",
			},
			wantString: "myschema.myfunction",
		},
		{
			name: "function with args",
			funcDesc: FunctionDesc{
				Name:      ObjectName{Name: "CONCAT"},
				Arguments: []string{"varchar", "varchar"},
			},
			wantString: "CONCAT([varchar varchar])",
		},
		{
			name: "function with schema and args",
			funcDesc: FunctionDesc{
				Name:      ObjectName{Name: "myfunc"},
				Schema:    "public",
				Arguments: []string{"int", "text"},
			},
			wantString: "public.myfunc([int text])",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test String
			if got := tt.funcDesc.String(); got != tt.wantString {
				t.Errorf("FunctionDesc.String() = %v, want %v", got, tt.wantString)
			}

			// Test TokenLiteral (should return String())
			if got := tt.funcDesc.TokenLiteral(); got != tt.wantString {
				t.Errorf("FunctionDesc.TokenLiteral() = %v, want %v", got, tt.wantString)
			}

			// Test Children (should be nil)
			if children := tt.funcDesc.Children(); children != nil {
				t.Errorf("FunctionDesc.Children() = %v, want nil", children)
			}
		})
	}
}
