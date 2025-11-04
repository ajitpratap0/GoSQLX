package ast

import "testing"

// Test AlterColumnOperation
func TestAlterColumnOperation(t *testing.T) {
	tests := []struct {
		name       string
		op         AlterColumnOperation
		wantString string
	}{
		{
			name:       "SET DEFAULT",
			op:         AlterColumnSetDefault,
			wantString: "SET DEFAULT",
		},
		{
			name:       "DROP DEFAULT",
			op:         AlterColumnDropDefault,
			wantString: "DROP DEFAULT",
		},
		{
			name:       "SET NOT NULL",
			op:         AlterColumnSetNotNull,
			wantString: "SET NOT NULL",
		},
		{
			name:       "DROP NOT NULL",
			op:         AlterColumnDropNotNull,
			wantString: "DROP NOT NULL",
		},
		{
			name:       "Unknown operation",
			op:         AlterColumnOperation(999),
			wantString: "UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.op.TokenLiteral(); got != tt.wantString {
				t.Errorf("AlterColumnOperation.TokenLiteral() = %v, want %v", got, tt.wantString)
			}

			// Test Children (should be nil)
			if children := tt.op.Children(); children != nil {
				t.Errorf("AlterColumnOperation.Children() = %v, want nil", children)
			}
		})
	}
}

// Test Query
func TestQuery(t *testing.T) {
	tests := []struct {
		name        string
		query       *Query
		wantLiteral string
	}{
		{
			name: "simple query",
			query: &Query{
				Text: "SELECT * FROM users",
			},
			wantLiteral: "QUERY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.query.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("Query.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children (should be nil)
			if children := tt.query.Children(); children != nil {
				t.Errorf("Query.Children() = %v, want nil", children)
			}
		})
	}
}

// Test Ident
func TestIdent(t *testing.T) {
	tests := []struct {
		name       string
		ident      *Ident
		wantString string
	}{
		{
			name:       "simple identifier",
			ident:      &Ident{Name: "user_id"},
			wantString: "user_id",
		},
		{
			name:       "qualified identifier",
			ident:      &Ident{Name: "users.id"},
			wantString: "users.id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test String
			if got := tt.ident.String(); got != tt.wantString {
				t.Errorf("Ident.String() = %v, want %v", got, tt.wantString)
			}

			// Test TokenLiteral
			if got := tt.ident.TokenLiteral(); got != tt.wantString {
				t.Errorf("Ident.TokenLiteral() = %v, want %v", got, tt.wantString)
			}

			// Test Children (should be nil)
			if children := tt.ident.Children(); children != nil {
				t.Errorf("Ident.Children() = %v, want nil", children)
			}

			// Test expressionNode
			tt.ident.expressionNode()

			// Test interface implementation
			var _ Expression = tt.ident
		})
	}
}

// Test CommentDef
func TestCommentDef(t *testing.T) {
	tests := []struct {
		name        string
		comment     *CommentDef
		wantLiteral string
	}{
		{
			name: "simple comment",
			comment: &CommentDef{
				Text: "This is a user table",
			},
			wantLiteral: "COMMENT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.comment.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("CommentDef.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children (should be nil)
			if children := tt.comment.Children(); children != nil {
				t.Errorf("CommentDef.Children() = %v, want nil", children)
			}
		})
	}
}

// Test OneOrManyWithParens
func TestOneOrManyWithParens(t *testing.T) {
	tests := []struct {
		name         string
		parens       *OneOrManyWithParens[*Ident]
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "multiple identifiers",
			parens: &OneOrManyWithParens[*Ident]{
				Items: []*Ident{
					{Name: "id"},
					{Name: "name"},
					{Name: "email"},
				},
			},
			wantLiteral:  "(",
			wantChildren: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.parens.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("OneOrManyWithParens.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.parens.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("OneOrManyWithParens.Children() count = %d, want %d", len(children), tt.wantChildren)
			}
		})
	}
}

// Test WrappedCollection
func TestWrappedCollection(t *testing.T) {
	tests := []struct {
		name         string
		wrapped      *WrappedCollection[*Ident]
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "wrapped identifiers",
			wrapped: &WrappedCollection[*Ident]{
				Items: []*Ident{
					{Name: "col1"},
					{Name: "col2"},
				},
				Wrapper: "COLUMNS",
			},
			wantLiteral:  "COLUMNS",
			wantChildren: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.wrapped.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("WrappedCollection.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.wrapped.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("WrappedCollection.Children() count = %d, want %d", len(children), tt.wantChildren)
			}
		})
	}
}

// Test ClusteredBy
func TestClusteredBy(t *testing.T) {
	tests := []struct {
		name         string
		clustered    *ClusteredBy
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "clustered by columns",
			clustered: &ClusteredBy{
				Columns: []Node{
					&Identifier{Name: "user_id"},
					&Identifier{Name: "created_at"},
				},
				Buckets: 10,
			},
			wantLiteral:  "CLUSTERED BY",
			wantChildren: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.clustered.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("ClusteredBy.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.clustered.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("ClusteredBy.Children() count = %d, want %d", len(children), tt.wantChildren)
			}
		})
	}
}

// Mock Expr for testing
type mockExpr struct{}

func (m *mockExpr) Children() []Node     { return nil }
func (m *mockExpr) TokenLiteral() string { return "EXPR" }
func (m *mockExpr) exprNode()            {}

// Test RowAccessPolicy
func TestRowAccessPolicy(t *testing.T) {
	tests := []struct {
		name         string
		policy       *RowAccessPolicy
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "policy without filter",
			policy: &RowAccessPolicy{
				Name:    "admin_policy",
				Enabled: true,
			},
			wantLiteral:  "ROW ACCESS POLICY",
			wantChildren: 0,
		},
		{
			name: "policy with filter",
			policy: &RowAccessPolicy{
				Name:    "user_policy",
				Filter:  &mockExpr{},
				Enabled: true,
			},
			wantLiteral:  "ROW ACCESS POLICY",
			wantChildren: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.policy.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("RowAccessPolicy.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.policy.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("RowAccessPolicy.Children() count = %d, want %d", len(children), tt.wantChildren)
			}
		})
	}
}

// Test StatementImpl
func TestStatementImpl(t *testing.T) {
	tests := []struct {
		name         string
		stmt         *StatementImpl
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "statement with SELECT variant",
			stmt: &StatementImpl{
				Variant: &SelectStatement{
					Columns: []Expression{
						&Identifier{Name: "id"},
					},
				},
			},
			wantLiteral:  "SELECT",
			wantChildren: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.stmt.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("StatementImpl.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.stmt.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("StatementImpl.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test statementNode
			tt.stmt.statementNode()

			// Test interface implementation
			var _ Statement = tt.stmt
		})
	}
}
