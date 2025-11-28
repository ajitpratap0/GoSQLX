package ast

import "testing"

// Test IndexType constants and String() method
func TestIndexType(t *testing.T) {
	tests := []struct {
		name       string
		indexType  IndexType
		wantString string
	}{
		{
			name:       "BTREE index",
			indexType:  BTree,
			wantString: "BTREE",
		},
		{
			name:       "HASH index",
			indexType:  Hash,
			wantString: "HASH",
		},
		{
			name:       "unknown index type",
			indexType:  IndexType(999),
			wantString: "UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.indexType.String()
			if got != tt.wantString {
				t.Errorf("IndexType.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

// Test IndexOption node
func TestIndexOption(t *testing.T) {
	btree := BTree
	hash := Hash

	tests := []struct {
		name       string
		option     *IndexOption
		wantString string
	}{
		{
			name: "USING BTREE",
			option: &IndexOption{
				Type:  UsingIndex,
				Using: &btree,
			},
			wantString: "USING BTREE",
		},
		{
			name: "USING HASH",
			option: &IndexOption{
				Type:  UsingIndex,
				Using: &hash,
			},
			wantString: "USING HASH",
		},
		{
			name: "COMMENT option",
			option: &IndexOption{
				Type:    CommentIndex,
				Comment: "primary key index",
			},
			wantString: "COMMENT 'primary key index'",
		},
		{
			name: "unknown option type",
			option: &IndexOption{
				Type: IndexOptionType(999),
			},
			wantString: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.option.String()
			if got != tt.wantString {
				t.Errorf("IndexOption.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

// Test NullsDistinctOption
func TestNullsDistinctOption(t *testing.T) {
	tests := []struct {
		name       string
		option     NullsDistinctOption
		wantString string
	}{
		{
			name:       "NullsDistinctNone",
			option:     NullsDistinctNone,
			wantString: "",
		},
		{
			name:       "NullsDistinct",
			option:     NullsDistinct,
			wantString: "NULLS DISTINCT",
		},
		{
			name:       "NullsNotDistinct",
			option:     NullsNotDistinct,
			wantString: "NULLS NOT DISTINCT",
		},
		{
			name:       "unknown option",
			option:     NullsDistinctOption(999),
			wantString: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.option.String()
			if got != tt.wantString {
				t.Errorf("NullsDistinctOption.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

// Test AlterStatement node with operations
func TestAlterStatementOperations(t *testing.T) {
	tests := []struct {
		name         string
		stmt         *AlterStatement
		wantLiteral  string
		wantChildren int
	}{
		{
			name: "ALTER TABLE with operation",
			stmt: &AlterStatement{
				Type: AlterTypeTable,
				Name: "users",
				Operation: &AlterTableOperation{
					Type: AddColumn,
					ColumnDef: &ColumnDef{
						Name: "age",
						Type: "INT",
					},
				},
			},
			wantLiteral:  "ALTER",
			wantChildren: 1,
		},
		{
			name: "ALTER ROLE without operation",
			stmt: &AlterStatement{
				Type:      AlterTypeRole,
				Name:      "admin",
				Operation: nil,
			},
			wantLiteral:  "ALTER",
			wantChildren: 0,
		},
		{
			name: "ALTER POLICY",
			stmt: &AlterStatement{
				Type: AlterTypePolicy,
				Name: "policy1",
				Operation: &AlterPolicyOperation{
					Type:    RenamePolicy,
					NewName: "new_policy",
				},
			},
			wantLiteral:  "ALTER",
			wantChildren: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.stmt.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("AlterStatement.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children count
			children := tt.stmt.Children()
			if len(children) != tt.wantChildren {
				t.Errorf("AlterStatement.Children() count = %d, want %d", len(children), tt.wantChildren)
			}

			// Test statementNode
			tt.stmt.statementNode()

			// Test interface implementation
			var _ Statement = tt.stmt
		})
	}
}

// Test AlterTableOperation node
func TestAlterTableOperation(t *testing.T) {
	tests := []struct {
		name        string
		op          *AlterTableOperation
		wantLiteral string
		minChildren int
	}{
		{
			name: "ADD COLUMN",
			op: &AlterTableOperation{
				Type:          AddColumn,
				ColumnKeyword: true,
				ColumnDef: &ColumnDef{
					Name: "email",
					Type: "VARCHAR(255)",
				},
			},
			wantLiteral: "ALTER TABLE",
			minChildren: 1,
		},
		{
			name: "ADD CONSTRAINT",
			op: &AlterTableOperation{
				Type: AddConstraint,
				Constraint: &TableConstraint{
					Type:    "PRIMARY KEY",
					Columns: []string{"id"},
				},
			},
			wantLiteral: "ALTER TABLE",
			minChildren: 1,
		},
		{
			name: "DROP COLUMN",
			op: &AlterTableOperation{
				Type: DropColumn,
			},
			wantLiteral: "ALTER TABLE",
			minChildren: 0,
		},
		{
			name: "RENAME COLUMN",
			op: &AlterTableOperation{
				Type: RenameColumn,
			},
			wantLiteral: "ALTER TABLE",
			minChildren: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.op.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("AlterTableOperation.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.op.Children()
			if len(children) < tt.minChildren {
				t.Errorf("AlterTableOperation.Children() count = %d, want at least %d", len(children), tt.minChildren)
			}

			// Test alterOperationNode
			tt.op.alterOperationNode()

			// Test interface implementation
			var _ AlterOperation = tt.op
		})
	}
}

// Test RoleOption String() method
func TestRoleOption(t *testing.T) {
	tests := []struct {
		name       string
		option     *RoleOption
		wantString string
	}{
		{
			name: "BYPASSRLS true",
			option: &RoleOption{
				Type:  BypassRLS,
				Value: true,
			},
			wantString: "BYPASSRLS",
		},
		{
			name: "BYPASSRLS false",
			option: &RoleOption{
				Type:  BypassRLS,
				Value: false,
			},
			wantString: "NOBYPASSRLS",
		},
		{
			name: "CONNECTION LIMIT",
			option: &RoleOption{
				Type:  ConnectionLimit,
				Value: 10,
			},
			wantString: "CONNECTION LIMIT 10",
		},
		{
			name: "CREATEDB true",
			option: &RoleOption{
				Type:  CreateDB,
				Value: true,
			},
			wantString: "CREATEDB",
		},
		{
			name: "CREATEDB false",
			option: &RoleOption{
				Type:  CreateDB,
				Value: false,
			},
			wantString: "NOCREATEDB",
		},
		{
			name: "CREATEROLE true",
			option: &RoleOption{
				Type:  CreateRole,
				Value: true,
			},
			wantString: "CREATEROLE",
		},
		{
			name: "CREATEROLE false",
			option: &RoleOption{
				Type:  CreateRole,
				Value: false,
			},
			wantString: "NOCREATEROLE",
		},
		{
			name: "INHERIT true",
			option: &RoleOption{
				Type:  Inherit,
				Value: true,
			},
			wantString: "INHERIT",
		},
		{
			name: "INHERIT false",
			option: &RoleOption{
				Type:  Inherit,
				Value: false,
			},
			wantString: "NOINHERIT",
		},
		{
			name: "LOGIN true",
			option: &RoleOption{
				Type:  Login,
				Value: true,
			},
			wantString: "LOGIN",
		},
		{
			name: "LOGIN false",
			option: &RoleOption{
				Type:  Login,
				Value: false,
			},
			wantString: "NOLOGIN",
		},
		{
			name: "PASSWORD with value",
			option: &RoleOption{
				Type:  Password,
				Value: "'secret123'",
			},
			wantString: "PASSWORD 'secret123'",
		},
		{
			name: "PASSWORD NULL",
			option: &RoleOption{
				Type:  Password,
				Value: nil,
			},
			wantString: "PASSWORD NULL",
		},
		{
			name: "REPLICATION true",
			option: &RoleOption{
				Type:  Replication,
				Value: true,
			},
			wantString: "REPLICATION",
		},
		{
			name: "REPLICATION false",
			option: &RoleOption{
				Type:  Replication,
				Value: false,
			},
			wantString: "NOREPLICATION",
		},
		{
			name: "SUPERUSER true",
			option: &RoleOption{
				Type:  SuperUser,
				Value: true,
			},
			wantString: "SUPERUSER",
		},
		{
			name: "SUPERUSER false",
			option: &RoleOption{
				Type:  SuperUser,
				Value: false,
			},
			wantString: "NOSUPERUSER",
		},
		{
			name: "VALID UNTIL",
			option: &RoleOption{
				Type:  ValidUntil,
				Value: "'2025-12-31'",
			},
			wantString: "VALID UNTIL '2025-12-31'",
		},
		{
			name: "unknown option type",
			option: &RoleOption{
				Type: RoleOptionType(999),
			},
			wantString: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.option.String()
			if got != tt.wantString {
				t.Errorf("RoleOption.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

// Test AlterRoleOperation node
func TestAlterRoleOperation(t *testing.T) {
	tests := []struct {
		name        string
		op          *AlterRoleOperation
		wantLiteral string
		minChildren int
	}{
		{
			name: "RENAME role",
			op: &AlterRoleOperation{
				Type:    RenameRole,
				NewName: "new_admin",
			},
			wantLiteral: "ALTER ROLE",
			minChildren: 0,
		},
		{
			name: "SET CONFIG",
			op: &AlterRoleOperation{
				Type:        SetConfig,
				ConfigName:  "search_path",
				ConfigValue: &LiteralValue{Value: "'public'"},
			},
			wantLiteral: "ALTER ROLE",
			minChildren: 1,
		},
		{
			name: "WITH OPTIONS",
			op: &AlterRoleOperation{
				Type: WithOptions,
				Options: []RoleOption{
					{Type: Login, Value: true},
					{Type: CreateDB, Value: true},
				},
			},
			wantLiteral: "ALTER ROLE",
			minChildren: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.op.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("AlterRoleOperation.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.op.Children()
			if len(children) < tt.minChildren {
				t.Errorf("AlterRoleOperation.Children() count = %d, want at least %d", len(children), tt.minChildren)
			}

			// Test alterOperationNode
			tt.op.alterOperationNode()

			// Test interface implementation
			var _ AlterOperation = tt.op
		})
	}
}

// Test AlterPolicyOperation node
func TestAlterPolicyOperation(t *testing.T) {
	tests := []struct {
		name        string
		op          *AlterPolicyOperation
		wantLiteral string
		minChildren int
	}{
		{
			name: "RENAME policy",
			op: &AlterPolicyOperation{
				Type:    RenamePolicy,
				NewName: "new_policy_name",
			},
			wantLiteral: "ALTER POLICY",
			minChildren: 0,
		},
		{
			name: "MODIFY policy with USING",
			op: &AlterPolicyOperation{
				Type: ModifyPolicy,
				Using: &BinaryExpression{
					Left:     &Identifier{Name: "user_id"},
					Operator: "=",
					Right:    &Identifier{Name: "current_user"},
				},
			},
			wantLiteral: "ALTER POLICY",
			minChildren: 1,
		},
		{
			name: "MODIFY policy with WITH CHECK",
			op: &AlterPolicyOperation{
				Type: ModifyPolicy,
				WithCheck: &BinaryExpression{
					Left:     &Identifier{Name: "status"},
					Operator: "=",
					Right:    &LiteralValue{Value: "active"},
				},
			},
			wantLiteral: "ALTER POLICY",
			minChildren: 1,
		},
		{
			name: "MODIFY policy with both USING and WITH CHECK",
			op: &AlterPolicyOperation{
				Type: ModifyPolicy,
				Using: &BinaryExpression{
					Left:     &Identifier{Name: "user_id"},
					Operator: "=",
					Right:    &Identifier{Name: "current_user"},
				},
				WithCheck: &BinaryExpression{
					Left:     &Identifier{Name: "status"},
					Operator: "=",
					Right:    &LiteralValue{Value: "active"},
				},
			},
			wantLiteral: "ALTER POLICY",
			minChildren: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.op.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("AlterPolicyOperation.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children
			children := tt.op.Children()
			if len(children) < tt.minChildren {
				t.Errorf("AlterPolicyOperation.Children() count = %d, want at least %d", len(children), tt.minChildren)
			}

			// Test alterOperationNode
			tt.op.alterOperationNode()

			// Test interface implementation
			var _ AlterOperation = tt.op
		})
	}
}

// Test AlterConnectorOperation node
func TestAlterConnectorOperation(t *testing.T) {
	tests := []struct {
		name        string
		op          *AlterConnectorOperation
		wantLiteral string
	}{
		{
			name: "ALTER CONNECTOR with properties",
			op: &AlterConnectorOperation{
				Properties: map[string]string{
					"host": "localhost",
					"port": "5432",
				},
			},
			wantLiteral: "ALTER CONNECTOR",
		},
		{
			name: "ALTER CONNECTOR with URL",
			op: &AlterConnectorOperation{
				URL: "jdbc:postgresql://localhost:5432/mydb",
			},
			wantLiteral: "ALTER CONNECTOR",
		},
		{
			name: "ALTER CONNECTOR with owner",
			op: &AlterConnectorOperation{
				Owner: &AlterConnectorOwner{
					IsUser: true,
					Name:   "admin",
				},
			},
			wantLiteral: "ALTER CONNECTOR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test TokenLiteral
			if got := tt.op.TokenLiteral(); got != tt.wantLiteral {
				t.Errorf("AlterConnectorOperation.TokenLiteral() = %v, want %v", got, tt.wantLiteral)
			}

			// Test Children (should always be nil)
			children := tt.op.Children()
			if children != nil {
				t.Errorf("AlterConnectorOperation.Children() = %v, want nil", children)
			}

			// Test alterOperationNode
			tt.op.alterOperationNode()

			// Test interface implementation
			var _ AlterOperation = tt.op
		})
	}
}
