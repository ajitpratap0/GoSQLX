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
	"fmt"
)

// IndexType represents the indexing method used by an index
type IndexType int

const (
	BTree IndexType = iota
	Hash
)

// String returns the SQL keyword for this index type: "BTREE" or "HASH".
func (t IndexType) String() string {
	switch t {
	case BTree:
		return "BTREE"
	case Hash:
		return "HASH"
	default:
		return "UNKNOWN"
	}
}

// IndexOption represents MySQL index options
type IndexOption struct {
	Type    IndexOptionType
	Using   *IndexType // Used for Using
	Comment string     // Used for Comment
}

// IndexOptionType identifies which kind of index option is represented.
type IndexOptionType int

const (
	// UsingIndex specifies the index access method (e.g. USING BTREE).
	UsingIndex IndexOptionType = iota
	// CommentIndex attaches a comment string to the index.
	CommentIndex
)

// String returns the SQL representation of this index option (e.g. "USING BTREE"
// or "COMMENT 'text'").
func (opt *IndexOption) String() string {
	switch opt.Type {
	case UsingIndex:
		return fmt.Sprintf("USING %s", opt.Using)
	case CommentIndex:
		return fmt.Sprintf("COMMENT '%s'", opt.Comment)
	default:
		return ""
	}
}

// NullsDistinctOption represents Postgres unique index nulls handling
type NullsDistinctOption int

const (
	NullsDistinctNone NullsDistinctOption = iota
	NullsDistinct
	NullsNotDistinct
)

// String returns the SQL keyword phrase for this nulls-distinct option:
// "NULLS DISTINCT", "NULLS NOT DISTINCT", or an empty string for the default.
func (opt NullsDistinctOption) String() string {
	switch opt {
	case NullsDistinct:
		return "NULLS DISTINCT"
	case NullsNotDistinct:
		return "NULLS NOT DISTINCT"
	default:
		return ""
	}
}

// AlterStatement represents an ALTER statement
type AlterStatement struct {
	Type      AlterType
	Name      string // Name of the object being altered
	Operation AlterOperation
}

func (a *AlterStatement) statementNode() {}

// TokenLiteral implements Node and returns "ALTER".
func (a AlterStatement) TokenLiteral() string { return "ALTER" }

// Children implements Node and returns the alter operation as a single child,
// or nil if no operation is set.
func (a AlterStatement) Children() []Node {
	if a.Operation != nil {
		return []Node{a.Operation}
	}
	return nil
}

// AlterType represents the type of object being altered
type AlterType int

const (
	AlterTypeTable AlterType = iota
	AlterTypeRole
	AlterTypePolicy
	AlterTypeConnector
)

// AlterOperation represents the operation to be performed
type AlterOperation interface {
	Node
	alterOperationNode()
}

// AlterTableOperation represents operations that can be performed on a table
type AlterTableOperation struct {
	Type             AlterTableOpType
	ColumnKeyword    bool                  // Used for AddColumn
	IfNotExists      bool                  // Used for AddColumn, AddPartition
	IfExists         bool                  // Used for DropColumn, DropConstraint, DropPartition
	ColumnDef        *ColumnDef            // Used for AddColumn
	ColumnPosition   *ColumnPosition       // Used for AddColumn, ChangeColumn, ModifyColumn
	Constraint       *TableConstraint      // Used for AddConstraint
	ProjectionName   *Ident                // Used for AddProjection, DropProjection
	ProjectionSelect *Select               // Used for AddProjection
	PartitionName    *Ident                // Used for MaterializeProjection, ClearProjection
	OldColumnName    *Ident                // Used for RenameColumn
	NewColumnName    *Ident                // Used for RenameColumn
	TableName        ObjectName            // Used for RenameTable
	NewTableName     ObjectName            // Used for RenameTable
	OldPartitions    []*Expression         // Used for RenamePartitions
	NewPartitions    []*Expression         // Used for RenamePartitions
	Partitions       []*Partition          // Used for AddPartitions
	DropBehavior     DropBehavior          // Used for DropColumn, DropConstraint
	ConstraintName   *Ident                // Used for DropConstraint
	OldName          *Ident                // Used for RenameConstraint
	NewName          *Ident                // Used for RenameConstraint
	ColumnName       *Ident                // Used for AlterColumn
	AlterColumnOp    *AlterColumnOperation // Used for AlterColumn
	CascadeDrops     bool                  // Used for DropColumn, DropConstraint
}

func (a *AlterTableOperation) alterOperationNode() {}

// TokenLiteral implements Node and returns "ALTER TABLE".
func (a AlterTableOperation) TokenLiteral() string { return "ALTER TABLE" }

// Children implements Node and returns the child nodes involved in this
// ALTER TABLE operation: the column definition, constraint, projection select,
// and/or alter column operation, depending on the operation type.
func (a AlterTableOperation) Children() []Node {
	var children []Node
	if a.ColumnDef != nil {
		children = append(children, a.ColumnDef)
	}
	if a.Constraint != nil {
		children = append(children, a.Constraint)
	}
	if a.ProjectionSelect != nil {
		children = append(children, a.ProjectionSelect)
	}
	if a.AlterColumnOp != nil {
		children = append(children, a.AlterColumnOp)
	}
	return children
}

// AlterTableOpType represents the type of table alteration
type AlterTableOpType int

const (
	AddConstraint AlterTableOpType = iota
	AddColumn
	AddProjection
	AlterColumn
	ChangeColumn
	ClearProjection
	DropColumn
	DropConstraint
	DropPartition
	DropProjection
	MaterializeProjection
	ModifyColumn
	RenameColumn
	RenameConstraint
	RenamePartitions
	RenameTable
)

// RoleOption represents an option in ROLE statement
type RoleOption struct {
	Name  string
	Type  RoleOptionType
	Value interface{} // Can be bool or Expression depending on Type
}

// RoleOptionType identifies which role attribute is being set.
type RoleOptionType int

const (
	// BypassRLS controls whether the role bypasses row-level security policies.
	BypassRLS RoleOptionType = iota
	// ConnectionLimit sets the maximum number of concurrent connections for the role.
	ConnectionLimit
	// CreateDB allows or prevents the role from creating new databases.
	CreateDB
	// CreateRole allows or prevents the role from creating new roles.
	CreateRole
	// Inherit controls whether the role inherits privileges of roles it is a member of.
	Inherit
	// Login allows or prevents the role from logging in.
	Login
	// Password sets the password for the role.
	Password
	// Replication controls whether the role can initiate streaming replication.
	Replication
	// SuperUser grants or revokes superuser privileges.
	SuperUser
	// ValidUntil sets the date and time after which the role's password is no longer valid.
	ValidUntil
)

// String returns the SQL keyword phrase for this role option (e.g. "SUPERUSER",
// "NOSUPERUSER", "LOGIN", "CONNECTION LIMIT 10", "PASSWORD NULL", etc.).
func (opt *RoleOption) String() string {
	switch opt.Type {
	case BypassRLS:
		if b, ok := opt.Value.(bool); ok && b {
			return "BYPASSRLS"
		}
		return "NOBYPASSRLS"
	case ConnectionLimit:
		return fmt.Sprintf("CONNECTION LIMIT %v", opt.Value)
	case CreateDB:
		if b, ok := opt.Value.(bool); ok && b {
			return "CREATEDB"
		}
		return "NOCREATEDB"
	case CreateRole:
		if b, ok := opt.Value.(bool); ok && b {
			return "CREATEROLE"
		}
		return "NOCREATEROLE"
	case Inherit:
		if b, ok := opt.Value.(bool); ok && b {
			return "INHERIT"
		}
		return "NOINHERIT"
	case Login:
		if b, ok := opt.Value.(bool); ok && b {
			return "LOGIN"
		}
		return "NOLOGIN"
	case Password:
		if opt.Value == nil {
			return "PASSWORD NULL"
		}
		return fmt.Sprintf("PASSWORD %v", opt.Value)
	case Replication:
		if b, ok := opt.Value.(bool); ok && b {
			return "REPLICATION"
		}
		return "NOREPLICATION"
	case SuperUser:
		if b, ok := opt.Value.(bool); ok && b {
			return "SUPERUSER"
		}
		return "NOSUPERUSER"
	case ValidUntil:
		return fmt.Sprintf("VALID UNTIL %v", opt.Value)
	default:
		return ""
	}
}

// AlterRoleOperation represents operations that can be performed on a role
type AlterRoleOperation struct {
	Type        AlterRoleOpType
	NewName     string
	Options     []RoleOption
	MemberName  string
	ConfigName  string
	ConfigValue Expression
	InDatabase  string
}

func (a *AlterRoleOperation) alterOperationNode() {}

// TokenLiteral implements Node and returns "ALTER ROLE".
func (a AlterRoleOperation) TokenLiteral() string { return "ALTER ROLE" }

// Children implements Node and returns the ConfigValue expression as a child,
// or nil if no config value is set.
func (a AlterRoleOperation) Children() []Node {
	var children []Node
	if a.ConfigValue != nil {
		children = append(children, a.ConfigValue)
	}
	return children
}

// AlterRoleOpType represents the type of role alteration
type AlterRoleOpType int

const (
	RenameRole AlterRoleOpType = iota
	AddMember
	DropMember
	SetConfig
	ResetConfig
	WithOptions
)

// AlterPolicyOperation represents operations that can be performed on a policy
type AlterPolicyOperation struct {
	Type      AlterPolicyOpType
	NewName   string
	To        []string
	Using     Expression
	WithCheck Expression
}

func (a *AlterPolicyOperation) alterOperationNode() {}

// TokenLiteral implements Node and returns "ALTER POLICY".
func (a AlterPolicyOperation) TokenLiteral() string { return "ALTER POLICY" }

// Children implements Node and returns the USING and WITH CHECK expressions
// as child nodes (any nil expressions are omitted).
func (a AlterPolicyOperation) Children() []Node {
	var children []Node
	if a.Using != nil {
		children = append(children, a.Using)
	}
	if a.WithCheck != nil {
		children = append(children, a.WithCheck)
	}
	return children
}

// AlterPolicyOpType represents the type of policy alteration
type AlterPolicyOpType int

const (
	RenamePolicy AlterPolicyOpType = iota
	ModifyPolicy
)

// AlterConnectorOperation represents operations that can be performed on a connector
type AlterConnectorOperation struct {
	Properties map[string]string
	URL        string
	Owner      *AlterConnectorOwner
}

func (a *AlterConnectorOperation) alterOperationNode() {}

// TokenLiteral implements Node and returns "ALTER CONNECTOR".
func (a AlterConnectorOperation) TokenLiteral() string { return "ALTER CONNECTOR" }

// Children implements Node and returns nil - AlterConnectorOperation has no child nodes.
func (a AlterConnectorOperation) Children() []Node { return nil }

// AlterConnectorOwner represents the new owner of a connector
type AlterConnectorOwner struct {
	IsUser bool
	Name   string
}
