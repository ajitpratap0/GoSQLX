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

type IndexOptionType int

const (
	UsingIndex IndexOptionType = iota
	CommentIndex
)

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

func (a *AlterStatement) statementNode()      {}
func (a AlterStatement) TokenLiteral() string { return "ALTER" }
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
func (a AlterTableOperation) TokenLiteral() string { return "ALTER TABLE" }
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

type RoleOptionType int

const (
	BypassRLS RoleOptionType = iota
	ConnectionLimit
	CreateDB
	CreateRole
	Inherit
	Login
	Password
	Replication
	SuperUser
	ValidUntil
)

func (opt *RoleOption) String() string {
	switch opt.Type {
	case BypassRLS:
		if opt.Value.(bool) {
			return "BYPASSRLS"
		}
		return "NOBYPASSRLS"
	case ConnectionLimit:
		return fmt.Sprintf("CONNECTION LIMIT %v", opt.Value)
	case CreateDB:
		if opt.Value.(bool) {
			return "CREATEDB"
		}
		return "NOCREATEDB"
	case CreateRole:
		if opt.Value.(bool) {
			return "CREATEROLE"
		}
		return "NOCREATEROLE"
	case Inherit:
		if opt.Value.(bool) {
			return "INHERIT"
		}
		return "NOINHERIT"
	case Login:
		if opt.Value.(bool) {
			return "LOGIN"
		}
		return "NOLOGIN"
	case Password:
		if opt.Value == nil {
			return "PASSWORD NULL"
		}
		return fmt.Sprintf("PASSWORD %v", opt.Value)
	case Replication:
		if opt.Value.(bool) {
			return "REPLICATION"
		}
		return "NOREPLICATION"
	case SuperUser:
		if opt.Value.(bool) {
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
func (a AlterRoleOperation) TokenLiteral() string { return "ALTER ROLE" }
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
func (a AlterPolicyOperation) TokenLiteral() string { return "ALTER POLICY" }
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
func (a AlterConnectorOperation) TokenLiteral() string { return "ALTER CONNECTOR" }
func (a AlterConnectorOperation) Children() []Node     { return nil }

// AlterConnectorOwner represents the new owner of a connector
type AlterConnectorOwner struct {
	IsUser bool
	Name   string
}
