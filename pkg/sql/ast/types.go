package ast

// ColumnPosition represents the position of a column in a table
type ColumnPosition struct {
	First    bool
	After    *Ident
	Position int
}

// Partition represents table partitioning information
type Partition struct {
	Name    string
	Columns []*Ident
}

// DropBehavior specifies the behavior when dropping objects
type DropBehavior int

const (
	DropCascade DropBehavior = iota
	DropRestrict
)

// AlterColumnOperation represents operations that can be performed on columns
type AlterColumnOperation int

const (
	AlterColumnSetDefault AlterColumnOperation = iota
	AlterColumnDropDefault
	AlterColumnSetNotNull
	AlterColumnDropNotNull
)

// Make AlterColumnOperation implement Node interface
func (a *AlterColumnOperation) Children() []Node { return nil }
func (a *AlterColumnOperation) TokenLiteral() string {
	switch *a {
	case AlterColumnSetDefault:
		return "SET DEFAULT"
	case AlterColumnDropDefault:
		return "DROP DEFAULT"
	case AlterColumnSetNotNull:
		return "SET NOT NULL"
	case AlterColumnDropNotNull:
		return "DROP NOT NULL"
	default:
		return "UNKNOWN"
	}
}

// HiveDistributionStyle represents Hive-specific distribution styles
type HiveDistributionStyle int

const (
	HiveDistributionNone HiveDistributionStyle = iota
	HiveDistributionHash
	HiveDistributionRandom
)

// HiveFormat represents Hive-specific storage formats
type HiveFormat int

const (
	HiveFormatNone HiveFormat = iota
	HiveFormatORC
	HiveFormatParquet
	HiveFormatAvro
)

// SqlOption represents SQL-specific options
type SqlOption struct {
	Name  string
	Value string
}

// FileFormat represents file format specifications
type FileFormat int

const (
	FileFormatNone FileFormat = iota
	FileFormatCSV
	FileFormatJSON
	FileFormatParquet
)

// Query represents a SQL query
type Query struct {
	Text string
}

func (q *Query) TokenLiteral() string { return "QUERY" }
func (q *Query) Children() []Node     { return nil }

// Setting represents a SET clause in an UPDATE statement
type Setting struct {
	Column *Ident
	Value  Expression
}

// Ident represents an identifier in SQL (table name, column name, etc.)
type Ident struct {
	Name string
}

func (i *Ident) String() string { return i.Name }

// Make Ident implement Expression interface
func (*Ident) expressionNode()        {}
func (i *Ident) TokenLiteral() string { return i.Name }
func (i *Ident) Children() []Node     { return nil }

// InputFormatClause represents the format specification for input data
type InputFormatClause struct {
	Format  string
	Options map[string]string
}

// TableEngine represents the storage engine for a table
type TableEngine string

// CommentDef represents a comment on a database object
type CommentDef struct {
	Text string
}

func (c *CommentDef) TokenLiteral() string { return "COMMENT" }
func (c *CommentDef) Children() []Node     { return nil }

// OnCommit represents the ON COMMIT behavior for temporary tables
type OnCommit int

const (
	OnCommitNone OnCommit = iota
	OnCommitDelete
	OnCommitPreserve
)

// Expr represents a SQL expression
type Expr interface {
	Node
	exprNode()
}

// OneOrManyWithParens represents a list of items enclosed in parentheses
type OneOrManyWithParens[T any] struct {
	Items []T
}

func (o *OneOrManyWithParens[T]) TokenLiteral() string { return "(" }
func (o *OneOrManyWithParens[T]) Children() []Node {
	nodes := make([]Node, len(o.Items))
	for i, item := range o.Items {
		if node, ok := any(item).(Node); ok {
			nodes[i] = node
		}
	}
	return nodes
}

// WrappedCollection represents a collection of items with optional wrapper
type WrappedCollection[T any] struct {
	Items   []T
	Wrapper string
}

func (w *WrappedCollection[T]) TokenLiteral() string { return w.Wrapper }
func (w *WrappedCollection[T]) Children() []Node {
	nodes := make([]Node, len(w.Items))
	for i, item := range w.Items {
		if node, ok := any(item).(Node); ok {
			nodes[i] = node
		}
	}
	return nodes
}

// ClusteredBy represents CLUSTERED BY clause
type ClusteredBy struct {
	Columns []Node
	Buckets int
}

func (c *ClusteredBy) TokenLiteral() string { return "CLUSTERED BY" }
func (c *ClusteredBy) Children() []Node     { return c.Columns }

// RowAccessPolicy represents row-level access policy
type RowAccessPolicy struct {
	Name    string
	Filter  Expr
	Enabled bool
}

func (r *RowAccessPolicy) TokenLiteral() string { return "ROW ACCESS POLICY" }
func (r *RowAccessPolicy) Children() []Node {
	if r.Filter != nil {
		return []Node{r.Filter}
	}
	return nil
}

// Tag represents a key-value metadata tag
type Tag struct {
	Key   string
	Value string
}

// StorageSerializationPolicy represents storage serialization policy
type StorageSerializationPolicy int

const (
	StorageSerializationNone StorageSerializationPolicy = iota
	StorageSerializationJSON
	StorageSerializationAvro
)

// StatementVariant represents a specific type of SQL statement
type StatementVariant interface {
	Node
	statementNode()
}

// StatementImpl represents a concrete implementation of a SQL statement
type StatementImpl struct {
	Variant StatementVariant
}

func (s *StatementImpl) TokenLiteral() string { return s.Variant.TokenLiteral() }
func (s *StatementImpl) Children() []Node     { return []Node{s.Variant} }
func (s *StatementImpl) statementNode()       {}

// CreateTable represents a CREATE TABLE statement
type CreateTable struct {
	Name                  ObjectName
	Columns               []ColumnDef
	Constraints           []TableConstraint
	Options               *[]SqlOption
	IfNotExists           bool
	Temporary             bool
	External              bool
	Stored                bool
	Transient             bool
	OrReplace             bool
	Global                *bool
	Volatile              bool
	Iceberg               bool
	HiveDistribution      HiveDistributionStyle
	HiveFormats           *HiveFormat
	TableProperties       []SqlOption
	WithOptions           []SqlOption
	FileFormat            *FileFormat
	Location              *string
	Query                 *Query
	WithoutRowID          bool
	Like                  *ObjectName
	Clone                 *ObjectName
	Engine                *TableEngine
	Comment               *CommentDef
	AutoIncrementOffset   *uint32
	DefaultCharset        *string
	Collation             *string
	OnCommit              *OnCommit
	OnCluster             *Ident
	PrimaryKey            *Expr
	OrderBy               *OneOrManyWithParens[Expr]
	PartitionBy           *Expr
	ClusterBy             *WrappedCollection[[]Ident]
	ClusteredBy           *ClusteredBy
	Strict                bool
	CopyGrants            bool
	EnableSchemaEvolution *bool
	ChangeTracking        *bool
	DataRetentionDays     *uint64
	MaxDataExtensionDays  *uint64
	DefaultDDLCollation   *string
	AggregationPolicy     *ObjectName
	RowAccessPolicy       *RowAccessPolicy
	Tags                  *[]Tag
	BaseLocation          *string
	ExternalVolume        *string
	Catalog               *string
	CatalogSync           *string
	SerializationPolicy   *StorageSerializationPolicy
}

func (*CreateTable) statementNode() {}
func (c *CreateTable) Children() []Node {
	nodes := []Node{c.Name}
	for _, col := range c.Columns {
		nodes = append(nodes, col)
	}
	for _, con := range c.Constraints {
		nodes = append(nodes, con)
	}
	if c.Query != nil {
		nodes = append(nodes, c.Query)
	}
	if c.Like != nil {
		nodes = append(nodes, c.Like)
	}
	if c.Clone != nil {
		nodes = append(nodes, c.Clone)
	}
	if c.Comment != nil {
		nodes = append(nodes, c.Comment)
	}
	if c.ClusteredBy != nil {
		nodes = append(nodes, c.ClusteredBy)
	}
	if c.RowAccessPolicy != nil {
		nodes = append(nodes, c.RowAccessPolicy)
	}
	return nodes
}
func (c *CreateTable) TokenLiteral() string { return "CREATE TABLE" }
