package ast

// Node represents any node in the AST
type Node interface {
	TokenLiteral() string
}

// Statement represents a SQL statement
type Statement interface {
	Node
	statementNode()
}

// Expression represents a SQL expression
type Expression interface {
	Node
	expressionNode()
}

// SelectStatement represents a SELECT SQL statement
type SelectStatement struct {
	Columns   []Expression
	TableName string
	Where     Expression
	OrderBy   []Expression
	Limit     *int
	Offset    *int
}

func (s *SelectStatement) statementNode()       {}
func (s *SelectStatement) TokenLiteral() string { return "SELECT" }

// Identifier represents a column or table name
type Identifier struct {
	Name string
}

func (i *Identifier) expressionNode()      {}
func (i *Identifier) TokenLiteral() string { return i.Name }

// BinaryExpression represents operations like WHERE column = value
type BinaryExpression struct {
	Left     Expression
	Operator string
	Right    Expression
}

func (b *BinaryExpression) expressionNode()      {}
func (b *BinaryExpression) TokenLiteral() string { return b.Operator }

// AST represents the root of the Abstract Syntax Tree
type AST struct {
	Statements []Statement
}

// NewAST creates a new AST
func NewAST() *AST {
	return &AST{
		Statements: make([]Statement, 0),
	}
}
