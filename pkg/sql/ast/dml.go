package ast

// Select represents a SELECT statement
type Select struct {
	Distinct bool
	Columns  []Expression
	From     []TableReference
	Where    Expression
	GroupBy  []Expression
	Having   Expression
	OrderBy  []Expression
	Limit    *int64
	Offset   *int64
}

func (s *Select) statementNode()      {}
func (s Select) TokenLiteral() string { return "SELECT" }
func (s Select) Children() []Node {
	children := make([]Node, 0)
	children = append(children, nodifyExpressions(s.Columns)...)
	for _, from := range s.From {
		from := from // G601: Create local copy to avoid memory aliasing
		children = append(children, &from)
	}
	if s.Where != nil {
		children = append(children, s.Where)
	}
	children = append(children, nodifyExpressions(s.GroupBy)...)
	if s.Having != nil {
		children = append(children, s.Having)
	}
	children = append(children, nodifyExpressions(s.OrderBy)...)
	return children
}

// Insert represents an INSERT statement
type Insert struct {
	Table           TableReference
	Columns         []Expression
	Values          [][]Expression
	ReturningClause []Expression
}

func (i *Insert) statementNode()      {}
func (i Insert) TokenLiteral() string { return "INSERT" }
func (i Insert) Children() []Node {
	children := make([]Node, 0)
	children = append(children, &i.Table)
	children = append(children, nodifyExpressions(i.Columns)...)
	for _, row := range i.Values {
		children = append(children, nodifyExpressions(row)...)
	}
	children = append(children, nodifyExpressions(i.ReturningClause)...)
	return children
}

// Delete represents a DELETE statement
type Delete struct {
	Table           TableReference
	Where           Expression
	ReturningClause []Expression
}

func (d *Delete) statementNode()      {}
func (d Delete) TokenLiteral() string { return "DELETE" }
func (d Delete) Children() []Node {
	children := make([]Node, 0)
	children = append(children, &d.Table)
	if d.Where != nil {
		children = append(children, d.Where)
	}
	children = append(children, nodifyExpressions(d.ReturningClause)...)
	return children
}

// Update represents an UPDATE statement
type Update struct {
	Table           TableReference
	Updates         []UpdateExpression
	Where           Expression
	ReturningClause []Expression
}

func (u *Update) statementNode()      {}
func (u Update) TokenLiteral() string { return "UPDATE" }
func (u Update) Children() []Node {
	children := make([]Node, 0)
	children = append(children, &u.Table)
	for _, update := range u.Updates {
		update := update // G601: Create local copy to avoid memory aliasing
		children = append(children, &update)
	}
	if u.Where != nil {
		children = append(children, u.Where)
	}
	children = append(children, nodifyExpressions(u.ReturningClause)...)
	return children
}
