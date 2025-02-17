package ast

// ObjectName represents a qualified or unqualified object name
type ObjectName struct {
	Name string
}

func (o ObjectName) TokenLiteral() string { return o.Name }
func (o ObjectName) Children() []Node     { return nil }
func (o ObjectName) String() string       { return o.Name }
