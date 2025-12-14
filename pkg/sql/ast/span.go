package ast

import "github.com/ajitpratap0/GoSQLX/pkg/models"

// Spanned represents an AST node that has source location information
type Spanned interface {
	// Span returns the source location span for this node
	Span() models.Span
}

// SpannedNode represents a basic AST node with source location information
type SpannedNode struct {
	span models.Span
}

// Span returns the source location span for this node
func (n *SpannedNode) Span() models.Span {
	return n.span
}

// SetSpan sets the source location span for this node
func (n *SpannedNode) SetSpan(span models.Span) {
	n.span = span
}

// UnionSpans returns the union of all spans in the given slice
func UnionSpans(spans []models.Span) models.Span {
	if len(spans) == 0 {
		return models.EmptySpan()
	}
	result := spans[0]
	for i := 1; i < len(spans); i++ {
		// Union the spans by taking the earliest start and latest end
		if spans[i].Start.Line < result.Start.Line ||
			(spans[i].Start.Line == result.Start.Line && spans[i].Start.Column < result.Start.Column) {
			result.Start = spans[i].Start
		}
		if spans[i].End.Line > result.End.Line ||
			(spans[i].End.Line == result.End.Line && spans[i].End.Column > result.End.Column) {
			result.End = spans[i].End
		}
	}
	return result
}

// Now let's implement Spanned for our core AST nodes

// Span returns the source location span for the AST
func (a *AST) Span() models.Span {
	if len(a.Statements) == 0 {
		return models.EmptySpan()
	}
	spans := make([]models.Span, len(a.Statements))
	for i, stmt := range a.Statements {
		if spanned, ok := stmt.(Spanned); ok {
			spans[i] = spanned.Span()
		}
	}
	return UnionSpans(spans)
}

// spanInfo stores source location information for AST nodes
var spanInfo = make(map[interface{}]models.Span)

// SetSpan sets the source location span for an AST node
func SetSpan(node interface{}, span models.Span) {
	spanInfo[node] = span
}

// GetSpan gets the source location span for an AST node
func GetSpan(node interface{}) models.Span {
	if span, ok := spanInfo[node]; ok {
		return span
	}
	return models.EmptySpan()
}

// Span returns the source location span for the SelectStatement
func (s *SelectStatement) Span() models.Span {
	return GetSpan(s)
}

// Span returns the source location span for the InsertStatement
func (i *InsertStatement) Span() models.Span {
	spans := make([]models.Span, 0)

	if i.With != nil {
		if spanned, ok := interface{}(i.With).(Spanned); ok {
			spans = append(spans, spanned.Span())
		}
	}

	for _, col := range i.Columns {
		if spanned, ok := col.(Spanned); ok {
			spans = append(spans, spanned.Span())
		}
	}

	for _, row := range i.Values {
		for _, val := range row {
			if spanned, ok := val.(Spanned); ok {
				spans = append(spans, spanned.Span())
			}
		}
	}

	if i.Query != nil {
		if spanned, ok := interface{}(i.Query).(Spanned); ok {
			spans = append(spans, spanned.Span())
		}
	}

	for _, expr := range i.Returning {
		if spanned, ok := expr.(Spanned); ok {
			spans = append(spans, spanned.Span())
		}
	}

	return UnionSpans(spans)
}

// Span returns the source location span for the UpdateStatement
func (u *UpdateStatement) Span() models.Span {
	return GetSpan(u)
}

// Span returns the source location span for the DeleteStatement
func (d *DeleteStatement) Span() models.Span {
	return GetSpan(d)
}

// Span returns the source location span for expressions
func (e *BinaryExpression) Span() models.Span {
	spans := make([]models.Span, 0)

	if e.Left != nil {
		if spanned, ok := e.Left.(Spanned); ok {
			spans = append(spans, spanned.Span())
		}
	}

	if e.Right != nil {
		if spanned, ok := e.Right.(Spanned); ok {
			spans = append(spans, spanned.Span())
		}
	}

	return UnionSpans(spans)
}

func (e *UnaryExpression) Span() models.Span {
	if e.Expr != nil {
		if spanned, ok := e.Expr.(Spanned); ok {
			return spanned.Span()
		}
	}
	return models.EmptySpan()
}

func (e *CastExpression) Span() models.Span {
	if e.Expr != nil {
		if spanned, ok := e.Expr.(Spanned); ok {
			return spanned.Span()
		}
	}
	return models.EmptySpan()
}

func (i *IntervalExpression) Span() models.Span {
	// IntervalExpression has no child expressions, return empty span
	return models.EmptySpan()
}

func (e *FunctionCall) Span() models.Span {
	spans := make([]models.Span, 0)

	for _, arg := range e.Arguments {
		if spanned, ok := arg.(Spanned); ok {
			spans = append(spans, spanned.Span())
		}
	}

	return UnionSpans(spans)
}
