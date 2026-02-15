package ast

import (
	"testing"
)

func TestPutFunctionCall(t *testing.T) {
	fc := GetFunctionCall()
	fc.Name = "count"
	fc.Arguments = append(fc.Arguments, &Identifier{Name: "x"})
	fc.Distinct = true
	PutFunctionCall(fc)
	PutFunctionCall(nil) // nil safety
}

func TestPutCaseExpression(t *testing.T) {
	ce := GetCaseExpression()
	ce.Value = &Identifier{Name: "x"}
	ce.WhenClauses = append(ce.WhenClauses, WhenClause{Condition: &Identifier{Name: "1"}, Result: &Identifier{Name: "a"}})
	ce.ElseClause = &Identifier{Name: "b"}
	PutCaseExpression(ce)
	PutCaseExpression(nil)
}

func TestPutBetweenExpression(t *testing.T) {
	be := GetBetweenExpression()
	be.Expr = &Identifier{Name: "x"}
	be.Lower = &LiteralValue{Value: "1"}
	be.Upper = &LiteralValue{Value: "10"}
	be.Not = true
	PutBetweenExpression(be)
	PutBetweenExpression(nil)
}

func TestPutInExpression(t *testing.T) {
	ie := GetInExpression()
	ie.Expr = &Identifier{Name: "x"}
	ie.List = append(ie.List, &LiteralValue{Value: "1"}, &LiteralValue{Value: "2"})
	ie.Not = true
	PutInExpression(ie)
	PutInExpression(nil)
}

func TestPutTupleExpression(t *testing.T) {
	te := GetTupleExpression()
	te.Expressions = append(te.Expressions, &LiteralValue{Value: "1"})
	PutTupleExpression(te)
	PutTupleExpression(nil)
}

func TestPutArrayConstructor(t *testing.T) {
	ac := GetArrayConstructor()
	ac.Elements = append(ac.Elements, &LiteralValue{Value: "1"})
	PutArrayConstructor(ac)
	PutArrayConstructor(nil)
}

func TestPutSubqueryExpression(t *testing.T) {
	se := GetSubqueryExpression()
	se.Subquery = &SelectStatement{Columns: []Expression{&Identifier{Name: "a"}}}
	PutSubqueryExpression(se)
	PutSubqueryExpression(nil)
}

func TestPutCastExpression(t *testing.T) {
	ce := GetCastExpression()
	ce.Expr = &Identifier{Name: "x"}
	ce.Type = "INT"
	PutCastExpression(ce)
	PutCastExpression(nil)
}

func TestPutIntervalExpression(t *testing.T) {
	ie := GetIntervalExpression()
	ie.Value = "1 day"
	PutIntervalExpression(ie)
	PutIntervalExpression(nil)
}

func TestPutAliasedExpression(t *testing.T) {
	ae := GetAliasedExpression()
	ae.Expr = &Identifier{Name: "x"}
	ae.Alias = "y"
	PutAliasedExpression(ae)
	PutAliasedExpression(nil)
}

func TestPutArraySubscriptExpression(t *testing.T) {
	ase := GetArraySubscriptExpression()
	ase.Array = &Identifier{Name: "arr"}
	ase.Indices = append(ase.Indices, &LiteralValue{Value: "1"})
	PutArraySubscriptExpression(ase)
	PutArraySubscriptExpression(nil)
}

func TestPutArraySliceExpression(t *testing.T) {
	ase := GetArraySliceExpression()
	ase.Array = &Identifier{Name: "arr"}
	ase.Start = &LiteralValue{Value: "1"}
	ase.End = &LiteralValue{Value: "3"}
	PutArraySliceExpression(ase)
	PutArraySliceExpression(nil)
}

func TestReleaseStatements(t *testing.T) {
	stmts := []Statement{
		&SelectStatement{Columns: []Expression{&Identifier{Name: "a"}}},
		&InsertStatement{TableName: "t"},
		&UpdateStatement{TableName: "t", Assignments: []UpdateExpression{{Column: &Identifier{Name: "x"}, Value: &LiteralValue{Value: "1"}}}},
		&DeleteStatement{TableName: "t"},
	}
	ReleaseStatements(stmts) // should not panic
}
