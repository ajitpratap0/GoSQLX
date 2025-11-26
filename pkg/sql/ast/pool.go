package ast

import (
	"sync"
)

var (
	// AST node pools
	astPool = sync.Pool{
		New: func() interface{} {
			return &AST{
				Statements: make([]Statement, 0, 8), // Increased initial capacity
			}
		},
	}

	// Statement pools
	selectStmtPool = sync.Pool{
		New: func() interface{} {
			return &SelectStatement{
				Columns: make([]Expression, 0, 4),
				OrderBy: make([]OrderByExpression, 0, 1),
			}
		},
	}

	insertStmtPool = sync.Pool{
		New: func() interface{} {
			return &InsertStatement{
				Columns: make([]Expression, 0, 4),
				Values:  make([]Expression, 0, 4),
			}
		},
	}

	updateStmtPool = sync.Pool{
		New: func() interface{} {
			return &UpdateStatement{
				Updates: make([]UpdateExpression, 0, 4),
			}
		},
	}

	deleteStmtPool = sync.Pool{
		New: func() interface{} {
			return &DeleteStatement{}
		},
	}

	// Expression pools
	identifierPool = sync.Pool{
		New: func() interface{} {
			return &Identifier{}
		},
	}

	binaryExprPool = sync.Pool{
		New: func() interface{} {
			return &BinaryExpression{}
		},
	}

	// Add a pool for LiteralValue to reduce allocations
	literalValuePool = sync.Pool{
		New: func() interface{} {
			return &LiteralValue{}
		},
	}

	updateExprPool = sync.Pool{
		New: func() interface{} {
			return &UpdateExpression{}
		},
	}

	// Additional expression pools for common expression types
	functionCallPool = sync.Pool{
		New: func() interface{} {
			return &FunctionCall{
				Arguments: make([]Expression, 0, 4),
			}
		},
	}

	caseExprPool = sync.Pool{
		New: func() interface{} {
			return &CaseExpression{
				WhenClauses: make([]WhenClause, 0, 2),
			}
		},
	}

	betweenExprPool = sync.Pool{
		New: func() interface{} {
			return &BetweenExpression{}
		},
	}

	inExprPool = sync.Pool{
		New: func() interface{} {
			return &InExpression{
				List: make([]Expression, 0, 4),
			}
		},
	}

	subqueryExprPool = sync.Pool{
		New: func() interface{} {
			return &SubqueryExpression{}
		},
	}

	castExprPool = sync.Pool{
		New: func() interface{} {
			return &CastExpression{}
		},
	}

	// Slice pools
	exprSlicePool = sync.Pool{
		New: func() interface{} {
			s := make([]Expression, 0, 16) // Double capacity for better performance
			return &s
		},
	}
)

// NewAST creates a new AST from the pool
func NewAST() *AST {
	return astPool.Get().(*AST)
}

// ReleaseAST returns an AST to the pool
func ReleaseAST(ast *AST) {
	if ast == nil {
		return
	}

	// Clean up all statements
	for i := range ast.Statements {
		switch stmt := ast.Statements[i].(type) {
		case *SelectStatement:
			PutSelectStatement(stmt)
		case *InsertStatement:
			PutInsertStatement(stmt)
		case *UpdateStatement:
			PutUpdateStatement(stmt)
		case *DeleteStatement:
			PutDeleteStatement(stmt)
		}
		ast.Statements[i] = nil
	}

	// Reset slice but keep capacity
	ast.Statements = ast.Statements[:0]

	// Return to pool
	astPool.Put(ast)
}

// GetInsertStatement gets an InsertStatement from the pool
func GetInsertStatement() *InsertStatement {
	return insertStmtPool.Get().(*InsertStatement)
}

// PutInsertStatement returns an InsertStatement to the pool
func PutInsertStatement(stmt *InsertStatement) {
	if stmt == nil {
		return
	}

	// Clean up expressions
	for i := range stmt.Columns {
		PutExpression(stmt.Columns[i])
		stmt.Columns[i] = nil
	}
	for i := range stmt.Values {
		PutExpression(stmt.Values[i])
		stmt.Values[i] = nil
	}

	// Reset slices but keep capacity
	stmt.Columns = stmt.Columns[:0]
	stmt.Values = stmt.Values[:0]
	stmt.TableName = ""

	// Return to pool
	insertStmtPool.Put(stmt)
}

// GetUpdateStatement gets an UpdateStatement from the pool
func GetUpdateStatement() *UpdateStatement {
	return updateStmtPool.Get().(*UpdateStatement)
}

// PutUpdateStatement returns an UpdateStatement to the pool
func PutUpdateStatement(stmt *UpdateStatement) {
	if stmt == nil {
		return
	}

	// Clean up expressions
	for i := range stmt.Updates {
		PutExpression(stmt.Updates[i].Column)
		PutExpression(stmt.Updates[i].Value)
		stmt.Updates[i].Column = nil
		stmt.Updates[i].Value = nil
	}
	PutExpression(stmt.Where)

	// Reset fields
	stmt.Updates = stmt.Updates[:0]
	stmt.Where = nil
	stmt.TableName = ""

	// Return to pool
	updateStmtPool.Put(stmt)
}

// GetDeleteStatement gets a DeleteStatement from the pool
func GetDeleteStatement() *DeleteStatement {
	return deleteStmtPool.Get().(*DeleteStatement)
}

// PutDeleteStatement returns a DeleteStatement to the pool
func PutDeleteStatement(stmt *DeleteStatement) {
	if stmt == nil {
		return
	}

	// Clean up expressions
	PutExpression(stmt.Where)

	// Reset fields
	stmt.Where = nil
	stmt.TableName = ""

	// Return to pool
	deleteStmtPool.Put(stmt)
}

// GetUpdateExpression gets an UpdateExpression from the pool
func GetUpdateExpression() *UpdateExpression {
	return updateExprPool.Get().(*UpdateExpression)
}

// PutUpdateExpression returns an UpdateExpression to the pool
func PutUpdateExpression(expr *UpdateExpression) {
	if expr == nil {
		return
	}

	// Clean up expressions
	PutExpression(expr.Column)
	PutExpression(expr.Value)

	// Reset fields
	expr.Column = nil
	expr.Value = nil

	// Return to pool
	updateExprPool.Put(expr)
}

// GetSelectStatement gets a SelectStatement from the pool
func GetSelectStatement() *SelectStatement {
	stmt := selectStmtPool.Get().(*SelectStatement)
	stmt.Columns = stmt.Columns[:0]
	stmt.OrderBy = stmt.OrderBy[:0]
	return stmt
}

// PutSelectStatement returns a SelectStatement to the pool
func PutSelectStatement(stmt *SelectStatement) {
	if stmt == nil {
		return
	}

	// Clean up resources
	for _, col := range stmt.Columns {
		PutExpression(col)
	}
	for _, orderBy := range stmt.OrderBy {
		if orderBy.Expression != nil {
			PutExpression(orderBy.Expression)
		}
	}
	if stmt.Where != nil {
		PutExpression(stmt.Where)
	}

	// Reset fields
	stmt.Columns = stmt.Columns[:0]
	stmt.OrderBy = stmt.OrderBy[:0]
	stmt.TableName = ""
	stmt.Where = nil
	stmt.Limit = nil
	stmt.Offset = nil

	// Return to pool
	selectStmtPool.Put(stmt)
}

// GetIdentifier gets an Identifier from the pool
func GetIdentifier() *Identifier {
	return identifierPool.Get().(*Identifier)
}

// PutIdentifier returns an Identifier to the pool
func PutIdentifier(ident *Identifier) {
	if ident == nil {
		return
	}
	ident.Name = ""
	identifierPool.Put(ident)
}

// GetBinaryExpression gets a BinaryExpression from the pool
func GetBinaryExpression() *BinaryExpression {
	return binaryExprPool.Get().(*BinaryExpression)
}

// PutBinaryExpression returns a BinaryExpression to the pool
func PutBinaryExpression(expr *BinaryExpression) {
	if expr == nil {
		return
	}
	PutExpression(expr.Left)
	PutExpression(expr.Right)
	expr.Left = nil
	expr.Right = nil
	expr.Operator = ""
	binaryExprPool.Put(expr)
}

// GetExpressionSlice gets a slice of Expression from the pool
func GetExpressionSlice() *[]Expression {
	slice := exprSlicePool.Get().(*[]Expression)
	*slice = (*slice)[:0]
	return slice
}

// PutExpressionSlice returns a slice of Expression to the pool
func PutExpressionSlice(slice *[]Expression) {
	if slice == nil {
		return
	}
	for i := range *slice {
		PutExpression((*slice)[i])
		(*slice)[i] = nil
	}
	exprSlicePool.Put(slice)
}

// GetLiteralValue gets a LiteralValue from the pool
func GetLiteralValue() *LiteralValue {
	return literalValuePool.Get().(*LiteralValue)
}

// PutLiteralValue returns a LiteralValue to the pool
func PutLiteralValue(lit *LiteralValue) {
	if lit == nil {
		return
	}

	// Reset fields (Value is interface{}, use nil as zero value)
	lit.Value = nil
	lit.Type = ""

	// Return to pool
	literalValuePool.Put(lit)
}

// PutExpression returns any Expression to the appropriate pool
func PutExpression(expr Expression) {
	if expr == nil {
		return
	}

	switch e := expr.(type) {
	case *Identifier:
		PutIdentifier(e)
	case *BinaryExpression:
		PutBinaryExpression(e)
	case *LiteralValue:
		PutLiteralValue(e)
	case *FunctionCall:
		PutFunctionCall(e)
	case *CaseExpression:
		PutCaseExpression(e)
	case *BetweenExpression:
		PutBetweenExpression(e)
	case *InExpression:
		PutInExpression(e)
	case *SubqueryExpression:
		PutSubqueryExpression(e)
	case *CastExpression:
		PutCastExpression(e)
	}
}

// GetFunctionCall gets a FunctionCall from the pool
func GetFunctionCall() *FunctionCall {
	fc := functionCallPool.Get().(*FunctionCall)
	fc.Arguments = fc.Arguments[:0]
	return fc
}

// PutFunctionCall returns a FunctionCall to the pool
func PutFunctionCall(fc *FunctionCall) {
	if fc == nil {
		return
	}
	for i := range fc.Arguments {
		PutExpression(fc.Arguments[i])
		fc.Arguments[i] = nil
	}
	fc.Arguments = fc.Arguments[:0]
	fc.Name = ""
	fc.Over = nil
	fc.Distinct = false
	fc.Filter = nil
	functionCallPool.Put(fc)
}

// GetCaseExpression gets a CaseExpression from the pool
func GetCaseExpression() *CaseExpression {
	ce := caseExprPool.Get().(*CaseExpression)
	ce.WhenClauses = ce.WhenClauses[:0]
	return ce
}

// PutCaseExpression returns a CaseExpression to the pool
func PutCaseExpression(ce *CaseExpression) {
	if ce == nil {
		return
	}
	PutExpression(ce.Value)
	ce.Value = nil
	for i := range ce.WhenClauses {
		PutExpression(ce.WhenClauses[i].Condition)
		PutExpression(ce.WhenClauses[i].Result)
	}
	ce.WhenClauses = ce.WhenClauses[:0]
	PutExpression(ce.ElseClause)
	ce.ElseClause = nil
	caseExprPool.Put(ce)
}

// GetBetweenExpression gets a BetweenExpression from the pool
func GetBetweenExpression() *BetweenExpression {
	return betweenExprPool.Get().(*BetweenExpression)
}

// PutBetweenExpression returns a BetweenExpression to the pool
func PutBetweenExpression(be *BetweenExpression) {
	if be == nil {
		return
	}
	PutExpression(be.Expr)
	PutExpression(be.Lower)
	PutExpression(be.Upper)
	be.Expr = nil
	be.Lower = nil
	be.Upper = nil
	be.Not = false
	betweenExprPool.Put(be)
}

// GetInExpression gets an InExpression from the pool
func GetInExpression() *InExpression {
	ie := inExprPool.Get().(*InExpression)
	ie.List = ie.List[:0]
	return ie
}

// PutInExpression returns an InExpression to the pool
func PutInExpression(ie *InExpression) {
	if ie == nil {
		return
	}
	PutExpression(ie.Expr)
	ie.Expr = nil
	for i := range ie.List {
		PutExpression(ie.List[i])
		ie.List[i] = nil
	}
	ie.List = ie.List[:0]
	ie.Subquery = nil
	ie.Not = false
	inExprPool.Put(ie)
}

// GetSubqueryExpression gets a SubqueryExpression from the pool
func GetSubqueryExpression() *SubqueryExpression {
	return subqueryExprPool.Get().(*SubqueryExpression)
}

// PutSubqueryExpression returns a SubqueryExpression to the pool
func PutSubqueryExpression(se *SubqueryExpression) {
	if se == nil {
		return
	}
	se.Subquery = nil
	subqueryExprPool.Put(se)
}

// GetCastExpression gets a CastExpression from the pool
func GetCastExpression() *CastExpression {
	return castExprPool.Get().(*CastExpression)
}

// PutCastExpression returns a CastExpression to the pool
func PutCastExpression(ce *CastExpression) {
	if ce == nil {
		return
	}
	PutExpression(ce.Expr)
	ce.Expr = nil
	ce.Type = ""
	castExprPool.Put(ce)
}
