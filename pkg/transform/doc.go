// Package transform provides composable SQL query rewriting via AST manipulation.
//
// This is GoSQLX's key differentiator — enabling safe, programmatic SQL modification.
// All transforms operate on AST nodes from pkg/sql/ast and preserve AST validity,
// meaning roundtrip (parse → transform → format/SQL) always produces valid SQL.
//
// # Design
//
// Transforms are implemented as [Rule] values that can be applied individually
// or composed via [Apply]. Each rule modifies the AST in-place (since Go uses
// pointers) and returns an error if the transform cannot be applied.
//
// # WHERE Clause Transforms
//
//	// Add a filter condition
//	rule := transform.AddWhereFromSQL("status = 'active'")
//	transform.Apply(stmt, rule)
//
// # Column Transforms
//
//	// Add a column to SELECT
//	rule := transform.AddColumn(&ast.Identifier{Name: "email"})
//	transform.Apply(stmt, rule)
//
// # JOIN Transforms
//
//	// Add a JOIN from SQL
//	rule := transform.AddJoinFromSQL("LEFT JOIN orders ON orders.user_id = users.id")
//	transform.Apply(stmt, rule)
//
// # Security
//
// WARNING: Functions that accept raw SQL strings (AddWhereFromSQL, AddJoinFromSQL)
// must not receive untrusted user input. Passing unsanitized input could produce
// unintended query modifications. Use parameterized queries or construct AST nodes
// directly (AddWhere, AddJoin) for untrusted input.
//
// # Composability
//
// Multiple transforms can be chained:
//
//	transform.Apply(stmt,
//	    transform.AddWhereFromSQL("active = true"),
//	    transform.SetLimit(10),
//	    transform.AddOrderBy("created_at", true),
//	)
package transform
