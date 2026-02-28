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

// Package transform provides composable SQL query rewriting via AST manipulation.
//
// This is GoSQLX's key differentiator — enabling safe, programmatic SQL modification
// without string concatenation. All transforms operate on AST nodes from pkg/sql/ast
// and preserve structural validity, meaning a roundtrip (parse -> transform -> format)
// always produces well-formed SQL. Transforms are defined by the Rule interface and
// applied individually or composed using Apply.
//
// # Available Transforms
//
// WHERE clause: AddWhere, AddWhereFromSQL, ReplaceWhere, RemoveWhere
// Columns:      AddColumn, RemoveColumn
// JOINs:        AddJoin, AddJoinFromSQL
// ORDER BY:     AddOrderBy
// LIMIT/OFFSET: SetLimit, SetOffset (for pagination)
// Tables:       RenameTable, AddTableAlias
//
// # WHERE Clause Transforms
//
//	// Add a filter condition using an AST node (safe for untrusted column values)
//	rule := transform.AddWhere(&ast.BinaryExpression{
//	    Left:     &ast.Identifier{Name: "status"},
//	    Operator: "=",
//	    Right:    &ast.LiteralValue{Value: "active"},
//	})
//	transform.Apply(stmt, rule)
//
//	// Add a filter from a trusted SQL string
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
// # Pagination
//
//	// Set LIMIT and OFFSET for pagination
//	transform.Apply(stmt,
//	    transform.SetLimit(20),
//	    transform.SetOffset(40),
//	)
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
// Multiple transforms can be chained in a single Apply call:
//
//	transform.Apply(stmt,
//	    transform.AddWhereFromSQL("active = true"),
//	    transform.SetLimit(10),
//	    transform.AddOrderBy("created_at", true),
//	)
package transform
