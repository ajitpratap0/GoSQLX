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

package formatter

import "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"

// Column definitions and table constraints render exactly as the AST's own
// SQL() does (ast/sql_columns.go): the constraint kinds, their quoting and the
// keyword allow-lists live in one place so the two renderers cannot drift.

// columnDefSQL renders a column definition.
func columnDefSQL(c *ast.ColumnDef) string { return ast.ColumnDefSQL(c) }

// tableConstraintSQL renders a table-level constraint or index element.
func tableConstraintSQL(tc *ast.TableConstraint) string { return ast.TableConstraintSQL(tc) }
