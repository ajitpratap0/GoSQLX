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

// Package formatter — backward-compatibility hook registration.
//
// This init() function registers the pkg/formatter rendering functions into the
// ast package's FormatStatementFunc / FormatExpressionFunc / FormatASTFunc
// variables. This allows the deprecated Format(FormatOptions) methods on AST
// statement and expression types (added in format_compat.go) to delegate to the
// new visitor-based renderer without creating an import cycle.
//
// The registration happens automatically whenever pkg/formatter is imported —
// which is the common case for any application that uses the formatter. Callers
// that only import pkg/sql/ast (without pkg/formatter) will receive SQL()
// fallback output from the deprecated shims.
package formatter

import (
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func init() {
	//lint:ignore SA1019 intentional bridge — pkg/formatter wires itself into the ast shim variables
	ast.FormatStatementFunc = FormatStatement //nolint:staticcheck
	//lint:ignore SA1019 intentional bridge — pkg/formatter wires itself into the ast shim variables
	ast.FormatExpressionFunc = FormatExpression //nolint:staticcheck
	//lint:ignore SA1019 intentional bridge — pkg/formatter wires itself into the ast shim variables
	ast.FormatASTFunc = FormatAST //nolint:staticcheck
}
