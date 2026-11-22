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

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// quoteQualifiedNames joins table-like names with ", ", quoting each part
// that needs it (see ast.QuoteQualifiedName).
func quoteQualifiedNames(names []string) string {
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = ast.QuoteQualifiedName(n)
	}
	return strings.Join(parts, ", ")
}

// quoteColumnNames joins single-part DDL column names with ", ", quoting
// each one that needs it (see ast.QuoteColumnName).
func quoteColumnNames(names []string) string {
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = ast.QuoteColumnName(n)
	}
	return strings.Join(parts, ", ")
}
