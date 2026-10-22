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

// dialectDelimiter returns the identifier delimiter a dialect requires
// instead of ANSI double quotes, or 0 when double quotes are fine. MySQL and
// MariaDB read "..." as a string literal unless ANSI_QUOTES is set, so a name
// they need delimited must use backticks.
func dialectDelimiter(dialect string) rune {
	switch strings.ToLower(dialect) {
	case "mysql", "mariadb":
		return '`'
	}
	return 0
}

// nq returns q with the target dialect's delimiter as its default style, so
// a name that needs delimiters only because of its content is written with
// the delimiters the dialect accepts (see dialectDelimiter). A style recorded
// from the source is kept.
func (f *nodeFormatter) nq(q ast.NameQuote) ast.NameQuote {
	if d := dialectDelimiter(f.opts.Dialect); d != 0 {
		return q.WithDefaultStyle(d)
	}
	return q
}

// quoteNamesWith renders a CTE or view column list like quoteNames,
// honouring each name's recorded delimiters (qs by index, may be nil).
func (f *nodeFormatter) quoteNamesWith(names []string, qs []ast.NameQuote) string {
	parts := make([]string, len(names))
	for i, n := range names {
		var q ast.NameQuote
		if i < len(qs) {
			q = qs[i]
		}
		parts[i] = ast.QuoteNameWith(n, f.nq(q))
	}
	return strings.Join(parts, ", ")
}

// quoteColumnNamesWith joins single-part DDL column names like
// quoteColumnNames, honouring each name's recorded delimiters (qs by index,
// may be nil).
func (f *nodeFormatter) quoteColumnNamesWith(names []string, qs []ast.NameQuote) string {
	parts := make([]string, len(names))
	for i, n := range names {
		var q ast.NameQuote
		if i < len(qs) {
			q = qs[i]
		}
		parts[i] = ast.QuoteColumnNameWith(n, f.nq(q))
	}
	return strings.Join(parts, ", ")
}
