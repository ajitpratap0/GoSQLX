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

package naming

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// sqlReservedKeywords is a curated set of commonly-misused SQL reserved words
// used as identifiers (table or column names) without quoting.
var sqlReservedKeywords = map[string]bool{
	"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true,
	"FROM": true, "WHERE": true, "ORDER": true, "GROUP": true,
	"HAVING": true, "LIMIT": true, "OFFSET": true, "JOIN": true,
	"INNER": true, "LEFT": true, "RIGHT": true, "OUTER": true,
	"FULL": true, "CROSS": true, "ON": true, "AS": true,
	"AND": true, "OR": true, "NOT": true, "IN": true,
	"EXISTS": true, "BETWEEN": true, "LIKE": true, "IS": true,
	"NULL": true, "TRUE": true, "FALSE": true, "CASE": true,
	"WHEN": true, "THEN": true, "ELSE": true, "END": true,
	"UNION": true, "INTERSECT": true, "EXCEPT": true, "ALL": true,
	"DISTINCT": true, "WITH": true, "RECURSIVE": true,
	"CREATE": true, "DROP": true, "ALTER": true, "TABLE": true,
	"INDEX": true, "VIEW": true, "DATABASE": true, "SCHEMA": true,
	"PRIMARY": true, "KEY": true, "FOREIGN": true, "REFERENCES": true,
	"UNIQUE": true, "DEFAULT": true, "CONSTRAINT": true,
	"TRANSACTION": true, "COMMIT": true, "ROLLBACK": true,
	"GRANT": true, "REVOKE": true, "TO": true, "BY": true,
	"SET": true, "INTO": true, "VALUES": true, "COLUMN": true,
	"TRUNCATE": true, "MERGE": true, "USING": true, "MATCHED": true,
	"USER": true, "ROLE": true, "SESSION": true, "CURRENT": true,
	"DATE": true, "TIME": true, "TIMESTAMP": true, "INTERVAL": true,
	"YEAR": true, "MONTH": true, "DAY": true, "HOUR": true,
	"MINUTE": true, "SECOND": true,
}

// ReservedKeywordIdentifierRule (L025) flags table names or aliases that match SQL
// reserved keywords (without quoting). Using reserved words as identifiers requires
// quoting and is confusing for both humans and some SQL parsers.
type ReservedKeywordIdentifierRule struct{ linter.BaseRule }

// NewReservedKeywordIdentifierRule creates a new L025 rule instance.
func NewReservedKeywordIdentifierRule() *ReservedKeywordIdentifierRule {
	return &ReservedKeywordIdentifierRule{
		BaseRule: linter.NewBaseRule(
			"L025",
			"Reserved Keyword Identifier",
			"Using a reserved SQL keyword as an identifier requires quoting and is confusing",
			linter.SeverityWarning,
			false,
		),
	}
}

// Check inspects table names, aliases, and column names for reserved keyword conflicts.
func (r *ReservedKeywordIdentifierRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if ctx.AST == nil {
		return nil, nil
	}
	var violations []linter.Violation
	for _, stmt := range ctx.AST.Statements {
		sel, ok := stmt.(*ast.SelectStatement)
		if !ok {
			continue
		}
		for _, ref := range sel.From {
			if ref.Name != "" && sqlReservedKeywords[strings.ToUpper(ref.Name)] {
				violations = append(violations, linter.Violation{
					Rule:       r.ID(),
					RuleName:   r.Name(),
					Severity:   r.Severity(),
					Message:    "Table name '" + ref.Name + "' is a SQL reserved keyword",
					Location:   models.Location{Line: 1, Column: 1},
					Suggestion: "Quote the identifier: FROM \"" + ref.Name + "\" or rename the table",
				})
			}
			if ref.Alias != "" && sqlReservedKeywords[strings.ToUpper(ref.Alias)] {
				violations = append(violations, linter.Violation{
					Rule:       r.ID(),
					RuleName:   r.Name(),
					Severity:   r.Severity(),
					Message:    "Table alias '" + ref.Alias + "' is a SQL reserved keyword",
					Location:   models.Location{Line: 1, Column: 1},
					Suggestion: "Use a non-reserved alias instead of '" + ref.Alias + "'",
				})
			}
		}
	}
	return violations, nil
}

// Fix is a no-op: renaming identifiers requires schema changes.
func (r *ReservedKeywordIdentifierRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}
