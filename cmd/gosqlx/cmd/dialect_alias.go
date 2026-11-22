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

package cmd

import (
	"sort"
	"strings"
)

// dialectAliases maps the alternative names users commonly type to the
// canonical dialect names of keywords.DialectNames. Matching is exact
// (lower case), like the canonical names.
var dialectAliases = map[string]string{
	"postgres":   "postgresql",
	"pg":         "postgresql",
	"mssql":      "sqlserver",
	"tsql":       "sqlserver",
	"sql-server": "sqlserver",
	"sqlite3":    "sqlite",
}

// canonicalDialect returns the canonical dialect name for name: aliases are
// resolved, anything else is returned unchanged for validateDialectName to
// accept or reject.
func canonicalDialect(name string) string {
	if canon, ok := dialectAliases[name]; ok {
		return canon
	}
	return name
}

// normalizeDialectFlag resolves aliases in the dialect flag value *name in
// place and rejects unknown dialects. Every command that takes --dialect
// calls it first, so "postgres", "pg", "mssql" and "tsql" work everywhere,
// not only in transpile.
func normalizeDialectFlag(name *string) error {
	*name = canonicalDialect(*name)
	return validateDialectName(*name)
}

// dialectAliasText lists the accepted aliases for error messages, e.g.
// "mssql, pg, postgres, sql-server, sqlite3, tsql".
func dialectAliasText() string {
	names := make([]string, 0, len(dialectAliases))
	for alias := range dialectAliases {
		names = append(names, alias)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
