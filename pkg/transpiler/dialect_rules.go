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

package transpiler

import (
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/transpiler/rules"
)

type dialectPair struct {
	from, to keywords.SQLDialect
}

var ruleRegistry = map[dialectPair][]RewriteRule{}

func init() {
	register(keywords.DialectMySQL, keywords.DialectPostgreSQL,
		rules.MySQLAutoIncrementToSerial,
		rules.MySQLBacktickToDoubleQuote,
		rules.MySQLLimitCommaToOffset,
		rules.MySQLBooleanToPgBool,
	)
	register(keywords.DialectPostgreSQL, keywords.DialectMySQL,
		rules.PgSerialToAutoIncrement,
		rules.PgDoubleQuoteToBacktick,
		rules.PgILikeToLower,
	)
	register(keywords.DialectPostgreSQL, keywords.DialectSQLite,
		rules.PgSerialToIntegerPK,
		rules.PgArrayToJSON,
	)
}

func register(from, to keywords.SQLDialect, rs ...RewriteRule) {
	key := dialectPair{from, to}
	ruleRegistry[key] = append(ruleRegistry[key], rs...)
}

// RulesFor returns the registered rewrite rules for a dialect pair.
// Returns nil (empty) for unregistered or same-dialect pairs.
// Exported for testing.
func RulesFor(from, to keywords.SQLDialect) []RewriteRule {
	if from == to {
		return nil
	}
	return ruleRegistry[dialectPair{from, to}]
}

// rulesFor is the internal version used by Transpile.
func rulesFor(from, to keywords.SQLDialect) []RewriteRule {
	return RulesFor(from, to)
}
