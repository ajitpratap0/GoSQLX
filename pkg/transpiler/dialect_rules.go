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
	"sync"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/dialect"
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
// Cross-dialect pairs include common row-limit rules; same-dialect pairs return nil.
// Exported for testing.
func RulesFor(from, to keywords.SQLDialect) []RewriteRule {
	return buildRules(from, to, true)
}

type rulesKey struct {
	from, to keywords.SQLDialect
	pipes    bool
}

// rulesCache is immutable after rulesCacheOnce publishes it. Only the nine
// supported dialects are cached; arbitrary caller strings cannot grow it.
var (
	rulesCacheOnce sync.Once
	rulesCache     map[rulesKey][]RewriteRule
)

func rulesForSource(from, to keywords.SQLDialect, pipes bool) []RewriteRule {
	rulesCacheOnce.Do(func() {
		dialects := [...]keywords.SQLDialect{
			keywords.DialectGeneric, keywords.DialectMySQL, keywords.DialectPostgreSQL,
			keywords.DialectSQLite, keywords.DialectSQLServer, keywords.DialectOracle,
			keywords.DialectSnowflake, keywords.DialectClickHouse, keywords.DialectMariaDB,
		}
		rulesCache = make(map[rulesKey][]RewriteRule, len(dialects)*len(dialects)*2)
		for _, f := range dialects {
			for _, t := range dialects {
				for _, p := range [...]bool{false, true} {
					rulesCache[rulesKey{f, t, p}] = buildRules(f, t, p)
				}
			}
		}
	})
	if rs, ok := rulesCache[rulesKey{from, to, pipes}]; ok {
		// Callers must never mutate the shared slice. rowLimitRule keeps all
		// mutable traversal state per invocation, so its closure is safe to share.
		return rs
	}
	return buildRules(from, to, pipes)
}

func buildRules(from, to keywords.SQLDialect, pipes bool) []RewriteRule {
	if from == to {
		return nil
	}
	rs := ruleRegistry[dialectPair{from, to}]
	// Never append into the registry's backing array.
	rs = append(rs[:len(rs):len(rs)], rowLimitRule(to))
	if !pipes {
		return rs
	}
	if r := pipesRule(from, to); r != nil {
		return append(rs, r)
	}
	return rs
}

// pipesRule returns the rule that keeps || meaning the same across the pair
// (#781), or nil. MySQL and MariaDB read || as logical OR; every other dialect
// reads it as concatenation. Going from concatenation to OR, || becomes
// CONCAT(); going from OR to concatenation, a || OR is written as OR.
func pipesRule(from, to keywords.SQLDialect) RewriteRule {
	fromOr := dialect.Parse(string(from)).Capabilities().PipesAsLogicalOr
	toOr := dialect.Parse(string(to)).Capabilities().PipesAsLogicalOr
	switch {
	case !fromOr && toOr:
		return rules.PgConcatToMySQLConcat
	case fromOr && !toOr:
		return rules.PipesOrToKeywordOr
	}
	return nil
}
