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

// alter_dialect.go holds the dialect gates for ALTER: which actions of
// ALTER TABLE and which object kinds of ALTER <object> each dialect accepts.
// A parser without a dialect accepts all of them.

package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// alterDialects is a set of dialects.
type alterDialects uint16

const (
	dialectPostgres alterDialects = 1 << iota
	dialectMySQL
	dialectMariaDB
	dialectOracle
	dialectSQLServer
	dialectSnowflake
	dialectClickHouse
	dialectSQLite
	dialectRedshift
	dialectBigQuery

	dialectMySQLFamily = dialectMySQL | dialectMariaDB
	// dialectAll is the set of a parser without a dialect.
	dialectAll alterDialects = 0xFFFF
)

// alterMask returns the dialect set of the parser: dialectAll when no
// dialect (or "generic") is configured.
func (p *Parser) alterMask() alterDialects {
	switch p.dialect {
	case string(keywords.DialectPostgreSQL):
		return dialectPostgres
	case string(keywords.DialectMySQL):
		return dialectMySQL
	case string(keywords.DialectMariaDB):
		return dialectMariaDB
	case string(keywords.DialectOracle):
		return dialectOracle
	case string(keywords.DialectSQLServer):
		return dialectSQLServer
	case string(keywords.DialectSnowflake):
		return dialectSnowflake
	case string(keywords.DialectClickHouse):
		return dialectClickHouse
	case string(keywords.DialectSQLite):
		return dialectSQLite
	case string(keywords.DialectRedshift):
		return dialectRedshift
	case string(keywords.DialectBigQuery):
		return dialectBigQuery
	}
	return dialectAll
}

// alterDialect reports whether the parser's dialect is in set, or no
// dialect is configured.
func (p *Parser) alterDialect(set ...alterDialects) bool {
	var m alterDialects
	for _, s := range set {
		m |= s
	}
	return p.alterMask()&m != 0
}

// alterDialectStrict is alterDialect for a parser that has a dialect: it is
// false when none is configured.
func (p *Parser) alterDialectStrict(set ...alterDialects) bool {
	return p.alterMask() != dialectAll && p.alterDialect(set...)
}

// alterKeywordWords are the words that continue the keyword phrase of an
// AlterTableOther action after its first word.
var alterKeywordWords = map[string]bool{
	"ENABLE": true, "DISABLE": true, "VALIDATE": true, "NOVALIDATE": true,
	"NOCHECK": true, "CHECK": true, "CONSTRAINT": true, "ROW": true, "LEVEL": true,
	"SECURITY": true, "FORCE": true, "NO": true, "TO": true, "WITH": true, "BY": true,
	"DROP": true, "ADD": true, "PARTITION": true, "PARTITIONING": true, "TABLESPACE": true,
	"TRIGGER": true, "KEYS": true, "CHARACTER": true, "SET": true, "DEFAULT": true,
	"TTL": true, "SETTING": true, "SETTINGS": true, "INDEX": true, "KEY": true,
	"COLUMN": true, "PROJECTION": true, "SYSTEM": true, "VERSIONING": true, "TAG": true,
	"ACCESS": true, "POLICY": true, "SEARCH": true, "OPTIMIZATION": true,
	"SUPPLEMENTAL": true, "LOG": true, "WITHOUT": true, "VALIDATION": true, "READ": true,
	"ONLY": true, "WRITE": true, "MOVEMENT": true, "DETACHED": true, "ID": true,
	"IDENTITY": true, "REPLICA": true, "ORDER": true, "DATA": true, "FROM": true,
	"POLICIES": true, "ALL": true, "PERIOD": true,
}

// alterGenericRules lists, per leading phrase, the dialects that accept the
// action as an AlterTableOther. A phrase is the first word of the action or,
// for actions after ADD / DROP / RENAME / ALTER / MODIFY, "PREFIX WORD".
var alterGenericRules = map[string]alterDialects{
	"ENABLE":     dialectPostgres | dialectOracle | dialectSQLServer | dialectMySQLFamily | dialectRedshift,
	"DISABLE":    dialectPostgres | dialectOracle | dialectSQLServer | dialectMySQLFamily | dialectRedshift,
	"VALIDATE":   dialectPostgres,
	"NOCHECK":    dialectSQLServer,
	"CHECK":      dialectSQLServer | dialectMySQLFamily,
	"FORCE":      dialectPostgres | dialectMySQLFamily,
	"NO":         dialectPostgres,
	"OWNER":      dialectPostgres | dialectRedshift,
	"SWAP":       dialectSnowflake,
	"CLUSTER":    dialectSnowflake | dialectPostgres,
	"SET":        dialectPostgres | dialectRedshift | dialectSnowflake | dialectSQLServer,
	"UNSET":      dialectSnowflake,
	"RESET":      dialectPostgres,
	"INHERIT":    dialectPostgres,
	"REPLICA":    dialectPostgres,
	"ATTACH":     dialectPostgres | dialectClickHouse,
	"DETACH":     dialectPostgres | dialectClickHouse,
	"MOVE":       dialectOracle | dialectClickHouse,
	"TRUNCATE":   dialectOracle | dialectMySQLFamily,
	"SWITCH":     dialectSQLServer,
	"REBUILD":    dialectMySQLFamily | dialectOracle | dialectSQLServer,
	"REORGANIZE": dialectMySQLFamily | dialectOracle | dialectSQLServer,
	"EXCHANGE":   dialectMySQLFamily | dialectOracle,
	"COALESCE":   dialectMySQLFamily | dialectOracle,
	"SPLIT":      dialectOracle,
	"MERGE":      dialectOracle,
	"SHRINK":     dialectOracle,
	"READ":       dialectOracle,
	"PARALLEL":   dialectOracle, "NOPARALLEL": dialectOracle,
	"LOGGING": dialectOracle, "NOLOGGING": dialectOracle,
	"COMPRESS": dialectOracle, "NOCOMPRESS": dialectOracle,
	"UPGRADE": dialectOracle,
	"ROW":     dialectOracle,

	// MySQL / MariaDB table options and maintenance actions.
	"OPTIMIZE": dialectMySQLFamily, "REPAIR": dialectMySQLFamily, "ANALYZE": dialectMySQLFamily,
	"REMOVE": dialectMySQLFamily | dialectClickHouse, "DISCARD": dialectMySQLFamily, "IMPORT": dialectMySQLFamily,
	"CONVERT": dialectMySQLFamily, "ENGINE": dialectMySQLFamily, "AUTO_INCREMENT": dialectMySQLFamily,
	"CHARSET": dialectMySQLFamily, "CHARACTER": dialectMySQLFamily, "COLLATE": dialectMySQLFamily,
	"ROW_FORMAT": dialectMySQLFamily, "ALGORITHM": dialectMySQLFamily, "LOCK": dialectMySQLFamily,
	"DEFAULT": dialectMySQLFamily, "INSERT_METHOD": dialectMySQLFamily, "MAX_ROWS": dialectMySQLFamily,
	"MIN_ROWS": dialectMySQLFamily, "PACK_KEYS": dialectMySQLFamily, "UNION": dialectMySQLFamily,
	"DELAY_KEY_WRITE": dialectMySQLFamily, "CHECKSUM": dialectMySQLFamily,
	"AVG_ROW_LENGTH": dialectMySQLFamily, "TABLESPACE": dialectMySQLFamily,
	"KEY_BLOCK_SIZE": dialectMySQLFamily, "ENCRYPTION": dialectMySQLFamily,
	"COMPRESSION": dialectMySQLFamily, "STATS_PERSISTENT": dialectMySQLFamily,
	"STATS_AUTO_RECALC": dialectMySQLFamily, "STATS_SAMPLE_PAGES": dialectMySQLFamily,
	"ORDER": dialectMySQLFamily, "WITH": dialectMySQLFamily, "WITHOUT": dialectMySQLFamily,
	"PASSWORD": dialectMySQLFamily, "CONNECTION": dialectMySQLFamily,
	"COMMENT": dialectMySQLFamily | dialectClickHouse,

	// ClickHouse.
	"MATERIALIZE": dialectClickHouse, "CLEAR": dialectClickHouse, "FREEZE": dialectClickHouse,
	"UNFREEZE": dialectClickHouse, "REPLACE": dialectClickHouse, "FETCH": dialectClickHouse,

	"ADD PARTITION":     dialectMySQLFamily | dialectOracle,
	"ADD SYSTEM":        dialectMariaDB,
	"ADD PERIOD":        dialectMariaDB,
	"ADD ROW":           dialectSnowflake,
	"ADD SEARCH":        dialectSnowflake,
	"ADD PROJECTION":    dialectClickHouse,
	"ADD SUPPLEMENTAL":  dialectOracle,
	"DROP PARTITION":    dialectMySQLFamily | dialectOracle | dialectClickHouse,
	"DROP SYSTEM":       dialectMariaDB,
	"DROP PERIOD":       dialectMariaDB,
	"DROP PROJECTION":   dialectClickHouse,
	"DROP DETACHED":     dialectClickHouse,
	"DROP ROW":          dialectSnowflake,
	"DROP ALL":          dialectSnowflake,
	"DROP SEARCH":       dialectSnowflake,
	"DROP SUPPLEMENTAL": dialectOracle,
	"RENAME INDEX":      dialectMySQLFamily,
	"RENAME KEY":        dialectMySQLFamily,
	"ALTER INDEX":       dialectMySQLFamily,
	"ALTER CHECK":       dialectMySQLFamily,
	"ALTER CONSTRAINT":  dialectPostgres | dialectMySQLFamily | dialectRedshift,
	"MODIFY TTL":        dialectClickHouse,
	"MODIFY SETTING":    dialectClickHouse,
	"MODIFY ORDER":      dialectClickHouse,
	"MODIFY QUERY":      dialectClickHouse,
	"MODIFY COMMENT":    dialectClickHouse,
	"MODIFY SAMPLE":     dialectClickHouse,
	"MODIFY PARTITION":  dialectOracle,
	"MODIFY CONSTRAINT": dialectOracle,
}

// alterGenericAllowed reports whether the action beginning with word w (after
// the already-read prefix ADD / DROP / ..., or "" for a leading word) is
// accepted as an AlterTableOther in the parser's dialect.
func (p *Parser) alterGenericAllowed(prefix, w string) bool {
	if w == "" {
		return false
	}
	key := w
	if prefix != "" {
		key = prefix + " " + w
	}
	m, ok := alterGenericRules[key]
	return ok && p.alterMask()&m != 0
}

// alterObjectKinds lists, per object word that may follow ALTER, the dialects
// that accept the statement; such statements are kept as written.
var alterObjectKinds = map[string]alterDialects{
	"ROLE":         dialectPostgres | dialectOracle | dialectSQLServer | dialectMySQLFamily | dialectSnowflake | dialectRedshift,
	"INDEX":        dialectPostgres | dialectOracle | dialectSQLServer | dialectMySQLFamily | dialectRedshift,
	"SESSION":      dialectOracle | dialectSnowflake,
	"SYSTEM":       dialectOracle | dialectClickHouse,
	"USER":         dialectOracle | dialectMySQLFamily | dialectPostgres | dialectSnowflake | dialectSQLServer | dialectRedshift | dialectClickHouse,
	"DATABASE":     dialectPostgres | dialectMySQLFamily | dialectSQLServer | dialectOracle | dialectSnowflake | dialectClickHouse | dialectRedshift,
	"SCHEMA":       dialectPostgres | dialectSnowflake | dialectSQLServer | dialectMySQLFamily | dialectRedshift,
	"VIEW":         dialectPostgres | dialectSnowflake | dialectSQLServer | dialectMySQLFamily | dialectOracle | dialectRedshift,
	"MATERIALIZED": dialectPostgres | dialectOracle,
	"SEQUENCE":     dialectPostgres | dialectOracle | dialectSQLServer | dialectSnowflake,
	"TABLESPACE":   dialectPostgres | dialectOracle | dialectMySQLFamily,
	"FUNCTION":     dialectPostgres | dialectMySQLFamily | dialectOracle | dialectSQLServer | dialectSnowflake,
	"PROCEDURE":    dialectPostgres | dialectMySQLFamily | dialectOracle | dialectSQLServer | dialectSnowflake,
	"TRIGGER":      dialectPostgres | dialectOracle | dialectSQLServer,
	"EVENT":        dialectMySQLFamily,
	"SERVER":       dialectPostgres | dialectMySQLFamily,
	"TYPE":         dialectPostgres | dialectOracle,
	"DOMAIN":       dialectPostgres,
	"EXTENSION":    dialectPostgres,
	"WAREHOUSE":    dialectSnowflake,
	"TASK":         dialectSnowflake,
	"ACCOUNT":      dialectSnowflake,
	"PIPE":         dialectSnowflake,
	"STREAM":       dialectSnowflake,
	"STAGE":        dialectSnowflake,
	"INTEGRATION":  dialectSnowflake,
	"SHARE":        dialectSnowflake,
	"DYNAMIC":      dialectSnowflake,
	"EXTERNAL":     dialectSnowflake,
	"NETWORK":      dialectSnowflake,
	"RESOURCE":     dialectSnowflake | dialectOracle,
	"LOGIN":        dialectSQLServer,
	"PROFILE":      dialectOracle | dialectClickHouse,
	"PLUGGABLE":    dialectOracle,
	"QUOTA":        dialectClickHouse,
	"ROW":          dialectClickHouse,
	"SETTINGS":     dialectClickHouse,
}

// alterObjectWord returns the upper-cased word of an ALTER <object> statement
// the parser keeps as written and accepts in its dialect.
func (p *Parser) alterObjectWord() (string, bool) {
	w := p.utilityWord(p.currentPos)
	if w == "" {
		return "", false
	}
	m, ok := alterObjectKinds[w]
	if !ok || p.alterMask()&m == 0 {
		return "", false
	}
	return w, true
}

// parseAlterVerbatim parses ALTER <object> ... as a UtilityStatement that
// keeps its text as written. The ALTER token has already been consumed.
func (p *Parser) parseAlterVerbatim(word string) (ast.Statement, error) {
	start := p.currentPos - 1
	if start < 0 || p.tokens[start].Token.Type != models.TokenTypeAlter {
		return nil, p.expectedError("ALTER")
	}
	end, err := p.utilityStatementEnd()
	if err != nil {
		return nil, err
	}
	// ALTER <object> alone is not a statement.
	if end <= p.currentPos+1 {
		p.seek(p.currentPos + 1)
		return nil, p.expectedError("name after ALTER " + word)
	}
	text := p.renderTokenRange(start, end)
	pos := p.tokens[start].Start
	p.seek(end)
	return &ast.UtilityStatement{Kind: "ALTER " + word, Text: text, Pos: pos}, nil
}
