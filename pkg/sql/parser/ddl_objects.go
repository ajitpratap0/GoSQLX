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

// Package parser - ddl_objects.go
// CREATE / DROP of schema objects other than tables, views and indexes
// (kept verbatim), CREATE TABLE heads (LIKE, CLONE, PARTITION OF, AS) and
// tails (generic table options, ClickHouse ENGINE clauses), and the shared
// option-list parser also used by CREATE INDEX and materialized views.

package parser

import (
	"fmt"
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// wordAt returns the upper-cased value of the token n positions ahead of
// the current one when it is an unquoted word (letters, digits, '_', not
// starting with a digit), and "" otherwise.
func (p *Parser) wordAt(n int) string {
	tok := p.tokenAt(n)
	t := tok.Token
	// A delimited identifier (`x`, [x]) is recognized by its span; keyword
	// tokens are never delimited, and the parts of a compound keyword
	// (ORDER BY) share the compound's span.
	if t.Quote != 0 || t.Value == "" ||
		(t.Type == models.TokenTypeIdentifier && isQuotedSpan(&tok)) {
		return ""
	}
	switch t.Type {
	case models.TokenTypeDoubleQuotedString, models.TokenTypeString,
		models.TokenTypeSingleQuotedString, models.TokenTypeDollarQuotedString,
		models.TokenTypeNumber, models.TokenTypePlaceholder, models.TokenTypeEOF:
		return ""
	}
	v := t.Value
	if c := v[0]; c >= '0' && c <= '9' {
		return ""
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c != '_' && (c < '0' || c > '9') && (c|0x20 < 'a' || c|0x20 > 'z') {
			return ""
		}
	}
	return strings.ToUpper(v)
}

// verbatimCreateKinds are the object kinds after CREATE that are kept
// verbatim as a UtilityStatement: their bodies (routines, triggers, user
// and role options, ...) are reproduced as written rather than modelled.
var verbatimCreateKinds = map[string]bool{
	"SCHEMA": true, "DATABASE": true, "EXTENSION": true, "TYPE": true, "DOMAIN": true,
	"ROLE": true, "USER": true, "SEQUENCE": true, "SYNONYM": true, "POLICY": true,
	"STAGE": true, "STREAM": true, "TASK": true, "PIPE": true, "FILE": true,
	"WAREHOUSE": true, "TAG": true, "DICTIONARY": true, "FUNCTION": true,
	"PROCEDURE": true, "PROC": true, "TRIGGER": true, "EVENT": true, "TABLESPACE": true,
	"PACKAGE": true, "AGGREGATE": true, "CAST": true, "COLLATION": true,
	"CONVERSION": true, "LANGUAGE": true, "OPERATOR": true, "PUBLICATION": true,
	"SUBSCRIPTION": true, "SERVER": true, "RULE": true, "STATISTICS": true,
	"TEXT": true, "ACCESS": true, "PROFILE": true, "QUOTA": true, "SETTINGS": true,
	"ROW": true, "MASKING": true, "NETWORK": true, "INTEGRATION": true, "SHARE": true,
	"SECRET": true, "ALERT": true, "LOGIN": true, "DIRECTORY": true, "CONTEXT": true,
	"LIBRARY": true, "NAMED": true, "FOREIGN": true, "ASSEMBLY": true,
	"CERTIFICATE": true, "CREDENTIAL": true, "VIRTUAL": true, "EXTERNAL": true,
	"DYNAMIC": true, "HYBRID": true, "ICEBERG": true, "LIVE": true, "WINDOW": true,
	"MACRO": true, "CATALOG": true, "SNAPSHOT": true, "RESOURCE": true,
	"PARTITION": true, "QUEUE": true, "SERVICE": true, "ENDPOINT": true,
	"CONTRACT": true, "MESSAGE": true, "XML": true, "SECURITY": true,
	"ROUTINE": true, "TRANSFORM": true, "OUTLINE": true, "DIMENSION": true,
	"CLUSTER": true, "JAVA": true, "EDITION": true, "LOCKDOWN": true,
	"PLUGGABLE": true, "CONTROLFILE": true, "PFILE": true, "SPFILE": true,
	"RESTORE": true, "AUDIT": true, "APPLICATION": true, "NOTEBOOK": true,
	"COMPUTE": true, "DATA": true, "MODEL": true,
}

// createModifierWords may precede the object kind after CREATE.
var createModifierWords = map[string]bool{
	"REPLACE": true, "ALTER": true, "TEMP": true, "TEMPORARY": true, "GLOBAL": true,
	"LOCAL": true, "UNLOGGED": true, "TRANSIENT": true, "VOLATILE": true,
	"SECURE": true, "FORCE": true, "NO": true, "PUBLIC": true, "EDITIONABLE": true,
	"NONEDITIONABLE": true, "TRUSTED": true, "PROCEDURAL": true, "RECURSIVE": true,
	"CONSTRAINT": true, "UNIQUE": true, "OR": true, "SHARED": true, "BIGFILE": true,
	"SMALLFILE": true, "UNDO": true,
}

// verbatimKindSuffixes extend an object kind with the following word for
// the UtilityStatement kind (FILE FORMAT, MASKING POLICY, DATABASE LINK).
var verbatimKindSuffixes = map[string]bool{
	"TABLE": true, "VIEW": true, "POLICY": true, "FORMAT": true, "LINK": true,
	"PROFILE": true, "BODY": true, "TRIGGER": true, "SYNONYM": true, "FUNCTION": true,
	"PROCEDURE": true, "TABLESPACE": true, "SEARCH": true, "METHOD": true,
	"COLLECTION": true, "WRAPPER": true, "SCHEME": true, "MONITOR": true,
}

// createVerbatimKind looks past the modifiers that follow CREATE (the
// current token is the one after CREATE) and returns the statement kind
// ("CREATE FUNCTION", "CREATE VIEW", ...) when the object is kept verbatim,
// or "" when it is parsed structurally. The parser position is unchanged.
func (p *Parser) createVerbatimKind() string {
	options := false // DEFINER / ALGORITHM / SQL SECURITY were written
	for i := 0; i < 24; i++ {
		w := p.wordAt(i)
		switch w {
		case "":
			return ""
		case "DEFINER", "ALGORITHM":
			// MySQL view and routine options: DEFINER = user,
			// ALGORITHM = MERGE. Skip to the next word that can follow.
			options = true
			j := i + 1
			for ; j < i+8 && !isCreateOptionFollower(p.wordAt(j)); j++ {
				if p.tokenAt(j).Token.Type == models.TokenTypeEOF {
					return ""
				}
			}
			if j == i+8 {
				return ""
			}
			i = j - 1
			continue
		case "SQL":
			if p.wordAt(i+1) != "SECURITY" {
				return ""
			}
			options = true
			i += 2
			continue
		case "OR":
			// OR REPLACE / OR ALTER only; anything else is left to the
			// structured parser, which reports it.
			if next := p.wordAt(i + 1); next != "REPLACE" && next != "ALTER" {
				return ""
			}
			i++
			continue
		case "REPLACE", "ALTER":
			return "" // only valid after OR
		case "TABLE", "INDEX", "MATERIALIZED", "FULLTEXT", "SPATIAL", "BITMAP",
			"CLUSTERED", "NONCLUSTERED":
			return ""
		case "VIEW":
			if options {
				return "CREATE VIEW"
			}
			return ""
		case "SEQUENCE":
			// MariaDB sequences have a dedicated node; MySQL has none.
			if (p.isMariaDB() && !options) || p.dialect == string(keywords.DialectMySQL) {
				return ""
			}
		}
		if createModifierWords[w] {
			continue
		}
		if !verbatimCreateKinds[w] {
			return ""
		}
		kind := w
		if next := p.wordAt(i + 1); verbatimKindSuffixes[next] {
			kind += " " + next
		}
		return "CREATE " + kind
	}
	return ""
}

// isCreateOptionFollower reports whether w may follow the value of a MySQL
// DEFINER = ... or ALGORITHM = ... option.
func isCreateOptionFollower(w string) bool {
	switch w {
	case "VIEW", "PROCEDURE", "FUNCTION", "TRIGGER", "EVENT", "SQL", "ALGORITHM",
		"DEFINER", "AGGREGATE":
		return true
	}
	return false
}

// parseVerbatimFrom re-reads the statement starting at token index start as
// a verbatim UtilityStatement of the given kind.
func (p *Parser) parseVerbatimFrom(start int, kind string) (ast.Statement, error) {
	if err := p.checkNamePartLimit(); err != nil {
		return nil, err
	}
	p.seek(start)
	stmt, _, err := p.parseVerbatimStatement(kind)
	return stmt, err
}

// checkNamePartLimit rejects, as parseQualifiedName does, a dotted name of
// more than maxQualifiedNameParts parts in the rest of the statement, so a
// verbatim statement does not accept a name every structured statement
// rejects. The parser position is unchanged.
func (p *Parser) checkNamePartLimit() error {
	parts := 0
	for i := p.currentPos; i < len(p.tokens); i++ {
		switch p.tokens[i].Token.Type {
		case models.TokenTypeSemicolon, models.TokenTypeEOF:
			return nil
		case models.TokenTypePeriod:
			if parts == 0 {
				continue
			}
			if parts == maxQualifiedNameParts {
				saved, savedTok := p.currentPos, p.currentToken
				p.seek(i + 1)
				err := goerrors.InvalidSyntaxError(
					fmt.Sprintf("qualified name has more than %d parts", maxQualifiedNameParts),
					p.currentLocation(),
					"",
				).WithCause(errQualifiedNameTooLong)
				p.currentPos, p.currentToken = saved, savedTok
				return err
			}
		default:
			if i > 0 && p.tokens[i-1].Token.Type == models.TokenTypePeriod && parts > 0 {
				parts++
			} else {
				parts = 1
			}
		}
	}
	return nil
}

// structuredDropKinds are the DROP object kinds with a dedicated AST node.
var structuredDropKinds = map[string]bool{
	"TABLE": true, "VIEW": true, "MATERIALIZED": true, "INDEX": true, "TEMPORARY": true,
}

// dropVerbatimKind returns the statement kind ("DROP FUNCTION", ...) when
// the DROP at the current token (the one after DROP) is kept verbatim, and
// "" when it is parsed structurally.
func (p *Parser) dropVerbatimKind() string {
	w := p.wordAt(0)
	if w == "" || structuredDropKinds[w] {
		return ""
	}
	if w == "SEQUENCE" && (p.isMariaDB() || p.dialect == string(keywords.DialectMySQL)) {
		return ""
	}
	if !verbatimCreateKinds[w] {
		// Of the CREATE modifiers only PUBLIC / GLOBAL / UNIQUE may lead a
		// DROP, and only before an object kind (DROP PUBLIC SYNONYM); DROP
		// REPLACE x or DROP OR x is not a statement.
		if w != "PUBLIC" && w != "UNIQUE" && w != "GLOBAL" {
			return ""
		}
		next := p.wordAt(1)
		if !verbatimCreateKinds[next] {
			return ""
		}
		return "DROP " + w + " " + next
	}
	if next := p.wordAt(1); verbatimKindSuffixes[next] {
		w += " " + next
	}
	return "DROP " + w
}

// ---------------------------------------------------------------------------
// Table options
// ---------------------------------------------------------------------------

// optionValue says what may follow a table option name.
type optionValue uint8

const (
	optEqValue    optionValue = iota // [=] value
	optEqRequired                    // = value
	optSpaced                        // value (no '=')
	optFlag                          // nothing
	optArgs                          // ( expr, ... )
	optList                          // ( name [= value], ... )
)

// optionSpec describes one table / index option: its words and value.
type optionSpec struct {
	words []string
	value optionValue
}

// tableOptionSpecs are the CREATE TABLE options recognized after the column
// list. Longer word sequences come before their prefixes.
var tableOptionSpecs = []optionSpec{
	{[]string{"DEFAULT", "CHARACTER", "SET"}, optEqValue},
	{[]string{"DEFAULT", "CHARSET"}, optEqValue},
	{[]string{"DEFAULT", "COLLATE"}, optEqValue},
	{[]string{"CHARACTER", "SET"}, optEqValue},
	{[]string{"CHARSET"}, optEqValue},
	{[]string{"COLLATE"}, optEqValue},
	{[]string{"ENGINE"}, optEqValue},
	{[]string{"COMMENT"}, optEqValue},
	{[]string{"AUTO_INCREMENT"}, optEqValue},
	{[]string{"ROW_FORMAT"}, optEqValue},
	{[]string{"KEY_BLOCK_SIZE"}, optEqValue},
	{[]string{"AVG_ROW_LENGTH"}, optEqValue},
	{[]string{"MAX_ROWS"}, optEqValue},
	{[]string{"MIN_ROWS"}, optEqValue},
	{[]string{"PACK_KEYS"}, optEqValue},
	{[]string{"CHECKSUM"}, optEqValue},
	{[]string{"DELAY_KEY_WRITE"}, optEqValue},
	{[]string{"STATS_PERSISTENT"}, optEqValue},
	{[]string{"STATS_AUTO_RECALC"}, optEqValue},
	{[]string{"STATS_SAMPLE_PAGES"}, optEqValue},
	{[]string{"COMPRESSION"}, optEqValue},
	{[]string{"ENCRYPTION"}, optEqValue},
	{[]string{"PAGE_CHECKSUM"}, optEqValue},
	{[]string{"TRANSACTIONAL"}, optEqValue},
	{[]string{"INSERT_METHOD"}, optEqValue},
	{[]string{"DATA", "DIRECTORY"}, optEqValue},
	{[]string{"INDEX", "DIRECTORY"}, optEqValue},
	{[]string{"TABLESPACE"}, optSpaced},
	{[]string{"USING"}, optSpaced},
	{[]string{"PCTFREE"}, optSpaced},
	{[]string{"PCTUSED"}, optSpaced},
	{[]string{"INITRANS"}, optSpaced},
	{[]string{"MAXTRANS"}, optSpaced},
	{[]string{"PARALLEL"}, optSpaced},
	{[]string{"DATA_RETENTION_TIME_IN_DAYS"}, optEqRequired},
	{[]string{"MAX_DATA_EXTENSION_TIME_IN_DAYS"}, optEqRequired},
	{[]string{"CHANGE_TRACKING"}, optEqRequired},
	{[]string{"DEFAULT_DDL_COLLATION"}, optEqRequired},
	{[]string{"ENABLE_SCHEMA_EVOLUTION"}, optEqRequired},
	{[]string{"CLUSTER", "BY"}, optArgs},
	{[]string{"WITH"}, optList},
	{[]string{"ON", "COMMIT", "DELETE", "ROWS"}, optFlag},
	{[]string{"ON", "COMMIT", "PRESERVE", "ROWS"}, optFlag},
	{[]string{"ON", "COMMIT", "DROP"}, optFlag},
	{[]string{"WITHOUT", "ROWID"}, optFlag},
	{[]string{"WITHOUT", "OIDS"}, optFlag},
	{[]string{"STRICT"}, optFlag},
	{[]string{"COPY", "GRANTS"}, optFlag},
	{[]string{"LOGGING"}, optFlag},
	{[]string{"NOLOGGING"}, optFlag},
	{[]string{"COMPRESS"}, optFlag},
	{[]string{"NOCOMPRESS"}, optFlag},
	{[]string{"NOCACHE"}, optFlag},
	{[]string{"NOPARALLEL"}, optFlag},
	{[]string{"ROWDEPENDENCIES"}, optFlag},
	{[]string{"NOROWDEPENDENCIES"}, optFlag},
	{[]string{"MONITORING"}, optFlag},
	{[]string{"NOMONITORING"}, optFlag},
	{[]string{"ENABLE", "ROW", "MOVEMENT"}, optFlag},
	{[]string{"DISABLE", "ROW", "MOVEMENT"}, optFlag},
	{[]string{"SEGMENT", "CREATION", "IMMEDIATE"}, optFlag},
	{[]string{"SEGMENT", "CREATION", "DEFERRED"}, optFlag},
	{[]string{"ORGANIZATION", "HEAP"}, optFlag},
	{[]string{"ORGANIZATION", "INDEX"}, optFlag},
}

// indexOptionSpecs are the CREATE INDEX options recognized after the
// column list.
var indexOptionSpecs = []optionSpec{
	{[]string{"NULLS", "NOT", "DISTINCT"}, optFlag},
	{[]string{"NULLS", "DISTINCT"}, optFlag},
	{[]string{"WITH"}, optList},
	{[]string{"TABLESPACE"}, optSpaced},
	{[]string{"USING"}, optSpaced},
	{[]string{"COMMENT"}, optSpaced},
	{[]string{"ALGORITHM"}, optEqValue},
	{[]string{"LOCK"}, optEqValue},
	{[]string{"KEY_BLOCK_SIZE"}, optEqValue},
	{[]string{"PARALLEL"}, optSpaced},
	{[]string{"LOCAL"}, optFlag},
	{[]string{"GLOBAL"}, optFlag},
	{[]string{"ONLINE"}, optFlag},
	{[]string{"REVERSE"}, optFlag},
	{[]string{"LOGGING"}, optFlag},
	{[]string{"NOLOGGING"}, optFlag},
	{[]string{"COMPRESS"}, optFlag},
	{[]string{"NOCOMPRESS"}, optFlag},
	{[]string{"NOPARALLEL"}, optFlag},
	{[]string{"VISIBLE"}, optFlag},
	{[]string{"INVISIBLE"}, optFlag},
}

// matchOptionSpec returns the spec whose words start at the current token.
func (p *Parser) matchOptionSpec(specs []optionSpec) *optionSpec {
	first := p.wordAt(0)
	if first == "" {
		return nil
	}
	for i := range specs {
		s := &specs[i]
		if s.words[0] != first {
			continue
		}
		ok := true
		for j := 1; j < len(s.words); j++ {
			if p.wordAt(j) != s.words[j] {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		switch s.value {
		case optArgs, optList:
			if p.tokenAt(len(s.words)).Token.Type != models.TokenTypeLParen {
				continue
			}
		case optEqRequired:
			if p.tokenAt(len(s.words)).Token.Type != models.TokenTypeEq {
				continue
			}
		}
		return s
	}
	return nil
}

// parseOptionValue parses a single option value (a word, string or number)
// into opt. A word may carry a parenthesized argument list (ENGINE =
// MergeTree(), ReplicatedMergeTree('/p', '{r}')) that is kept with it.
func (p *Parser) parseOptionValue(opt *ast.TableOption) error {
	switch {
	case p.isStringLiteral():
		opt.ValueKind = ast.TableOptionString
		opt.Value = p.currentToken.Token.Value
		p.advance()
		return nil
	case p.isType(models.TokenTypeNumber):
		if _, ok := p.isPlainIntToken(); !ok {
			return p.expectedError("option value")
		}
		opt.ValueKind = ast.TableOptionNumber
		opt.Value = p.currentToken.Token.Value
		p.advance()
		return nil
	case p.isIdentifier() || p.isWordToken():
		opt.Value = p.currentToken.Token.Value
		p.advance()
		if p.isType(models.TokenTypeLParen) {
			args, err := p.parseTypeArgsString()
			if err != nil {
				return err
			}
			opt.Value += args
		}
		return nil
	}
	return p.expectedError("option value")
}

// parseOptionSpec parses the option described by spec at the current token.
func (p *Parser) parseOptionSpec(spec *optionSpec) (ast.TableOption, error) {
	opt := ast.TableOption{Name: strings.Join(spec.words, " ")}
	for range spec.words {
		p.advance()
	}
	switch spec.value {
	case optFlag:
		opt.Form = ast.TableOptionFlag
		return opt, nil
	case optArgs:
		opt.Form = ast.TableOptionArgs
		p.advance() // (
		for {
			e, err := p.parseExpression()
			if err != nil {
				return opt, err
			}
			opt.Args = append(opt.Args, e)
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance()
		}
		if !p.isType(models.TokenTypeRParen) {
			return opt, p.expectedError(")")
		}
		p.advance()
		return opt, nil
	case optList:
		opt.Form = ast.TableOptionList
		sub, err := p.parseOptionList()
		opt.Sub = sub
		return opt, err
	case optSpaced:
		opt.Form = ast.TableOptionSpaced
		if p.isType(models.TokenTypeEq) {
			opt.Form = ast.TableOptionEquals
			p.advance()
		}
	default:
		if p.isType(models.TokenTypeEq) {
			p.advance()
		} else {
			opt.Form = ast.TableOptionSpaced
		}
	}
	return opt, p.parseOptionValue(&opt)
}

// parseOptionList parses "( name [= value] [, ...] )" with the current
// token at "(": a PostgreSQL storage-parameter or SQL Server index-option
// list.
func (p *Parser) parseOptionList() ([]ast.OptionParam, error) {
	p.advance() // (
	var list []ast.OptionParam
	for {
		var words []string
		for p.wordAt(0) != "" && !p.isType(models.TokenTypeEq) {
			words = append(words, p.currentToken.Token.Value)
			p.advance()
			if p.isType(models.TokenTypePeriod) && p.wordAt(1) != "" {
				// toast.autovacuum_enabled
				p.advance()
				words[len(words)-1] += "." + p.currentToken.Token.Value
				p.advance()
			}
		}
		if len(words) == 0 {
			return nil, p.expectedError("option name")
		}
		param := ast.OptionParam{Name: strings.Join(words, " ")}
		if p.isType(models.TokenTypeEq) {
			p.advance()
			var v ast.TableOption
			if err := p.parseOptionValue(&v); err != nil {
				return nil, err
			}
			if strings.IndexByte(v.Value, '(') >= 0 {
				return nil, p.expectedError("option value")
			}
			param.HasValue, param.Value, param.ValueKind = true, v.Value, v.ValueKind
		}
		list = append(list, param)
		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance()
	}
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(")")
	}
	p.advance()
	return list, nil
}

// parseTableOptions parses the options matched by specs, separated by
// optional commas, appending them to opts.
func (p *Parser) parseTableOptions(specs []optionSpec, opts []ast.TableOption) ([]ast.TableOption, error) {
	for {
		spec := p.matchOptionSpec(specs)
		if spec == nil && p.isType(models.TokenTypeComma) && len(opts) > 0 {
			// MySQL and SQLite separate table options with optional commas.
			saved, savedTok := p.currentPos, p.currentToken
			p.advance()
			if spec = p.matchOptionSpec(specs); spec == nil {
				p.currentPos, p.currentToken = saved, savedTok
			}
		}
		if spec == nil {
			return opts, nil
		}
		opt, err := p.parseOptionSpec(spec)
		if err != nil {
			return opts, err
		}
		opts = append(opts, opt)
	}
}

// ---------------------------------------------------------------------------
// CREATE TABLE heads and tails
// ---------------------------------------------------------------------------

// parseOnCluster parses an optional ClickHouse ON CLUSTER name.
func (p *Parser) parseOnCluster() (string, error) {
	if p.dialect != string(keywords.DialectClickHouse) || !p.isType(models.TokenTypeOn) ||
		p.wordAt(1) != "CLUSTER" {
		return "", nil
	}
	p.advance() // ON
	p.advance() // CLUSTER
	if p.isStringLiteral() {
		name := p.currentToken.Token.Value
		p.advance()
		return name, nil
	}
	name, err := p.parseQualifiedName()
	if err != nil {
		return "", p.qualifiedNameError(err, "cluster name")
	}
	return name, nil
}

// isQueryStart reports whether the current token starts a query expression.
func (p *Parser) isQueryStart() bool {
	switch p.currentToken.Token.Type {
	case models.TokenTypeSelect, models.TokenTypeWith:
		return true
	case models.TokenTypeLParen:
		return p.isInsertQueryParenStart()
	}
	return false
}

// parseCreateTableSource parses the forms of CREATE TABLE that take their
// structure from elsewhere instead of a column list: LIKE src, CLONE src,
// PARTITION OF parent, and ClickHouse AS other_table. It reports whether one
// was parsed.
func (p *Parser) parseCreateTableSource(stmt *ast.CreateTableStatement) (bool, error) {
	switch {
	case p.isType(models.TokenTypeLike):
		p.advance() // LIKE
		name, q, err := p.parseQualifiedNameQuoted()
		if err != nil {
			return true, p.qualifiedNameError(err, "source table after LIKE")
		}
		stmt.Like = name
		stmt.SourceQuote = q
		return true, nil
	case p.dialect == string(keywords.DialectSnowflake) && p.wordAt(0) == "CLONE":
		p.advance() // CLONE
		name, q, err := p.parseQualifiedNameQuoted()
		if err != nil {
			return true, p.qualifiedNameError(err, "source table after CLONE")
		}
		stmt.SourceQuote = q
		clone := &ast.TableClone{Source: name}
		if at := p.wordAt(0); (at == "AT" || at == "BEFORE") &&
			p.tokenAt(1).Token.Type == models.TokenTypeLParen {
			clone.At = at
			p.advance() // AT / BEFORE
			p.advance() // (
			kind := p.wordAt(0)
			if keywordIn(kind, "TIMESTAMP", "OFFSET", "STATEMENT", "STREAM") == "" {
				return true, p.expectedError("TIMESTAMP, OFFSET, STATEMENT or STREAM")
			}
			clone.PointKind = kind
			p.advance()
			if !p.isType(models.TokenTypeRArrow) {
				return true, p.expectedError("=>")
			}
			p.advance()
			e, err := p.parseExpression()
			if err != nil {
				return true, err
			}
			clone.Point = e
			if !p.isType(models.TokenTypeRParen) {
				return true, p.expectedError(")")
			}
			p.advance()
		}
		stmt.Clone = clone
		return true, nil
	case p.isType(models.TokenTypePartition) && p.wordAt(1) == "OF":
		p.advance() // PARTITION
		p.advance() // OF
		name, q, err := p.parseQualifiedNameQuoted()
		if err != nil {
			return true, p.qualifiedNameError(err, "parent table after PARTITION OF")
		}
		stmt.PartitionOf = name
		stmt.SourceQuote = q
		bound, err := p.parsePartitionBound()
		if err != nil {
			return true, err
		}
		stmt.PartitionBound = bound
		return true, nil
	case p.isType(models.TokenTypeAs) && p.dialect == string(keywords.DialectClickHouse) &&
		p.tokenAt(1).Token.Type != models.TokenTypeSelect &&
		p.tokenAt(1).Token.Type != models.TokenTypeWith &&
		p.tokenAt(1).Token.Type != models.TokenTypeLParen:
		p.advance() // AS
		name, q, err := p.parseQualifiedNameQuoted()
		if err != nil {
			return true, p.qualifiedNameError(err, "source table after AS")
		}
		stmt.AsTable = name
		stmt.SourceQuote = q
		return true, nil
	}
	return false, nil
}

// keywordIn returns w when it is one of set and "" otherwise.
func keywordIn(w string, set ...string) string {
	for _, s := range set {
		if w == s {
			return w
		}
	}
	return ""
}

// parsePartitionBound parses a PostgreSQL partition bound:
// FOR VALUES IN (...) | FROM (...) TO (...) | WITH (MODULUS n, REMAINDER m),
// or DEFAULT.
func (p *Parser) parsePartitionBound() (*ast.PartitionBound, error) {
	if p.isType(models.TokenTypeDefault) {
		p.advance()
		return &ast.PartitionBound{Default: true}, nil
	}
	if !p.isType(models.TokenTypeFor) {
		return nil, p.expectedError("FOR VALUES or DEFAULT")
	}
	p.advance() // FOR
	if !p.isType(models.TokenTypeValues) {
		return nil, p.expectedError("VALUES")
	}
	p.advance() // VALUES
	b := &ast.PartitionBound{}
	var err error
	switch {
	case p.isType(models.TokenTypeIn):
		p.advance()
		b.In, err = p.parseParenExprList()
	case p.isType(models.TokenTypeFrom):
		p.advance()
		if b.From, err = p.parseParenExprList(); err != nil {
			return nil, err
		}
		if !p.isType(models.TokenTypeTo) {
			return nil, p.expectedError("TO")
		}
		p.advance()
		b.To, err = p.parseParenExprList()
	case p.isType(models.TokenTypeWith):
		p.advance()
		if !p.isType(models.TokenTypeLParen) {
			return nil, p.expectedError("(")
		}
		p.advance()
		if p.wordAt(0) != "MODULUS" {
			return nil, p.expectedError("MODULUS")
		}
		p.advance()
		if b.Modulus, err = p.parseExpression(); err != nil {
			return nil, err
		}
		if !p.isType(models.TokenTypeComma) || p.wordAt(1) != "REMAINDER" {
			return nil, p.expectedError(", REMAINDER")
		}
		p.advance()
		p.advance()
		if b.Remainder, err = p.parseExpression(); err != nil {
			return nil, err
		}
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance()
	default:
		return nil, p.expectedError("IN, FROM or WITH")
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}

// parseParenExprList parses "( expr [, expr]... )" with the current token at
// "(". MINVALUE and MAXVALUE are accepted as bare bounds.
func (p *Parser) parseParenExprList() ([]ast.Expression, error) {
	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("(")
	}
	p.advance()
	var list []ast.Expression
	for {
		var e ast.Expression
		if w := p.wordAt(0); w == "MAXVALUE" || w == "MINVALUE" {
			switch p.tokenAt(1).Token.Type {
			case models.TokenTypeComma, models.TokenTypeRParen:
				e = &ast.Identifier{Name: w}
				p.advance()
			}
		}
		if e == nil {
			if p.isType(models.TokenTypeDefault) {
				e = &ast.Identifier{Name: "DEFAULT"}
				p.advance()
			} else {
				var err error
				if e, err = p.parseExpression(); err != nil {
					return nil, err
				}
			}
		}
		list = append(list, e)
		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance()
	}
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(")")
	}
	p.advance()
	return list, nil
}

// isEngineClauseStart reports whether the current token starts a ClickHouse
// table clause written after ENGINE = ...
func (p *Parser) isEngineClauseStart() bool { return p.isEngineClauseStartAt(0) }

// isEngineClauseStartAt is isEngineClauseStart for the token n positions
// ahead.
func (p *Parser) isEngineClauseStartAt(n int) bool {
	switch w := p.wordAt(n); w {
	case "ORDER", "PARTITION", "SAMPLE":
		return p.wordAt(n+1) == "BY"
	case "PRIMARY":
		return p.wordAt(n+1) == "KEY"
	case "TTL", "SETTINGS":
		return true
	case "COMMENT":
		t := p.tokenAt(n + 1).Token.Type
		return t == models.TokenTypeString || t == models.TokenTypeSingleQuotedString
	}
	return false
}

// parseEngineExpr parses the expression of an engine clause. A lone
// keyword-named column (ORDER BY hash) is read as a column reference.
func (p *Parser) parseEngineExpr() (ast.Expression, error) {
	if p.wordAt(0) != "" && !p.isIdentifier() {
		switch p.tokenAt(1).Token.Type {
		case models.TokenTypeEOF, models.TokenTypeSemicolon, models.TokenTypeAs:
			id := &ast.Identifier{Name: p.currentToken.Token.Value}
			p.advance()
			return id, nil
		}
		if p.isEngineClauseStartAt(1) || p.wordAt(1) == "POPULATE" {
			id := &ast.Identifier{Name: p.currentToken.Token.Value}
			p.advance()
			return id, nil
		}
	}
	return p.parseExpression()
}

// parseEngineClauses parses the ClickHouse clauses written after
// ENGINE = ...: PARTITION BY, PRIMARY KEY, ORDER BY, SAMPLE BY, TTL,
// SETTINGS and COMMENT, in any order, each at most once.
func (p *Parser) parseEngineClauses(e *ast.TableEngineClauses) error {
	for p.isEngineClauseStart() {
		word := p.wordAt(0)
		var dst *ast.Expression
		switch word {
		case "ORDER":
			dst = &e.OrderBy
		case "PARTITION":
			dst = &e.PartitionBy
		case "PRIMARY":
			dst = &e.PrimaryKey
		case "SAMPLE":
			dst = &e.SampleBy
		}
		if dst != nil {
			if *dst != nil {
				return p.expectedError("a single " + word + " clause")
			}
			p.advance() // ORDER / PARTITION / PRIMARY / SAMPLE
			p.advance() // BY / KEY
			x, err := p.parseEngineExpr()
			if err != nil {
				return err
			}
			*dst = x
			continue
		}
		switch word {
		case "TTL":
			if e.TTL != nil {
				return p.expectedError("a single TTL clause")
			}
			p.advance() // TTL
			for {
				rule, err := p.parseTTLRule()
				if err != nil {
					return err
				}
				e.TTL = append(e.TTL, rule)
				if !p.isType(models.TokenTypeComma) {
					break
				}
				p.advance()
			}
		case "SETTINGS":
			if e.Settings != nil {
				return p.expectedError("a single SETTINGS clause")
			}
			settings, err := p.parseQuerySettingsList()
			if err != nil {
				return err
			}
			e.Settings = settings
		case "COMMENT":
			if e.Comment != nil {
				return p.expectedError("a single COMMENT clause")
			}
			p.advance() // COMMENT
			c := p.currentToken.Token.Value
			e.Comment = &c
			p.advance()
		}
	}
	return nil
}

// parseTTLRule parses one ClickHouse TTL rule:
// expr [DELETE | TO DISK 'd' | TO VOLUME 'v'] [WHERE cond]
// [GROUP BY keys [SET name = expr, ...]].
func (p *Parser) parseTTLRule() (ast.TTLRule, error) {
	var r ast.TTLRule
	x, err := p.parseExpression()
	if err != nil {
		return r, err
	}
	r.Expr = x
	switch {
	case p.isType(models.TokenTypeDelete):
		r.Action = "DELETE"
		p.advance()
	case p.isType(models.TokenTypeTo) && (p.wordAt(1) == "DISK" || p.wordAt(1) == "VOLUME"):
		r.Action = "TO " + p.wordAt(1)
		p.advance()
		p.advance()
		if !p.isStringLiteral() {
			return r, p.expectedError("disk or volume name")
		}
		r.Target = p.currentToken.Token.Value
		p.advance()
	}
	if p.isType(models.TokenTypeWhere) {
		p.advance()
		if r.Where, err = p.parseExpression(); err != nil {
			return r, err
		}
	}
	if p.isType(models.TokenTypeGroup) && p.wordAt(1) == "BY" {
		p.advance()
		p.advance()
		for {
			g, err := p.parseExpression()
			if err != nil {
				return r, err
			}
			r.GroupBy = append(r.GroupBy, g)
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance()
		}
		if p.isType(models.TokenTypeSet) {
			p.advance()
			for {
				if !p.isQuerySettingName() {
					return r, p.expectedError("column name")
				}
				s := ast.QuerySetting{Name: p.currentToken.Token.Value, Pos: p.currentLocation()}
				p.advance()
				if !p.isType(models.TokenTypeEq) {
					return r, p.expectedError("=")
				}
				p.advance()
				if s.Value, err = p.parseExpression(); err != nil {
					return r, err
				}
				r.Set = append(r.Set, s)
				// A comma continues the SET list only when "name =" follows;
				// otherwise it separates TTL rules.
				if !p.isType(models.TokenTypeComma) || p.tokenAt(2).Token.Type != models.TokenTypeEq {
					break
				}
				p.advance()
			}
		}
	}
	return r, nil
}

// parseCreateTableTail parses everything after the column list (or the
// LIKE / CLONE / PARTITION OF / AS source) of CREATE TABLE: INHERITS,
// WITH SYSTEM VERSIONING, PARTITION BY, table options, ClickHouse engine
// clauses and the AS query.
func (p *Parser) parseCreateTableTail(stmt *ast.CreateTableStatement) error {
	clickhouse := p.dialect == string(keywords.DialectClickHouse)
	for {
		switch {
		case p.wordAt(0) == "INHERITS" && p.tokenAt(1).Token.Type == models.TokenTypeLParen &&
			stmt.Inherits == nil:
			p.advance() // INHERITS
			p.advance() // (
			for {
				name, err := p.parseQualifiedName()
				if err != nil {
					return p.qualifiedNameError(err, "parent table")
				}
				stmt.Inherits = append(stmt.Inherits, name)
				if !p.isType(models.TokenTypeComma) {
					break
				}
				p.advance()
			}
			if !p.isType(models.TokenTypeRParen) {
				return p.expectedError(")")
			}
			p.advance()
		case p.isType(models.TokenTypeWith) && p.wordAt(1) == "SYSTEM" && p.wordAt(2) == "VERSIONING" &&
			!stmt.WithSystemVersioning:
			p.advance()
			p.advance()
			p.advance()
			stmt.WithSystemVersioning = true
		case clickhouse && p.isEngineClauseStart():
			if stmt.Engine == nil {
				stmt.Engine = &ast.TableEngineClauses{}
			}
			if err := p.parseEngineClauses(stmt.Engine); err != nil {
				return err
			}
		case !clickhouse && p.isType(models.TokenTypePartition) && p.wordAt(1) == "BY" &&
			stmt.PartitionBy == nil:
			p.advance() // PARTITION
			p.advance() // BY
			stmt.OptionsBeforePartition = len(stmt.Options)
			pb, err := p.parsePartitionByClause()
			if err != nil {
				return err
			}
			stmt.PartitionBy = pb
			if p.isType(models.TokenTypeLParen) {
				p.advance() // (
				for {
					partDef, err := p.parsePartitionDefinition()
					if err != nil {
						return err
					}
					stmt.Partitions = append(stmt.Partitions, *partDef)
					if !p.isType(models.TokenTypeComma) {
						break
					}
					p.advance()
				}
				if !p.isType(models.TokenTypeRParen) {
					return p.expectedError(")")
				}
				p.advance()
			}
		case p.isType(models.TokenTypeAs) && stmt.AsQuery == nil:
			p.advance() // AS
			q, err := p.parseQueryExpression("SELECT after AS")
			if err != nil {
				return err
			}
			stmt.AsQuery = q
			if p.isType(models.TokenTypeWith) {
				if p.wordAt(1) == "DATA" {
					p.advance()
					p.advance()
					v := true
					stmt.WithData = &v
				} else if p.wordAt(1) == "NO" && p.wordAt(2) == "DATA" {
					p.advance()
					p.advance()
					p.advance()
					v := false
					stmt.WithData = &v
				}
			}
			return nil
		default:
			n := len(stmt.Options)
			opts, err := p.parseTableOptions(tableOptionSpecs, stmt.Options)
			stmt.Options = opts
			if err != nil {
				return err
			}
			if len(opts) == n {
				return nil
			}
			for _, o := range opts[n:] {
				if o.Name == "WITHOUT ROWID" {
					stmt.WithoutRowID = true
				}
			}
		}
	}
}
