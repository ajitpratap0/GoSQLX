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

// Package parser - ddl.go
// DDL statement parsing: CREATE dispatch, CREATE TABLE core, partitioning,
// DROP, TRUNCATE.
// Related modules:
//   - ddl_columns.go  - column definitions and table constraints
//   - ddl_index.go    - CREATE INDEX
//   - ddl_view.go     - CREATE VIEW, CREATE MATERIALIZED VIEW, REFRESH
//   - ddl_objects.go  - verbatim objects, CREATE TABLE heads/tails, options

package parser

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// isTokenMatch checks if the current token matches the given keyword
// This handles both keyword tokens and identifier tokens with matching literal values
// (needed because some keywords like DATA, NO may be tokenized as identifiers)
func (p *Parser) isTokenMatch(keyword string) bool {
	// Check if token literal matches the keyword (case-insensitive)
	return strings.EqualFold(p.currentToken.Token.Value, keyword)
}

// parseCreateStatement parses CREATE statements. TABLE, VIEW, MATERIALIZED
// VIEW and INDEX (and MariaDB SEQUENCE) get dedicated AST nodes; every other
// object (SCHEMA, FUNCTION, TRIGGER, USER, ...) is kept verbatim as a
// UtilityStatement so it round-trips unchanged.
func (p *Parser) parseCreateStatement() (ast.Statement, error) {
	createIdx := p.currentPos - 1 // the CREATE token
	if kind := p.createVerbatimKind(); kind != "" {
		return p.parseVerbatimFrom(createIdx, kind)
	}

	// Modifiers: OR REPLACE, OR ALTER, and the table / view kind words.
	orReplace, orAlter := false, false
	var mods []string
	for {
		if p.isType(models.TokenTypeOr) {
			p.advance() // Consume OR
			switch {
			case p.isType(models.TokenTypeReplace):
				orReplace = true
			case p.isTokenMatch("ALTER"):
				orAlter = true
			default:
				return nil, p.expectedError("REPLACE after OR")
			}
			p.advance() // Consume REPLACE / ALTER
			continue
		}
		switch w := p.wordAt(0); w {
		case "TEMPORARY", "TEMP", "GLOBAL", "LOCAL", "UNLOGGED", "TRANSIENT",
			"VOLATILE", "SECURE", "FORCE", "RECURSIVE":
			mods = append(mods, w)
			p.advance()
			continue
		case "NO":
			if p.wordAt(1) == "FORCE" {
				mods = append(mods, "NO", "FORCE")
				p.advance()
				p.advance()
				continue
			}
		}
		break
	}
	modText := strings.Join(mods, " ")
	temporary := false
	for _, m := range mods {
		if m == "TEMP" || m == "TEMPORARY" {
			temporary = true
		}
	}

	// Determine object type
	switch {
	case p.isType(models.TokenTypeMaterialized):
		p.advance() // Consume MATERIALIZED
		if !p.isType(models.TokenTypeView) {
			return nil, p.expectedError("VIEW after MATERIALIZED")
		}
		p.advance() // Consume VIEW
		if modText != "" || orAlter {
			return nil, p.expectedError("MATERIALIZED VIEW without " + modText)
		}
		stmt, err := p.parseCreateMaterializedView()
		if err != nil {
			return nil, err
		}
		stmt.OrReplace = orReplace
		return stmt, nil
	case p.isType(models.TokenTypeView):
		p.advance() // Consume VIEW
		stmt, err := p.parseCreateView(orReplace, temporary)
		if err != nil {
			return nil, err
		}
		stmt.OrAlter = orAlter
		if modText != "TEMPORARY" {
			stmt.Modifiers = modText
		}
		return stmt, nil
	case p.isType(models.TokenTypeTable):
		p.advance() // Consume TABLE
		if orAlter || (modText != "" && ast.TableKindText(modText) == "") {
			return nil, p.expectedError("TABLE kind")
		}
		stmt, err := p.parseCreateTable(temporary)
		if err != nil {
			return nil, err
		}
		stmt.OrReplace = orReplace
		if modText != "TEMPORARY" {
			stmt.Kind = modText
		}
		return stmt, nil
	}
	if modText != "" || orAlter {
		return nil, p.expectedError("TABLE or VIEW after " + modText)
	}

	// [UNIQUE] [FULLTEXT | SPATIAL | BITMAP | [NON]CLUSTERED] INDEX
	unique := false
	if p.isType(models.TokenTypeUnique) {
		p.advance() // Consume UNIQUE
		unique = true
	}
	indexKind := ""
	if k := ast.IndexKindText(p.wordAt(0)); k != "" && p.wordAt(1) == "INDEX" {
		indexKind = k
		p.advance()
	}
	if p.isType(models.TokenTypeIndex) {
		p.advance() // Consume INDEX
		stmt, err := p.parseCreateIndex(unique)
		if err != nil {
			return nil, err
		}
		stmt.Kind = indexKind
		stmt.OrReplace = orReplace
		return stmt, nil
	}
	if unique {
		return nil, p.expectedError("INDEX after UNIQUE")
	}

	if p.isMariaDB() && p.isTokenMatch("SEQUENCE") {
		seqPos := p.currentLocation() // position of SEQUENCE token
		p.advance()                   // Consume SEQUENCE
		stmt, err := p.parseCreateSequenceStatement(orReplace)
		if err != nil {
			return nil, err
		}
		if stmt.Pos.IsZero() {
			stmt.Pos = seqPos
		}
		return stmt, nil
	}

	return nil, p.expectedError("TABLE, VIEW, MATERIALIZED VIEW, or INDEX after CREATE")
}

// parseCreateTable parses CREATE TABLE after the TABLE keyword: the column
// list, or one of the LIKE / CLONE / PARTITION OF / AS forms, followed by
// partitioning, table options, ClickHouse engine clauses and an optional
// AS query.
func (p *Parser) parseCreateTable(temporary bool) (*ast.CreateTableStatement, error) {
	stmt := &ast.CreateTableStatement{
		Temporary: temporary,
	}

	// Check for IF NOT EXISTS
	if p.isType(models.TokenTypeIf) {
		p.advance() // Consume IF
		if !p.isType(models.TokenTypeNot) {
			return nil, p.expectedError("NOT after IF")
		}
		p.advance() // Consume NOT
		if !p.isType(models.TokenTypeExists) {
			return nil, p.expectedError("EXISTS after NOT")
		}
		p.advance() // Consume EXISTS
		stmt.IfNotExists = true
	}

	// Parse table name (supports schema.table qualification and double-quoted identifiers)
	createTableName, createTableQuote, err := p.parseQualifiedNameQuoted()
	if err != nil {
		return nil, p.qualifiedNameError(err, "table name")
	}
	stmt.Name = createTableName
	stmt.NameQuote = createTableQuote

	if stmt.OnCluster, err = p.parseOnCluster(); err != nil {
		return nil, err
	}

	// Snowflake: COPY GRANTS may precede the column list or AS query.
	if p.wordAt(0) == "COPY" && p.wordAt(1) == "GRANTS" {
		p.advance() // COPY
		p.advance() // GRANTS
		stmt.Options = append(stmt.Options, ast.TableOption{Name: "COPY GRANTS", Form: ast.TableOptionFlag})
	}

	hasSource, err := p.parseCreateTableSource(stmt)
	if err != nil {
		return nil, err
	}
	if !hasSource && p.isType(models.TokenTypeLParen) && !p.isInsertQueryParenStart() {
		if err := p.parseCreateTableElements(stmt); err != nil {
			return nil, err
		}
	} else if !hasSource && !p.isType(models.TokenTypeAs) && p.matchOptionSpec(tableOptionSpecs) == nil &&
		!(p.dialect == string(keywords.DialectClickHouse) && p.isEngineClauseStart()) {
		return nil, p.expectedError("(")
	}

	if err := p.parseCreateTableTail(stmt); err != nil {
		return nil, err
	}
	// Without a column list, a source or a query there is nothing to
	// create: CREATE TABLE t ENGINE = x.
	if !hasSource && stmt.AsQuery == nil &&
		len(stmt.Columns)+len(stmt.Constraints)+len(stmt.PeriodDefinitions) == 0 {
		return nil, p.expectedError("( or AS")
	}
	return stmt, nil
}

// parseCreateTableElements parses the parenthesized column definitions,
// table constraints and MariaDB PERIOD FOR clauses of CREATE TABLE.
func (p *Parser) parseCreateTableElements(stmt *ast.CreateTableStatement) error {
	p.advance() // Consume (

	// Parse column definitions and constraints
	likeSeen := false
	for {
		// MariaDB: PERIOD FOR name (start_col, end_col) — application-time or system-time period
		if p.isMariaDB() && p.isTokenMatch("PERIOD") {
			periodPos := p.currentLocation() // position of PERIOD keyword
			pd, err := p.parsePeriodDefinition()
			if err != nil {
				return err
			}
			pd.Pos = periodPos
			stmt.PeriodDefinitions = append(stmt.PeriodDefinitions, pd)
		} else if p.isTableConstraintStart() {
			// Check for table-level constraints and index elements
			constraint, err := p.parseTableConstraint()
			if err != nil {
				return err
			}
			likeSeen = likeSeen || constraint.Type == "LIKE"
			stmt.Constraints = append(stmt.Constraints, *constraint)
		} else {
			// The constraint list is rendered after the columns, which
			// would move the columns before a LIKE source's own.
			if likeSeen {
				return p.expectedError("no column definition after LIKE source_table")
			}
			// Parse column definition
			colDef, err := p.parseColumnDef()
			if err != nil {
				return err
			}
			stmt.Columns = append(stmt.Columns, *colDef)
		}

		// Check for more definitions
		if p.isType(models.TokenTypeComma) {
			p.advance() // Consume comma
			continue
		}
		break
	}

	// Expect closing parenthesis
	if !p.isType(models.TokenTypeRParen) {
		return p.expectedError(")")
	}
	p.advance() // Consume )
	return nil
}

// parsePartitionByClause parses the partitioning method and key after
// PARTITION BY: RANGE | LIST [COLUMNS] (key), [LINEAR] HASH | KEY (key)
// [PARTITIONS n], Oracle INTERVAL (expr), and MariaDB SYSTEM_TIME
// [INTERVAL n unit].
func (p *Parser) parsePartitionByClause() (*ast.PartitionBy, error) {
	partitionBy := &ast.PartitionBy{}

	if p.wordAt(0) == "LINEAR" {
		partitionBy.Linear = true
		p.advance()
	}
	switch w := p.wordAt(0); {
	case w == "RANGE" || w == "LIST":
		partitionBy.Type = w
		p.advance()
		if p.wordAt(0) == "COLUMNS" {
			partitionBy.Type += " COLUMNS"
			p.advance()
		}
	case w == "HASH" || w == "KEY":
		partitionBy.Type = w
		p.advance()
	case w == "SYSTEM_TIME" && !partitionBy.Linear:
		partitionBy.Type = w
		p.advance()
		if p.isType(models.TokenTypeInterval) {
			e, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			partitionBy.Interval = e
		}
		return partitionBy, nil
	default:
		return nil, p.expectedError("RANGE, LIST, or HASH")
	}
	if partitionBy.Linear && partitionBy.Type != "HASH" && partitionBy.Type != "KEY" {
		return nil, p.expectedError("HASH or KEY after LINEAR")
	}

	// Expect opening parenthesis
	if !p.isType(models.TokenTypeLParen) {
		return nil, p.expectedError("(")
	}
	p.advance() // Consume (

	// Parse the partition key: plain columns, or expressions such as
	// YEAR(created_at). KEY () may be empty.
	plain := true
	var exprs []ast.Expression
	for !(partitionBy.Type == "KEY" && p.isType(models.TokenTypeRParen) && len(exprs) == 0) {
		next := p.peekToken().Token.Type
		if p.isIdentifier() && (next == models.TokenTypeComma || next == models.TokenTypeRParen) {
			partitionBy.Columns = append(partitionBy.Columns, p.currentToken.Token.Value)
			exprs = append(exprs, &ast.Identifier{Name: p.currentToken.Token.Value})
			p.advance()
		} else {
			e, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			plain = false
			exprs = append(exprs, e)
		}
		if p.isType(models.TokenTypeComma) {
			p.advance() // Consume comma
			continue
		}
		break
	}
	if !plain {
		partitionBy.Columns = nil
		partitionBy.Expressions = exprs
	}

	// Expect closing parenthesis
	if !p.isType(models.TokenTypeRParen) {
		return nil, p.expectedError(")")
	}
	p.advance() // Consume )

	// Oracle interval partitioning: INTERVAL (expr)
	if partitionBy.Type == "RANGE" && p.isType(models.TokenTypeInterval) &&
		p.peekToken().Token.Type == models.TokenTypeLParen {
		p.advance() // INTERVAL
		p.advance() // (
		e, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		if !p.isType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}
		p.advance()
		partitionBy.Interval = e
	}
	// MySQL / Oracle partition count: PARTITIONS n
	if p.wordAt(0) == "PARTITIONS" && p.peekToken().Token.Type == models.TokenTypeNumber {
		p.advance()
		e, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		partitionBy.Partitions = e
	}

	return partitionBy, nil
}

// parsePartitionDefinition parses a single partition definition:
// PARTITION name [VALUES LESS THAN (...) | VALUES IN (...) | VALUES (...) |
// VALUES FROM (...) TO (...) | HISTORY | CURRENT] [TABLESPACE ts].
func (p *Parser) parsePartitionDefinition() (*ast.PartitionDefinition, error) {
	partDef := &ast.PartitionDefinition{}

	// Expect PARTITION keyword
	if !p.isType(models.TokenTypePartition) {
		return nil, p.expectedError("PARTITION")
	}
	p.advance() // Consume PARTITION

	// Parse partition name (supports double-quoted identifiers)
	if !p.isIdentifier() && !p.isNonReservedKeyword() {
		return nil, p.expectedError("partition name")
	}
	partDef.Name = p.currentToken.Token.Value
	p.advance()

	switch w := p.wordAt(0); {
	case w == "HISTORY" || w == "CURRENT":
		// MariaDB system-versioning partitions
		partDef.Type = w
		p.advance()
	case p.isType(models.TokenTypeValues):
		p.advance() // Consume VALUES
		if err := p.parsePartitionValues(partDef); err != nil {
			return nil, err
		}
	}

	// Parse optional TABLESPACE
	if p.isTokenMatch("TABLESPACE") {
		p.advance() // Consume TABLESPACE
		if !p.isIdentifier() && !p.isNonReservedKeyword() {
			return nil, p.expectedError("tablespace name")
		}
		partDef.Tablespace = p.currentToken.Token.Value
		p.advance()
	}

	return partDef, nil
}

// parsePartitionValues parses the value specification after VALUES in a
// partition definition.
func (p *Parser) parsePartitionValues(partDef *ast.PartitionDefinition) error {
	switch {
	case p.isTokenMatch("LESS"):
		p.advance() // Consume LESS
		if !p.isTokenMatch("THAN") {
			return p.expectedError("THAN after LESS")
		}
		p.advance() // Consume THAN
		partDef.Type = "LESS THAN"

		// Parse value or MAXVALUE
		if p.isType(models.TokenTypeLParen) {
			list, err := p.parseParenExprList()
			if err != nil {
				return err
			}
			if len(list) == 1 {
				partDef.LessThan = list[0]
			} else {
				partDef.Values = list
			}
		} else if p.isTokenMatch("MAXVALUE") {
			partDef.LessThan = &ast.Identifier{Name: "MAXVALUE"}
			p.advance()
		} else {
			return p.expectedError("( or MAXVALUE")
		}
	case p.isType(models.TokenTypeIn):
		p.advance() // Consume IN
		partDef.Type = "IN"
		list, err := p.parseParenExprList()
		if err != nil {
			return err
		}
		partDef.InValues = list
	case p.isType(models.TokenTypeFrom):
		p.advance() // Consume FROM
		partDef.Type = "FROM TO"
		from, err := p.parseParenExprList()
		if err != nil {
			return err
		}
		if len(from) != 1 {
			return p.expectedError("one FROM value")
		}
		partDef.From = from[0]
		// Expect TO
		if !p.isType(models.TokenTypeTo) {
			return p.expectedError("TO")
		}
		p.advance() // Consume TO
		to, err := p.parseParenExprList()
		if err != nil {
			return err
		}
		if len(to) != 1 {
			return p.expectedError("one TO value")
		}
		partDef.To = to[0]
	case p.isType(models.TokenTypeLParen):
		// Oracle list partition: VALUES ('a', 'b') or VALUES (DEFAULT)
		partDef.Type = "VALUES"
		list, err := p.parseParenExprList()
		if err != nil {
			return err
		}
		partDef.Values = list
	default:
		return p.expectedError("LESS THAN, IN or (")
	}
	return nil
}

// parseDropStatement parses DROP TABLE / VIEW / MATERIALIZED VIEW / INDEX.
// DROP of any other object (SCHEMA, FUNCTION, USER, ...) is kept verbatim.
func (p *Parser) parseDropStatement() (ast.Statement, error) {
	dropIdx := p.currentPos - 1 // the DROP token
	if kind := p.dropVerbatimKind(); kind != "" {
		return p.parseVerbatimFrom(dropIdx, kind)
	}
	stmt := &ast.DropStatement{}

	// MySQL: DROP TEMPORARY TABLE
	if p.wordAt(0) == "TEMPORARY" && p.peekToken().Token.Type == models.TokenTypeTable {
		p.advance()
		stmt.Temporary = true
	}

	// Determine object type
	if p.isType(models.TokenTypeMaterialized) {
		p.advance() // Consume MATERIALIZED
		if !p.isType(models.TokenTypeView) {
			return nil, p.expectedError("VIEW after MATERIALIZED")
		}
		p.advance() // Consume VIEW
		stmt.ObjectType = "MATERIALIZED VIEW"
	} else if p.isType(models.TokenTypeView) {
		p.advance() // Consume VIEW
		stmt.ObjectType = "VIEW"
	} else if p.isType(models.TokenTypeTable) {
		p.advance() // Consume TABLE
		stmt.ObjectType = "TABLE"
	} else if p.isType(models.TokenTypeIndex) {
		p.advance() // Consume INDEX
		stmt.ObjectType = "INDEX"
		if p.wordAt(0) == "CONCURRENTLY" {
			p.advance()
			stmt.Concurrently = true
		}
	} else {
		return nil, p.expectedError("TABLE, VIEW, MATERIALIZED VIEW, or INDEX after DROP")
	}

	// Check for IF EXISTS
	if p.isType(models.TokenTypeIf) {
		p.advance() // Consume IF
		if !p.isType(models.TokenTypeExists) {
			return nil, p.expectedError("EXISTS after IF")
		}
		p.advance() // Consume EXISTS
		stmt.IfExists = true
	}

	// Parse object names (can be comma-separated, supports schema.name qualification)
	for {
		dropName, dropQuote, err := p.parseQualifiedNameQuoted()
		if err != nil {
			return nil, p.qualifiedNameError(err, "object name")
		}
		stmt.NameQuotes = nameQuoteList(stmt.NameQuotes, len(stmt.Names), dropQuote)
		stmt.Names = append(stmt.Names, dropName)

		if p.isType(models.TokenTypeComma) {
			p.advance() // Consume comma
			continue
		}
		break
	}

	var err error
	if stmt.OnCluster, err = p.parseOnCluster(); err != nil {
		return nil, err
	}
	// MySQL / SQL Server / MariaDB: DROP INDEX name ON table
	if stmt.ObjectType == "INDEX" && p.isType(models.TokenTypeOn) && len(stmt.Names) == 1 {
		p.advance() // ON
		table, tableQuote, err := p.parseQualifiedNameQuoted()
		if err != nil {
			return nil, p.qualifiedNameError(err, "table name after ON")
		}
		stmt.OnTable = table
		stmt.OnTableQuote = tableQuote
	}

	// Parse optional CASCADE [CONSTRAINTS] / RESTRICT
	if p.isType(models.TokenTypeCascade) {
		stmt.CascadeType = "CASCADE"
		p.advance()
		if p.wordAt(0) == "CONSTRAINTS" {
			stmt.CascadeType = "CASCADE CONSTRAINTS"
			p.advance()
		}
	} else if p.isType(models.TokenTypeRestrict) {
		stmt.CascadeType = "RESTRICT"
		p.advance()
	}
	if p.wordAt(0) == "PURGE" {
		stmt.Purge = true
		p.advance()
	}
	if p.dialect == string(keywords.DialectClickHouse) && p.wordAt(0) == "SYNC" {
		stmt.Sync = true
		p.advance()
	}

	return stmt, nil
}

// parseTruncateStatement parses TRUNCATE TABLE statement
// Syntax: TRUNCATE [TABLE] table_name [, table_name ...] [RESTART IDENTITY | CONTINUE IDENTITY] [CASCADE | RESTRICT]
func (p *Parser) parseTruncateStatement() (*ast.TruncateStatement, error) {
	stmt := &ast.TruncateStatement{}

	// Optional TABLE keyword
	if p.isType(models.TokenTypeTable) {
		p.advance() // Consume TABLE
	}

	// Parse table names (can be comma-separated, supports schema.table qualification)
	for {
		truncTableName, truncQuote, err := p.parseQualifiedNameQuoted()
		if err != nil {
			return nil, p.qualifiedNameError(err, "table name")
		}
		stmt.TableQuotes = nameQuoteList(stmt.TableQuotes, len(stmt.Tables), truncQuote)
		stmt.Tables = append(stmt.Tables, truncTableName)

		if p.isType(models.TokenTypeComma) {
			p.advance() // Consume comma
			continue
		}
		break
	}

	// Parse optional RESTART IDENTITY / CONTINUE IDENTITY
	if p.isTokenMatch("RESTART") {
		p.advance() // Consume RESTART
		if !p.isTokenMatch("IDENTITY") {
			return nil, p.expectedError("IDENTITY after RESTART")
		}
		p.advance() // Consume IDENTITY
		stmt.RestartIdentity = true
	} else if p.isTokenMatch("CONTINUE") {
		p.advance() // Consume CONTINUE
		if !p.isTokenMatch("IDENTITY") {
			return nil, p.expectedError("IDENTITY after CONTINUE")
		}
		p.advance() // Consume IDENTITY
		stmt.ContinueIdentity = true
	}

	// Parse optional CASCADE/RESTRICT
	if p.isType(models.TokenTypeCascade) {
		stmt.CascadeType = "CASCADE"
		p.advance()
	} else if p.isType(models.TokenTypeRestrict) {
		stmt.CascadeType = "RESTRICT"
		p.advance()
	}

	// Oracle: DROP [ALL] STORAGE | REUSE STORAGE
	switch {
	case p.isType(models.TokenTypeDrop) && p.wordAt(1) == "STORAGE":
		stmt.Storage = "DROP STORAGE"
	case p.isType(models.TokenTypeDrop) && p.wordAt(1) == "ALL" && p.wordAt(2) == "STORAGE":
		stmt.Storage = "DROP ALL STORAGE"
	case p.wordAt(0) == "REUSE" && p.wordAt(1) == "STORAGE":
		stmt.Storage = "REUSE STORAGE"
	}
	for i := strings.Count(stmt.Storage, " "); stmt.Storage != "" && i >= 0; i-- {
		p.advance()
	}

	return stmt, nil
}
