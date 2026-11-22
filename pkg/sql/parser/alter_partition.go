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

package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// isMySQLPartitionAction reports whether the current token starts a MySQL /
// MariaDB partition action (partition_options of ALTER TABLE).
func (p *Parser) isMySQLPartitionAction() bool {
	switch p.utilityWord(p.currentPos) {
	case "PARTITION":
		return p.utilityWord(p.currentPos+1) == "BY"
	case "ADD", "DROP", "TRUNCATE", "REORGANIZE", "COALESCE", "EXCHANGE", "ANALYZE",
		"CHECK", "OPTIMIZE", "REBUILD", "REPAIR", "DISCARD", "IMPORT":
		return p.utilityWord(p.currentPos+1) == "PARTITION"
	case "REMOVE", "UPGRADE":
		return p.utilityWord(p.currentPos+1) == "PARTITIONING"
	}
	return false
}

// parseMySQLPartitionActionOrGeneric parses a MySQL / MariaDB partition
// action structurally. Forms the structured grammar does not cover (partition
// options such as ENGINE or COMMENT, subpartitions, MariaDB CONVERT
// PARTITION, ...) fall back to the generic as-written action, as before.
func (p *Parser) parseMySQLPartitionActionOrGeneric(op *ast.AlterTableOperation) (*ast.AlterTableOperation, bool) {
	start := p.currentPos
	res, err := p.parseMySQLPartitionAction(op)
	if err == nil && (p.isType(models.TokenTypeComma) || p.isType(models.TokenTypeSemicolon) ||
		p.isType(models.TokenTypeEOF) || p.isStatementStartingKeyword() || p.statementMayEndAt(p.currentPos)) {
		return res, true
	}
	p.seek(start)
	*op = ast.AlterTableOperation{}
	return nil, false
}

func (p *Parser) parseMySQLPartitionAction(op *ast.AlterTableOperation) (*ast.AlterTableOperation, error) {
	verb := p.utilityWord(p.currentPos)
	op.Type = ast.AlterPartitioning
	op.Keyword = verb + " " + p.utilityWord(p.currentPos+1)
	p.advance()
	p.advance()
	mariadb := p.dialect == string(keywords.DialectMariaDB)
	switch verb {
	case "PARTITION":
		part, err := p.parsePartitionByClause()
		if err != nil {
			return nil, err
		}
		switch part.Type {
		case "RANGE", "RANGE COLUMNS", "LIST", "LIST COLUMNS", "HASH", "KEY":
			if part.Interval != nil {
				return nil, p.expectedError("MySQL partition options")
			}
		case "SYSTEM_TIME":
			if !mariadb {
				return nil, p.expectedError("RANGE, LIST, HASH, or KEY")
			}
		default:
			return nil, p.expectedError("RANGE, LIST, HASH, or KEY")
		}
		op.Partitioning = part
		if p.isType(models.TokenTypeLParen) {
			if err := p.parseAlterPartitionDefinitions(op); err != nil {
				return nil, err
			}
		}
	case "ADD":
		// MariaDB: ADD PARTITION [IF NOT EXISTS] (...)
		if mariadb && p.isType(models.TokenTypeIf) && p.utilityWord(p.currentPos+1) == "NOT" &&
			p.utilityWord(p.currentPos+2) == "EXISTS" {
			p.advance()
			p.advance()
			p.advance()
			op.IfNotExists = true
		}
		// HASH / KEY: ADD PARTITION PARTITIONS n
		if !op.IfNotExists && p.utilityWord(p.currentPos) == "PARTITIONS" {
			p.advance()
			if err := p.parsePartitionCount(op); err != nil {
				return nil, err
			}
			break
		}
		if err := p.parseAlterPartitionDefinitions(op); err != nil {
			return nil, err
		}
	case "DROP":
		// MariaDB: DROP PARTITION [IF EXISTS] names
		if mariadb && p.isType(models.TokenTypeIf) && p.utilityWord(p.currentPos+1) == "EXISTS" {
			p.advance()
			p.advance()
			op.IfExists = true
		}
		if err := p.parsePartitionNames(op, false); err != nil {
			return nil, err
		}
	case "REORGANIZE":
		if err := p.parsePartitionNames(op, false); err != nil {
			return nil, err
		}
		if !p.matchType(models.TokenTypeInto) {
			return nil, p.expectedError("INTO")
		}
		if err := p.parseAlterPartitionDefinitions(op); err != nil {
			return nil, err
		}
	case "TRUNCATE", "ANALYZE", "CHECK", "OPTIMIZE", "REBUILD", "REPAIR":
		if err := p.parsePartitionNames(op, true); err != nil {
			return nil, err
		}
	case "DISCARD", "IMPORT":
		if err := p.parsePartitionNames(op, true); err != nil {
			return nil, err
		}
		if p.utilityWord(p.currentPos) != "TABLESPACE" {
			return nil, p.expectedError("TABLESPACE")
		}
		p.advance()
	case "COALESCE":
		if err := p.parsePartitionCount(op); err != nil {
			return nil, err
		}
	case "EXCHANGE":
		name, err := p.parsePartitionName()
		if err != nil {
			return nil, err
		}
		op.PartitionNames = []*ast.Ident{name}
		if p.utilityWord(p.currentPos) != "WITH" || p.utilityWord(p.currentPos+1) != "TABLE" {
			return nil, p.expectedError("WITH TABLE")
		}
		p.advance()
		p.advance()
		tbl, quote, err := p.parseQualifiedNameQuoted()
		if err != nil {
			return nil, p.qualifiedNameError(err, "table name")
		}
		op.ExchangeTable = ast.ObjectName{Name: tbl, Quote: quote}
		if w := p.utilityWord(p.currentPos); (w == "WITH" || w == "WITHOUT") && p.utilityWord(p.currentPos+1) == "VALIDATION" {
			op.Validation = w
			p.advance()
			p.advance()
		}
	}
	return op, nil
}

// parsePartitionName parses one partition name.
func (p *Parser) parsePartitionName() (*ast.Ident, error) {
	if !p.isIdentifier() && !p.isNonReservedKeyword() {
		return nil, p.expectedError("partition name")
	}
	name := p.parseColumnName()
	if name == nil {
		return nil, p.expectedError("partition name")
	}
	return &ast.Ident{Name: name.Name, Quote: name.Quotes}, nil
}

// parsePartitionNames parses a partition name list, or ALL when allowAll.
// The list stops before ", ALGORITHM = ..." / ", LOCK = ...": table options
// that follow a partition action are further ALTER TABLE actions.
func (p *Parser) parsePartitionNames(op *ast.AlterTableOperation, allowAll bool) error {
	if allowAll && p.isType(models.TokenTypeAll) {
		p.advance()
		op.PartitionAll = true
		return nil
	}
	for {
		name, err := p.parsePartitionName()
		if err != nil {
			return err
		}
		op.PartitionNames = append(op.PartitionNames, name)
		if !p.isType(models.TokenTypeComma) || p.tableOptionFollowsComma() {
			return nil
		}
		p.advance()
	}
}

// tableOptionFollowsComma reports whether the current ',' is followed by a
// table option (name = value, or ALGORITHM / LOCK with "=" omitted).
func (p *Parser) tableOptionFollowsComma() bool {
	w := p.utilityWord(p.currentPos + 1)
	if w == "" {
		return false
	}
	if p.tokenIsEq(p.currentPos + 2) {
		return true
	}
	return (w == "ALGORITHM" || w == "LOCK") && p.utilityWord(p.currentPos+2) != ""
}

// parsePartitionCount parses the partition count of COALESCE PARTITION n and
// ADD PARTITION PARTITIONS n.
func (p *Parser) parsePartitionCount(op *ast.AlterTableOperation) error {
	if !p.isType(models.TokenTypeNumber) {
		return p.expectedError("partition count")
	}
	e, err := p.parsePrimaryExpression()
	if err != nil {
		return err
	}
	op.PartitionCount = e
	return nil
}

func (p *Parser) parseAlterPartitionDefinitions(op *ast.AlterTableOperation) error {
	if !p.matchType(models.TokenTypeLParen) {
		return p.expectedError("( before partition definitions")
	}
	for {
		def, err := p.parsePartitionDefinition()
		if err != nil {
			return err
		}
		want := ""
		if op.Partitioning != nil {
			switch op.Partitioning.Type {
			case "RANGE", "RANGE COLUMNS":
				want = "LESS THAN"
			case "LIST", "LIST COLUMNS":
				want = "IN"
			case "SYSTEM_TIME":
				if def.Type != "HISTORY" && def.Type != "CURRENT" {
					return p.expectedError("HISTORY or CURRENT")
				}
			default:
				return p.expectedError("partition count instead of definitions for HASH or KEY")
			}
		}
		if want != "" && def.Type != want {
			return p.expectedError("VALUES " + want)
		}
		if op.Partitioning == nil {
			switch def.Type {
			case "", "LESS THAN", "IN":
			case "HISTORY", "CURRENT":
				if p.dialect != string(keywords.DialectMariaDB) {
					return p.expectedError("VALUES LESS THAN or VALUES IN")
				}
			default:
				return p.expectedError("VALUES LESS THAN or VALUES IN")
			}
		}
		op.PartitionDefinitions = append(op.PartitionDefinitions, *def)
		if !p.matchType(models.TokenTypeComma) {
			break
		}
	}
	if !p.matchType(models.TokenTypeRParen) {
		return p.expectedError(") after partition definitions")
	}
	return nil
}
