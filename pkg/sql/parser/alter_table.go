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

// alter_table.go parses ALTER TABLE: qualified names, IF EXISTS / ONLY /
// ON CLUSTER, comma-separated action lists and the per-dialect actions
// (ADD / DROP / ALTER / MODIFY / CHANGE / RENAME of columns, constraints and
// indexes, ClickHouse mutations, and the long tail of dialect-specific
// actions kept as a keyword phrase plus text as written).

package parser

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// parseAlterTableStatement parses the part of ALTER TABLE after the TABLE
// keyword: [IF EXISTS] [ONLY] name [ON CLUSTER c] action [, action ...].
func (p *Parser) parseAlterTableStatement(stmt *ast.AlterStatement) (*ast.AlterStatement, error) {
	if p.isType(models.TokenTypeIf) && p.peekToken().Token.Type == models.TokenTypeExists {
		p.advance() // IF
		p.advance() // EXISTS
		stmt.IfExists = true
	}
	if p.utilityWord(p.currentPos) == "ONLY" && p.alterDialect(dialectPostgres) {
		if next := p.utilityWord(p.currentPos + 1); !p.alterActionWord(next) {
			p.advance() // ONLY
			stmt.Only = true
		}
	}
	name, nameQuote, err := p.parseQualifiedNameQuoted()
	if err != nil {
		return nil, p.qualifiedNameError(err, "table name")
	}
	stmt.Name = name
	stmt.NameQuote = nameQuote
	if p.alterDialect(dialectClickHouse) && p.isType(models.TokenTypeOn) && p.utilityWord(p.currentPos+1) == "CLUSTER" {
		p.advance() // ON
		p.advance() // CLUSTER
		if p.currentPos >= len(p.tokens) || p.isType(models.TokenTypeEOF) {
			return nil, p.expectedError("cluster name")
		}
		stmt.OnCluster = p.renderTokenRange(p.currentPos, p.currentPos+1)
		p.advance()
	}

	for {
		op, err := p.parseAlterTableAction()
		if err != nil {
			return nil, err
		}
		stmt.Operations = append(stmt.Operations, op)
		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance()
	}
	stmt.Operation = stmt.Operations[0]
	// The statement ends at ';', EOF, or (as for every other statement, and
	// as T-SQL scripts without semicolons rely on) the next statement keyword.
	if !p.isType(models.TokenTypeSemicolon) && !p.isType(models.TokenTypeEOF) &&
		!p.isStatementStartingKeyword() && !p.statementMayEndAt(p.currentPos) {
		return nil, p.expectedError("end of ALTER TABLE action")
	}
	return stmt, nil
}

// parseAlterTableAction parses one ALTER TABLE action.
func (p *Parser) parseAlterTableAction() (*ast.AlterTableOperation, error) {
	op := &ast.AlterTableOperation{}
	word := p.utilityWord(p.currentPos)

	// SQL Server: WITH CHECK | WITH NOCHECK ADD CONSTRAINT ...
	if word == "WITH" && p.dialect == string(keywords.DialectSQLServer) {
		if w := p.utilityWord(p.currentPos + 1); (w == "CHECK" || w == "NOCHECK") && p.utilityWord(p.currentPos+2) == "ADD" {
			op.Modifier = "WITH " + w
			p.advance()
			p.advance()
			word = "ADD"
		}
	}

	// MySQL ORDER BY col [, col ...]. The tokenizer joins ORDER BY and the
	// parser splits it again, giving both tokens the span of the pair, which
	// utilityWord reads as a delimited identifier.
	if p.isType(models.TokenTypeOrder) && p.peekToken().Token.Type == models.TokenTypeBy && p.alterDialect(dialectMySQLFamily) {
		p.advance()
		p.advance()
		op.Type = ast.AlterTableOther
		op.Keyword = "ORDER BY"
		end, err := p.alterActionEnd(true)
		if err != nil {
			return nil, err
		}
		op.Text = p.renderTokenRange(p.currentPos, end)
		p.seek(end)
		return op, nil
	}

	switch word {
	case "ADD":
		p.advance()
		return p.parseAlterAdd(op)
	case "DROP":
		p.advance()
		return p.parseAlterDrop(op)
	case "ALTER":
		if !p.alterColumnFollows(1) {
			return p.parseAlterGeneric(op, "")
		}
		p.advance()
		return p.parseAlterColumn(op, ast.AlterColumn)
	case "MODIFY":
		if p.alterGenericAllowed("MODIFY", p.utilityWord(p.currentPos+1)) {
			return p.parseAlterGeneric(op, "")
		}
		if !p.alterDialect(dialectMySQLFamily, dialectOracle, dialectClickHouse, dialectSnowflake) {
			break
		}
		p.advance()
		return p.parseAlterColumn(op, ast.ModifyColumn)
	case "CHANGE":
		if !p.alterDialect(dialectMySQLFamily) {
			break
		}
		p.advance()
		return p.parseAlterChange(op)
	case "RENAME":
		p.advance()
		return p.parseAlterRename(op)
	case "UPDATE":
		if p.alterDialect(dialectClickHouse) {
			p.advance()
			return p.parseAlterMutation(op, ast.UpdateMutation)
		}
	case "DELETE":
		if p.alterDialect(dialectClickHouse) {
			p.advance()
			return p.parseAlterMutation(op, ast.DeleteMutation)
		}
	}
	if word != "" && p.alterGenericAllowed("", word) {
		return p.parseAlterGeneric(op, "")
	}
	return nil, p.expectedError("ADD, DROP, RENAME, or ALTER")
}

// alterColumnFollows reports whether the token at offset n from the current
// one is the COLUMN keyword or, for PostgreSQL / SQL Server, a column name
// rather than ALTER INDEX / CHECK / CONSTRAINT.
func (p *Parser) alterColumnFollows(n int) bool {
	switch p.utilityWord(p.currentPos + n) {
	case "INDEX", "CHECK", "CONSTRAINT":
		return !p.alterGenericAllowed("ALTER", p.utilityWord(p.currentPos+n))
	}
	return true
}

// parseAlterAdd parses the action after ADD.
func (p *Parser) parseAlterAdd(op *ast.AlterTableOperation) (*ast.AlterTableOperation, error) {
	word := p.utilityWord(p.currentPos)
	next := p.utilityWord(p.currentPos + 1)
	switch word {
	case "COLUMN":
		p.advance()
		return p.parseAlterAddColumns(op, false)
	case "IF":
		if next == "NOT" && p.utilityWord(p.currentPos+2) == "EXISTS" {
			op.NoColumnKeyword = true
			return p.parseAlterAddColumns(op, true)
		}
	case "CONSTRAINT", "PRIMARY", "FOREIGN", "CHECK":
		return p.parseAlterAddConstraint(op)
	case "UNIQUE":
		if p.alterDialectStrict(dialectMySQLFamily, dialectClickHouse) {
			return p.parseAlterAddIndex(op)
		}
		return p.parseAlterAddConstraint(op)
	case "INDEX", "KEY", "FULLTEXT", "SPATIAL":
		if p.alterDialect(dialectMySQLFamily, dialectClickHouse) {
			return p.parseAlterAddIndex(op)
		}
	}
	if p.alterGenericAllowed("ADD", word) {
		return p.parseAlterGeneric(op, "ADD")
	}
	op.NoColumnKeyword = true
	return p.parseAlterAddColumns(op, false)
}

// parseAlterAddColumns parses [IF NOT EXISTS] column definitions after
// ADD [COLUMN]. withIfNotExists is true when the current token is IF.
func (p *Parser) parseAlterAddColumns(op *ast.AlterTableOperation, withIfNotExists bool) (*ast.AlterTableOperation, error) {
	op.Type = ast.AddColumn
	if p.utilityWord(p.currentPos) == "IF" && p.utilityWord(p.currentPos+1) == "NOT" && p.utilityWord(p.currentPos+2) == "EXISTS" {
		p.advance()
		p.advance()
		p.advance()
		op.IfNotExists = true
	} else if withIfNotExists {
		return nil, p.expectedError("IF NOT EXISTS")
	}
	if err := p.parseAlterColumnDefs(op); err != nil {
		return nil, err
	}
	op.ColumnPosition = p.parseAlterColumnPosition()
	return op, nil
}

// parseAlterColumnDefs parses the column definition(s) of an ADD or MODIFY:
// one definition, an Oracle / MySQL parenthesized list, or (SQL Server) a
// comma-separated list that follows ADD without repeating it.
func (p *Parser) parseAlterColumnDefs(op *ast.AlterTableOperation) error {
	if p.isType(models.TokenTypeLParen) {
		p.advance()
		for {
			def, err := p.parseColumnDef()
			if err != nil {
				return err
			}
			op.ColumnDefs = append(op.ColumnDefs, def)
			if !p.isType(models.TokenTypeComma) {
				break
			}
			p.advance()
		}
		if !p.isType(models.TokenTypeRParen) {
			return p.expectedError(")")
		}
		p.advance()
		op.Parenthesized = true
		op.ColumnDef = op.ColumnDefs[0]
		return nil
	}
	def, err := p.parseColumnDef()
	if err != nil {
		return err
	}
	op.ColumnDef = def
	for p.dialect == string(keywords.DialectSQLServer) && p.isType(models.TokenTypeComma) && !p.alterActionStartsAt(p.currentPos+1) {
		p.advance()
		more, err := p.parseColumnDef()
		if err != nil {
			return err
		}
		if op.ColumnDefs == nil {
			op.ColumnDefs = []*ast.ColumnDef{def}
		}
		op.ColumnDefs = append(op.ColumnDefs, more)
	}
	return nil
}

// parseAlterColumnPosition parses MySQL / MariaDB / ClickHouse FIRST and
// AFTER column. It returns nil when neither follows.
func (p *Parser) parseAlterColumnPosition() *ast.ColumnPosition {
	if !p.alterDialect(dialectMySQLFamily, dialectClickHouse) {
		return nil
	}
	switch p.utilityWord(p.currentPos) {
	case "FIRST":
		p.advance()
		return &ast.ColumnPosition{First: true}
	case "AFTER":
		saved, savedTok := p.currentPos, p.currentToken
		p.advance()
		if name := p.parseColumnName(); name != nil {
			return &ast.ColumnPosition{After: &ast.Ident{Name: name.Name, Quote: name.Quotes}}
		}
		p.currentPos, p.currentToken = saved, savedTok
	}
	return nil
}

// parseAlterAddConstraint parses ADD [CONSTRAINT [name]] PRIMARY KEY | UNIQUE
// | FOREIGN KEY | CHECK, with the SQL Server CLUSTERED / NONCLUSTERED word and
// a trailing NOT VALID / DEFERRABLE / ... phrase.
func (p *Parser) parseAlterAddConstraint(op *ast.AlterTableOperation) (*ast.AlterTableOperation, error) {
	op.Type = ast.AddConstraint
	op.BareConstraint = !p.isType(models.TokenTypeConstraint)
	name := ""
	var nameQuote ast.NameQuote
	if !op.BareConstraint {
		p.advance() // CONSTRAINT
		if p.isIdentifier() && !p.isAnyType(models.TokenTypePrimary, models.TokenTypeForeign, models.TokenTypeUnique, models.TokenTypeCheck) {
			name = p.currentToken.Token.Value
			nameQuote = p.currentNameQuote()
			p.advance()
		}
	}
	var c *ast.TableConstraint
	if i := p.clusteringWordAt(); i > 0 {
		op.Clustering = p.utilityWord(i)
		c = &ast.TableConstraint{Name: name, NameQuote: nameQuote}
		if p.isType(models.TokenTypePrimary) {
			c.Type = "PRIMARY KEY"
			p.advance() // PRIMARY
		} else {
			c.Type = "UNIQUE"
		}
		p.advance() // KEY or UNIQUE
		p.advance() // CLUSTERED / NONCLUSTERED
		cols, colQuotes, err := p.parseConstraintColumnListQuoted()
		if err != nil {
			return nil, err
		}
		c.Columns = cols
		c.ColumnQuotes = colQuotes
	} else {
		var err error
		c, err = p.parseTableConstraint()
		if err != nil {
			return nil, err
		}
		if name != "" {
			c.Name = name
			c.NameQuote = nameQuote
		}
	}
	op.Constraint = c
	if p.alterConstraintSuffixStarts() {
		end, err := p.alterActionEnd(false)
		if err != nil {
			return nil, err
		}
		op.ConstraintSuffix = p.renderTokenRange(p.currentPos, end)
		p.seek(end)
	}
	return op, nil
}

// clusteringWordAt returns the token index of a CLUSTERED / NONCLUSTERED
// word that follows PRIMARY KEY or UNIQUE at the current position (SQL
// Server), or 0.
func (p *Parser) clusteringWordAt() int {
	i := p.currentPos
	switch {
	case p.isType(models.TokenTypePrimary):
		i += 2
	case p.isType(models.TokenTypeUnique):
		i++
	default:
		return 0
	}
	if w := p.utilityWord(i); w == "CLUSTERED" || w == "NONCLUSTERED" {
		return i
	}
	return 0
}

// alterConstraintSuffixStarts reports whether the current token starts a
// constraint attribute that follows a table constraint.
func (p *Parser) alterConstraintSuffixStarts() bool {
	switch p.utilityWord(p.currentPos) {
	case "NOT", "DEFERRABLE", "INITIALLY", "ENFORCED", "NOENFORCED", "ENABLE", "DISABLE", "VALIDATE",
		"NOVALIDATE", "RELY", "NORELY", "USING", "WITH", "ON", "INVISIBLE", "VISIBLE", "COMMENT":
		return true
	}
	return p.isType(models.TokenTypeOn) || p.isType(models.TokenTypeUsing) || p.isType(models.TokenTypeNot)
}

// parseAlterAddIndex parses ADD [UNIQUE | FULLTEXT | SPATIAL] [INDEX | KEY]
// [IF NOT EXISTS] [name] followed by the index definition as written.
func (p *Parser) parseAlterAddIndex(op *ast.AlterTableOperation) (*ast.AlterTableOperation, error) {
	op.Type = ast.AddIndex
	switch w := p.utilityWord(p.currentPos); w {
	case "UNIQUE", "FULLTEXT", "SPATIAL":
		op.IndexKind = w
		p.advance()
	}
	switch w := p.utilityWord(p.currentPos); w {
	case "INDEX", "KEY":
		op.IndexKeyword = w
		p.advance()
	}
	if p.utilityWord(p.currentPos) == "IF" && p.utilityWord(p.currentPos+1) == "NOT" && p.utilityWord(p.currentPos+2) == "EXISTS" {
		p.advance()
		p.advance()
		p.advance()
		op.IfNotExists = true
	}
	if !p.isType(models.TokenTypeLParen) && !p.isType(models.TokenTypeUsing) {
		if name := p.parseColumnName(); name != nil {
			op.IndexName = name.Name
		}
	}
	return p.parseAlterTail(op)
}

// parseAlterTail stores the rest of the action, as written, in op.Text.
func (p *Parser) parseAlterTail(op *ast.AlterTableOperation) (*ast.AlterTableOperation, error) {
	end, err := p.alterActionEnd(false)
	if err != nil {
		return nil, err
	}
	op.Text = p.renderTokenRange(p.currentPos, end)
	p.seek(end)
	return op, nil
}

// parseAlterDrop parses the action after DROP.
func (p *Parser) parseAlterDrop(op *ast.AlterTableOperation) (*ast.AlterTableOperation, error) {
	word := p.utilityWord(p.currentPos)
	switch word {
	case "COLUMN":
		p.advance()
		return p.parseAlterDropColumn(op)
	case "CONSTRAINT":
		p.advance()
		op.Type = ast.DropConstraint
		return p.parseAlterDropNames(op, "constraint name", func(i *ast.Ident) { op.ConstraintName = i })
	case "PRIMARY":
		if p.utilityWord(p.currentPos+1) == "KEY" {
			p.advance()
			p.advance()
			op.Type = ast.DropConstraint
			op.ConstraintKind = "PRIMARY KEY"
			return op, nil
		}
	case "FOREIGN":
		if p.utilityWord(p.currentPos+1) == "KEY" && p.alterDialect(dialectMySQLFamily) {
			p.advance()
			p.advance()
			op.Type = ast.DropConstraint
			op.ConstraintKind = "FOREIGN KEY"
			return p.parseAlterDropNames(op, "constraint name", func(i *ast.Ident) { op.ConstraintName = i })
		}
	case "CHECK":
		if p.alterDialect(dialectMySQLFamily) {
			p.advance()
			op.Type = ast.DropConstraint
			op.ConstraintKind = "CHECK"
			return p.parseAlterDropNames(op, "constraint name", func(i *ast.Ident) { op.ConstraintName = i })
		}
	case "INDEX", "KEY":
		if p.alterDialect(dialectMySQLFamily, dialectClickHouse) {
			p.advance()
			op.Type = ast.DropIndex
			op.IndexKeyword = word
			if p.utilityWord(p.currentPos) == "IF" && p.utilityWord(p.currentPos+1) == "EXISTS" {
				p.advance()
				p.advance()
				op.IfExists = true
			}
			name := p.parseColumnName()
			if name == nil {
				return nil, p.expectedError("index name")
			}
			op.IndexName = name.Name
			return op, nil
		}
	}
	if p.alterGenericAllowed("DROP", word) {
		return p.parseAlterGeneric(op, "DROP")
	}
	// DROP name / DROP IF EXISTS name: a column without the COLUMN keyword.
	op.NoColumnKeyword = true
	return p.parseAlterDropColumn(op)
}

// parseAlterDropColumn parses [IF EXISTS] name [, name ...] [CASCADE | RESTRICT]
// after DROP [COLUMN].
func (p *Parser) parseAlterDropColumn(op *ast.AlterTableOperation) (*ast.AlterTableOperation, error) {
	op.Type = ast.DropColumn
	return p.parseAlterDropNames(op, "column name", func(i *ast.Ident) { op.ColumnName = i })
}

// parseAlterDropNames parses [IF EXISTS] name [, name ...] [CASCADE |
// RESTRICT]. The first name is stored through set; the further names of a
// SQL Server list go to op.ExtraNames.
func (p *Parser) parseAlterDropNames(op *ast.AlterTableOperation, what string, set func(*ast.Ident)) (*ast.AlterTableOperation, error) {
	if p.isType(models.TokenTypeIf) && p.peekToken().Token.Type == models.TokenTypeExists {
		p.advance()
		p.advance()
		op.IfExists = true
	}
	name := p.parseColumnName()
	if name == nil {
		return nil, p.expectedError(what)
	}
	set(&ast.Ident{Name: name.Name, Quote: name.Quotes})
	for p.dialect == string(keywords.DialectSQLServer) && p.isType(models.TokenTypeComma) && !p.alterActionStartsAt(p.currentPos+1) {
		p.advance()
		more := p.parseColumnName()
		if more == nil {
			return nil, p.expectedError(what)
		}
		op.ExtraNames = append(op.ExtraNames, &ast.Ident{Name: more.Name, Quote: more.Quotes})
	}
	if p.matchType(models.TokenTypeCascade) {
		op.CascadeDrops = true
	} else if p.matchType(models.TokenTypeRestrict) {
		op.Restrict = true
	}
	return op, nil
}

// parseAlterRename parses the action after RENAME.
func (p *Parser) parseAlterRename(op *ast.AlterTableOperation) (*ast.AlterTableOperation, error) {
	word := p.utilityWord(p.currentPos)
	switch {
	case p.isType(models.TokenTypeTo) || (word == "AS" && p.alterDialect(dialectMySQLFamily)):
		p.advance()
		return p.parseAlterRenameTable(op)
	case word == "COLUMN":
		p.advance()
		return p.parseAlterRenameColumn(op)
	case word == "CONSTRAINT":
		p.advance()
		op.Type = ast.RenameConstraint
		old := p.parseColumnName()
		if old == nil {
			return nil, p.expectedError("constraint name")
		}
		if !p.matchType(models.TokenTypeTo) {
			return nil, p.expectedError("TO")
		}
		newName := p.parseColumnName()
		if newName == nil {
			return nil, p.expectedError("new constraint name")
		}
		op.OldName = &ast.Ident{Name: old.Name, Quote: old.Quotes}
		op.NewName = &ast.Ident{Name: newName.Name, Quote: newName.Quotes}
		return op, nil
	case p.alterGenericAllowed("RENAME", word):
		return p.parseAlterGeneric(op, "RENAME")
	case p.isIdentifier() && p.peekToken().Token.Type == models.TokenTypeTo:
		op.NoColumnKeyword = true
		return p.parseAlterRenameColumn(op)
	case p.dialect == string(keywords.DialectMySQL) || p.dialect == string(keywords.DialectMariaDB):
		// RENAME new_name
		return p.parseAlterRenameTable(op)
	}
	return nil, p.expectedError("TO or COLUMN")
}

// parseAlterRenameTable parses the new name of RENAME [TO] name.
func (p *Parser) parseAlterRenameTable(op *ast.AlterTableOperation) (*ast.AlterTableOperation, error) {
	name, nameQuote, err := p.parseQualifiedNameQuoted()
	if err != nil {
		return nil, p.qualifiedNameError(err, "table name")
	}
	op.Type = ast.RenameTable
	op.NewTableName = ast.ObjectName{Name: name, Quote: nameQuote}
	return op, nil
}

// parseAlterRenameColumn parses old TO new after RENAME [COLUMN].
func (p *Parser) parseAlterRenameColumn(op *ast.AlterTableOperation) (*ast.AlterTableOperation, error) {
	op.Type = ast.RenameColumn
	if p.isType(models.TokenTypeIf) && p.peekToken().Token.Type == models.TokenTypeExists {
		p.advance()
		p.advance()
		op.IfExists = true
	}
	old := p.parseColumnName()
	if old == nil {
		return nil, p.expectedError("column name")
	}
	op.ColumnName = &ast.Ident{Name: old.Name, Quote: old.Quotes}
	if !p.matchType(models.TokenTypeTo) {
		return nil, p.expectedError("TO")
	}
	newName := p.parseColumnName()
	if newName == nil {
		return nil, p.expectedError("new column name")
	}
	op.NewColumnName = &ast.Ident{Name: newName.Name, Quote: newName.Quotes}
	return op, nil
}

// parseAlterColumn parses ALTER [COLUMN] and MODIFY [COLUMN] after the
// leading word (typ is ast.AlterColumn or ast.ModifyColumn).
func (p *Parser) parseAlterColumn(op *ast.AlterTableOperation, typ ast.AlterTableOpType) (*ast.AlterTableOperation, error) {
	op.Type = typ
	if p.utilityWord(p.currentPos) == "COLUMN" {
		p.advance()
	} else {
		op.NoColumnKeyword = true
	}
	if typ == ast.ModifyColumn && p.isType(models.TokenTypeLParen) {
		if err := p.parseAlterColumnDefs(op); err != nil {
			return nil, err
		}
		return op, nil
	}
	start, startTok := p.currentPos, p.currentToken
	name := p.parseColumnName()
	if name == nil {
		return nil, p.expectedError("column name")
	}
	subActions := typ == ast.AlterColumn || p.alterDialect(dialectSnowflake, dialectClickHouse)
	if subActions {
		ok, err := p.parseAlterColumnSub(op)
		if err != nil {
			return nil, err
		}
		if ok {
			op.ColumnName = &ast.Ident{Name: name.Name, Quote: name.Quotes}
			return op, nil
		}
	}
	// A full column definition: ALTER COLUMN c INT NOT NULL, MODIFY c INT.
	p.currentPos, p.currentToken = start, startTok
	def, err := p.parseColumnDef()
	if err != nil {
		return nil, err
	}
	op.ColumnDef = def
	op.ColumnName = &ast.Ident{Name: def.Name, Quote: def.NameQuote}
	op.ColumnPosition = p.parseAlterColumnPosition()
	return op, nil
}

// parseAlterColumnSub parses the sub-action that follows ALTER COLUMN name:
// SET / DROP DEFAULT, SET / DROP NOT NULL, [SET DATA] TYPE t [USING e] and
// the other keyword-led forms. ok is false (nothing consumed) when the next
// token starts a column definition instead.
func (p *Parser) parseAlterColumnSub(op *ast.AlterTableOperation) (bool, error) {
	w1 := p.utilityWord(p.currentPos)
	w2 := p.utilityWord(p.currentPos + 1)
	w3 := p.utilityWord(p.currentPos + 2)
	var sub ast.AlterColumnOperation
	switch {
	case w1 == "SET" && w2 == "DEFAULT", w1 == "DROP" && w2 == "DEFAULT":
		sub = ast.AlterColumnDropDefault
		if w1 == "SET" {
			sub = ast.AlterColumnSetDefault
		}
		p.advance()
		p.advance()
		if sub == ast.AlterColumnSetDefault {
			expr, err := p.parseExpression()
			if err != nil {
				return false, err
			}
			op.DefaultValue = expr
		}
	case w2 == "NOT" && w3 == "NULL" && (w1 == "SET" || w1 == "DROP"):
		sub = ast.AlterColumnSetNotNull
		if w1 == "DROP" {
			sub = ast.AlterColumnDropNotNull
		}
		p.advance()
		p.advance()
		p.advance()
	case w1 == "TYPE" || (w1 == "SET" && w2 == "DATA" && w3 == "TYPE"):
		sub = ast.AlterColumnSetDataType
		op.Keyword = "TYPE"
		if w1 == "SET" {
			op.Keyword = "SET DATA TYPE"
			p.advance()
			p.advance()
		}
		p.advance()
		typeName, err := p.parseDataType()
		if err != nil {
			return false, err
		}
		op.DataType = typeName
		if p.isType(models.TokenTypeUsing) {
			p.advance()
			expr, err := p.parseExpression()
			if err != nil {
				return false, err
			}
			op.Using = expr
		}
	case w1 == "SET", w1 == "DROP", w1 == "ADD", w1 == "RESTART", w1 == "RESET", w1 == "UNSET", w1 == "COMMENT":
		sub = ast.AlterColumnOther
		var kw []string
		for len(kw) == 0 || alterKeywordWords[p.utilityWord(p.currentPos)] {
			w := p.utilityWord(p.currentPos)
			if w == "" || p.tokenIsEq(p.currentPos+1) {
				break
			}
			kw = append(kw, w)
			p.advance()
		}
		op.Keyword = strings.Join(kw, " ")
		end, err := p.alterActionEnd(false)
		if err != nil {
			return false, err
		}
		op.Text = p.renderTokenRange(p.currentPos, end)
		p.seek(end)
	default:
		return false, nil
	}
	op.AlterColumnOp = &sub
	return true, nil
}

// parseAlterChange parses MySQL CHANGE [COLUMN] old new_definition [FIRST |
// AFTER col].
func (p *Parser) parseAlterChange(op *ast.AlterTableOperation) (*ast.AlterTableOperation, error) {
	op.Type = ast.ChangeColumn
	if p.utilityWord(p.currentPos) == "COLUMN" {
		p.advance()
	} else {
		op.NoColumnKeyword = true
	}
	old := p.parseColumnName()
	if old == nil {
		return nil, p.expectedError("column name")
	}
	op.ColumnName = &ast.Ident{Name: old.Name, Quote: old.Quotes}
	def, err := p.parseColumnDef()
	if err != nil {
		return nil, err
	}
	op.ColumnDef = def
	op.ColumnPosition = p.parseAlterColumnPosition()
	return op, nil
}

// parseAlterMutation parses the ClickHouse mutations after UPDATE / DELETE:
//
//	UPDATE col = expr [, ...] [IN PARTITION p] WHERE cond
//	DELETE [IN PARTITION p] WHERE cond
func (p *Parser) parseAlterMutation(op *ast.AlterTableOperation, typ ast.AlterTableOpType) (*ast.AlterTableOperation, error) {
	op.Type = typ
	if typ == ast.UpdateMutation {
		// The assignments end at IN PARTITION or WHERE; IN would otherwise be
		// read as the operator of the last value. Parse them against the
		// tokens up to that point.
		stop := p.mutationClauseStart()
		full := p.tokens
		if stop > p.currentPos {
			p.tokens = full[:stop]
		}
		err := p.parseMutationAssignments(op)
		p.tokens = full
		p.seek(p.currentPos)
		if err != nil {
			return nil, err
		}
	}
	if p.isType(models.TokenTypeIn) && p.utilityWord(p.currentPos+1) == "PARTITION" {
		p.advance()
		p.advance()
		part, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		op.PartitionExpr = part
	}
	if !p.isType(models.TokenTypeWhere) {
		return nil, p.expectedError("WHERE")
	}
	p.advance()
	where, err := p.parseExpression()
	if err != nil {
		return nil, err
	}
	op.Where = where
	return op, nil
}

// parseAlterGeneric parses an AlterTableOther action: the keyword phrase
// (prefix, already consumed, plus the leading keyword words) and the text
// that follows it up to the end of the action, as written.
func (p *Parser) parseAlterGeneric(op *ast.AlterTableOperation, prefix string) (*ast.AlterTableOperation, error) {
	op.Type = ast.AlterTableOther
	var kw []string
	if prefix != "" {
		kw = append(kw, prefix)
	}
	for {
		w := p.utilityWord(p.currentPos)
		if w == "" || p.tokenIsEq(p.currentPos+1) {
			break
		}
		if len(kw) > 0 && !alterKeywordWords[w] {
			break
		}
		kw = append(kw, w)
		p.advance()
	}
	commaInside := false
	switch {
	case len(kw) > 0 && p.dialect == string(keywords.DialectSnowflake) && (kw[0] == "SET" || kw[0] == "UNSET"):
		commaInside = true
	case p.dialect == string(keywords.DialectClickHouse) && len(kw) > 1 && (kw[1] == "SETTING" || kw[1] == "SETTINGS"):
		commaInside = true
	case p.alterDialectStrict(dialectMySQLFamily) && alterKeywordHas(kw, "PARTITION"):
		// DROP PARTITION p1, p2: the comma lists partitions; MySQL does not
		// allow other actions next to a partition operation.
		commaInside = true
	}
	end, err := p.alterActionEnd(commaInside)
	if err != nil {
		return nil, err
	}
	op.Keyword = strings.Join(kw, " ")
	op.Text = p.renderTokenRange(p.currentPos, end)
	p.seek(end)
	if op.Keyword == "" && op.Text == "" {
		return nil, p.expectedError("ALTER TABLE action")
	}
	return op, nil
}

// alterKeywordHas reports whether kw contains word.
func alterKeywordHas(kw []string, word string) bool {
	for _, k := range kw {
		if k == word {
			return true
		}
	}
	return false
}

// tokenIsEq reports whether the token at index i is "=".
func (p *Parser) tokenIsEq(i int) bool {
	return i >= 0 && i < len(p.tokens) && p.tokens[i].Token.Type == models.TokenTypeEq
}

// alterActionEnd returns the index of the token that ends the action starting
// at the current token: the next top-level ',' (unless commaInside), a ';'
// or the end of input.
func (p *Parser) alterActionEnd(commaInside bool) (int, error) {
	depth := 0
	i := p.currentPos
	// T-SQL scripts need no ';': the action also ends where the next
	// statement starts (ALTER TABLE t NOCHECK CONSTRAINT ALL ALTER TABLE u ...).
	// The action's keyword was consumed, so the statement began before it.
	tsql := p.IsSQLServer()
	for ; i < len(p.tokens); i++ {
		if tsql && depth == 0 && i > 0 {
			if _, ok := p.batchSeparatorEnd(i); ok {
				return i, nil
			}
			if p.startsNewDDLStatement(i, p.currentPos-1, false) {
				p.markImplicitEnd(i)
				return i, nil
			}
		}
		switch p.tokens[i].Token.Type {
		case models.TokenTypeLParen:
			depth++
		case models.TokenTypeRParen:
			depth--
			if depth < 0 {
				p.seek(i)
				return 0, p.expectedError("end of ALTER TABLE action")
			}
		case models.TokenTypeComma:
			if depth == 0 && !commaInside {
				return i, nil
			}
		case models.TokenTypeSemicolon:
			if depth == 0 {
				return i, nil
			}
		case models.TokenTypeEOF:
			if depth != 0 {
				p.seek(i)
				return 0, p.expectedError(")")
			}
			return i, nil
		}
	}
	if depth != 0 {
		p.seek(i)
		return 0, p.expectedError(")")
	}
	return i, nil
}

// alterActionStartsAt reports whether the token at index i starts an ALTER
// TABLE action rather than a further item of a column / name list.
func (p *Parser) alterActionStartsAt(i int) bool {
	w := p.utilityWord(i)
	return w != "" && (p.alterActionWord(w) || p.alterGenericAllowed("", w))
}

// alterActionWord reports whether w is a word that begins an ALTER TABLE
// action in every dialect.
func (p *Parser) alterActionWord(w string) bool {
	switch w {
	case "ADD", "DROP", "ALTER", "MODIFY", "CHANGE", "RENAME":
		return true
	}
	return false
}

// mutationClauseStart returns the index of the IN PARTITION or WHERE that
// ends the assignments of a ClickHouse UPDATE mutation, or 0 when the action
// has neither.
func (p *Parser) mutationClauseStart() int {
	depth := 0
	for i := p.currentPos; i < len(p.tokens); i++ {
		switch p.tokens[i].Token.Type {
		case models.TokenTypeLParen:
			depth++
		case models.TokenTypeRParen:
			depth--
		case models.TokenTypeSemicolon:
			if depth == 0 {
				return 0
			}
		case models.TokenTypeWhere:
			if depth == 0 {
				return i
			}
		case models.TokenTypeIn:
			if depth == 0 && p.utilityWord(i+1) == "PARTITION" {
				return i
			}
		}
	}
	return 0
}

// parseMutationAssignments parses col = expr [, col = expr ...].
func (p *Parser) parseMutationAssignments(op *ast.AlterTableOperation) error {
	for {
		col := p.parseColumnName()
		if col == nil {
			return p.expectedError("column name")
		}
		if !p.matchType(models.TokenTypeEq) {
			return p.expectedError("=")
		}
		val, err := p.parseExpression()
		if err != nil {
			return err
		}
		op.Assignments = append(op.Assignments, ast.UpdateExpression{
			Column: &ast.Identifier{Name: col.Name, Pos: col.Pos},
			Value:  val,
		})
		if !p.isType(models.TokenTypeComma) {
			return nil
		}
		p.advance()
	}
}
