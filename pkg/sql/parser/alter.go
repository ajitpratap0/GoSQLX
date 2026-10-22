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
)

// parseAlterStatement parses ALTER statements. ALTER TABLE, ROLE, POLICY and
// CONNECTOR are parsed into an *ast.AlterStatement; the other object kinds
// (INDEX, SESSION, SYSTEM, USER, DATABASE, WAREHOUSE, ...) are kept as
// written in an *ast.UtilityStatement.
func (p *Parser) parseAlterStatement() (ast.Statement, error) {
	var parse func(*ast.AlterStatement) (*ast.AlterStatement, error)
	var typ ast.AlterType
	// MariaDB ALTER [ONLINE] [IGNORE] TABLE.
	var modifiers []string
	if p.alterDialect(dialectMySQLFamily) {
		for {
			w := p.utilityWord(p.currentPos)
			if (w != "ONLINE" && w != "IGNORE") || !p.alterModifierFollows(p.currentPos+1) {
				break
			}
			modifiers = append(modifiers, w)
			p.advance()
		}
	}
	switch {
	case p.matchType(models.TokenTypeTable):
		typ, parse = ast.AlterTypeTable, p.parseAlterTableStatement
	case p.matchType(models.TokenTypeRole):
		typ, parse = ast.AlterTypeRole, p.parseAlterRoleStatement
	case p.matchType(models.TokenTypePolicy):
		typ, parse = ast.AlterTypePolicy, p.parseAlterPolicyStatement
	case p.matchType(models.TokenTypeConnector):
		typ, parse = ast.AlterTypeConnector, p.parseAlterConnectorStatement
	default:
		if word, ok := p.alterObjectWord(); ok {
			return p.parseAlterVerbatim(word)
		}
		return nil, p.expectedError("TABLE, ROLE, POLICY, or CONNECTOR")
	}
	if len(modifiers) > 0 && typ != ast.AlterTypeTable {
		return nil, p.expectedError("TABLE")
	}
	stmt := ast.GetAlterStatement()
	stmt.Type = typ
	stmt.Modifiers = modifiers
	out, err := parse(stmt)
	if err != nil {
		ast.PutAlterStatement(stmt)
		return nil, err
	}
	return out, nil
}

// alterModifierFollows reports whether the token at index i is TABLE or
// another ALTER modifier (ONLINE, IGNORE).
func (p *Parser) alterModifierFollows(i int) bool {
	if i < len(p.tokens) && p.tokens[i].Token.Type == models.TokenTypeTable {
		return true
	}
	w := p.utilityWord(i)
	return w == "ONLINE" || w == "IGNORE"
}

// parseAlterRoleStatement parses ALTER ROLE statements
func (p *Parser) parseAlterRoleStatement(stmt *ast.AlterStatement) (*ast.AlterStatement, error) {
	stmt.Name = p.parseIdentAsString()
	op := &ast.AlterRoleOperation{}

	switch {
	case p.matchType(models.TokenTypeRename):
		if !p.matchType(models.TokenTypeTo) {
			return nil, p.expectedError("TO")
		}
		op.Type = ast.RenameRole
		op.NewName = p.parseIdentAsString()

	case p.matchType(models.TokenTypeAdd):
		if !p.matchType(models.TokenTypeMember) {
			return nil, p.expectedError("MEMBER")
		}
		op.Type = ast.AddMember
		op.MemberName = p.parseIdentAsString()

	case p.matchType(models.TokenTypeDrop):
		if !p.matchType(models.TokenTypeMember) {
			return nil, p.expectedError("MEMBER")
		}
		op.Type = ast.DropMember
		op.MemberName = p.parseIdentAsString()

	case p.matchType(models.TokenTypeSet):
		op.Type = ast.SetConfig
		op.ConfigName = p.parseIdentAsString()
		if p.matchType(models.TokenTypeTo) || p.matchType(models.TokenTypeEq) {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			op.ConfigValue = expr
		}

	case p.matchType(models.TokenTypeReset):
		op.Type = ast.ResetConfig
		if p.matchType(models.TokenTypeAll) {
			op.ConfigName = "ALL"
		} else {
			op.ConfigName = p.parseIdentAsString()
		}

	case p.matchType(models.TokenTypeWith):
		op.Type = ast.WithOptions
		for {
			option, err := p.parseRoleOption()
			if err != nil {
				return nil, err
			}
			op.Options = append(op.Options, *option)
			if !p.matchType(models.TokenTypeComma) {
				break
			}
		}

	default:
		return nil, p.expectedError("RENAME, ADD MEMBER, DROP MEMBER, SET, RESET, or WITH")
	}

	stmt.Operation = op
	return stmt, nil
}

// parseAlterPolicyStatement parses ALTER POLICY statements
func (p *Parser) parseAlterPolicyStatement(stmt *ast.AlterStatement) (*ast.AlterStatement, error) {
	stmt.Name = p.parseIdentAsString()
	if !p.matchType(models.TokenTypeOn) {
		return nil, p.expectedError("ON")
	}
	p.parseIdentAsString() // table name

	op := &ast.AlterPolicyOperation{}

	if p.matchType(models.TokenTypeRename) {
		if !p.matchType(models.TokenTypeTo) {
			return nil, p.expectedError("TO")
		}
		op.Type = ast.RenamePolicy
		op.NewName = p.parseIdentAsString()
	} else {
		op.Type = ast.ModifyPolicy
		if p.matchType(models.TokenTypeTo) {
			for {
				op.To = append(op.To, p.parseIdentAsString())
				if !p.matchType(models.TokenTypeComma) {
					break
				}
			}
		}
		if p.matchType(models.TokenTypeUsing) {
			if !p.matchType(models.TokenTypeLParen) {
				return nil, p.expectedError("(")
			}
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			op.Using = expr
			if !p.matchType(models.TokenTypeRParen) {
				return nil, p.expectedError(")")
			}
		}
		if p.matchType(models.TokenTypeWith) && p.matchType(models.TokenTypeCheck) {
			if !p.matchType(models.TokenTypeLParen) {
				return nil, p.expectedError("(")
			}
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			op.WithCheck = expr
			if !p.matchType(models.TokenTypeRParen) {
				return nil, p.expectedError(")")
			}
		}
	}

	stmt.Operation = op
	return stmt, nil
}

// parseAlterConnectorStatement parses ALTER CONNECTOR statements
func (p *Parser) parseAlterConnectorStatement(stmt *ast.AlterStatement) (*ast.AlterStatement, error) {
	stmt.Name = p.parseIdentAsString()
	if !p.matchType(models.TokenTypeSet) {
		return nil, p.expectedError("SET")
	}

	op := &ast.AlterConnectorOperation{}

	switch {
	case p.matchType(models.TokenTypeDcproperties):
		if !p.matchType(models.TokenTypeLParen) {
			return nil, p.expectedError("(")
		}
		op.Properties = make(map[string]string)
		for {
			// DCPROPERTIES keys are arbitrary user-defined names that may
			// coincide with SQL keywords (e.g. "key", "url").  Accept any
			// word-like token as a bare identifier here.
			key := p.parseBareWordAsString()
			if !p.matchType(models.TokenTypeEq) {
				return nil, p.expectedError("=")
			}
			value := p.parseStringLiteral()
			op.Properties[key] = value

			if !p.matchType(models.TokenTypeComma) {
				break
			}
		}
		if !p.matchType(models.TokenTypeRParen) {
			return nil, p.expectedError(")")
		}

	case p.matchType(models.TokenTypeUrl):
		op.URL = p.parseStringLiteral()

	case p.matchType(models.TokenTypeOwner):
		owner := &ast.AlterConnectorOwner{}
		if p.matchType(models.TokenTypeUser) {
			owner.IsUser = true
		} else if p.matchType(models.TokenTypeRole) {
			owner.IsUser = false
		} else {
			return nil, p.expectedError("USER or ROLE")
		}
		owner.Name = p.parseIdentAsString()
		op.Owner = owner

	default:
		return nil, p.expectedError("DCPROPERTIES, URL, or OWNER")
	}

	stmt.Operation = op
	return stmt, nil
}

// parseRoleOption parses a role option
func (p *Parser) parseRoleOption() (*ast.RoleOption, error) {
	option := &ast.RoleOption{}

	switch {
	case p.isType(models.TokenTypeSuperuser):
		option.Name = "SUPERUSER"
		option.Type = ast.SuperUser
		option.Value = true
		p.advance()
	case p.isType(models.TokenTypeNosuperuser):
		option.Name = "SUPERUSER"
		option.Type = ast.SuperUser
		option.Value = false
		p.advance()

	case p.isType(models.TokenTypeCreateDB):
		option.Name = "CREATEDB"
		option.Type = ast.CreateDB
		option.Value = true
		p.advance()
	case p.isType(models.TokenTypeNocreatedb):
		option.Name = "CREATEDB"
		option.Type = ast.CreateDB
		option.Value = false
		p.advance()

	case p.isType(models.TokenTypeCreateRole):
		option.Name = "CREATEROLE"
		option.Type = ast.CreateRole
		option.Value = true
		p.advance()
	case p.isType(models.TokenTypeNocreaterole):
		option.Name = "CREATEROLE"
		option.Type = ast.CreateRole
		option.Value = false
		p.advance()

	case p.isType(models.TokenTypeLogin):
		option.Name = "LOGIN"
		option.Type = ast.Login
		option.Value = true
		p.advance()
	case p.isType(models.TokenTypeNologin):
		option.Name = "LOGIN"
		option.Type = ast.Login
		option.Value = false
		p.advance()

	case p.matchType(models.TokenTypePassword):
		option.Name = "PASSWORD"
		option.Type = ast.Password
		if p.matchType(models.TokenTypeNull) {
			option.Value = nil
		} else {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			option.Value = expr
		}

	case p.matchType(models.TokenTypeValid):
		option.Name = "VALID"
		option.Type = ast.ValidUntil
		if !p.matchType(models.TokenTypeUntil) {
			return nil, p.expectedError("UNTIL")
		}
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		option.Value = expr

	default:
		return nil, p.expectedError("role option")
	}

	return option, nil
}
