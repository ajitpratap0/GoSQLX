package parser

import (
	"github.com/ajitpratapsingh/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratapsingh/GoSQLX/pkg/sql/token"
)

// parseAlterStatement parses ALTER statements
func (p *Parser) parseAlterStatement() (*ast.AlterStatement, error) {
	stmt := &ast.AlterStatement{}

	// Parse the type of object being altered
	switch {
	case p.matchToken(token.TABLE):
		stmt.Type = ast.AlterTypeTable
		return p.parseAlterTableStatement(stmt)
	case p.matchToken(token.ROLE):
		stmt.Type = ast.AlterTypeRole
		return p.parseAlterRoleStatement(stmt)
	case p.matchToken(token.POLICY):
		stmt.Type = ast.AlterTypePolicy
		return p.parseAlterPolicyStatement(stmt)
	case p.matchToken(token.CONNECTOR):
		stmt.Type = ast.AlterTypeConnector
		return p.parseAlterConnectorStatement(stmt)
	default:
		return nil, p.expectedError("TABLE, ROLE, POLICY, or CONNECTOR")
	}
}

// parseAlterTableStatement parses ALTER TABLE statements
func (p *Parser) parseAlterTableStatement(stmt *ast.AlterStatement) (*ast.AlterStatement, error) {
	stmt.Name = p.parseIdentAsString()
	op := &ast.AlterTableOperation{}

	switch {
	case p.matchToken(token.ADD):
		if p.matchToken(token.COLUMN) {
			op.Type = ast.AddColumn
			colDef, err := p.parseColumnDef()
			if err != nil {
				return nil, err
			}
			op.ColumnDef = colDef
		} else if p.matchToken(token.CONSTRAINT) {
			op.Type = ast.AddConstraint
			constraint, err := p.parseTableConstraint()
			if err != nil {
				return nil, err
			}
			op.Constraint = constraint
		} else {
			return nil, p.expectedError("COLUMN or CONSTRAINT")
		}

	case p.matchToken(token.DROP):
		if p.matchToken(token.COLUMN) {
			op.Type = ast.DropColumn
			// Convert ast.Identifier to ast.Ident
			ident := p.parseIdent()
			op.ColumnName = &ast.Ident{Name: ident.Name}
			if p.matchToken(token.CASCADE) {
				op.CascadeDrops = true
			}
		} else if p.matchToken(token.CONSTRAINT) {
			op.Type = ast.DropConstraint
			// Convert ast.Identifier to ast.Ident
			ident := p.parseIdent()
			op.ConstraintName = &ast.Ident{Name: ident.Name}
			if p.matchToken(token.CASCADE) {
				op.CascadeDrops = true
			}
		} else {
			return nil, p.expectedError("COLUMN or CONSTRAINT")
		}

	case p.matchToken(token.RENAME):
		if p.matchToken(token.TO) {
			op.Type = ast.RenameTable
			op.NewTableName = p.parseObjectName()
		} else if p.matchToken(token.COLUMN) {
			op.Type = ast.RenameColumn
			// Convert ast.Identifier to ast.Ident
			ident := p.parseIdent()
			op.ColumnName = &ast.Ident{Name: ident.Name}
			if !p.matchToken(token.TO) {
				return nil, p.expectedError("TO")
			}
			// Convert ast.Identifier to ast.Ident
			newIdent := p.parseIdent()
			op.NewColumnName = &ast.Ident{Name: newIdent.Name}
		} else {
			return nil, p.expectedError("TO or COLUMN")
		}

	case p.matchToken(token.ALTER):
		if !p.matchToken(token.COLUMN) {
			return nil, p.expectedError("COLUMN")
		}
		op.Type = ast.AlterColumn
		// Convert ast.Identifier to ast.Ident
		ident := p.parseIdent()
		op.ColumnName = &ast.Ident{Name: ident.Name}
		colDef, err := p.parseColumnDef()
		if err != nil {
			return nil, err
		}
		op.ColumnDef = colDef

	default:
		return nil, p.expectedError("ADD, DROP, RENAME, or ALTER")
	}

	stmt.Operation = op
	return stmt, nil
}

// parseAlterRoleStatement parses ALTER ROLE statements
func (p *Parser) parseAlterRoleStatement(stmt *ast.AlterStatement) (*ast.AlterStatement, error) {
	stmt.Name = p.parseIdentAsString()
	op := &ast.AlterRoleOperation{}

	switch {
	case p.matchToken(token.RENAME):
		if !p.matchToken(token.TO) {
			return nil, p.expectedError("TO")
		}
		op.Type = ast.RenameRole
		op.NewName = p.parseIdentAsString()

	case p.matchToken(token.ADD):
		if !p.matchToken(token.MEMBER) {
			return nil, p.expectedError("MEMBER")
		}
		op.Type = ast.AddMember
		op.MemberName = p.parseIdentAsString()

	case p.matchToken(token.DROP):
		if !p.matchToken(token.MEMBER) {
			return nil, p.expectedError("MEMBER")
		}
		op.Type = ast.DropMember
		op.MemberName = p.parseIdentAsString()

	case p.matchToken(token.SET):
		op.Type = ast.SetConfig
		op.ConfigName = p.parseIdentAsString()
		if p.matchToken(token.TO) || p.matchToken(token.EQUAL) {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			op.ConfigValue = expr
		}

	case p.matchToken(token.RESET):
		op.Type = ast.ResetConfig
		if p.matchToken(token.ALL) {
			op.ConfigName = "ALL"
		} else {
			op.ConfigName = p.parseIdentAsString()
		}

	case p.matchToken(token.WITH):
		op.Type = ast.WithOptions
		for {
			option, err := p.parseRoleOption()
			if err != nil {
				return nil, err
			}
			op.Options = append(op.Options, *option)
			if !p.matchToken(token.COMMA) {
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
	if !p.matchToken(token.ON) {
		return nil, p.expectedError("ON")
	}
	p.parseIdentAsString() // table name

	op := &ast.AlterPolicyOperation{}

	if p.matchToken(token.RENAME) {
		if !p.matchToken(token.TO) {
			return nil, p.expectedError("TO")
		}
		op.Type = ast.RenamePolicy
		op.NewName = p.parseIdentAsString()
	} else {
		op.Type = ast.ModifyPolicy
		if p.matchToken(token.TO) {
			for {
				op.To = append(op.To, p.parseIdentAsString())
				if !p.matchToken(token.COMMA) {
					break
				}
			}
		}
		if p.matchToken(token.USING) {
			if !p.matchToken(token.LPAREN) {
				return nil, p.expectedError("(")
			}
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			op.Using = expr
			if !p.matchToken(token.RPAREN) {
				return nil, p.expectedError(")")
			}
		}
		if p.matchToken(token.WITH) && p.matchToken(token.CHECK) {
			if !p.matchToken(token.LPAREN) {
				return nil, p.expectedError("(")
			}
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			op.WithCheck = expr
			if !p.matchToken(token.RPAREN) {
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
	if !p.matchToken(token.SET) {
		return nil, p.expectedError("SET")
	}

	op := &ast.AlterConnectorOperation{}

	switch {
	case p.matchToken(token.DCPROPERTIES):
		if !p.matchToken(token.LPAREN) {
			return nil, p.expectedError("(")
		}
		op.Properties = make(map[string]string)
		for {
			key := p.parseIdentAsString()
			if !p.matchToken(token.EQUAL) {
				return nil, p.expectedError("=")
			}
			value := p.parseStringLiteral()
			op.Properties[key] = value

			if !p.matchToken(token.COMMA) {
				break
			}
		}
		if !p.matchToken(token.RPAREN) {
			return nil, p.expectedError(")")
		}

	case p.matchToken(token.URL):
		op.URL = p.parseStringLiteral()

	case p.matchToken(token.OWNER):
		owner := &ast.AlterConnectorOwner{}
		if p.matchToken(token.USER) {
			owner.IsUser = true
		} else if p.matchToken(token.ROLE) {
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
	case p.matchToken(token.SUPERUSER), p.matchToken(token.NOSUPERUSER):
		option.Name = "SUPERUSER"
		option.Type = ast.SuperUser
		option.Value = p.currentToken.Type == token.SUPERUSER

	case p.matchToken(token.CREATEDB), p.matchToken(token.NOCREATEDB):
		option.Name = "CREATEDB"
		option.Type = ast.CreateDB
		option.Value = p.currentToken.Type == token.CREATEDB

	case p.matchToken(token.CREATEROLE), p.matchToken(token.NOCREATEROLE):
		option.Name = "CREATEROLE"
		option.Type = ast.CreateRole
		option.Value = p.currentToken.Type == token.CREATEROLE

	case p.matchToken(token.LOGIN), p.matchToken(token.NOLOGIN):
		option.Name = "LOGIN"
		option.Type = ast.Login
		option.Value = p.currentToken.Type == token.LOGIN

	case p.matchToken(token.PASSWORD):
		option.Name = "PASSWORD"
		option.Type = ast.Password
		if p.matchToken(token.NULL) {
			option.Value = nil
		} else {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			option.Value = expr
		}

	case p.matchToken(token.VALID):
		option.Name = "VALID"
		option.Type = ast.ValidUntil
		if !p.matchToken(token.UNTIL) {
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
