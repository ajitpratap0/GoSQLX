package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// parseAlterStatement parses ALTER statements
func (p *Parser) parseAlterStatement() (*ast.AlterStatement, error) {
	stmt := &ast.AlterStatement{}

	// Parse the type of object being altered
	switch {
	case p.matchType(models.TokenTypeTable):
		stmt.Type = ast.AlterTypeTable
		return p.parseAlterTableStatement(stmt)
	case p.matchType(models.TokenTypeRole):
		stmt.Type = ast.AlterTypeRole
		return p.parseAlterRoleStatement(stmt)
	case p.matchType(models.TokenTypePolicy):
		stmt.Type = ast.AlterTypePolicy
		return p.parseAlterPolicyStatement(stmt)
	case p.matchType(models.TokenTypeConnector):
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
	case p.matchType(models.TokenTypeAdd):
		if p.matchType(models.TokenTypeColumn) {
			op.Type = ast.AddColumn
			colDef, err := p.parseColumnDef()
			if err != nil {
				return nil, err
			}
			op.ColumnDef = colDef
		} else if p.matchType(models.TokenTypeConstraint) {
			op.Type = ast.AddConstraint
			constraint, err := p.parseTableConstraint()
			if err != nil {
				return nil, err
			}
			op.Constraint = constraint
		} else {
			return nil, p.expectedError("COLUMN or CONSTRAINT")
		}

	case p.matchType(models.TokenTypeDrop):
		if p.matchType(models.TokenTypeColumn) {
			op.Type = ast.DropColumn
			// Convert ast.Identifier to ast.Ident
			ident := p.parseIdent()
			if ident == nil {
				return nil, p.expectedError("column name")
			}
			op.ColumnName = &ast.Ident{Name: ident.Name}
			if p.matchType(models.TokenTypeCascade) {
				op.CascadeDrops = true
			}
		} else if p.matchType(models.TokenTypeConstraint) {
			op.Type = ast.DropConstraint
			// Convert ast.Identifier to ast.Ident
			ident := p.parseIdent()
			if ident == nil {
				return nil, p.expectedError("constraint name")
			}
			op.ConstraintName = &ast.Ident{Name: ident.Name}
			if p.matchType(models.TokenTypeCascade) {
				op.CascadeDrops = true
			}
		} else {
			return nil, p.expectedError("COLUMN or CONSTRAINT")
		}

	case p.matchType(models.TokenTypeRename):
		if p.matchType(models.TokenTypeTo) {
			op.Type = ast.RenameTable
			op.NewTableName = p.parseObjectName()
		} else if p.matchType(models.TokenTypeColumn) {
			op.Type = ast.RenameColumn
			// Convert ast.Identifier to ast.Ident
			ident := p.parseIdent()
			if ident == nil {
				return nil, p.expectedError("column name")
			}
			op.ColumnName = &ast.Ident{Name: ident.Name}
			if !p.matchType(models.TokenTypeTo) {
				return nil, p.expectedError("TO")
			}
			// Convert ast.Identifier to ast.Ident
			newIdent := p.parseIdent()
			if newIdent == nil {
				return nil, p.expectedError("new column name")
			}
			op.NewColumnName = &ast.Ident{Name: newIdent.Name}
		} else {
			return nil, p.expectedError("TO or COLUMN")
		}

	case p.matchType(models.TokenTypeAlter):
		if !p.matchType(models.TokenTypeColumn) {
			return nil, p.expectedError("COLUMN")
		}
		op.Type = ast.AlterColumn
		// Convert ast.Identifier to ast.Ident
		ident := p.parseIdent()
		if ident == nil {
			return nil, p.expectedError("column name")
		}
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
			key := p.parseIdentAsString()
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
