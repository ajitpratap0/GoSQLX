package parser

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// parseAlterStatement parses ALTER statements
func (p *Parser) parseAlterStatement() (*ast.AlterStatement, error) {
	stmt := &ast.AlterStatement{}

	switch {
	case p.matchType(models.TokenTypeTable):
		stmt.Type = ast.AlterTypeTable
		return p.parseAlterTableStatement(stmt)
	case p.matchType(models.TokenTypeRole):
		stmt.Type = ast.AlterTypeRole
		return p.parseAlterRoleStatement(stmt)
	case p.matchKeyword("POLICY"):
		stmt.Type = ast.AlterTypePolicy
		return p.parseAlterPolicyStatement(stmt)
	case p.matchKeyword("CONNECTOR"):
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
	case p.matchKeyword("ADD"):
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
		if p.matchKeyword("TO") {
			op.Type = ast.RenameTable
			op.NewTableName = p.parseObjectName()
		} else if p.matchType(models.TokenTypeColumn) {
			op.Type = ast.RenameColumn
			ident := p.parseIdent()
			if ident == nil {
				return nil, p.expectedError("column name")
			}
			op.ColumnName = &ast.Ident{Name: ident.Name}
			if !p.matchKeyword("TO") {
				return nil, p.expectedError("TO")
			}
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
		if !p.matchKeyword("TO") {
			return nil, p.expectedError("TO")
		}
		op.Type = ast.RenameRole
		op.NewName = p.parseIdentAsString()

	case p.matchKeyword("ADD"):
		if !p.matchKeyword("MEMBER") {
			return nil, p.expectedError("MEMBER")
		}
		op.Type = ast.AddMember
		op.MemberName = p.parseIdentAsString()

	case p.matchType(models.TokenTypeDrop):
		if !p.matchKeyword("MEMBER") {
			return nil, p.expectedError("MEMBER")
		}
		op.Type = ast.DropMember
		op.MemberName = p.parseIdentAsString()

	case p.matchType(models.TokenTypeSet):
		op.Type = ast.SetConfig
		op.ConfigName = p.parseIdentAsString()
		if p.matchKeyword("TO") || p.matchType(models.TokenTypeEq) {
			expr, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			op.ConfigValue = expr
		}

	case p.matchKeyword("RESET"):
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
		if !p.matchKeyword("TO") {
			return nil, p.expectedError("TO")
		}
		op.Type = ast.RenamePolicy
		op.NewName = p.parseIdentAsString()
	} else {
		op.Type = ast.ModifyPolicy
		if p.matchKeyword("TO") {
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
	case p.matchKeyword("DCPROPERTIES"):
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

	case p.matchKeyword("URL"):
		op.URL = p.parseStringLiteral()

	case p.matchKeyword("OWNER"):
		owner := &ast.AlterConnectorOwner{}
		if p.matchKeyword("USER") {
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
	case p.matchType(models.TokenTypeSuperuser):
		option.Name = "SUPERUSER"
		option.Type = ast.SuperUser
		option.Value = true

	case p.matchType(models.TokenTypeNoSuperuser):
		option.Name = "SUPERUSER"
		option.Type = ast.SuperUser
		option.Value = false

	case p.matchType(models.TokenTypeCreateDB):
		option.Name = "CREATEDB"
		option.Type = ast.CreateDB
		option.Value = true

	case p.matchType(models.TokenTypeNoCreateDB):
		option.Name = "CREATEDB"
		option.Type = ast.CreateDB
		option.Value = false

	case p.matchType(models.TokenTypeCreateRole):
		option.Name = "CREATEROLE"
		option.Type = ast.CreateRole
		option.Value = true

	case p.matchType(models.TokenTypeNoCreateRole):
		option.Name = "CREATEROLE"
		option.Type = ast.CreateRole
		option.Value = false

	case p.matchType(models.TokenTypeLogin):
		option.Name = "LOGIN"
		option.Type = ast.Login
		option.Value = true

	case p.matchType(models.TokenTypeNoLogin):
		option.Name = "LOGIN"
		option.Type = ast.Login
		option.Value = false

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

	case p.matchKeyword("VALID"):
		option.Name = "VALID"
		option.Type = ast.ValidUntil
		if !p.matchKeyword("UNTIL") {
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
