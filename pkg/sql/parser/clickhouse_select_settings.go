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

// Package parser - clickhouse_select_settings.go
// ClickHouse query-level SETTINGS clause on SELECT:
//
//	SELECT ... SETTINGS name = expr [, name = expr]... [FORMAT <name>]

package parser

import (
	"fmt"
	"strings"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// parseTrailingSelectSettings parses a ClickHouse trailing SETTINGS clause and
// stores it on the rightmost SelectStatement of stmt (for a set operation the
// clause syntactically follows the last operand). The current token must be
// SETTINGS.
func (p *Parser) parseTrailingSelectSettings(stmt ast.Statement) error {
	loc := p.currentLocation()
	settings, err := p.parseQuerySettingsList()
	if err != nil {
		return err
	}
	target := rightmostSelect(stmt)
	if target == nil {
		return goerrors.InvalidSyntaxError("SETTINGS must follow a SELECT", loc, "")
	}
	target.Settings = settings
	return nil
}

// parseQuerySettingsList parses "SETTINGS name = expr [, name = expr]...".
// The current token must be SETTINGS. Setting names may tokenize as keywords
// (limit, final), so any non-string token starting with a letter or '_' is
// accepted as a name.
func (p *Parser) parseQuerySettingsList() ([]ast.QuerySetting, error) {
	p.advance() // SETTINGS

	var settings []ast.QuerySetting
	for {
		if !p.isQuerySettingName() {
			return nil, p.expectedError("setting name")
		}
		pos := p.currentLocation()
		name := p.currentToken.Token.Value
		p.advance()

		if !p.isType(models.TokenTypeEq) {
			return nil, p.expectedError("=")
		}
		p.advance()

		value, err := p.parseExpression()
		if err != nil {
			return nil, goerrors.InvalidSyntaxError(
				fmt.Sprintf("failed to parse SETTINGS value for %s: %v", name, err),
				p.currentLocation(),
				"",
			).WithCause(err)
		}
		settings = append(settings, ast.QuerySetting{Name: name, Value: value, Pos: pos})

		if !p.isType(models.TokenTypeComma) {
			break
		}
		p.advance() // ,
	}

	// Trailing ClickHouse output-format hint: SETTINGS ... FORMAT <name>.
	// Parse-only; FORMAT is not modeled on the AST (pre-existing, see the
	// INSERT ... FORMAT handling in dml_insert.go). Format names may tokenize
	// as keywords or literals (Values, Null), so any word token is accepted,
	// using the same rule as setting names. A name is required.
	if !p.isStringLiteral() && strings.EqualFold(p.currentToken.Token.Value, "FORMAT") {
		p.advance() // FORMAT
		if !p.isQuerySettingName() {
			return nil, p.expectedError("format name after FORMAT")
		}
		p.advance() // format name
	}
	return settings, nil
}

// isQuerySettingName reports whether the current token can name a ClickHouse
// setting: an identifier, or a keyword-like token (limit, final, ...) whose
// text starts with an ASCII letter or '_'.
func (p *Parser) isQuerySettingName() bool {
	if p.isIdentifier() {
		return true
	}
	if p.isStringLiteral() {
		return false
	}
	v := p.currentToken.Token.Value
	if v == "" {
		return false
	}
	c := v[0]
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// rightmostSelect returns the last SelectStatement operand of stmt, walking
// down the right side of nested set operations, or nil if there is none.
func rightmostSelect(stmt ast.Statement) *ast.SelectStatement {
	for {
		so, ok := stmt.(*ast.SetOperation)
		if !ok {
			break
		}
		stmt = so.Right
	}
	sel, ok := stmt.(*ast.SelectStatement)
	if !ok {
		return nil
	}
	return sel
}
