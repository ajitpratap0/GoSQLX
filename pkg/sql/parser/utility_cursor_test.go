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
	"errors"
	"strings"
	"testing"

	goerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestUtilityCursorUnclosedGroups(t *testing.T) {
	dialects := []keywords.SQLDialect{
		keywords.DialectPostgreSQL, keywords.DialectMySQL, keywords.DialectMariaDB,
		keywords.DialectSQLServer, keywords.DialectOracle, keywords.DialectSQLite,
		keywords.DialectSnowflake, keywords.DialectClickHouse,
	}
	cases := []struct{ sql, expected string }{
		{"GRANT SELECT ON t TO [", "]"},
		{"GRANT SELECT ON t TO CURRENT_USER(", ")"},
		{"GRANT SELECT ON t TO [AppUser", "]"},
	}
	for _, dialect := range dialects {
		for _, tc := range cases {
			t.Run(string(dialect)+"/"+tc.sql, func(t *testing.T) {
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Fatalf("parse panicked: %v", recovered)
					}
				}()
				tree, err := ParseWithDialect(tc.sql, dialect)
				if tree != nil {
					defer ast.ReleaseAST(tree)
				}
				if err == nil {
					t.Fatal("expected an error for an unclosed group")
				}
				if dialect == keywords.DialectSQLServer || dialect == keywords.DialectSQLite {
					var structured *goerrors.Error
					if !errors.As(err, &structured) {
						t.Fatalf("expected a structured error, got %T: %v", err, err)
					}
					return
				}
				assertUtilityExpectedError(t, err, tc.expected)
			})
		}
	}
}

func TestUtilityCursorOtherUnclosedGroups(t *testing.T) {
	cases := []struct {
		dialect       keywords.SQLDialect
		sql, expected string
	}{
		{keywords.DialectMariaDB, "CREATE USER u IDENTIFIED VIA ed25519 USING PASSWORD(", ")"},
		{keywords.DialectPostgreSQL, "COPY (SELECT 1", ")"},
		{keywords.DialectMariaDB, "GRANT SELECT ON t TO u IDENTIFIED VIA ed25519 USING PASSWORD(", ")"},
	}
	for _, tc := range cases {
		t.Run(tc.sql, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("parse panicked: %v", recovered)
				}
			}()
			tree, err := ParseWithDialect(tc.sql, tc.dialect)
			if tree != nil {
				defer ast.ReleaseAST(tree)
			}
			assertUtilityExpectedError(t, err, tc.expected)
		})
	}
}

func assertUtilityExpectedError(t *testing.T, err error, expected string) {
	t.Helper()
	var structured *goerrors.Error
	if !errors.As(err, &structured) {
		t.Fatalf("expected a structured parser error, got %T: %v", err, err)
	}
	if structured.Code != goerrors.ErrCodeExpectedToken {
		t.Errorf("code = %s, want E2002: %v", structured.Code, err)
	}
	if !strings.Contains(structured.Message, "expected "+expected) {
		t.Errorf("message = %q, want expected %s", structured.Message, expected)
	}
	if structured.Location.Line < 1 || structured.Location.Column < 1 {
		t.Errorf("invalid error position: %+v", structured.Location)
	}
}

func TestParserSeekNegativeIndex(t *testing.T) {
	p := NewParser()
	defer p.Release()
	p.tokens = []models.TokenWithSpan{{Token: models.Token{Type: models.TokenTypeSelect}}}
	p.seek(0)
	p.seek(-1)
	if p.currentPos != len(p.tokens) {
		t.Errorf("position = %d, want EOF at %d", p.currentPos, len(p.tokens))
	}
	if p.currentToken != (models.TokenWithSpan{}) {
		t.Errorf("token = %+v, want zero EOF token", p.currentToken)
	}
}
