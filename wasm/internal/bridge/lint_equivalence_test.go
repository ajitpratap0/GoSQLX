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

package bridge

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestLint_MatchesDoubleParseReference(t *testing.T) {
	inputs := bridgeCorpusInputs(t)
	goldens.Parallel(len(inputs), func(i int) {
		in := inputs[i]
		got, want := Lint(in.sql, in.dialect), lintReference(in.sql, in.dialect)
		if !reflect.DeepEqual(got.Violations, want.Violations) || got.Error != want.Error || !reflect.DeepEqual(got.ParseErrorSpan, want.ParseErrorSpan) {
			t.Errorf("sql=%q dialect=%q: got %#v want %#v", in.sql, in.dialect, got, want)
			return
		}
		// E2004 also wraps ordinary parser errors; only tokenization wrappers change.
		tokenizerChange := Dialect(in.dialect) != "" && strings.HasPrefix(want.ParseError, "gosqlx: syntax error: ") && strings.Contains(want.ParseError, "E2004") && strings.Contains(want.ParseError, "tokenization error:")
		if tokenizerChange {
			if !strings.HasPrefix(got.ParseError, "gosqlx: tokenize error: ") {
				t.Errorf("tokenizer error sql=%q dialect=%q: got %q", in.sql, in.dialect, got.ParseError)
			}
			return
		}
		if strings.Contains(want.ParseError, "E2005") && noStatementTokens(in.sql, in.dialect) {
			if got.ParseError != "" {
				t.Errorf("no-statements error sql=%q dialect=%q: got %q", in.sql, in.dialect, got.ParseError)
			}
			return
		}
		if got.ParseError != want.ParseError {
			t.Errorf("unexpected lint difference sql=%q dialect=%q: got %q want %q", in.sql, in.dialect, got.ParseError, want.ParseError)
		}
	})
}

// noStatementTokens checks the selected dialect for comment-only input.
func noStatementTokens(sql, dialect string) bool {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	if d := Dialect(dialect); d != "" {
		tkz.SetDialect(d)
	}
	tokens, err := tkz.TokenizeString(sql)
	if err != nil {
		return false
	}
	for _, token := range tokens {
		if token.Token.Type != models.TokenTypeEOF {
			return false
		}
	}
	return true
}

func lintReference(sql, dialect string) LintResponse {
	resp := LintResponse{Violations: []LintViolation{}}

	if _, err := Parse(sql, dialect); err != nil {
		resp.ParseError = err.Error()
		resp.ParseErrorSpan = errorSpan(sql, err)
	}

	result, err := gosqlx.LintWithDialect(sql, Dialect(dialect))
	if err != nil {
		// Invalid SQL is reported through ParseError above; the violations of
		// the rules that still ran are returned with the error.
		invalidSQL := errors.Is(err, gosqlx.ErrSyntax) || errors.Is(err, gosqlx.ErrTokenize)
		if result == nil || !invalidSQL {
			resp.Error = err.Error()
			return resp
		}
	}
	for _, v := range result.Violations {
		resp.Violations = append(resp.Violations, LintViolation{
			Rule:       v.Rule,
			RuleName:   v.RuleName,
			Severity:   string(v.Severity),
			Message:    v.Message,
			Line:       v.Location.Line,
			Column:     v.Location.Column,
			Suggestion: v.Suggestion,
		})
	}
	return resp
}
