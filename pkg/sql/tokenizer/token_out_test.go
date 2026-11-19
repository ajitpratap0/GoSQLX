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

package tokenizer

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/tokscratch"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// TestStoreToken_CopiesEveryField guards storeToken's field-by-field copy: a
// field added to models.Token must be copied too, or tokens from the bridged
// readers would silently lose it.
func TestStoreToken_CopiesEveryField(t *testing.T) {
	var v models.Token
	rv := reflect.ValueOf(&v).Elem()
	for i := 0; i < rv.NumField(); i++ {
		f := rv.Field(i)
		switch f.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			f.SetInt(int64(i + 1))
		case reflect.String:
			f.SetString("v")
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Pointer:
			f.Set(reflect.New(f.Type().Elem()))
		default:
			t.Fatalf("models.Token.%s has kind %s: extend this test and storeToken", rv.Type().Field(i).Name, f.Kind())
		}
	}

	var out models.Token
	if err := storeToken(&out, v, nil); err != nil {
		t.Fatalf("storeToken: %v", err)
	}
	if !reflect.DeepEqual(out, v) {
		t.Fatalf("storeToken copied %+v, want %+v", out, v)
	}

	want := errors.New("boom")
	out = models.Token{}
	if err := storeToken(&out, v, want); err != want {
		t.Fatalf("storeToken error = %v, want %v", err, want)
	}
	if out != (models.Token{}) {
		t.Fatalf("storeToken wrote %+v on error, want no write", out)
	}
}

// TestTokenize_GrowsPastEstimate covers the slot growth path: "{}" pairs are
// one prescan word but two tokens each, so the capacity estimate falls short
// and the token slice must grow while tokens are built in place.
func TestTokenize_GrowsPastEstimate(t *testing.T) {
	const pairs = 200
	sql := strings.Repeat("{}", pairs)

	probe, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	probe.load([]byte(sql), sql)
	if est := probe.prescan(); est >= 2*pairs+1 {
		t.Fatalf("precondition: prescan estimate %d covers all %d tokens", est, 2*pairs+1)
	}

	check := func(t *testing.T, got []models.TokenWithSpan) {
		t.Helper()
		if len(got) != 2*pairs+1 {
			t.Fatalf("got %d tokens, want %d", len(got), 2*pairs+1)
		}
		for i, tw := range got[:2*pairs] {
			want := models.TokenWithSpan{
				Token: models.Token{Type: models.TokenTypeLBrace, Value: "{"},
				Start: models.Location{Line: 1, Column: i + 1},
				End:   models.Location{Line: 1, Column: i + 2},
			}
			if i%2 == 1 {
				want.Token = models.Token{Type: models.TokenTypeRBrace, Value: "}"}
			}
			if tw != want {
				t.Fatalf("token %d = %+v, want %+v", i, tw, want)
			}
		}
		if eof := got[2*pairs].Token; eof.Type != models.TokenTypeEOF {
			t.Fatalf("last token = %+v, want EOF", eof)
		}
	}

	t.Run("public", func(t *testing.T) {
		tkz := GetTokenizer()
		defer PutTokenizer(tkz)
		got, err := tkz.TokenizeString(sql)
		if err != nil {
			t.Fatalf("TokenizeString: %v", err)
		}
		check(t, got)
	})
	t.Run("scratch", func(t *testing.T) {
		tkz := GetTokenizer()
		defer PutTokenizer(tkz)
		for round := 0; round < 2; round++ { // the second round reuses tokBuf
			got, err := tokscratch.String(tkz, sql)
			if err != nil {
				t.Fatalf("round %d: %v", round, err)
			}
			check(t, got)
		}
	})
}

// TestTokenize_ErrorLeavesSpareSlotsZero checks the tokBuf invariant
// (tokBuf[len:cap] is zero) after a reader fails in the slot it was given,
// for each reader family, and that the next call on the same tokenizer still
// matches the public API exactly. The tokenize loop zeroes a failed slot, so
// the invariant holds even for a reader that writes part of a token before
// it fails.
func TestTokenize_ErrorLeavesSpareSlotsZero(t *testing.T) {
	tests := []struct {
		name    string
		dialect keywords.SQLDialect
		sql     string
	}{
		{"single quoted string", "", "SELECT a, 'unterminated"},
		{"double quoted identifier", "", `SELECT a, "unterminated`},
		{"backtick identifier", keywords.DialectMySQL, "SELECT a, `unterminated"},
		{"bracket identifier", keywords.DialectSQLServer, "SELECT a, [unterminated"},
		{"unicode escape unsupported", keywords.DialectOracle, "SELECT a, U&'x'"},
		{"unicode escape bad", keywords.DialectPostgreSQL, `SELECT a, U&'\zz'`},
		{"escape string", keywords.DialectPostgreSQL, `SELECT a, E'unterminated`},
		{"national string", keywords.DialectMySQL, "SELECT a, N'unterminated"},
		{"triple quoted string", keywords.DialectBigQuery, "SELECT a, '''unterminated"},
		{"invalid number", "", "SELECT a, 1abc"},
		{"unexpected character", "", "SELECT a, §"},
	}
	const after = "SELECT b, 'ok', \"q\", 1.5 FROM t WHERE c >= 2"
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tkz := GetTokenizer()
			defer PutTokenizer(tkz)
			tkz.SetDialect(tc.dialect)
			pub, err := NewWithDialect(tc.dialect)
			if err != nil {
				t.Fatalf("NewWithDialect: %v", err)
			}

			_, wantErr := pub.TokenizeString(tc.sql)
			if wantErr == nil {
				t.Fatalf("precondition: %q tokenizes without error", tc.sql)
			}
			_, gotErr := tokscratch.String(tkz, tc.sql)
			if gotErr == nil || gotErr.Error() != wantErr.Error() {
				t.Fatalf("scratch error = %v, want %v", gotErr, wantErr)
			}
			spare := tkz.tokBuf[len(tkz.tokBuf):cap(tkz.tokBuf)]
			for i := range spare {
				if spare[i] != (models.TokenWithSpan{}) {
					t.Fatalf("tokBuf[%d] = %+v after the error, want zero", len(tkz.tokBuf)+i, spare[i])
				}
			}

			want, err := pub.TokenizeString(after)
			if err != nil {
				t.Fatalf("public TokenizeString: %v", err)
			}
			got, err := tokscratch.String(tkz, after)
			if err != nil {
				t.Fatalf("scratch after the error: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("scratch after the error:\n got %+v\nwant %+v", got, want)
			}
		})
	}
}
