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

package keywords_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/keywords"
)

// Walk every SQL file, including nested corpus directories. Fail on missing
// fixtures so a working-directory mistake cannot silently weaken coverage.
func walkSQL(tb testing.TB, visit func(path, dialect, sql string)) {
	tb.Helper()
	for _, root := range []string{"../../../../testdata/realworld", "../../../../testdata/corpus"} {
		count := 0
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || filepath.Ext(path) != ".sql" {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			dialect := ""
			if strings.HasSuffix(root, "realworld") {
				dialect = strings.Split(rel, string(filepath.Separator))[0]
			}
			visit(path, dialect, string(data))
			count++
			return nil
		})
		if err != nil {
			tb.Fatal(err)
		}
		if count == 0 {
			tb.Fatalf("no SQL fixtures in %s", root)
		}
	}
}

func TestKeywordCaseDifferential(t *testing.T) {
	check := func(t *testing.T, sql string) {
		t.Helper()
		for _, style := range []keywords.CaseStyle{"", keywords.CaseUpper, keywords.CaseLower, "other"} {
			rule := keywords.NewKeywordCaseRule(style)
			preferred := style
			if preferred == "" {
				preferred = keywords.CaseUpper
			}
			old := &legacyKeywordCaseRule{KeywordCaseRule: rule, preferredStyle: preferred}
			ctx := linter.NewContext(sql, "differential.sql")
			want, wantErr := old.Check(ctx)
			got, gotErr := rule.Check(ctx)
			if wantErr != nil || gotErr != nil {
				t.Fatalf("Check errors: old=%v new=%v", wantErr, gotErr)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("style %q SQL %q\nnew: %#v\nold: %#v", style, sql, got, want)
			}
			// Fix is unchanged, but verify that applying either violation set yields
			// exactly the same output and that another application is stable.
			wantFix, err := rule.Fix(sql, want)
			if err != nil {
				t.Fatal(err)
			}
			gotFix, err := rule.Fix(sql, got)
			if err != nil {
				t.Fatal(err)
			}
			again, err := rule.Fix(gotFix, got)
			if err != nil {
				t.Fatal(err)
			}
			if gotFix != wantFix || again != gotFix {
				t.Fatalf("style %q: fixes differ or are unstable", style)
			}
		}
	}
	cases := []string{
		"", "SeLeCt id, name FrOm users WhErE active = TrUe",
		"ſelect caſe when true then 1 end from café where 日本語٢ = 1",
		"select selecté, éselect, _from, from2, 2where, select\u0301 from таблица",
		"select \"from\", `where`, [select] from users",
		"select 'from ''where'' select', \"join \"\"on\"\"\" from users",
		"select 1 -- from WHERE\n/* select 'where' */ FrOm users",
		"select 'unterminated from\nwhere id = 1\r\n\torder by id",
		"\xffselect \xc0 from \xe2\x82 where\x00true",
		"ſelectſelectſelectſelect from abcdefghijklmnopqrstuvwxyz",
		"select'x'from\"t\"where\"a\"='b'",
		"SELECT\"col\"FROM t",
		"select`a`from`b`",
	}
	for _, sql := range cases {
		t.Run(sql, func(t *testing.T) { check(t, sql) })
	}
	statements := 0
	walkSQL(t, func(path, dialect, sql string) {
		t.Run(path, func(t *testing.T) {
			check(t, sql)
			for _, statement := range gosqlx.SplitStatements(sql, dialect) {
				check(t, statement)
				statements++
			}
		})
	})
	t.Logf("compared %d corpus and realworld statements plus full files and edge cases", statements)
}
