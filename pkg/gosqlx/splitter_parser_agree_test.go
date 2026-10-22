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

package gosqlx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// splitDialect maps a SplitStatements dialect name to the parser dialect.
func splitDialect(d string) keywords.SQLDialect {
	switch d {
	case "mssql", "tsql":
		return keywords.DialectSQLServer
	}
	return keywords.SQLDialect(d)
}

// assertOneStatementPerPiece parses every piece SplitStatements returns for
// sql and requires each piece that parses to hold exactly one statement: the
// splitter and the parser must agree on where statements end. Pieces the
// parser rejects are left to the tests of the features they use.
func assertOneStatementPerPiece(t *testing.T, label, sql, dialect string) {
	t.Helper()
	for i, piece := range SplitStatements(sql, dialect) {
		if onlyComments(piece) {
			continue
		}
		tree, err := ParseWithDialect(piece, splitDialect(dialect))
		if err != nil {
			continue
		}
		if n := len(tree.Statements); n != 1 {
			t.Errorf("%s#%d: SplitStatements returned one statement, the parser found %d: %s",
				label, i, n, compact(piece))
		}
	}
}

// multiStatementPieces are the procedural split cases whose pieces hold
// several statements by design.
var multiStatementPieces = map[string]string{
	"tsql end then if without semicolon":       "T-SQL needs no ';' between statements",
	"go not alone on line":                     "GO is an alias there, and T-SQL needs no ';'",
	"delimiter lowercase and double semicolon": "the client sends SELECT 1; SELECT 2 as one batch",
}

// TestSplitStatements_AgreesWithParser checks that every piece of the
// procedural split cases and of the real-world corpus parses as exactly one
// statement. Files whose name says they are written without semicolons hold
// several statements per batch by design and are only required to parse
// (TestRealWorldCorpus checks that).
func TestSplitStatements_AgreesWithParser(t *testing.T) {
	for _, tc := range proceduralSplitCases {
		if tc.dialect == "" || multiStatementPieces[tc.name] != "" {
			continue // the generic dialect parses neither PL blocks nor GO
		}
		assertOneStatementPerPiece(t, tc.name, tc.sql, tc.dialect)
	}

	dirs, err := os.ReadDir(realworldRoot)
	if os.IsNotExist(err) {
		t.Skip("testdata/realworld not present")
	}
	if err != nil {
		t.Fatalf("read %s: %v", realworldRoot, err)
	}
	checked := 0
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		files, _ := filepath.Glob(filepath.Join(realworldRoot, d.Name(), "*.sql"))
		for _, file := range files {
			if strings.Contains(filepath.Base(file), "no_semicolons") {
				continue
			}
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read %s: %v", file, err)
			}
			assertOneStatementPerPiece(t, d.Name()+"/"+filepath.Base(file), string(data), d.Name())
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no corpus files checked")
	}
}
