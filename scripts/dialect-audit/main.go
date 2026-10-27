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

// Command dialect-audit runs real-world SQL files through the user-facing
// pipeline (split → parse with dialect → format → reparse → reformat) and
// reports every statement that fails a stage.
// JSON mode emits failures only, even when -v is also supplied.
//
// Usage:
//
//	go run ./scripts/dialect-audit -dialect postgresql testdata/realworld/postgresql/*.sql
//	go run ./scripts/dialect-audit -dialect mysql -json file.sql
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/ajitpratap0/GoSQLX/internal/dialectaudit"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

type result struct {
	File   string `json:"file"`
	Index  int    `json:"index"`
	Stage  string `json:"stage"` // parse | reparse | idempotent | drop | panic | ok
	SQL    string `json:"sql"`
	Error  string `json:"error,omitempty"`
	Format string `json:"formatted,omitempty"`
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("dialect-audit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dialect := flags.String("dialect", "generic", "SQL dialect")
	asJSON := flags.Bool("json", false, "emit JSON lines for every failure")
	verbose := flags.Bool("v", false, "print passing statements too")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if !keywords.IsValidDialect(*dialect) {
		fmt.Fprintf(stderr, "invalid SQL dialect: %q\n", *dialect)
		return 2
	}

	d := keywords.SQLDialect(*dialect)
	total, failed := 0, 0
	stages := map[string]int{}
	enc := json.NewEncoder(stdout)

	for _, path := range flags.Args() {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "read %s: %v\n", path, err)
			return 2
		}
		for i, stmt := range gosqlx.SplitStatements(string(data), *dialect) {
			audit := dialectaudit.Check(stmt, d, gosqlx.ParseWithDialect, func(tree *ast.AST) string { return gosqlx.FormatAST(tree) })
			if audit.Stage == "empty" {
				continue
			}
			total++
			r := result{File: path, Index: i, SQL: stmt, Stage: audit.Stage, Error: audit.Error, Format: audit.Format}
			stages[r.Stage]++
			if r.Stage == "ok" {
				if *verbose && !*asJSON {
					fmt.Fprintf(stdout, "ok   %s#%d\n", path, i)
				}
				continue
			}
			failed++
			if *asJSON {
				if err := enc.Encode(r); err != nil {
					fmt.Fprintf(stderr, "encode failure: %v\n", err)
					return 2
				}
				continue
			}
			fmt.Fprintf(stdout, "FAIL %s#%d [%s] %s\n  sql: %s\n", path, i, r.Stage, r.Error, dialectaudit.Compact(r.SQL))
			if r.Format != "" {
				fmt.Fprintf(stdout, "  fmt: %s\n", dialectaudit.Compact(r.Format))
			}
		}
	}
	fmt.Fprintf(stderr, "dialect=%s total=%d passed=%d failed=%d stages=%v\n",
		*dialect, total, total-failed, failed, stages)
	if failed > 0 {
		return 1
	}
	return 0
}
