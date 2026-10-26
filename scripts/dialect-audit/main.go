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
	"os"
	"strings"

	"github.com/ajitpratap0/GoSQLX/internal/dropcheck"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
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

func main() {
	dialect := flag.String("dialect", "generic", "SQL dialect")
	asJSON := flag.Bool("json", false, "emit JSON lines for every failure")
	verbose := flag.Bool("v", false, "print passing statements too")
	flag.Parse()

	d := keywords.SQLDialect(*dialect)
	total, failed := 0, 0
	stages := map[string]int{}
	enc := json.NewEncoder(os.Stdout)

	for _, path := range flag.Args() {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
			os.Exit(2)
		}
		for i, stmt := range gosqlx.SplitStatements(string(data), *dialect) {
			if strings.TrimSpace(stripComments(stmt)) == "" {
				continue
			}
			total++
			r := check(path, i, stmt, d)
			stages[r.Stage]++
			if r.Stage == "ok" {
				if *verbose {
					fmt.Printf("ok   %s#%d\n", path, i)
				}
				continue
			}
			failed++
			if *asJSON {
				_ = enc.Encode(r)
				continue
			}
			fmt.Printf("FAIL %s#%d [%s] %s\n  sql: %s\n", path, i, r.Stage, r.Error, oneLine(r.SQL))
			if r.Format != "" {
				fmt.Printf("  fmt: %s\n", oneLine(r.Format))
			}
		}
	}
	fmt.Fprintf(os.Stderr, "dialect=%s total=%d passed=%d failed=%d stages=%v\n",
		*dialect, total, total-failed, failed, stages)
	if failed > 0 {
		os.Exit(1)
	}
}

func check(path string, i int, stmt string, d keywords.SQLDialect) (r result) {
	r = result{File: path, Index: i, SQL: stmt}
	defer func() {
		if p := recover(); p != nil {
			r.Stage, r.Error = "panic", fmt.Sprint(p)
		}
	}()
	tree, err := gosqlx.ParseWithDialect(stmt, d)
	if err != nil {
		r.Stage, r.Error = "parse", err.Error()
		return r
	}
	f1 := gosqlx.FormatAST(tree)
	r.Format = f1
	tree2, err := gosqlx.ParseWithDialect(f1, d)
	if err != nil {
		r.Stage, r.Error = "reparse", err.Error()
		return r
	}
	if f2 := gosqlx.FormatAST(tree2); f2 != f1 {
		r.Stage, r.Error = "idempotent", "format(parse(format(x))) != format(x): "+oneLine(f2)
		return r
	}
	if lost := dropcheck.DroppedWords(stmt, f1); len(lost) > 0 {
		r.Stage, r.Error = "drop", "formatter output lost words: "+strings.Join(lost, " ")
		return r
	}
	r.Stage, r.Format = "ok", ""
	return r
}

func stripComments(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "--") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 300 {
		s = string(r[:300]) + "…"
	}
	return s
}
