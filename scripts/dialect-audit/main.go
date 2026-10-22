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
	if lost := droppedWords(stmt, f1); len(lost) > 0 {
		r.Stage, r.Error = "drop", "formatter output lost words: "+strings.Join(lost, " ")
		return r
	}
	r.Stage, r.Format = "ok", ""
	return r
}

// droppedWords reports words of the input (outside comments and string
// literals) that are missing from the formatted output — a cheap detector for
// clauses the formatter silently drops even though its output reparses.
func droppedWords(in, out string) []string {
	have := map[string]bool{}
	for _, w := range sqlWords(out) {
		have[w] = true
	}
	var lost []string
	seen := map[string]bool{}
	for _, w := range sqlWords(in) {
		if !have[w] && !ignorableWords[w] && !seen[w] {
			seen[w] = true
			lost = append(lost, w)
		}
	}
	return lost
}

// ignorableWords are noise words the formatter may legitimately add or drop.
var ignorableWords = map[string]bool{"AS": true, "ASC": true, "INNER": true, "OUTER": true}

// sqlWords returns the upper-cased identifier-like words of s, skipping
// comments and quoted string literals but keeping quoted identifiers' text.
func sqlWords(s string) []string {
	var words []string
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '-' && i+1 < len(s) && s[i+1] == '-':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '/' && i+1 < len(s) && s[i+1] == '*':
			end := strings.Index(s[i+2:], "*/")
			if end < 0 {
				return words
			}
			i += end + 4
		case c == '\'':
			for i++; i < len(s); i++ {
				if s[i] == '\\' {
					i++
					continue
				}
				if s[i] == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						i++
						continue
					}
					break
				}
			}
			i++
		case c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= 0x80:
			j := i
			for j < len(s) && (s[j] == '_' || s[j] == '$' || s[j] >= '0' && s[j] <= '9' ||
				s[j] >= 'A' && s[j] <= 'Z' || s[j] >= 'a' && s[j] <= 'z' || s[j] >= 0x80) {
				j++
			}
			words = append(words, strings.ToUpper(s[i:j]))
			i = j
		case c >= '0' && c <= '9':
			for i < len(s) && (s[i] == '.' || s[i] == '_' || s[i] >= '0' && s[i] <= '9' ||
				s[i] >= 'A' && s[i] <= 'Z' || s[i] >= 'a' && s[i] <= 'z') {
				i++
			}
		default:
			i++
		}
	}
	return words
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
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
