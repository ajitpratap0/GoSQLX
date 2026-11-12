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

package security

import "strings"

// stackedMatches fills each pattern's first match, preserving view precedence.
func stackedMatches(views []string) (matches [3]string) {
	verbs := [...]struct {
		word string
		slot int
	}{
		{"DROP", 0}, {"DELETE", 0}, {"TRUNCATE", 0}, {"UPDATE", 0},
		{"INSERT", 0}, {"ALTER", 0}, {"EXEC", 1}, {"EXECUTE", 2},
	}
	for _, view := range views {
		for i := 0; i < len(view); {
			if matches[0] != "" && matches[1] != "" && matches[2] != "" {
				return matches
			}
			off := strings.IndexByte(view[i:], ';')
			if off < 0 {
				break
			}
			start := i + off
			j := start + 1
			for j < len(view) && (view[j] == ' ' || view[j] >= '\t' && view[j] <= '\r') {
				j++
			}
			i = j
			for _, verb := range verbs {
				if matches[verb.slot] != "" {
					continue
				}
				end := j
				for k := 0; k < len(verb.word); k++ {
					if end >= len(view) {
						end = -1
						break
					}
					c := view[end]
					if c >= 'a' && c <= 'z' {
						c -= 'a' - 'A'
					}
					if c == verb.word[k] {
						end++
						continue
					}
					if verb.word[k] == 'S' && end+1 < len(view) && view[end] == 0xc5 && view[end+1] == 0xbf {
						end += 2
						continue
					}
					end = -1
					break
				}
				if end < 0 {
					continue
				}
				if end < len(view) && (view[end] >= 'a' && view[end] <= 'z' || view[end] >= 'A' && view[end] <= 'Z' || view[end] >= '0' && view[end] <= '9' || view[end] == '_') {
					continue
				}
				matches[verb.slot] = view[start:end]
			}
		}
	}
	return matches
}

// stackedPrefilter holds the CNF the removed stacked-query regexes derived: a
// ';' and at least one statement keyword somewhere in the raw SQL.
var stackedPrefilter = compiledPattern{cnf: [][]string{
	{";"},
	{"drop", "delete", "truncate", "update", "insert", "alter", "exec", "execute"},
}}

func detectStackedQueries(s *Scanner, views []string, pf scanPrefilter, result *ScanResult) {
	if pf.on && !stackedPrefilter.filter.pass(pf.present) {
		return
	}
	// A single view without ';' cannot match; skip the common single-statement
	// case before touching pattern state.
	if len(views) == 1 && strings.IndexByte(views[0], ';') < 0 {
		return
	}
	patternsOnce.Do(initPatterns)
	group := regexGroups[PatternStackedQuery]
	if !s.shouldInclude(group.severity) {
		return
	}
	for _, m := range stackedMatches(views) {
		if m == "" {
			continue
		}
		result.Findings = append(result.Findings, Finding{Severity: group.severity, Pattern: PatternStackedQuery,
			Description: "Pattern detected: " + m, Risk: group.risk, Suggestion: group.suggestion})
	}
}
