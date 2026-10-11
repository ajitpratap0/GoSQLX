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

package safety

import (
	"unicode"
	"unicode/utf8"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// SelectIntoOutfileRule (L015) flags SELECT ... INTO OUTFILE / INTO DUMPFILE patterns.
// These operations write data to the server filesystem — a significant security risk.
// This rule works at the text level since SELECT INTO OUTFILE is a MySQL extension
// that may not always produce a full AST node.
type SelectIntoOutfileRule struct{ linter.BaseRule }

// NewSelectIntoOutfileRule creates a new L015 rule instance.
func NewSelectIntoOutfileRule() *SelectIntoOutfileRule {
	return &SelectIntoOutfileRule{
		BaseRule: linter.NewBaseRule(
			"L015",
			"Select Into Outfile",
			"SELECT INTO OUTFILE/DUMPFILE writes data to the server filesystem",
			linter.SeverityError,
			false,
		),
	}
}

// Check scans the SQL text for SELECT ... INTO OUTFILE or INTO DUMPFILE patterns.
// The scan is case-insensitive and allocation-free.
func (r *SelectIntoOutfileRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	var violations []linter.Violation
	if containsUpperFold(ctx.SQL, "INTO OUTFILE") || containsUpperFold(ctx.SQL, "INTO DUMPFILE") {
		violations = append(violations, linter.Violation{
			Rule:       r.ID(),
			RuleName:   r.Name(),
			Severity:   r.Severity(),
			Message:    "SELECT INTO OUTFILE/DUMPFILE writes data to the server filesystem",
			Location:   models.Location{Line: 1, Column: 1},
			Suggestion: "Use application-layer export instead of server-side file write",
		})
	}
	return violations, nil
}

// Fix is a no-op: removing OUTFILE requires understanding export intent.
func (r *SelectIntoOutfileRule) Fix(content string, violations []linter.Violation) (string, error) {
	return content, nil
}

// containsUpperFold reports whether strings.ToUpper(s) would contain pat,
// where pat is upper-case ASCII, without allocating the upper-cased copy.
// It is equivalent to strings.Contains(strings.ToUpper(s), pat): ToUpper maps
// rune by rune with unicode.ToUpper (invalid UTF-8 bytes become
// utf8.RuneError), and because pat is pure ASCII a byte match in the
// upper-cased text is exactly a rune-wise match here.
func containsUpperFold(s, pat string) bool {
	if len(pat) == 0 {
		return true
	}
	first := pat[0]
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			// ASCII fast path: skip positions that cannot start a match.
			if 'a' <= c && c <= 'z' {
				c -= 'a' - 'A'
			}
			if c != first {
				i++
				continue
			}
			if matchUpperAt(s[i:], pat) {
				return true
			}
			i++
			continue
		}
		if matchUpperAt(s[i:], pat) {
			return true
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
	}
	return false
}

// matchUpperAt reports whether the upper-cased runes at the start of s equal pat.
func matchUpperAt(s, pat string) bool {
	for j := 0; j < len(pat); j++ {
		if len(s) == 0 {
			return false
		}
		c := s[0]
		r, size := rune(c), 1
		if c < utf8.RuneSelf {
			if 'a' <= c && c <= 'z' {
				r -= 'a' - 'A'
			}
		} else {
			r, size = utf8.DecodeRuneInString(s)
			r = unicode.ToUpper(r)
		}
		if r != rune(pat[j]) {
			return false
		}
		s = s[size:]
	}
	return true
}
