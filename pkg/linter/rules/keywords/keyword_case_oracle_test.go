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

// The original L007 Check and tokenizer are retained as a differential oracle.
package keywords_test

import (
	"strings"
	"unicode"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

type legacyKeywordCaseRule struct {
	*keywords.KeywordCaseRule
	preferredStyle keywords.CaseStyle
}

const CaseUpper = keywords.CaseUpper

var sqlKeywords = map[string]bool{
	"SELECT": true, "FROM": true, "WHERE": true, "AND": true, "OR": true,
	"NOT": true, "IN": true, "IS": true, "NULL": true, "LIKE": true,
	"BETWEEN": true, "EXISTS": true, "CASE": true, "WHEN": true, "THEN": true,
	"ELSE": true, "END": true, "AS": true, "ON": true, "JOIN": true,
	"INNER": true, "LEFT": true, "RIGHT": true, "FULL": true, "OUTER": true,
	"CROSS": true, "NATURAL": true, "USING": true, "GROUP": true, "BY": true,
	"HAVING": true, "ORDER": true, "ASC": true, "DESC": true, "LIMIT": true,
	"OFFSET": true, "UNION": true, "ALL": true, "EXCEPT": true, "INTERSECT": true,
	"INSERT": true, "INTO": true, "VALUES": true, "UPDATE": true, "SET": true,
	"DELETE": true, "CREATE": true, "TABLE": true, "INDEX": true, "VIEW": true,
	"DROP": true, "ALTER": true, "ADD": true, "COLUMN": true, "CONSTRAINT": true,
	"PRIMARY": true, "KEY": true, "FOREIGN": true, "REFERENCES": true,
	"UNIQUE": true, "CHECK": true, "DEFAULT": true, "CASCADE": true,
	"WITH": true, "RECURSIVE": true, "DISTINCT": true, "TRUE": true, "FALSE": true,
	"OVER": true, "PARTITION": true, "ROWS": true, "RANGE": true, "UNBOUNDED": true,
	"PRECEDING": true, "FOLLOWING": true, "CURRENT": true, "ROW": true,
	"RETURNING": true, "COALESCE": true, "NULLIF": true, "CAST": true,
	"MERGE": true, "MATCHED": true, "MATERIALIZED": true, "REFRESH": true,
	"ROLLUP": true, "CUBE": true, "GROUPING": true, "SETS": true,
}

func (r *legacyKeywordCaseRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	violations := []linter.Violation{}

	for lineNum, line := range ctx.Lines {
		// Tokenize the line to find keywords
		words := tokenizeLine(line)

		for _, word := range words {
			upperWord := strings.ToUpper(word.text)
			if sqlKeywords[upperWord] {
				// Check if case matches preferred style
				hasViolation := false
				var expectedCase string

				if r.preferredStyle == CaseUpper {
					hasViolation = word.text != upperWord
					expectedCase = upperWord
				} else {
					lowerWord := strings.ToLower(word.text)
					hasViolation = word.text != lowerWord
					expectedCase = lowerWord
				}

				if hasViolation {
					violations = append(violations, linter.Violation{
						Rule:       r.ID(),
						RuleName:   r.Name(),
						Severity:   r.Severity(),
						Message:    "Keyword '" + word.text + "' should be " + string(r.preferredStyle) + "case: '" + expectedCase + "'",
						Location:   models.Location{Line: lineNum + 1, Column: word.column},
						Line:       line,
						Suggestion: "Change '" + word.text + "' to '" + expectedCase + "'",
						CanAutoFix: true,
					})
				}
			}
		}
	}

	return violations, nil
}

// wordToken represents a word extracted from a line with its position.
type wordToken struct {
	text   string
	column int // 1-indexed column position in the line
}

// tokenizeLine extracts words from a line with their column positions.
//
// Parses the line character by character, extracting sequences of letters, digits,
// and underscores as words. Skips content inside string literals (both single and
// double quoted) to avoid extracting keywords from SQL string values.
//
// Returns a slice of wordTokens representing each word and its position.
func tokenizeLine(line string) []wordToken {
	words := []wordToken{}
	inString := false
	stringChar := rune(0)
	wordStart := -1
	currentWord := strings.Builder{}

	for i, ch := range line {
		// Handle string literals - skip keywords inside strings
		if !inString && (ch == '\'' || ch == '"') {
			inString = true
			stringChar = ch
			if wordStart >= 0 {
				words = append(words, wordToken{
					text:   currentWord.String(),
					column: wordStart + 1, // 1-indexed
				})
				currentWord.Reset()
				wordStart = -1
			}
			continue
		}

		if inString {
			if ch == stringChar {
				inString = false
				stringChar = 0
			}
			continue
		}

		// Handle identifiers and keywords
		if unicode.IsLetter(ch) || ch == '_' || (wordStart >= 0 && unicode.IsDigit(ch)) {
			if wordStart < 0 {
				wordStart = i
			}
			currentWord.WriteRune(ch)
		} else if wordStart >= 0 {
			words = append(words, wordToken{
				text:   currentWord.String(),
				column: wordStart + 1, // 1-indexed
			})
			currentWord.Reset()
			wordStart = -1
		}
	}

	// Don't forget the last word
	if wordStart >= 0 {
		words = append(words, wordToken{
			text:   currentWord.String(),
			column: wordStart + 1,
		})
	}

	return words
}
