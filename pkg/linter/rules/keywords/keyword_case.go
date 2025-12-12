package keywords

import (
	"strings"
	"unicode"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// CaseStyle represents the preferred keyword case style for SQL keywords.
type CaseStyle string

const (
	// CaseUpper enforces uppercase keywords (SELECT, FROM, WHERE).
	// This is the traditional SQL style and is recommended by most database vendors.
	CaseUpper CaseStyle = "upper"

	// CaseLower enforces lowercase keywords (select, from, where).
	// This style is preferred by some modern development teams for consistency
	// with application code conventions.
	CaseLower CaseStyle = "lower"
)

// sqlKeywords contains all recognized SQL keywords across multiple dialects.
// Keywords are stored in uppercase for case-insensitive matching.
//
// Includes keywords from:
//   - SQL-99 standard
//   - PostgreSQL (including v1.6.0 extensions)
//   - MySQL/MariaDB
//   - SQL Server (T-SQL)
//   - Oracle (PL/SQL)
//   - SQLite
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

// KeywordCaseRule (L007) enforces consistent case for SQL keywords.
//
// Inconsistent keyword casing reduces readability and looks unprofessional. This
// rule detects keywords that don't match the configured case style and supports
// automatic conversion to the preferred style.
//
// Rule ID: L007
// Severity: Warning
// Auto-fix: Supported
//
// Example violation (CaseUpper style):
//
//	select * from users where active = true  <- Lowercase keywords (violation)
//
// Fixed output:
//
//	SELECT * FROM users WHERE active = true  <- Uppercase keywords
//
// The rule recognizes 60+ SQL keywords across multiple dialects including DDL, DML,
// JOINs, window functions, CTEs, and PostgreSQL extensions. Identifiers (table names,
// column names) are never modified.
//
// String literal handling:
//   - Keywords inside 'single quotes' are NOT converted
//   - Keywords inside "double quotes" are NOT converted
//   - Only keywords in SQL code are affected
type KeywordCaseRule struct {
	linter.BaseRule
	preferredStyle CaseStyle
}

// NewKeywordCaseRule creates a new L007 rule instance.
//
// Parameters:
//   - preferredStyle: CaseUpper or CaseLower (defaults to CaseUpper if empty)
//
// Returns a configured KeywordCaseRule ready for use with the linter.
func NewKeywordCaseRule(preferredStyle CaseStyle) *KeywordCaseRule {
	if preferredStyle == "" {
		preferredStyle = CaseUpper // Default to uppercase
	}
	return &KeywordCaseRule{
		BaseRule: linter.NewBaseRule(
			"L007",
			"Keyword Case Consistency",
			"SQL keywords should use consistent case",
			linter.SeverityWarning,
			true, // Supports auto-fix
		),
		preferredStyle: preferredStyle,
	}
}

// Check performs the keyword case consistency check on SQL content.
//
// Tokenizes each line to find words, checks if each word is a SQL keyword, and
// compares its case against the preferred style. String literals are skipped to
// avoid flagging keywords that appear in quoted strings.
//
// Returns a slice of violations (one per keyword not matching preferred case) and nil error.
func (r *KeywordCaseRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
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
		} else {
			if wordStart >= 0 {
				words = append(words, wordToken{
					text:   currentWord.String(),
					column: wordStart + 1, // 1-indexed
				})
				currentWord.Reset()
				wordStart = -1
			}
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

// Fix converts all keywords to the preferred case in SQL content.
//
// Processes content line by line, converting keywords to the configured case style
// while preserving:
//   - Identifier case (table names, column names, aliases)
//   - String literal content (keywords inside quotes are not changed)
//   - Whitespace and formatting
//
// The fix is applied to all keywords regardless of violations parameter, ensuring
// consistent case throughout the content.
//
// Returns the fixed content with all keywords in preferred case, and nil error.
func (r *KeywordCaseRule) Fix(content string, violations []linter.Violation) (string, error) {
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		lines[i] = r.fixLine(line)
	}

	return strings.Join(lines, "\n"), nil
}

// fixLine fixes keyword case in a single line.
//
// Uses a state machine to track whether currently inside a string literal. For
// words outside strings, checks if they're keywords and converts them to the
// preferred case. Non-keywords are preserved unchanged.
//
// Returns the fixed line with keywords in preferred case.
func (r *KeywordCaseRule) fixLine(line string) string {
	result := strings.Builder{}
	inString := false
	stringChar := rune(0)
	wordStart := -1
	currentWord := strings.Builder{}

	runes := []rune(line)
	for i, ch := range runes {
		// Handle string literals - don't modify keywords inside strings
		if !inString && (ch == '\'' || ch == '"') {
			// Flush current word first
			if wordStart >= 0 {
				result.WriteString(r.convertKeyword(currentWord.String()))
				currentWord.Reset()
				wordStart = -1
			}
			inString = true
			stringChar = ch
			result.WriteRune(ch)
			continue
		}

		if inString {
			result.WriteRune(ch)
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
		} else {
			if wordStart >= 0 {
				result.WriteString(r.convertKeyword(currentWord.String()))
				currentWord.Reset()
				wordStart = -1
			}
			result.WriteRune(ch)
		}
	}

	// Don't forget the last word
	if wordStart >= 0 {
		result.WriteString(r.convertKeyword(currentWord.String()))
	}

	return result.String()
}

// convertKeyword converts a word to the preferred case if it's a keyword.
//
// Checks if the word (case-insensitively) is a recognized SQL keyword. If yes,
// converts to preferred case. If no, returns the word unchanged.
//
// Parameters:
//   - word: The word to potentially convert
//
// Returns the word in preferred case if it's a keyword, otherwise unchanged.
func (r *KeywordCaseRule) convertKeyword(word string) string {
	upperWord := strings.ToUpper(word)
	if sqlKeywords[upperWord] {
		if r.preferredStyle == CaseUpper {
			return upperWord
		}
		return strings.ToLower(word)
	}
	return word // Not a keyword, preserve original case
}
