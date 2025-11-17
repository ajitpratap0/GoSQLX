package linter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Result represents the linting result for one or more files
type Result struct {
	Files           []FileResult
	TotalFiles      int
	TotalViolations int
}

// FileResult represents linting results for a single file
type FileResult struct {
	Filename   string
	Violations []Violation
	Error      error
}

// Linter performs SQL linting with configurable rules
type Linter struct {
	rules []Rule
}

// New creates a new linter with the given rules
func New(rules ...Rule) *Linter {
	return &Linter{
		rules: rules,
	}
}

// Rules returns the list of rules configured for this linter
func (l *Linter) Rules() []Rule {
	return l.rules
}

// LintFile lints a single SQL file
func (l *Linter) LintFile(filename string) FileResult {
	// Read file
	content, err := os.ReadFile(filename)
	if err != nil {
		return FileResult{
			Filename: filename,
			Error:    fmt.Errorf("failed to read file: %w", err),
		}
	}

	return l.LintString(string(content), filename)
}

// LintString lints SQL content provided as a string
func (l *Linter) LintString(sql string, filename string) FileResult {
	result := FileResult{
		Filename:   filename,
		Violations: []Violation{},
	}

	// Create linting context
	ctx := NewContext(sql, filename)

	// Attempt tokenization (best effort - some rules don't need it)
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, tokenErr := tkz.Tokenize([]byte(sql))
	if tokenErr == nil {
		ctx.WithTokens(tokens)

		// Attempt parsing (best effort - some rules are token-only)
		convertedTokens, convErr := parser.ConvertTokensForParser(tokens)
		if convErr == nil {
			p := parser.NewParser()
			astObj, parseErr := p.Parse(convertedTokens)
			ctx.WithAST(astObj, parseErr)
		}
	}

	// Run all rules
	for _, rule := range l.rules {
		violations, err := rule.Check(ctx)
		if err != nil {
			result.Error = fmt.Errorf("rule %s failed: %w", rule.ID(), err)
			return result
		}
		result.Violations = append(result.Violations, violations...)
	}

	return result
}

// LintFiles lints multiple files
func (l *Linter) LintFiles(filenames []string) Result {
	result := Result{
		Files:      make([]FileResult, 0, len(filenames)),
		TotalFiles: len(filenames),
	}

	for _, filename := range filenames {
		fileResult := l.LintFile(filename)
		result.Files = append(result.Files, fileResult)
		result.TotalViolations += len(fileResult.Violations)
	}

	return result
}

// LintDirectory recursively lints all SQL files in a directory
func (l *Linter) LintDirectory(dir string, pattern string) Result {
	var files []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			matched, matchErr := filepath.Match(pattern, filepath.Base(path))
			if matchErr != nil {
				return matchErr
			}
			if matched {
				files = append(files, path)
			}
		}

		return nil
	})

	if err != nil {
		return Result{
			Files: []FileResult{{
				Filename: dir,
				Error:    fmt.Errorf("failed to walk directory: %w", err),
			}},
		}
	}

	return l.LintFiles(files)
}

// FormatViolation returns a formatted string representation of a violation
func FormatViolation(v Violation) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("[%s] %s at line %d, column %d\n",
		v.Rule, v.RuleName, v.Location.Line, v.Location.Column))
	sb.WriteString(fmt.Sprintf("  Severity: %s\n", v.Severity))
	sb.WriteString(fmt.Sprintf("  %s\n", v.Message))

	if v.Line != "" {
		sb.WriteString(fmt.Sprintf("\n  %4d | %s\n", v.Location.Line, v.Line))
		// Add indicator for column position
		if v.Location.Column > 0 {
			sb.WriteString("       | ")
			sb.WriteString(strings.Repeat(" ", v.Location.Column-1))
			sb.WriteString("^\n")
		}
	}

	if v.Suggestion != "" {
		sb.WriteString(fmt.Sprintf("\n  Suggestion: %s\n", v.Suggestion))
	}

	return sb.String()
}

// FormatResult returns a formatted string representation of linting results
func FormatResult(result Result) string {
	var sb strings.Builder

	for _, fileResult := range result.Files {
		if fileResult.Error != nil {
			sb.WriteString(fmt.Sprintf("\n%s: ERROR: %v\n", fileResult.Filename, fileResult.Error))
			continue
		}

		if len(fileResult.Violations) == 0 {
			continue
		}

		sb.WriteString(fmt.Sprintf("\n%s: %d violation(s)\n", fileResult.Filename, len(fileResult.Violations)))
		sb.WriteString(strings.Repeat("=", 80) + "\n")

		for _, violation := range fileResult.Violations {
			sb.WriteString(FormatViolation(violation))
			sb.WriteString("\n")
		}
	}

	// Summary
	sb.WriteString(fmt.Sprintf("\n%s\n", strings.Repeat("=", 80)))
	sb.WriteString(fmt.Sprintf("Total files: %d\n", result.TotalFiles))
	sb.WriteString(fmt.Sprintf("Total violations: %d\n", result.TotalViolations))

	return sb.String()
}
