package linter

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Result represents the linting result for one or more files.
// It aggregates individual file results and provides summary statistics
// for batch linting operations.
//
// Fields:
//   - Files: Results for each file that was linted
//   - TotalFiles: Total number of files processed
//   - TotalViolations: Sum of violations across all files
//
// Use FormatResult to generate human-readable output.
type Result struct {
	Files           []FileResult
	TotalFiles      int
	TotalViolations int
}

// FileResult represents linting results for a single file.
//
// Fields:
//   - Filename: Path to the file that was linted
//   - Violations: All rule violations found in this file
//   - Error: Any error encountered during linting (file read, rule execution)
//
// A FileResult with non-nil Error may still contain partial violations
// from rules that executed successfully before the error occurred.
type FileResult struct {
	Filename   string
	Violations []Violation
	Error      error
}

// Linter performs SQL linting with configurable rules.
// A Linter instance is thread-safe and can be reused across goroutines.
//
// The linter executes all configured rules independently, collecting violations
// from each. Rules have access to SQL text, tokens (if tokenization succeeds),
// and AST (if parsing succeeds), allowing multi-level analysis.
//
// Example:
//
//	linter := linter.New(
//	    whitespace.NewTrailingWhitespaceRule(),
//	    keywords.NewKeywordCaseRule(keywords.CaseUpper),
//	)
//	result := linter.LintFile("query.sql")
type Linter struct {
	rules []Rule
}

// New creates a new linter with the given rules.
//
// Rules are executed in the order provided, though results are order-independent.
// The same linter instance can be safely reused for multiple files.
//
// Example:
//
//	linter := linter.New(
//	    whitespace.NewTrailingWhitespaceRule(),
//	    whitespace.NewMixedIndentationRule(),
//	    keywords.NewKeywordCaseRule(keywords.CaseUpper),
//	)
func New(rules ...Rule) *Linter {
	return &Linter{
		rules: rules,
	}
}

// Rules returns the list of rules configured for this linter.
// The returned slice should not be modified.
func (l *Linter) Rules() []Rule {
	return l.rules
}

// LintFile lints a single SQL file.
//
// The file is read from disk and processed through all configured rules.
// If the file cannot be read, a FileResult with a non-nil Error is returned.
//
// Returns a FileResult containing any violations found and potential errors.
//
// Example:
//
//	result := linter.LintFile("queries/user_search.sql")
//	if result.Error != nil {
//	    log.Printf("Error linting file: %v", result.Error)
//	}
//	for _, v := range result.Violations {
//	    fmt.Println(linter.FormatViolation(v))
//	}
func (l *Linter) LintFile(filename string) FileResult {
	// Read file
	content, err := os.ReadFile(filepath.Clean(filename)) // #nosec G304 // #nosec G304
	if err != nil {
		return FileResult{
			Filename: filename,
			Error:    fmt.Errorf("failed to read file: %w", err),
		}
	}

	return l.LintString(string(content), filename)
}

// LintString lints SQL content provided as a string.
//
// This method is useful for linting SQL from sources other than files (e.g.,
// in-memory queries, database dumps, or editor buffers). The filename parameter
// is used only for violation reporting and can be a logical name.
//
// The method performs best-effort tokenization and parsing. If tokenization fails,
// only text-based rules execute. If parsing fails, token-based rules still run.
// This allows partial linting of syntactically invalid SQL.
//
// Returns a FileResult containing violations. The Error field is only set if
// a rule execution fails, not for tokenization/parsing failures.
//
// Example:
//
//	sql := "SELECT * FROM users WHERE status = 'active'"
//	result := linter.LintString(sql, "<stdin>")
//	fmt.Printf("Found %d violations\n", len(result.Violations))
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
		p := parser.GetParser()
		astObj, parseErr := p.ParseFromModelTokens(tokens)
		parser.PutParser(p)
		ctx.WithAST(astObj, parseErr)
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

// LintFiles lints multiple files in batch.
//
// Each file is linted independently. Errors reading or linting one file don't
// prevent processing of other files. Individual file errors are captured in
// each FileResult.Error field.
//
// Returns a Result with aggregated statistics and individual FileResults.
//
// Example:
//
//	files := []string{
//	    "queries/search.sql",
//	    "queries/reports.sql",
//	    "schema/tables.sql",
//	}
//	result := linter.LintFiles(files)
//	fmt.Printf("Processed %d files, found %d violations\n",
//	    result.TotalFiles, result.TotalViolations)
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

// LintDirectory recursively lints all SQL files in a directory.
//
// The directory is walked recursively, and all files matching the pattern
// are linted. The pattern uses filepath.Match syntax (e.g., "*.sql", "test_*.sql").
//
// Directory walk errors are returned in a single FileResult with Error set.
// Individual file linting errors are handled per-file.
//
// Returns a Result with all matching files processed.
//
// Example:
//
//	// Lint all .sql files in directory tree
//	result := linter.LintDirectory("./database", "*.sql")
//
//	// Lint only test files
//	result := linter.LintDirectory("./database", "test_*.sql")
//
//	// Process results
//	for _, fileResult := range result.Files {
//	    if fileResult.Error != nil {
//	        log.Printf("Error: %s: %v", fileResult.Filename, fileResult.Error)
//	    }
//	    for _, violation := range fileResult.Violations {
//	        fmt.Println(linter.FormatViolation(violation))
//	    }
//	}
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

// FormatViolation returns a formatted string representation of a violation.
//
// The output includes:
//   - Rule ID and name
//   - Location (line and column)
//   - Severity level
//   - Message describing the violation
//   - The actual line content with column indicator
//   - Suggestion for fixing (if available)
//
// Example output:
//
//	[L001] Trailing Whitespace at line 42, column 80
//	  Severity: warning
//	  Line has trailing whitespace
//
//	    42 | SELECT * FROM users
//	       |                    ^
//
//	  Suggestion: Remove trailing spaces or tabs from the end of the line
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

// FormatResult returns a formatted string representation of linting results.
//
// Produces a comprehensive report including:
//   - Per-file violation details with formatted violations
//   - File-level error messages for files that couldn't be linted
//   - Summary statistics (total files, total violations)
//
// Files with no violations are omitted from the output for clarity.
//
// Example output:
//
//	queries/search.sql: 3 violation(s)
//	================================================================================
//	[L001] Trailing Whitespace at line 5, column 42
//	  Severity: warning
//	  ...
//
//	================================================================================
//	Total files: 10
//	Total violations: 15
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
