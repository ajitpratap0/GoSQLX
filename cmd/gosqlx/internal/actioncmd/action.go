// Package actioncmd implements the gosqlx action subcommand for GitHub Actions CI.
package actioncmd

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/style"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/whitespace"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// builtinRules returns all built-in lint rules. This is the single source of
// truth — both defaultLinter() and allRules() derive from it.
func builtinRules() []linter.Rule {
	return []linter.Rule{
		whitespace.NewTrailingWhitespaceRule(),           // L001
		whitespace.NewMixedIndentationRule(),             // L002
		whitespace.NewConsecutiveBlankLinesRule(2),       // L003
		whitespace.NewIndentationDepthRule(10, 4),        // L004
		whitespace.NewLongLinesRule(120),                 // L005
		style.NewColumnAlignmentRule(),                   // L006
		keywords.NewKeywordCaseRule(keywords.CaseUpper),  // L007
		style.NewCommaPlacementRule(style.CommaTrailing), // L008
		style.NewAliasingConsistencyRule(true),           // L009
		whitespace.NewRedundantWhitespaceRule(),          // L010
	}
}

var (
	actionFiles    string
	actionRules    string
	actionSeverity string
	actionConfig   string
	actionTimeout  int
)

// NewCmd returns the action cobra.Command.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "action",
		Short: "Run GoSQLX checks for GitHub Actions CI",
		Long: `Run SQL validation and linting with GitHub Actions annotation output.

This command replaces the shell-based entrypoint for the GoSQLX GitHub Action.
It finds SQL files matching a glob pattern, runs validation and linting on each,
and outputs results as GitHub Actions annotations (::error::, ::warning::, ::notice::).

Environment variables (also settable via flags):
  SQL_FILES  - glob pattern for SQL files (default: **/*.sql)
  RULES      - comma-separated lint rules
  SEVERITY   - threshold: error, warning, info (default: warning)
  CONFIG     - path to .gosqlx.yml config file
  TIMEOUT    - per-file timeout in seconds (default: 600)`,
		RunE: runAction,
	}

	cmd.Flags().StringVar(&actionFiles, "files", "", "glob pattern for SQL files (env: SQL_FILES)")
	cmd.Flags().StringVar(&actionRules, "rules", "", "comma-separated lint rules (env: RULES)")
	cmd.Flags().StringVar(&actionSeverity, "severity", "", "severity threshold: error, warning, info (env: SEVERITY)")
	cmd.Flags().StringVar(&actionConfig, "config", "", "path to config file (env: CONFIG)")
	cmd.Flags().IntVar(&actionTimeout, "timeout", 0, "per-file timeout in seconds (env: TIMEOUT)")

	return cmd
}

func envDefault(flagVal, envKey, fallback string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	return fallback
}

func runAction(_ *cobra.Command, _ []string) error {
	pattern := envDefault(actionFiles, "SQL_FILES", "**/*.sql")
	rules := envDefault(actionRules, "RULES", "")
	severity := envDefault(actionSeverity, "SEVERITY", "warning")
	cfgPath := envDefault(actionConfig, "CONFIG", "")

	timeoutSec := actionTimeout
	if timeoutSec == 0 {
		if v := os.Getenv("TIMEOUT"); v != "" {
			if parsed, err := strconv.Atoi(v); err == nil {
				timeoutSec = parsed
			}
		}
		if timeoutSec == 0 {
			timeoutSec = 600
		}
	}

	fmt.Printf("SQL file pattern: %s\n", pattern)
	fmt.Printf("Severity threshold: %s\n", severity)

	if cfgPath != "" {
		if _, err := os.Stat(cfgPath); err == nil {
			fmt.Printf("Using config: %s\n", cfgPath)
			if err := os.Setenv("GOSQLX_CONFIG", cfgPath); err != nil {
				return fmt.Errorf("setting GOSQLX_CONFIG: %w", err)
			}
		} else {
			ghAnnotation("warning", "", 0, fmt.Sprintf("Config file not found: %s", cfgPath))
		}
	}

	files, err := findSQLFiles(pattern)
	if err != nil {
		return fmt.Errorf("finding SQL files: %w", err)
	}
	if len(files) == 0 {
		ghAnnotation("warning", "", 0, fmt.Sprintf("No SQL files found matching pattern: %s", pattern))
		return nil
	}
	fmt.Printf("Found %d SQL file(s)\n", len(files))

	var ruleList []string
	if rules != "" {
		for _, r := range strings.Split(rules, ",") {
			r = strings.TrimSpace(r)
			if r != "" {
				ruleList = append(ruleList, r)
			}
		}
	}

	var (
		lintErrors     int
		lintWarnings   int
		validateErrors int
		totalValid     int
	)

	timeout := time.Duration(timeoutSec) * time.Second
	lineRe := regexp.MustCompile(`(?i)line\s*(\d+)`)

	for _, file := range files {
		displayFile := strings.TrimPrefix(file, "./")

		vErr := validateFileWithTimeout(file, timeout)
		if vErr != nil {
			validateErrors++
			if strings.Contains(vErr.Error(), "timeout") {
				ghAnnotation("error", displayFile, 0, fmt.Sprintf("Validation timed out after %ds", timeoutSec))
			} else {
				for _, line := range strings.Split(vErr.Error(), "\n") {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					lineno := extractLineNumber(lineRe, line)
					ghAnnotation("error", displayFile, lineno, line)
				}
			}
		} else {
			totalValid++
		}

		violations := lintFile(file, ruleList)
		for _, v := range violations {
			level := "notice"
			if strings.EqualFold(v.Severity, "error") {
				level = "error"
				lintErrors++
			} else if strings.EqualFold(v.Severity, "warning") {
				level = "warning"
				lintWarnings++
			}
			ghAnnotation(level, displayFile, v.Line, v.Message)
		}
	}

	fmt.Println()
	fmt.Println("==============================")
	fmt.Println("  GoSQLX Results Summary")
	fmt.Println("==============================")
	fmt.Printf("  Files scanned:      %d\n", len(files))
	fmt.Printf("  Validation passed:  %d\n", totalValid)
	fmt.Printf("  Validation errors:  %d\n", validateErrors)
	fmt.Printf("  Lint errors:        %d\n", lintErrors)
	fmt.Printf("  Lint warnings:      %d\n", lintWarnings)
	fmt.Println("==============================")

	if summaryPath := os.Getenv("GITHUB_STEP_SUMMARY"); summaryPath != "" {
		writeStepSummary(summaryPath, len(files), totalValid, validateErrors, lintErrors, lintWarnings)
	}

	fail := false
	switch severity {
	case "error":
		fail = validateErrors > 0 || lintErrors > 0
	case "warning", "info":
		fail = validateErrors > 0 || lintErrors > 0 || lintWarnings > 0
	}
	if fail {
		return fmt.Errorf("checks failed: %d validation errors, %d lint errors, %d lint warnings",
			validateErrors, lintErrors, lintWarnings)
	}
	return nil
}

func ghAnnotation(level, file string, line int, msg string) {
	params := ""
	if file != "" {
		params = "file=" + file
		if line > 0 {
			params += fmt.Sprintf(",line=%d", line)
		}
	}
	if params != "" {
		fmt.Printf("::%s %s::%s\n", level, params, msg)
	} else {
		fmt.Printf("::%s::%s\n", level, msg)
	}
}

func extractLineNumber(re *regexp.Regexp, text string) int {
	m := re.FindStringSubmatch(text)
	if len(m) >= 2 {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}

func findSQLFiles(pattern string) ([]string, error) {
	var files []string

	switch {
	case pattern == "**/*.sql":
		err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() && strings.HasSuffix(strings.ToLower(path), ".sql") {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	case pattern == "*.sql":
		entries, err := os.ReadDir(".")
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".sql") {
				files = append(files, e.Name())
			}
		}
	default:
		matched, err := filepath.Glob(pattern)
		if err == nil && len(matched) > 0 {
			for _, m := range matched {
				info, statErr := os.Stat(m)
				if statErr == nil && !info.IsDir() {
					files = append(files, m)
				}
			}
		} else {
			err = filepath.Walk(".", func(path string, info os.FileInfo, walkErr error) error {
				if walkErr != nil {
					return nil
				}
				if !info.IsDir() {
					if ok, _ := filepath.Match(pattern, path); ok {
						files = append(files, path)
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
	}
	return files, nil
}

type lintViolation struct {
	Line     int
	Severity string
	Message  string
}

// defaultLinter creates a linter with all built-in rules.
func defaultLinter() *linter.Linter {
	return linter.New(builtinRules()...)
}

// allRules returns every built-in rule keyed by its ID.
func allRules() map[string]linter.Rule {
	all := builtinRules()
	m := make(map[string]linter.Rule, len(all))
	for _, r := range all {
		m[r.ID()] = r
	}
	return m
}

// lintFile runs the linter on a file and returns violations.
// When ruleList is non-empty only the rules whose IDs match are executed.
func lintFile(filePath string, ruleList []string) []lintViolation {
	var l *linter.Linter
	if len(ruleList) == 0 {
		l = defaultLinter()
	} else {
		available := allRules()
		var selected []linter.Rule
		for _, id := range ruleList {
			if r, ok := available[id]; ok {
				selected = append(selected, r)
			}
		}
		if len(selected) == 0 {
			return nil
		}
		l = linter.New(selected...)
	}
	result := l.LintFile(filePath)

	if result.Error != nil {
		return []lintViolation{{Line: 0, Severity: "error", Message: fmt.Sprintf("lint error: %v", result.Error)}}
	}

	var violations []lintViolation
	for _, v := range result.Violations {
		sev := "warning"
		if v.Severity == linter.SeverityError {
			sev = "error"
		}
		violations = append(violations, lintViolation{
			Line:     v.Location.Line,
			Severity: sev,
			Message:  fmt.Sprintf("[%s] %s", v.Rule, v.Message),
		})
	}
	return violations
}

func validateFileWithTimeout(filePath string, timeout time.Duration) error {
	type result struct {
		err error
	}
	ch := make(chan result, 1)

	go func() {
		data, err := os.ReadFile(filepath.Clean(filePath))
		if err != nil {
			ch <- result{err: fmt.Errorf("cannot read file: %w", err)}
			return
		}
		ch <- result{err: parser.ValidateBytes(data)}
	}()

	select {
	case r := <-ch:
		return r.err
	case <-time.After(timeout):
		return fmt.Errorf("timeout after %v", timeout)
	}
}

func writeStepSummary(path string, total, valid, valErrors, lintErrors, lintWarnings int) {
	f, err := os.OpenFile(filepath.Clean(path), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()

	summary := fmt.Sprintf(`
## GoSQLX Lint + Validation Results

| Metric | Count |
|--------|-------|
| Files Scanned | %d |
| Validation Passed | %d |
| Validation Errors | %d |
| Lint Errors | %d |
| Lint Warnings | %d |
`, total, valid, valErrors, lintErrors, lintWarnings)

	fmt.Fprint(f, summary)
}
