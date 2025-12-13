// Package linter provides a comprehensive SQL linting engine for GoSQLX with
// configurable rules, auto-fix capabilities, and detailed violation reporting.
//
// The linter engine analyzes SQL code at multiple levels (text, tokens, AST) to
// enforce coding standards, style guidelines, and best practices. It includes
// 10 built-in rules covering whitespace, formatting, keywords, and style consistency.
//
// # Architecture
//
// The linter follows a pipeline architecture:
//
//  1. Input: SQL content (string or file)
//  2. Context Creation: Builds linting context with line splitting
//  3. Tokenization: Best-effort tokenization for token-based rules
//  4. Parsing: Best-effort AST generation for AST-based rules
//  5. Rule Execution: All rules check the context independently
//  6. Result Collection: Violations aggregated with severity levels
//
// The pipeline is designed to be fault-tolerant - tokenization and parsing
// failures don't prevent text-based rules from executing. This allows linting
// of partially valid or syntactically incorrect SQL.
//
// # Built-in Rules
//
// The linter includes 10 production-ready rules (v1.6.0):
//
// Whitespace Rules:
//   - L001: Trailing Whitespace - removes trailing spaces/tabs (auto-fix)
//   - L002: Mixed Indentation - enforces consistent tabs/spaces (auto-fix)
//   - L003: Consecutive Blank Lines - limits consecutive blank lines (auto-fix)
//   - L004: Indentation Depth - warns about excessive nesting (no auto-fix)
//   - L005: Line Length - enforces maximum line length (no auto-fix)
//   - L010: Redundant Whitespace - removes multiple consecutive spaces (auto-fix)
//
// Style Rules:
//   - L006: Column Alignment - checks SELECT column alignment (no auto-fix)
//   - L008: Comma Placement - enforces trailing/leading comma style (no auto-fix)
//   - L009: Aliasing Consistency - checks consistent table alias usage (no auto-fix)
//
// Keyword Rules:
//   - L007: Keyword Case - enforces uppercase/lowercase keywords (auto-fix)
//
// # Basic Usage
//
// Create a linter with desired rules and lint SQL content:
//
//	import (
//	    "fmt"
//	    "github.com/ajitpratap0/GoSQLX/pkg/linter"
//	    "github.com/ajitpratap0/GoSQLX/pkg/linter/rules/whitespace"
//	    "github.com/ajitpratap0/GoSQLX/pkg/linter/rules/keywords"
//	)
//
//	func main() {
//	    // Create linter with selected rules
//	    l := linter.New(
//	        whitespace.NewTrailingWhitespaceRule(),
//	        whitespace.NewMixedIndentationRule(),
//	        keywords.NewKeywordCaseRule(keywords.CaseUpper),
//	    )
//
//	    // Lint SQL string
//	    sql := "SELECT * FROM users WHERE active = true  "
//	    result := l.LintString(sql, "query.sql")
//
//	    // Check for violations
//	    if len(result.Violations) > 0 {
//	        fmt.Println(linter.FormatResult(linter.Result{
//	            Files: []linter.FileResult{result},
//	            TotalFiles: 1,
//	            TotalViolations: len(result.Violations),
//	        }))
//	    }
//	}
//
// # Linting Files and Directories
//
// The linter supports single files, multiple files, and directory recursion:
//
//	// Lint single file
//	fileResult := l.LintFile("path/to/query.sql")
//
//	// Lint multiple files
//	files := []string{"query1.sql", "query2.sql", "schema.sql"}
//	result := l.LintFiles(files)
//
//	// Lint directory recursively with pattern matching
//	result := l.LintDirectory("/path/to/sql/files", "*.sql")
//	fmt.Printf("Found %d violations in %d files\n",
//	    result.TotalViolations, result.TotalFiles)
//
// # Auto-Fix Support
//
// Five rules support automatic fixing (L001, L002, L003, L007, L010):
//
//	sql := "select  *  from  users"  // Multiple spaces, lowercase keywords
//
//	// Lint to find violations
//	result := l.LintString(sql, "query.sql")
//
//	// Apply auto-fixes for rules that support it
//	fixedSQL := sql
//	for _, rule := range l.Rules() {
//	    if rule.CanAutoFix() {
//	        violations := filterViolationsByRule(result.Violations, rule.ID())
//	        if len(violations) > 0 {
//	            fixedSQL, _ = rule.Fix(fixedSQL, violations)
//	        }
//	    }
//	}
//	// Result: "SELECT * FROM users" (uppercase keywords, single spaces)
//
// # Custom Rules
//
// Implement the Rule interface to create custom linting rules:
//
//	type CustomRule struct {
//	    linter.BaseRule
//	}
//
//	func NewCustomRule() *CustomRule {
//	    return &CustomRule{
//	        BaseRule: linter.NewBaseRule(
//	            "C001",                          // Unique rule ID
//	            "Custom Rule Name",              // Human-readable name
//	            "Description of what it checks", // Rule description
//	            linter.SeverityWarning,          // Default severity
//	            false,                           // Auto-fix support
//	        ),
//	    }
//	}
//
//	func (r *CustomRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
//	    violations := []linter.Violation{}
//
//	    // Access SQL content
//	    for lineNum, line := range ctx.Lines {
//	        // Your custom logic here
//	        if hasViolation(line) {
//	            violations = append(violations, linter.Violation{
//	                Rule:       r.ID(),
//	                RuleName:   r.Name(),
//	                Severity:   r.Severity(),
//	                Message:    "Violation description",
//	                Location:   models.Location{Line: lineNum + 1, Column: 1},
//	                Line:       line,
//	                Suggestion: "How to fix this",
//	                CanAutoFix: false,
//	            })
//	        }
//	    }
//
//	    return violations, nil
//	}
//
//	func (r *CustomRule) Fix(content string, violations []linter.Violation) (string, error) {
//	    // Return unchanged if no auto-fix support
//	    return content, nil
//	}
//
// # Accessing Context Data
//
// Rules receive a Context with multi-level access to SQL:
//
//	func (r *CustomRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
//	    // Text level: Raw SQL and lines
//	    sql := ctx.SQL           // Complete SQL string
//	    lines := ctx.Lines       // Split into lines
//	    line5 := ctx.GetLine(5)  // Get specific line (1-indexed)
//	    count := ctx.GetLineCount()
//
//	    // Token level: Tokenization results (if available)
//	    if ctx.Tokens != nil {
//	        for _, tok := range ctx.Tokens {
//	            // Check token type, value, position
//	            fmt.Printf("Token: %s at %d:%d\n",
//	                tok.Token.Type, tok.Span.Start.Line, tok.Span.Start.Column)
//	        }
//	    }
//
//	    // AST level: Parsed structure (if available)
//	    if ctx.AST != nil && ctx.ParseErr == nil {
//	        for _, stmt := range ctx.AST.Statements {
//	            // Analyze statement structure
//	            if selectStmt, ok := stmt.(*ast.SelectStatement); ok {
//	                // Check SELECT statement properties
//	            }
//	        }
//	    }
//
//	    // Metadata
//	    filename := ctx.Filename
//
//	    return violations, nil
//	}
//
// # Severity Levels
//
// Violations are categorized by severity:
//
//   - SeverityError: Critical issues that should block deployment
//   - SeverityWarning: Important issues that should be addressed
//   - SeverityInfo: Style preferences and suggestions
//
// Severity affects violation reporting priority and can be used for CI/CD
// failure thresholds (e.g., fail on errors, warn on warnings).
//
// # Violation Reporting
//
// Each violation includes detailed context:
//
//	violation := linter.Violation{
//	    Rule:       "L001",                               // Rule ID
//	    RuleName:   "Trailing Whitespace",                // Rule name
//	    Severity:   linter.SeverityWarning,               // Severity level
//	    Message:    "Line has trailing whitespace",       // What's wrong
//	    Location:   models.Location{Line: 42, Column: 80}, // Where (1-indexed)
//	    Line:       "SELECT * FROM users  ",              // Actual line
//	    Suggestion: "Remove trailing spaces",             // How to fix
//	    CanAutoFix: true,                                 // Auto-fix available
//	}
//
// Use FormatViolation() and FormatResult() for human-readable output:
//
//	fmt.Println(linter.FormatViolation(violation))
//	// Output:
//	// [L001] Trailing Whitespace at line 42, column 80
//	//   Severity: warning
//	//   Line has trailing whitespace
//	//
//	//     42 | SELECT * FROM users
//	//        |                    ^
//	//
//	//   Suggestion: Remove trailing spaces
//
// # Configuration Example
//
// Typical production configuration with commonly used rules:
//
//	import (
//	    "github.com/ajitpratap0/GoSQLX/pkg/linter"
//	    "github.com/ajitpratap0/GoSQLX/pkg/linter/rules/whitespace"
//	    "github.com/ajitpratap0/GoSQLX/pkg/linter/rules/keywords"
//	    "github.com/ajitpratap0/GoSQLX/pkg/linter/rules/style"
//	)
//
//	func NewProductionLinter() *linter.Linter {
//	    return linter.New(
//	        // Whitespace rules (all with auto-fix)
//	        whitespace.NewTrailingWhitespaceRule(),
//	        whitespace.NewMixedIndentationRule(),
//	        whitespace.NewConsecutiveBlankLinesRule(1),      // Max 1 blank line
//	        whitespace.NewIndentationDepthRule(4, 4),        // Max 4 levels, 4 spaces
//	        whitespace.NewLongLinesRule(100),                // Max 100 chars
//	        whitespace.NewRedundantWhitespaceRule(),
//
//	        // Keyword rules
//	        keywords.NewKeywordCaseRule(keywords.CaseUpper), // Uppercase keywords
//
//	        // Style rules
//	        style.NewColumnAlignmentRule(),
//	        style.NewCommaPlacementRule(style.CommaTrailing), // Trailing commas
//	        style.NewAliasingConsistencyRule(true),           // Explicit AS keyword
//	    )
//	}
//
// # Integration with CLI
//
// The linter is integrated into the gosqlx CLI tool:
//
//	# Lint with default rules
//	gosqlx lint query.sql
//
//	# Lint with auto-fix
//	gosqlx lint --fix query.sql
//
//	# Lint entire directory
//	gosqlx lint --recursive /path/to/sql/files
//
//	# Configure via .gosqlx.yml
//	linter:
//	  rules:
//	    - id: L001
//	      enabled: true
//	    - id: L007
//	      enabled: true
//	      config:
//	        case_style: upper
//	    - id: L005
//	      enabled: true
//	      config:
//	        max_length: 120
//
// # Performance Characteristics
//
// The linter is designed for production use with efficient resource usage:
//
//   - Text-based rules: O(n) where n is line count, fastest
//   - Token-based rules: O(t) where t is token count, uses object pooling
//   - AST-based rules: O(n) where n is AST node count, uses object pooling
//   - Auto-fix operations: O(n) line processing, preserves string literals
//   - Memory: Minimal allocations, reuses tokenizer/parser pools
//
// Typical performance: 10,000+ lines/second per rule on modern hardware.
//
// # Thread Safety
//
// The Linter type is thread-safe and can be reused across goroutines:
//
//	linter := linter.New(rules...)
//
//	// Safe to call concurrently
//	var wg sync.WaitGroup
//	for _, file := range files {
//	    wg.Add(1)
//	    go func(f string) {
//	        defer wg.Done()
//	        result := linter.LintFile(f)
//	        processResult(result)
//	    }(file)
//	}
//	wg.Wait()
//
// The Context and Rule implementations are designed for concurrent execution,
// using read-only access patterns and avoiding shared mutable state.
//
// # Error Handling
//
// The linter uses graceful error handling:
//
//   - File read errors: Returned in FileResult.Error, don't stop batch processing
//   - Tokenization errors: Logged but don't prevent text-based rules from running
//   - Parse errors: Stored in Context.ParseErr, AST-based rules can fall back to text
//   - Rule errors: Returned in FileResult.Error, indicate rule implementation issues
//
// Example error handling:
//
//	result := linter.LintFile("query.sql")
//	if result.Error != nil {
//	    log.Printf("Linting error: %v", result.Error)
//	    // Continue processing other files
//	}
//	// Check violations even if errors occurred
//	for _, v := range result.Violations {
//	    handleViolation(v)
//	}
//
// # See Also
//
//   - docs/LINTING_RULES.md - Complete reference for all 10 rules
//   - docs/CONFIGURATION.md - Configuration file (.gosqlx.yml) reference
//   - pkg/linter/rules/ - Rule implementations by category
package linter
