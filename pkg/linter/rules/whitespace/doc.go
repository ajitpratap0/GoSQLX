// Package whitespace provides linting rules for whitespace and formatting issues.
//
// This package includes 6 whitespace-related rules (L001-L005, L010) that enforce
// consistent whitespace usage, indentation, and line formatting in SQL code.
//
// # Rules in this Package
//
// L001: Trailing Whitespace (auto-fix)
//   - Detects and removes unnecessary trailing spaces or tabs at line ends
//   - Severity: Warning
//   - Common issue: Editor artifacts, copy-paste problems
//
// L002: Mixed Indentation (auto-fix)
//   - Enforces consistent use of tabs or spaces for indentation
//   - Converts all indentation to spaces (4 spaces per tab)
//   - Severity: Error
//   - Common issue: Multiple developers with different editor settings
//
// L003: Consecutive Blank Lines (auto-fix)
//   - Limits consecutive blank lines to a configurable maximum
//   - Default: Maximum 1 blank line between statements
//   - Severity: Warning
//   - Common issue: Excessive vertical spacing reducing code density
//
// L004: Indentation Depth (no auto-fix)
//   - Warns about excessive indentation depth indicating complex queries
//   - Configurable maximum depth (default: 4 levels)
//   - Severity: Warning
//   - Common issue: Deeply nested subqueries needing refactoring
//
// L005: Line Length (no auto-fix)
//   - Enforces maximum line length for readability
//   - Configurable maximum (default: 100 characters)
//   - Skips comment-only lines
//   - Severity: Info
//   - Common issue: Long lines hard to read in code reviews
//
// L010: Redundant Whitespace (auto-fix)
//   - Removes multiple consecutive spaces (preserves indentation and strings)
//   - Severity: Info
//   - Common issue: Inconsistent spacing between SQL keywords
//
// # Usage Examples
//
// Using trailing whitespace rule:
//
//	import "github.com/ajitpratap0/GoSQLX/pkg/linter/rules/whitespace"
//
//	rule := whitespace.NewTrailingWhitespaceRule()
//	violations, err := rule.Check(ctx)
//	if len(violations) > 0 {
//	    fixed, _ := rule.Fix(sql, violations)
//	    // Use fixed SQL
//	}
//
// Using mixed indentation rule:
//
//	rule := whitespace.NewMixedIndentationRule()
//	violations, _ := rule.Check(ctx)
//	// Converts all tabs to 4 spaces
//	fixed, _ := rule.Fix(sql, violations)
//
// Using consecutive blank lines with custom limit:
//
//	rule := whitespace.NewConsecutiveBlankLinesRule(2)  // Allow max 2 blank lines
//	violations, _ := rule.Check(ctx)
//	fixed, _ := rule.Fix(sql, violations)
//
// Using indentation depth with custom settings:
//
//	rule := whitespace.NewIndentationDepthRule(5, 4)  // Max 5 levels, 4 spaces per level
//	violations, _ := rule.Check(ctx)
//	// No auto-fix available - violations indicate refactoring needed
//
// Using line length with custom maximum:
//
//	rule := whitespace.NewLongLinesRule(120)  // Max 120 characters
//	violations, _ := rule.Check(ctx)
//	// No auto-fix available - requires manual line breaking
//
// Using redundant whitespace rule:
//
//	rule := whitespace.NewRedundantWhitespaceRule()
//	violations, _ := rule.Check(ctx)
//	fixed, _ := rule.Fix(sql, violations)  // Multiple spaces become single space
//
// # Auto-Fix Behavior
//
// Four rules support auto-fixing (L001, L002, L003, L010):
//
// L001 (Trailing Whitespace):
//   - Strips trailing spaces and tabs from each line
//   - Preserves line content and newlines
//   - Safe to apply without review
//
// L002 (Mixed Indentation):
//   - Converts tabs to 4 spaces in leading whitespace only
//   - Preserves tabs inside SQL strings and comments
//   - Should be reviewed if project uses tabs intentionally
//
// L003 (Consecutive Blank Lines):
//   - Reduces consecutive blank lines to configured maximum
//   - Trims excess blank lines at file end
//   - Safe to apply without review
//
// L010 (Redundant Whitespace):
//   - Reduces 2+ consecutive spaces to single space
//   - Preserves leading indentation
//   - Preserves spaces inside string literals
//   - Safe to apply without review
//
// Rules without auto-fix (L004, L005) require manual refactoring or line breaking.
//
// # Configuration Recommendations
//
// Production environments:
//
//	whitespace.NewTrailingWhitespaceRule()              // Always enable
//	whitespace.NewMixedIndentationRule()                // Always enable
//	whitespace.NewConsecutiveBlankLinesRule(1)          // 1 blank line max
//	whitespace.NewIndentationDepthRule(4, 4)            // Warn at 4 levels
//	whitespace.NewLongLinesRule(100)                    // 100 char limit
//	whitespace.NewRedundantWhitespaceRule()             // Always enable
//
// Strict style enforcement:
//
//	whitespace.NewTrailingWhitespaceRule()              // Error on trailing whitespace
//	whitespace.NewMixedIndentationRule()                // Error on mixed indentation
//	whitespace.NewConsecutiveBlankLinesRule(1)          // Max 1 blank line
//	whitespace.NewIndentationDepthRule(3, 4)            // Warn at 3 levels (stricter)
//	whitespace.NewLongLinesRule(80)                     // 80 char limit (stricter)
//	whitespace.NewRedundantWhitespaceRule()             // Clean up spacing
//
// Relaxed style (legacy code):
//
//	whitespace.NewTrailingWhitespaceRule()              // Still remove trailing whitespace
//	// Skip L002 if tabs are intentional
//	whitespace.NewConsecutiveBlankLinesRule(2)          // Allow 2 blank lines
//	whitespace.NewIndentationDepthRule(6, 4)            // Warn only at 6 levels
//	whitespace.NewLongLinesRule(120)                    // 120 char limit
//	// Skip L010 if varied spacing is intentional
//
// # Performance Characteristics
//
// All whitespace rules are text-based and do not require tokenization or parsing.
// They operate on line-by-line scanning with O(n) complexity where n is line count.
//
// Typical performance (lines per second):
//   - L001, L002, L003, L010: 100,000+ lines/sec
//   - L004: 80,000+ lines/sec (includes depth calculation)
//   - L005: 100,000+ lines/sec
//
// Auto-fix operations add minimal overhead (<10% slowdown).
//
// # Thread Safety
//
// All rule types in this package are stateless and thread-safe.
// Rule instances can be shared across goroutines safely.
package whitespace
