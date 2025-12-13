// Package keywords provides linting rules for SQL keyword formatting and consistency.
//
// This package includes rules that enforce consistent keyword case and formatting
// across SQL code, improving readability and maintaining coding standards.
//
// # Rules in this Package
//
// L007: Keyword Case Consistency (auto-fix)
//   - Enforces consistent uppercase or lowercase for SQL keywords
//   - Configurable style: CaseUpper (SELECT) or CaseLower (select)
//   - Severity: Warning
//   - Supports 60+ common SQL keywords across dialects
//
// # Supported Keywords
//
// The L007 rule recognizes keywords from multiple SQL dialects:
//
// Core SQL:
//
//	SELECT, FROM, WHERE, AND, OR, NOT, IN, IS, NULL, LIKE, BETWEEN,
//	EXISTS, CASE, WHEN, THEN, ELSE, END, AS, TRUE, FALSE
//
// JOINs:
//
//	JOIN, INNER, LEFT, RIGHT, FULL, OUTER, CROSS, NATURAL, ON, USING
//
// Grouping & Ordering:
//
//	GROUP, BY, HAVING, ORDER, ASC, DESC, LIMIT, OFFSET
//
// Set Operations:
//
//	UNION, ALL, EXCEPT, INTERSECT
//
// DML (Data Manipulation):
//
//	INSERT, INTO, VALUES, UPDATE, SET, DELETE
//
// DDL (Data Definition):
//
//	CREATE, TABLE, INDEX, VIEW, DROP, ALTER, ADD, COLUMN, CONSTRAINT
//
// Constraints:
//
//	PRIMARY, KEY, FOREIGN, REFERENCES, UNIQUE, CHECK, DEFAULT, CASCADE
//
// Advanced Features (v1.6.0):
//
//	WITH, RECURSIVE, DISTINCT, OVER, PARTITION, ROWS, RANGE, UNBOUNDED,
//	PRECEDING, FOLLOWING, CURRENT, ROW, RETURNING, COALESCE, NULLIF, CAST,
//	MERGE, MATCHED, MATERIALIZED, REFRESH, ROLLUP, CUBE, GROUPING, SETS
//
// # Usage Examples
//
// Enforce uppercase keywords (most common):
//
//	import "github.com/ajitpratap0/GoSQLX/pkg/linter/rules/keywords"
//
//	rule := keywords.NewKeywordCaseRule(keywords.CaseUpper)
//	violations, _ := rule.Check(ctx)
//	if len(violations) > 0 {
//	    fixed, _ := rule.Fix(sql, violations)
//	    // Result: "SELECT * FROM users WHERE active = true"
//	}
//
// Enforce lowercase keywords:
//
//	rule := keywords.NewKeywordCaseRule(keywords.CaseLower)
//	violations, _ := rule.Check(ctx)
//	fixed, _ := rule.Fix(sql, violations)
//	// Result: "select * from users where active = true"
//
// Default behavior (uppercase if not specified):
//
//	rule := keywords.NewKeywordCaseRule("")  // Defaults to CaseUpper
//
// # Auto-Fix Behavior
//
// The L007 rule supports automatic fixing with intelligent string handling:
//
// Conversion:
//   - Uppercase mode: Converts all keywords to UPPERCASE
//   - Lowercase mode: Converts all keywords to lowercase
//   - Preserves identifiers (table names, column names) in original case
//
// String Literal Handling:
//   - Keywords inside single quotes ('SELECT') are NOT converted
//   - Keywords inside double quotes ("SELECT") are NOT converted
//   - Only keywords in actual SQL code are affected
//
// Example transformations:
//
//	Input:  "Select * From users Where status = 'Active'"
//	Upper:  "SELECT * FROM users WHERE status = 'Active'"
//	Lower:  "select * from users where status = 'Active'"
//
//	Input:  "INSERT INTO logs (action) VALUES ('SELECT operation')"
//	Upper:  "INSERT INTO logs (action) VALUES ('SELECT operation')"
//	        ^^^^^^^^                   ^^^^^^
//	        (keywords converted, string preserved)
//
// # Style Recommendations
//
// Uppercase keywords (recommended for most projects):
//   - Pros: Clear visual distinction between keywords and identifiers
//   - Pros: Traditional SQL style, matches most documentation
//   - Pros: Used in most database tools and ORMs
//   - Cons: Can feel "shouty" in modern codebases
//
// Lowercase keywords:
//   - Pros: Consistent with modern programming language conventions
//   - Pros: Less visually prominent, cleaner appearance
//   - Pros: Easier to type without shift key
//   - Cons: Less distinction from identifiers
//   - Cons: Less common in SQL community
//
// Industry standards:
//   - Most style guides recommend uppercase: Oracle, Microsoft, PostgreSQL docs
//   - Some modern tools prefer lowercase: sqlfluff (configurable), some ORMs
//   - Choose based on team preference and existing codebase
//
// # Configuration Examples
//
// Strict enterprise style (uppercase):
//
//	rule := keywords.NewKeywordCaseRule(keywords.CaseUpper)
//	// Enforce across entire codebase with auto-fix in CI/CD
//
// Modern application style (lowercase):
//
//	rule := keywords.NewKeywordCaseRule(keywords.CaseLower)
//	// Consistent with application code conventions
//
// Mixed case handling (migration scenario):
//
//	// Phase 1: Detect inconsistencies (don't auto-fix yet)
//	rule := keywords.NewKeywordCaseRule(keywords.CaseUpper)
//	violations, _ := rule.Check(ctx)
//	logViolations(violations)  // Review before fixing
//
//	// Phase 2: Auto-fix after team review
//	fixed, _ := rule.Fix(sql, violations)
//	// Gradually migrate codebase
//
// # Integration with Linter
//
// The keyword case rule integrates seamlessly with the linter:
//
//	linter := linter.New(
//	    keywords.NewKeywordCaseRule(keywords.CaseUpper),
//	    // other rules...
//	)
//	result := linter.LintFile("query.sql")
//
// CLI usage:
//
//	# Check keyword case
//	gosqlx lint query.sql
//
//	# Auto-fix keyword case
//	gosqlx lint --fix query.sql
//
// Configuration file (.gosqlx.yml):
//
//	linter:
//	  rules:
//	    - id: L007
//	      enabled: true
//	      config:
//	        case_style: upper  # or 'lower'
//
// # Performance Characteristics
//
// L007 is a text-based rule with efficient line-by-line processing:
//
// Performance:
//   - Speed: 50,000+ lines/sec on modern hardware
//   - Complexity: O(n) where n is line count
//   - Memory: Minimal allocations, single-pass scanning
//
// Auto-fix performance:
//   - Speed: 40,000+ lines/sec (includes string building)
//   - Preserves all whitespace and formatting
//   - Single-pass conversion with string literal tracking
//
// # Thread Safety
//
// All rule types in this package are stateless and thread-safe.
// Rule instances can be shared across goroutines safely.
//
// # Dialect Compatibility
//
// The keyword list covers keywords from:
//   - SQL-99 standard (core compliance)
//   - PostgreSQL (including extensions)
//   - MySQL/MariaDB
//   - SQL Server (T-SQL)
//   - Oracle (PL/SQL common keywords)
//   - SQLite
//
// Dialect-specific keywords are included for broad compatibility.
package keywords
