package linter

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Severity represents the severity level of a lint violation.
//
// Severity levels can be used to categorize violations and determine
// CI/CD failure thresholds (e.g., fail builds on errors, warn on warnings).
type Severity string

const (
	// SeverityError indicates critical issues that should block deployment.
	// Examples: mixed indentation, syntax errors, security vulnerabilities.
	SeverityError Severity = "error"

	// SeverityWarning indicates important issues that should be addressed.
	// Examples: trailing whitespace, inconsistent keyword case, missing aliases.
	SeverityWarning Severity = "warning"

	// SeverityInfo indicates style preferences and suggestions.
	// Examples: line length, column alignment, comma placement.
	SeverityInfo Severity = "info"
)

// Violation represents a single linting rule violation with full context.
//
// Violations include precise location information, the actual problematic code,
// and suggestions for fixing. Violations may support automatic fixing depending
// on the rule.
//
// Example:
//
//	violation := linter.Violation{
//	    Rule:       "L001",
//	    RuleName:   "Trailing Whitespace",
//	    Severity:   linter.SeverityWarning,
//	    Message:    "Line has trailing whitespace",
//	    Location:   models.Location{Line: 42, Column: 80},
//	    Line:       "SELECT * FROM users  ",
//	    Suggestion: "Remove trailing spaces or tabs",
//	    CanAutoFix: true,
//	}
type Violation struct {
	Rule       string          // Rule ID (e.g., "L001")
	RuleName   string          // Human-readable rule name
	Severity   Severity        // Severity level
	Message    string          // Violation description
	Location   models.Location // Position in source (1-based line and column)
	Line       string          // The actual line content
	Suggestion string          // How to fix the violation
	CanAutoFix bool            // Whether this violation can be auto-fixed
}

// Rule defines the interface that all linting rules must implement.
//
// Rules check SQL content at various levels (text, tokens, AST) and report
// violations. Rules can optionally support automatic fixing of violations.
//
// Implementing a custom rule:
//
//	type MyRule struct {
//	    linter.BaseRule
//	}
//
//	func NewMyRule() *MyRule {
//	    return &MyRule{
//	        BaseRule: linter.NewBaseRule(
//	            "C001",                    // Unique ID
//	            "My Custom Rule",          // Name
//	            "Description of rule",     // Description
//	            linter.SeverityWarning,    // Severity
//	            false,                     // Auto-fix support
//	        ),
//	    }
//	}
//
//	func (r *MyRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
//	    // Implement rule logic
//	    return violations, nil
//	}
//
//	func (r *MyRule) Fix(content string, violations []linter.Violation) (string, error) {
//	    // Implement fix logic (if CanAutoFix is true)
//	    return content, nil
//	}
//
// Rules should be stateless and thread-safe for concurrent use.
type Rule interface {
	// ID returns the unique rule identifier (e.g., "L001", "L002").
	// IDs should be unique across all rules in a linter instance.
	// Built-in rules use L001-L010, custom rules should use a different prefix.
	ID() string

	// Name returns the human-readable rule name displayed in violation reports.
	// Example: "Trailing Whitespace", "Keyword Case Consistency"
	Name() string

	// Description returns a detailed description of what the rule checks.
	// This should explain the rule's purpose and what patterns it enforces.
	Description() string

	// Severity returns the default severity level for this rule.
	// Returns one of: SeverityError, SeverityWarning, or SeverityInfo.
	Severity() Severity

	// Check performs the rule check and returns any violations found.
	//
	// The context provides access to SQL text, tokens (if available), and
	// AST (if available). Rules should handle missing tokenization/parsing
	// gracefully by checking ctx.Tokens and ctx.AST for nil.
	//
	// Returns a slice of violations (empty if none found) and any error
	// encountered during checking. Errors should indicate rule implementation
	// issues, not SQL syntax problems.
	Check(ctx *Context) ([]Violation, error)

	// CanAutoFix returns whether this rule supports automatic fixing.
	// If true, the Fix method should be implemented to apply corrections.
	CanAutoFix() bool

	// Fix applies automatic fixes for the given violations.
	//
	// Takes the original SQL content and violations from this rule, returns
	// the fixed content. If the rule doesn't support auto-fixing, this should
	// return the content unchanged.
	//
	// The Fix implementation should:
	//   - Preserve SQL semantics (don't change query meaning)
	//   - Handle edge cases (string literals, comments)
	//   - Be idempotent (applying twice produces same result)
	//
	// Returns the fixed content and any error encountered during fixing.
	Fix(content string, violations []Violation) (string, error)
}

// BaseRule provides common functionality for implementing rules.
//
// Embedding BaseRule in custom rule types eliminates the need to implement
// ID(), Name(), Description(), Severity(), and CanAutoFix() methods manually.
// Only Check() and Fix() need to be implemented.
//
// Example:
//
//	type MyRule struct {
//	    linter.BaseRule
//	}
//
//	func NewMyRule() *MyRule {
//	    return &MyRule{
//	        BaseRule: linter.NewBaseRule(
//	            "C001",
//	            "My Custom Rule",
//	            "Checks for custom patterns",
//	            linter.SeverityWarning,
//	            false,
//	        ),
//	    }
//	}
type BaseRule struct {
	id          string
	name        string
	description string
	severity    Severity
	canAutoFix  bool
}

// NewBaseRule creates a new base rule with the specified properties.
//
// Parameters:
//   - id: Unique rule identifier (e.g., "L001", "C001")
//   - name: Human-readable rule name
//   - description: Detailed description of what the rule checks
//   - severity: Default severity level (Error, Warning, or Info)
//   - canAutoFix: Whether the rule supports automatic fixing
//
// Returns a BaseRule that can be embedded in custom rule implementations.
func NewBaseRule(id, name, description string, severity Severity, canAutoFix bool) BaseRule {
	return BaseRule{
		id:          id,
		name:        name,
		description: description,
		severity:    severity,
		canAutoFix:  canAutoFix,
	}
}

// ID returns the rule ID
func (r BaseRule) ID() string {
	return r.id
}

// Name returns the rule name
func (r BaseRule) Name() string {
	return r.name
}

// Description returns the rule description
func (r BaseRule) Description() string {
	return r.description
}

// Severity returns the rule severity
func (r BaseRule) Severity() Severity {
	return r.severity
}

// CanAutoFix returns whether auto-fix is supported
func (r BaseRule) CanAutoFix() bool {
	return r.canAutoFix
}

// ValidRuleIDs returns the set of all implemented rule IDs.
// Use this to validate that user-specified rule names in configuration
// files (e.g., .gosqlx.yml) reference actual rules.
var ValidRuleIDs = map[string]string{
	"L001": "Trailing Whitespace",
	"L002": "Mixed Indentation",
	"L003": "Consecutive Blank Lines",
	"L004": "Indentation Depth",
	"L005": "Long Lines",
	"L006": "Column Alignment",
	"L007": "Keyword Case Consistency",
	"L008": "Comma Placement",
	"L009": "Aliasing Consistency",
	"L010": "Redundant Whitespace",
}

// IsValidRuleID checks whether a rule ID corresponds to an implemented rule.
func IsValidRuleID(id string) bool {
	_, ok := ValidRuleIDs[id]
	return ok
}
