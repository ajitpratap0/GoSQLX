package linter

import (
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Severity represents the severity level of a lint violation
type Severity string

const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
	SeverityInfo    Severity = "info"
)

// Violation represents a single linting rule violation
type Violation struct {
	Rule       string          // Rule ID (e.g., "L001")
	RuleName   string          // Human-readable rule name
	Severity   Severity        // Severity level
	Message    string          // Violation description
	Location   models.Location // Position in source (1-based)
	Line       string          // The actual line content
	Suggestion string          // How to fix the violation
	CanAutoFix bool            // Whether this violation can be auto-fixed
}

// Rule defines the interface for all linting rules
type Rule interface {
	// ID returns the unique rule identifier (e.g., "L001")
	ID() string

	// Name returns the human-readable rule name
	Name() string

	// Description returns a description of what the rule checks
	Description() string

	// Severity returns the default severity level for this rule
	Severity() Severity

	// Check performs the rule check and returns violations
	Check(ctx *Context) ([]Violation, error)

	// CanAutoFix returns whether this rule supports auto-fixing
	CanAutoFix() bool

	// Fix applies automatic fixes if supported
	// Returns the fixed content or an error
	Fix(content string, violations []Violation) (string, error)
}

// BaseRule provides common functionality for rules
type BaseRule struct {
	id          string
	name        string
	description string
	severity    Severity
	canAutoFix  bool
}

// NewBaseRule creates a new base rule
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
