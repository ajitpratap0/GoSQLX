package parser

import "errors"

// Sentinel errors for the parser package.
var (
	// ErrUnexpectedStatement indicates a statement type was not expected in context.
	ErrUnexpectedStatement = errors.New("unexpected statement type")
)
