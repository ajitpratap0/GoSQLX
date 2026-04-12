// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gosqlx

import (
	stderrors "errors"

	"github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// ErrorCode extracts the structured error code from an error returned by Parse,
// Validate, or other gosqlx functions. It unwraps through fmt.Errorf wrapping
// to find the underlying *errors.Error.
//
// Returns the ErrorCode (e.g., "E2001") if found, or empty string if the error
// is not a structured GoSQLX error.
//
// Example:
//
//	_, err := gosqlx.Parse("SELECT * FORM users")
//	code := gosqlx.ErrorCode(err)
//	if code == errors.ErrCodeExpectedToken {
//	    // handle expected-token error
//	}
func ErrorCode(err error) errors.ErrorCode {
	var e *errors.Error
	if stderrors.As(err, &e) {
		return e.Code
	}
	return ""
}

// ErrorLocation extracts the source location (line/column) from an error
// returned by Parse, Validate, or other gosqlx functions. It unwraps through
// fmt.Errorf wrapping to find the underlying *errors.Error.
//
// Returns a pointer to the Location if found, or nil if the error is not a
// structured GoSQLX error.
//
// Example:
//
//	_, err := gosqlx.Parse("SELECT * FORM users")
//	if loc := gosqlx.ErrorLocation(err); loc != nil {
//	    fmt.Printf("Error at line %d, column %d\n", loc.Line, loc.Column)
//	}
func ErrorLocation(err error) *models.Location {
	var e *errors.Error
	if stderrors.As(err, &e) {
		return &e.Location
	}
	return nil
}

// ErrorHint extracts the hint/suggestion from an error returned by Parse,
// Validate, or other gosqlx functions.
//
// Returns the hint string if found, or empty string if the error is not a
// structured GoSQLX error or has no hint.
//
// Example:
//
//	_, err := gosqlx.Parse("SELECT * FORM users")
//	if hint := gosqlx.ErrorHint(err); hint != "" {
//	    fmt.Printf("Hint: %s\n", hint)
//	}
func ErrorHint(err error) string {
	var e *errors.Error
	if stderrors.As(err, &e) {
		return e.Hint
	}
	return ""
}
