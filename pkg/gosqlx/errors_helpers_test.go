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
	"fmt"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

func TestErrorCode_StructuredError(t *testing.T) {
	// Parse invalid SQL to get a structured error
	_, err := Parse("SELECT * FROM")
	if err == nil {
		t.Fatal("expected error for incomplete SQL")
	}

	code := ErrorCode(err)
	if code == "" {
		t.Error("expected non-empty error code from structured parse error")
	}
}

func TestErrorCode_NonStructuredError(t *testing.T) {
	err := fmt.Errorf("some generic error")
	code := ErrorCode(err)
	if code != "" {
		t.Errorf("expected empty error code for non-structured error, got %q", code)
	}
}

func TestErrorCode_Nil(t *testing.T) {
	code := ErrorCode(nil)
	if code != "" {
		t.Errorf("expected empty error code for nil error, got %q", code)
	}
}

func TestErrorLocation_StructuredError(t *testing.T) {
	_, err := Parse("SELECT * FROM")
	if err == nil {
		t.Fatal("expected error for incomplete SQL")
	}

	loc := ErrorLocation(err)
	if loc == nil {
		t.Error("expected non-nil location from structured parse error")
	}
}

func TestErrorLocation_NonStructuredError(t *testing.T) {
	err := fmt.Errorf("some generic error")
	loc := ErrorLocation(err)
	if loc != nil {
		t.Error("expected nil location for non-structured error")
	}
}

func TestErrorHint_StructuredError(t *testing.T) {
	// Hint may or may not be present depending on the error, so just test that
	// it doesn't panic and returns a string.
	_, err := Parse("SELECT * FORM users")
	if err == nil {
		t.Fatal("expected error for typo SQL")
	}

	// ErrorHint should not panic
	_ = ErrorHint(err)
}

func TestErrorHint_NonStructuredError(t *testing.T) {
	err := fmt.Errorf("generic error")
	hint := ErrorHint(err)
	if hint != "" {
		t.Errorf("expected empty hint for non-structured error, got %q", hint)
	}
}

func TestErrorCode_WrappedError(t *testing.T) {
	// Simulate the wrapping that gosqlx.Parse does
	inner := errors.NewError(errors.ErrCodeUnexpectedToken, "unexpected token", models.Location{})
	wrapped := fmt.Errorf("parsing failed: %w", inner)

	code := ErrorCode(wrapped)
	if code != errors.ErrCodeUnexpectedToken {
		t.Errorf("expected %q, got %q", errors.ErrCodeUnexpectedToken, code)
	}
}
