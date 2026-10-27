// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package fingerprint_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/fingerprint"
)

func TestNormalizeRejectsNumericTrailingJunk(t *testing.T) {
	out, err := fingerprint.Normalize("SELECT 1x")
	if err == nil || !strings.Contains(err.Error(), "tokenization failed") || out != "" {
		t.Fatalf("got %q, %v; want tokenization error", out, err)
	}
}
