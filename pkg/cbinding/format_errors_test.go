// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFormatResultReportsNumericTrailingJunk(t *testing.T) {
	for _, dialect := range []string{"", "postgresql"} {
		result := formatResultFor("SELECT 1x", dialect)
		if result.Success || result.Formatted != "" || !strings.Contains(result.Error, "numeric literal") {
			t.Fatalf("dialect=%q: %+v; want error result", dialect, result)
		}
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		decoded := decodeMap(t, string(raw))
		success, ok := decoded["success"].(bool)
		if !ok || success || errorOf(decoded) == "" {
			t.Fatalf("error JSON = %s", raw)
		}
	}
}
