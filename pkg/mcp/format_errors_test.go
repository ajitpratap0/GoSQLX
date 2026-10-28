// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"testing"
)

func TestFormatToolReportsNumericTrailingJunk(t *testing.T) {
	result, err := handleFormatSQL(context.Background(), makeReq(map[string]any{"sql": "SELECT 1x"}))
	requireToolError(t, result, err, "format failed")
}
