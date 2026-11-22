// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package transpiler_test

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/transpiler"
)

func TestTranspileRejectsUnsupportedXor(t *testing.T) {
	out, err := transpiler.Transpile("SELECT a ^ b", keywords.DialectMySQL, keywords.DialectSQLite)
	if err == nil || !strings.Contains(err.Error(), "XOR") || out != "" {
		t.Fatalf("got %q, %v; want XOR error", out, err)
	}
}
