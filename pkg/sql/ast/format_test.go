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

// Tests for FormatOptions types and factory functions. Rendering tests live in
// pkg/formatter/render_test.go (the visitor-based formatter).
package ast

import (
	"testing"
)

func TestCompactStyle(t *testing.T) {
	opts := CompactStyle()
	if opts.NewlinePerClause {
		t.Error("CompactStyle should not have NewlinePerClause")
	}
	if opts.IndentWidth != 0 {
		t.Error("CompactStyle should have IndentWidth 0")
	}
	if opts.AddSemicolon {
		t.Error("CompactStyle should not add semicolons")
	}
}

func TestReadableStyle(t *testing.T) {
	opts := ReadableStyle()
	if !opts.NewlinePerClause {
		t.Error("ReadableStyle should have NewlinePerClause")
	}
	if opts.KeywordCase != KeywordUpper {
		t.Error("ReadableStyle should have KeywordUpper")
	}
	if !opts.AddSemicolon {
		t.Error("ReadableStyle should add semicolons")
	}
	if opts.IndentWidth <= 0 {
		t.Error("ReadableStyle should have positive IndentWidth")
	}
}

func TestKeywordCaseConstants(t *testing.T) {
	// Verify the iota ordering is stable.
	if KeywordUpper != 0 {
		t.Error("KeywordUpper should be 0")
	}
	if KeywordLower != 1 {
		t.Error("KeywordLower should be 1")
	}
	if KeywordPreserve != 2 {
		t.Error("KeywordPreserve should be 2")
	}
}

func TestIndentStyleConstants(t *testing.T) {
	if IndentSpaces != 0 {
		t.Error("IndentSpaces should be 0")
	}
	if IndentTabs != 1 {
		t.Error("IndentTabs should be 1")
	}
}
