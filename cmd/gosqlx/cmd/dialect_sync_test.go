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

// Package cmd - dialect_sync_test.go
// Drift guards: every user-facing dialect list (CLI --dialect help, CLI
// errors, VS Code extension settings) must match keywords.DialectNames().

package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// vscodeExtensionDir is the VS Code extension directory relative to this
// package (cmd/gosqlx/cmd).
var vscodeExtensionDir = filepath.Join("..", "..", "..", "vscode-extension")

func TestDialectFlagHelp_ListsEveryDialect(t *testing.T) {
	names := keywords.DialectNames()
	found := 0
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if f := c.Flags().Lookup("dialect"); f != nil {
			found++
			for _, name := range names {
				if !strings.Contains(f.Usage, name) {
					t.Errorf("%q --dialect help %q does not mention %q", c.CommandPath(), f.Usage, name)
				}
			}
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)
	// parse, format, analyze, lint, validate at minimum.
	if found < 5 {
		t.Errorf("found %d commands with a --dialect flag, want at least 5", found)
	}
}

func TestValidateDialectName_AcceptsLibraryDialects(t *testing.T) {
	for _, name := range keywords.DialectNames() {
		if err := validateDialectName(name); err != nil {
			t.Errorf("validateDialectName(%q) = %v, want nil", name, err)
		}
	}

	// Case handling is unchanged: names are matched case-sensitively.
	if err := validateDialectName("MySQL"); err == nil {
		t.Error(`validateDialectName("MySQL") = nil, want error (case-sensitive)`)
	}

	err := validateDialectName("bogus")
	if err == nil {
		t.Fatal(`validateDialectName("bogus") = nil, want error`)
	}
	for _, name := range keywords.DialectNames() {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error %q does not list dialect %q", err.Error(), name)
		}
	}
}

func TestVSCodeDialectSetting_MatchesLibrary(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(vscodeExtensionDir, "package.json"))
	if err != nil {
		t.Fatalf("read vscode-extension/package.json: %v", err)
	}
	var manifest struct {
		Contributes struct {
			Configuration struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"configuration"`
		} `json:"contributes"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse vscode-extension/package.json: %v", err)
	}
	raw, ok := manifest.Contributes.Configuration.Properties["gosqlx.dialect"]
	if !ok {
		t.Fatal("gosqlx.dialect setting not found in vscode-extension/package.json")
	}
	var setting struct {
		Enum    []string `json:"enum"`
		Default string   `json:"default"`
	}
	if err := json.Unmarshal(raw, &setting); err != nil {
		t.Fatalf("parse gosqlx.dialect setting: %v", err)
	}
	want := keywords.DialectNames()
	if !reflect.DeepEqual(setting.Enum, want) {
		t.Errorf("gosqlx.dialect enum = %v, want %v (keywords.DialectNames)", setting.Enum, want)
	}
	if !keywords.IsValidDialect(setting.Default) {
		t.Errorf("gosqlx.dialect default %q is not a valid dialect", setting.Default)
	}
}

func TestVSCodeValidDialects_MatchesLibrary(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(vscodeExtensionDir, "src", "utils", "validation.ts"))
	if err != nil {
		t.Fatalf("read vscode-extension/src/utils/validation.ts: %v", err)
	}
	block := regexp.MustCompile(`(?s)export const VALID_DIALECTS = \[(.*?)\] as const;`).FindSubmatch(data)
	if block == nil {
		t.Fatal("VALID_DIALECTS declaration not found in validation.ts")
	}
	var got []string
	for _, m := range regexp.MustCompile(`'([^']*)'`).FindAllSubmatch(block[1], -1) {
		got = append(got, string(m[1]))
	}
	want := keywords.DialectNames()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("VALID_DIALECTS = %v, want %v (keywords.DialectNames)", got, want)
	}
}

// TestDocDialectLists_MatchLibrary checks the hand-written dialect lists in
// docs and example configs. Each file must contain at least one line naming
// postgresql and mysql, and every such line must name every dialect.
func TestDocDialectLists_MatchLibrary(t *testing.T) {
	repoRoot := filepath.Join("..", "..", "..")
	files := []string{
		"cmd/gosqlx/doc.go",
		"cmd/gosqlx/internal/config/README.md",
		"pkg/config/README.md",
		".gosqlx.example.yml",
		".gosqlx.yml",
		".github/workflows/examples/.gosqlx-example.yml",
		"docs/MCP_GUIDE.md",
		"docs/CLI_GUIDE.md",
		"docs/CONFIGURATION.md",
	}
	listLine := regexp.MustCompile("`?postgresql`?, `?mysql`?")
	names := keywords.DialectNames()
	for _, rel := range files {
		data, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
		if err != nil {
			t.Errorf("read %s: %v", rel, err)
			continue
		}
		lists := 0
		for i, line := range strings.Split(string(data), "\n") {
			if !listLine.MatchString(line) {
				continue
			}
			lists++
			for _, name := range names {
				if !strings.Contains(line, name) {
					t.Errorf("%s:%d: dialect list does not mention %q: %s", rel, i+1, name, strings.TrimSpace(line))
				}
			}
		}
		if lists == 0 {
			t.Errorf("%s: no dialect list found (update this test if the list moved)", rel)
		}
	}
}
