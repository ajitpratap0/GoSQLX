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
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestVersionManifestsMatchVersion fails when a versioned manifest in the
// repository disagrees with the Version const. v1.15.0 shipped with several
// of these still at 1.14.0; release.yml only checks the tag against Version,
// so this keeps everything else in step with it on every commit.
func TestVersionManifestsMatchVersion(t *testing.T) {
	root := filepath.Join("..", "..")

	jsonVersion := func(rel string, get func(map[string]any) any) func(*testing.T) string {
		return func(t *testing.T) string {
			t.Helper()
			data, err := os.ReadFile(filepath.Join(root, rel))
			if os.IsNotExist(err) {
				t.Skipf("%s not present (not a repository checkout)", rel)
			}
			if err != nil {
				t.Fatalf("read %s: %v", rel, err)
			}
			var m map[string]any
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatalf("parse %s: %v", rel, err)
			}
			v, ok := get(m).(string)
			if !ok {
				t.Fatalf("%s: version field not found", rel)
			}
			return v
		}
	}
	topLevel := func(m map[string]any) any { return m["version"] }

	cases := []struct {
		file    string
		version func(*testing.T) string
	}{
		{"glama.json", jsonVersion("glama.json", topLevel)},
		{"server.json", jsonVersion("server.json", topLevel)},
		{"vscode-extension/package.json", jsonVersion("vscode-extension/package.json", topLevel)},
		{"plugins/gosqlx/.claude-plugin/plugin.json", jsonVersion("plugins/gosqlx/.claude-plugin/plugin.json", topLevel)},
		{"performance_baselines.json", jsonVersion("performance_baselines.json", topLevel)},
		{".claude-plugin/marketplace.json", jsonVersion(".claude-plugin/marketplace.json", func(m map[string]any) any {
			plugins, ok := m["plugins"].([]any)
			if !ok || len(plugins) == 0 {
				return nil
			}
			p, ok := plugins[0].(map[string]any)
			if !ok {
				return nil
			}
			return p["version"]
		})},
		// pygosqlx is versioned in lockstep; Python-only releases add .postN.
		{"python/pyproject.toml", func(t *testing.T) string {
			t.Helper()
			data, err := os.ReadFile(filepath.Join(root, "python", "pyproject.toml"))
			if os.IsNotExist(err) {
				t.Skip("python/pyproject.toml not present (not a repository checkout)")
			}
			if err != nil {
				t.Fatalf("read python/pyproject.toml: %v", err)
			}
			m := regexp.MustCompile(`(?m)^version = "([^"]+)"`).FindSubmatch(data)
			if m == nil {
				t.Fatal("python/pyproject.toml: version not found")
			}
			return strings.SplitN(string(m[1]), ".post", 2)[0]
		}},
	}

	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			if got := tc.version(t); got != Version {
				t.Errorf("%s version = %q, want gosqlx.Version %q; bump it in the release PR", tc.file, got, Version)
			}
		})
	}
}
