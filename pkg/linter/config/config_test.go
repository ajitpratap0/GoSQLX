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

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
)

// --- test fixtures -----------------------------------------------------------

// fakeRule is a minimal linter.Rule used to exercise Apply without importing
// the entire rules tree (which would create unnecessary transitive deps for
// this package's tests).
type fakeRule struct {
	id       string
	sev      linter.Severity
	violate  bool // if true, Check returns one violation
	checkErr error
}

func (r *fakeRule) ID() string                { return r.id }
func (r *fakeRule) Name() string              { return "fake " + r.id }
func (r *fakeRule) Description() string       { return "fake rule for testing" }
func (r *fakeRule) Severity() linter.Severity { return r.sev }
func (r *fakeRule) CanAutoFix() bool          { return false }
func (r *fakeRule) Fix(s string, _ []linter.Violation) (string, error) {
	return s, nil
}
func (r *fakeRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	if r.checkErr != nil {
		return nil, r.checkErr
	}
	if !r.violate {
		return nil, nil
	}
	return []linter.Violation{{
		Rule:     r.id,
		RuleName: r.Name(),
		Severity: r.sev,
		Message:  "fake violation",
	}}, nil
}

// --- Load / parse tests ------------------------------------------------------

func TestLoad_Valid(t *testing.T) {
	cfg, err := Load(filepath.Join("testdata", "valid.yml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load returned nil config")
	}

	// Spot-check the parsed structure.
	if got := cfg.Rules["L001"].Severity; got != "error" {
		t.Errorf("L001 severity = %q, want error", got)
	}
	if cfg.Rules["L011"].Enabled == nil || *cfg.Rules["L011"].Enabled {
		t.Errorf("L011 should be explicitly disabled")
	}
	if got, ok := cfg.Rules["L005"].Params["max_length"]; !ok || got != 120 {
		t.Errorf("L005 params[max_length] = %v (%T), want 120 (int)", got, got)
	}
	if cfg.DefaultSeverity != "warning" {
		t.Errorf("DefaultSeverity = %q, want warning", cfg.DefaultSeverity)
	}
	wantIgnore := []string{"migrations/*.sql", "vendor/**", "**/generated/**"}
	if len(cfg.Ignore) != len(wantIgnore) {
		t.Fatalf("Ignore length = %d, want %d (%v)", len(cfg.Ignore), len(wantIgnore), cfg.Ignore)
	}
	for i, p := range wantIgnore {
		if cfg.Ignore[i] != p {
			t.Errorf("Ignore[%d] = %q, want %q", i, cfg.Ignore[i], p)
		}
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("expected no warnings for valid.yml, got %v", cfg.Warnings)
	}
	if !strings.HasSuffix(cfg.Path, "valid.yml") {
		t.Errorf("Path not populated: %q", cfg.Path)
	}
}

func TestLoad_Minimal(t *testing.T) {
	cfg, err := Load(filepath.Join("testdata", "minimal.yml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Rules["L001"].Severity != "error" {
		t.Errorf("L001 severity = %q, want error", cfg.Rules["L001"].Severity)
	}
	if len(cfg.Ignore) != 0 {
		t.Errorf("Ignore should be empty, got %v", cfg.Ignore)
	}
	if cfg.DefaultSeverity != "" {
		t.Errorf("DefaultSeverity should be empty, got %q", cfg.DefaultSeverity)
	}
}

func TestLoad_Invalid(t *testing.T) {
	_, err := Load(filepath.Join("testdata", "invalid.yml"))
	if err == nil {
		t.Fatal("expected parse error for invalid.yml, got nil")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("error does not mention parse: %v", err)
	}
}

func TestLoad_UnknownTopLevelField(t *testing.T) {
	_, err := Load(filepath.Join("testdata", "unknown_field.yml"))
	if err == nil {
		t.Fatal("expected error for unknown top-level field, got nil")
	}
}

func TestLoad_UnknownRuleID_IsWarningNotError(t *testing.T) {
	cfg, err := Load(filepath.Join("testdata", "unknown_rule.yml"))
	if err != nil {
		t.Fatalf("Load returned error for unknown rule (should be warning): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "L999") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected warning mentioning L999, got %v", cfg.Warnings)
	}
}

func TestLoad_BadSeverity_IsWarningNotError(t *testing.T) {
	cfg, err := Load(filepath.Join("testdata", "bad_severity.yml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DefaultSeverity != "" {
		t.Errorf("bad default_severity should be cleared, got %q", cfg.DefaultSeverity)
	}
	var haveRuleWarn, haveDefaultWarn bool
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "rule L001") && strings.Contains(w, "critical") {
			haveRuleWarn = true
		}
		if strings.Contains(w, "default_severity") && strings.Contains(w, "fatal") {
			haveDefaultWarn = true
		}
	}
	if !haveRuleWarn {
		t.Errorf("missing warning about L001 severity=critical in %v", cfg.Warnings)
	}
	if !haveDefaultWarn {
		t.Errorf("missing warning about default_severity=fatal in %v", cfg.Warnings)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load(filepath.Join("testdata", "does-not-exist.yml"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yml")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("empty file should parse: %v", err)
	}
	if len(cfg.Rules) != 0 || len(cfg.Ignore) != 0 || cfg.DefaultSeverity != "" {
		t.Errorf("empty file produced non-zero config: %+v", cfg)
	}
}

// --- LoadDefault walk-up test ------------------------------------------------

func TestLoadDefault_WalksUp(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(root, DefaultFilename)
	body := "rules:\n  L001:\n    severity: error\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadDefaultFrom(deep)
	if err != nil {
		t.Fatalf("loadDefaultFrom: %v", err)
	}
	if cfg.Rules["L001"].Severity != "error" {
		t.Errorf("unexpected config: %+v", cfg.Rules)
	}
	// Path should be the root-level file, not somewhere inside deep.
	absCfg, _ := filepath.Abs(cfgPath)
	if cfg.Path != absCfg {
		t.Errorf("Path = %q, want %q", cfg.Path, absCfg)
	}
}

func TestLoadDefault_NotFound(t *testing.T) {
	// Build a directory tree with no .gosqlx.yml anywhere under it, then walk
	// from the deepest dir. Since the walk continues up to the filesystem
	// root, we can't perfectly isolate from real configs above t.TempDir().
	// Instead, we pick a path we know doesn't have a gosqlx.yml by using a
	// random tmp dir — if the developer has a .gosqlx.yml in a parent of
	// $TMPDIR, this test is informational only.
	root := t.TempDir()
	deep := filepath.Join(root, "x", "y")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := loadDefaultFrom(deep)
	// Only assert ErrNotFound if no parent actually has a .gosqlx.yml.
	// Walk up manually to double-check.
	d := deep
	foundUpstream := false
	for {
		if _, statErr := os.Stat(filepath.Join(d, DefaultFilename)); statErr == nil {
			foundUpstream = true
			break
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	if !foundUpstream {
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	} else {
		t.Logf("parent directory %q contains a .gosqlx.yml; skipping ErrNotFound assertion", d)
	}
}

// --- Apply tests -------------------------------------------------------------

func TestApply_DisablesRule(t *testing.T) {
	disabled := false
	cfg := &Config{
		Rules: map[string]RuleConfig{
			"L001": {Enabled: &disabled},
		},
	}
	rules := []linter.Rule{
		&fakeRule{id: "L001", sev: linter.SeverityWarning},
		&fakeRule{id: "L002", sev: linter.SeverityInfo},
	}
	out := cfg.Apply(rules)
	if len(out) != 1 || out[0].ID() != "L002" {
		t.Errorf("expected only L002 after disabling L001, got %v", ids(out))
	}
}

func TestApply_SeverityOverride(t *testing.T) {
	cfg := &Config{
		Rules: map[string]RuleConfig{
			"L001": {Severity: "error"},
		},
	}
	rule := &fakeRule{id: "L001", sev: linter.SeverityWarning, violate: true}
	out := cfg.Apply([]linter.Rule{rule})
	if len(out) != 1 {
		t.Fatalf("Apply dropped rules: %v", ids(out))
	}
	if out[0].Severity() != linter.SeverityError {
		t.Errorf("Severity() = %q, want error", out[0].Severity())
	}

	// Violations returned by Check should also carry the new severity.
	vs, err := out[0].Check(linter.NewContext("", "x.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 1 || vs[0].Severity != linter.SeverityError {
		t.Errorf("violation severity not rewritten: %+v", vs)
	}
	// Original rule must be untouched (immutability check).
	if rule.sev != linter.SeverityWarning {
		t.Errorf("wrapping mutated the underlying rule: %v", rule.sev)
	}
}

func TestApply_DefaultSeverity(t *testing.T) {
	cfg := &Config{
		DefaultSeverity: "info",
		Rules: map[string]RuleConfig{
			// Explicit override should beat default.
			"L001": {Severity: "error"},
		},
	}
	rules := []linter.Rule{
		&fakeRule{id: "L001", sev: linter.SeverityWarning},
		&fakeRule{id: "L002", sev: linter.SeverityWarning},
	}
	out := cfg.Apply(rules)
	if len(out) != 2 {
		t.Fatalf("Apply dropped rules: %v", ids(out))
	}
	if out[0].Severity() != linter.SeverityError {
		t.Errorf("L001 should keep its explicit override error, got %q", out[0].Severity())
	}
	if out[1].Severity() != linter.SeverityInfo {
		t.Errorf("L002 should take default info, got %q", out[1].Severity())
	}
}

func TestApply_NoOverride_NoWrap(t *testing.T) {
	cfg := &Config{}
	r := &fakeRule{id: "L001", sev: linter.SeverityWarning}
	out := cfg.Apply([]linter.Rule{r})
	if len(out) != 1 || out[0] != linter.Rule(r) {
		t.Errorf("rule should pass through unchanged when no override applies")
	}
}

func TestApply_NilConfig(t *testing.T) {
	var cfg *Config
	rules := []linter.Rule{&fakeRule{id: "L001"}}
	out := cfg.Apply(rules)
	if len(out) != 1 {
		t.Errorf("nil config should pass rules through unchanged")
	}
}

// --- ShouldIgnore tests ------------------------------------------------------

func TestShouldIgnore(t *testing.T) {
	cfg := &Config{
		Ignore: []string{
			"migrations/*.sql",
			"vendor/**",
			"**/generated/**",
		},
	}
	cases := []struct {
		name   string
		path   string
		ignore bool
	}{
		{"direct match", "migrations/001_init.sql", true},
		{"nested not matched by single star", "migrations/sub/001.sql", false},
		{"vendor top-level", "vendor/foo.sql", true},
		{"vendor deep", "vendor/a/b/c/foo.sql", true},
		{"generated anywhere", "pkg/x/generated/y.sql", true},
		{"not ignored", "queries/user.sql", false},
		{"empty path", "", false},
		{"windows-style separators", "vendor\\foo.sql", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cfg.ShouldIgnore(tc.path); got != tc.ignore {
				t.Errorf("ShouldIgnore(%q) = %v, want %v", tc.path, got, tc.ignore)
			}
		})
	}
}

func TestShouldIgnore_NilConfig(t *testing.T) {
	var cfg *Config
	if cfg.ShouldIgnore("any.sql") {
		t.Error("nil config should never ignore")
	}
}

// --- matchGlob focused tests -------------------------------------------------

func TestMatchGlob(t *testing.T) {
	cases := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"*.sql", "foo.sql", true},
		{"*.sql", "sub/foo.sql", false}, // single-star doesn't cross "/"
		{"**/*.sql", "foo.sql", true},
		{"**/*.sql", "a/b/foo.sql", true},
		{"a/**/c.sql", "a/c.sql", true},
		{"a/**/c.sql", "a/b/c.sql", true},
		{"a/**/c.sql", "a/b/d/c.sql", true},
		{"a/**/c.sql", "x/c.sql", false},
		{"exact.sql", "exact.sql", true},
		{"**", "anything/here.sql", true},
	}
	for _, tc := range cases {
		got, err := matchGlob(tc.pattern, tc.path)
		if err != nil {
			t.Errorf("matchGlob(%q, %q): unexpected error %v", tc.pattern, tc.path, err)
			continue
		}
		if got != tc.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

// --- helpers -----------------------------------------------------------------

func ids(rs []linter.Rule) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.ID())
	}
	return out
}
