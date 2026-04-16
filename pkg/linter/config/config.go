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

// Package config provides .gosqlx.yml configuration loading for the linter.
//
// The configuration file controls which rules run, their severity overrides,
// optional per-rule parameters, and file ignore patterns. It is typically
// committed to a project root so a team shares a consistent lint policy.
//
// Example .gosqlx.yml:
//
//	rules:
//	  L001:
//	    enabled: true
//	    severity: error
//	  L005:
//	    enabled: true
//	    params:
//	      max_length: 120
//	  L011:
//	    enabled: false
//	ignore:
//	  - "migrations/*.sql"
//	  - "vendor/**"
//	default_severity: warning
//
// Typical use:
//
//	cfg, err := config.LoadDefault()
//	if err != nil && !errors.Is(err, config.ErrNotFound) {
//	    log.Fatal(err)
//	}
//	rules := cfg.Apply(allRules)
//	l := linter.NewWithConfig(cfg, rules...)
//
// Unknown rule IDs in the config file are reported via Config.Warnings but do
// not cause Load to fail. This allows forward compatibility when older
// installations read configs that reference newer rules.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"gopkg.in/yaml.v3"
)

// DefaultFilename is the conventional name for the linter configuration file.
const DefaultFilename = ".gosqlx.yml"

// ErrNotFound is returned by LoadDefault when no .gosqlx.yml is found while
// walking up from the current working directory. Callers that want to treat a
// missing config as "use built-in defaults" should check with errors.Is.
var ErrNotFound = errors.New("gosqlx: no .gosqlx.yml found")

// RuleConfig represents per-rule configuration entries.
//
// A rule entry may set Enabled (default true if the rule appears at all),
// override Severity (error | warning | info), and supply rule-specific Params.
// Unknown params are preserved and may be consumed by rules that understand
// them; rules that don't read params simply ignore them.
type RuleConfig struct {
	// Enabled is an optional pointer so the zero value ("not set") differs
	// from an explicit `enabled: false`.
	Enabled *bool `yaml:"enabled"`

	// Severity overrides the rule's default severity. Empty means "no override".
	Severity string `yaml:"severity"`

	// Params are rule-specific parameters (e.g. max_length for L005).
	// The types are whatever YAML produces (int, string, bool, []interface{}, map).
	Params map[string]any `yaml:"params"`
}

// Config represents the parsed contents of a .gosqlx.yml file.
//
// Config is immutable after Load returns. Methods on *Config do not mutate it.
type Config struct {
	// Rules maps rule IDs (e.g. "L001") to per-rule configuration.
	Rules map[string]RuleConfig `yaml:"rules"`

	// Ignore is a list of glob patterns for file paths to skip during linting.
	// Patterns support "*" (single path segment) and "**" (any number of
	// segments). Patterns are matched against the filename passed to the
	// linter (LintFile, LintString's filename arg, or LintDirectory entries).
	Ignore []string `yaml:"ignore"`

	// DefaultSeverity, if set, is applied to rules whose RuleConfig.Severity
	// is empty. Valid values: "error", "warning", "info". Empty means the
	// rule's built-in severity is used.
	DefaultSeverity string `yaml:"default_severity"`

	// Path is the absolute filesystem path the config was loaded from.
	// Empty for configs constructed in memory.
	Path string `yaml:"-"`

	// Warnings are non-fatal diagnostics produced during Load (e.g. unknown
	// rule IDs, unknown severity values). They are forward-compatibility
	// signals, not errors.
	Warnings []string `yaml:"-"`
}

// Load reads and parses the configuration file at the given path.
//
// Returns an error if the file cannot be read or contains invalid YAML.
// Unknown rule IDs and unknown severity values become Warnings rather than
// errors so the linter can keep running against newer configs.
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("gosqlx config: resolve path %q: %w", path, err)
	}

	data, err := os.ReadFile(filepath.Clean(abs)) // #nosec G304 -- config path is user-provided by design
	if err != nil {
		return nil, fmt.Errorf("gosqlx config: read %s: %w", abs, err)
	}

	return parse(data, abs)
}

// LoadDefault searches for .gosqlx.yml starting at the current working
// directory and walking up toward the filesystem root. It returns the first
// match found, or ErrNotFound if none exists.
//
// Use errors.Is(err, ErrNotFound) to distinguish "no config" from a real
// I/O or parse error.
func LoadDefault() (*Config, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("gosqlx config: getwd: %w", err)
	}
	return loadDefaultFrom(cwd)
}

// loadDefaultFrom is the testable version of LoadDefault that walks up from
// the given start directory instead of the process cwd.
func loadDefaultFrom(start string) (*Config, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return nil, fmt.Errorf("gosqlx config: abs %q: %w", start, err)
	}

	for {
		candidate := filepath.Join(dir, DefaultFilename)
		if info, statErr := os.Stat(candidate); statErr == nil && !info.IsDir() {
			return Load(candidate)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return nil, ErrNotFound
}

// parse parses YAML bytes into a *Config. It attaches Path for diagnostics
// and populates Warnings for unknown rule IDs / unknown severities. Invalid
// YAML or unknown top-level keys produce a hard error.
func parse(data []byte, path string) (*Config, error) {
	cfg := &Config{Path: path}

	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true) // reject unknown top-level keys to catch typos

	if err := dec.Decode(cfg); err != nil {
		// Empty file is fine; yaml returns io.EOF on empty input.
		if strings.TrimSpace(string(data)) == "" {
			return cfg, nil
		}
		return nil, fmt.Errorf("gosqlx config: parse %s: %w", path, err)
	}

	// Validate default_severity.
	if cfg.DefaultSeverity != "" && !isValidSeverity(cfg.DefaultSeverity) {
		cfg.Warnings = append(cfg.Warnings,
			fmt.Sprintf("unknown default_severity %q (valid: error, warning, info)", cfg.DefaultSeverity))
		cfg.DefaultSeverity = ""
	}

	// Warn on unknown rule IDs and unknown per-rule severities.
	for id, rc := range cfg.Rules {
		if !linter.IsValidRuleID(id) {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("unknown rule ID %q (forward-compat: ignored)", id))
		}
		if rc.Severity != "" && !isValidSeverity(rc.Severity) {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("rule %s: unknown severity %q (valid: error, warning, info)", id, rc.Severity))
		}
	}

	// Validate ignore patterns compile as globs. We test via matchGlob against
	// a probe string so malformed patterns get surfaced as warnings now rather
	// than later.
	for _, pat := range cfg.Ignore {
		if _, err := matchGlob(pat, "probe.sql"); err != nil {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("invalid ignore pattern %q: %v", pat, err))
		}
	}

	return cfg, nil
}

// isValidSeverity reports whether s is one of the three accepted severity
// strings. Empty strings are NOT considered valid by this function (callers
// that treat empty as "no override" should check that separately).
func isValidSeverity(s string) bool {
	switch linter.Severity(s) {
	case linter.SeverityError, linter.SeverityWarning, linter.SeverityInfo:
		return true
	}
	return false
}

// Apply filters and configures the given rules per this config.
//
// Behavior:
//   - A rule entry with Enabled == &false drops the rule from the result.
//   - A rule entry with a valid Severity wraps the rule so Severity()
//     returns the override, and emitted Violations carry that severity.
//   - A rule with no entry uses DefaultSeverity if set and valid; otherwise
//     the rule's built-in severity.
//   - Rules in the config that don't appear in the input slice are ignored
//     (no rule is instantiated from nothing).
//
// The returned slice has the same order as the input, minus disabled rules.
// The input slice is not mutated.
func (c *Config) Apply(rules []linter.Rule) []linter.Rule {
	if c == nil {
		return rules
	}

	out := make([]linter.Rule, 0, len(rules))
	for _, r := range rules {
		rc, hasEntry := c.Rules[r.ID()]

		// Explicit disable.
		if hasEntry && rc.Enabled != nil && !*rc.Enabled {
			continue
		}

		// Determine effective severity override.
		sev := ""
		switch {
		case hasEntry && rc.Severity != "" && isValidSeverity(rc.Severity):
			sev = rc.Severity
		case c.DefaultSeverity != "" && isValidSeverity(c.DefaultSeverity):
			// Only apply default if rule has no explicit override.
			if !(hasEntry && rc.Severity != "") {
				sev = c.DefaultSeverity
			}
		}

		if sev != "" && linter.Severity(sev) != r.Severity() {
			r = wrapWithSeverity(r, linter.Severity(sev))
		}
		out = append(out, r)
	}
	return out
}

// ShouldIgnore reports whether filename matches any Ignore pattern.
//
// Matching is performed against both the raw filename and its cleaned form.
// Patterns use "**" for "any number of path segments" and "*" for a single
// path segment. A nil or empty config returns false.
func (c *Config) ShouldIgnore(filename string) bool {
	if c == nil || len(c.Ignore) == 0 || filename == "" {
		return false
	}
	// Normalize path separators so Windows-style inputs still match POSIX
	// patterns. filepath.ToSlash is a no-op on non-Windows, so we replace
	// backslashes explicitly for cross-platform robustness.
	target := strings.ReplaceAll(filepath.ToSlash(filename), `\`, "/")
	cleanTarget := strings.ReplaceAll(filepath.ToSlash(filepath.Clean(filename)), `\`, "/")

	for _, pat := range c.Ignore {
		for _, candidate := range []string{target, cleanTarget} {
			match, err := matchGlob(pat, candidate)
			if err == nil && match {
				return true
			}
		}
	}
	return false
}

// configuredRule wraps a Rule to override its reported severity. All
// Violations returned by Check are rewritten to carry the override so reports
// are consistent with what Severity() reports.
type configuredRule struct {
	linter.Rule
	sev linter.Severity
}

func wrapWithSeverity(r linter.Rule, sev linter.Severity) linter.Rule {
	return &configuredRule{Rule: r, sev: sev}
}

// Severity returns the override severity.
func (c *configuredRule) Severity() linter.Severity { return c.sev }

// Check runs the wrapped rule and rewrites each violation's Severity field
// to the override, keeping all other fields intact.
func (c *configuredRule) Check(ctx *linter.Context) ([]linter.Violation, error) {
	vs, err := c.Rule.Check(ctx)
	if err != nil {
		return vs, err
	}
	for i := range vs {
		vs[i].Severity = c.sev
	}
	return vs, nil
}

// matchGlob implements a minimal glob matcher supporting "**" (any number of
// path segments, including zero) and "*" (a single path segment with no "/").
// It differs from filepath.Match which treats "**" the same as "*".
//
// Returns (matched, error). Errors indicate malformed patterns.
func matchGlob(pattern, name string) (bool, error) {
	pattern = filepath.ToSlash(pattern)
	name = filepath.ToSlash(name)

	// Exact match short-circuit.
	if pattern == name {
		return true, nil
	}

	// Split pattern on "/" but preserve "**" segments.
	patSegs := strings.Split(pattern, "/")
	nameSegs := strings.Split(name, "/")
	return matchSegments(patSegs, nameSegs)
}

// matchSegments matches path segments with "**" wildcard semantics.
func matchSegments(pat, name []string) (bool, error) {
	for len(pat) > 0 {
		p := pat[0]
		if p == "**" {
			// Skip consecutive "**" segments.
			for len(pat) > 0 && pat[0] == "**" {
				pat = pat[1:]
			}
			if len(pat) == 0 {
				return true, nil // trailing ** matches everything remaining
			}
			// Try to match the remaining pattern at every suffix of name.
			for i := 0; i <= len(name); i++ {
				ok, err := matchSegments(pat, name[i:])
				if err != nil {
					return false, err
				}
				if ok {
					return true, nil
				}
			}
			return false, nil
		}

		if len(name) == 0 {
			return false, nil
		}

		// Non-** segment must match a single name segment via filepath.Match.
		ok, err := filepath.Match(p, name[0])
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
		pat = pat[1:]
		name = name[1:]
	}
	return len(name) == 0, nil
}
