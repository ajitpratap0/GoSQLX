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

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// resetCLIFlags returns every flag of every command to its default. Flag
// values live in package variables that survive from one rootCmd.Execute to
// the next, so each run starts from a clean slate.
func resetCLIFlags() {
	var walk func(c *cobra.Command)
	reset := func(f *pflag.Flag) {
		if sv, ok := f.Value.(pflag.SliceValue); ok {
			_ = sv.Replace(nil)
		} else {
			_ = f.Value.Set(f.DefValue)
		}
		f.Changed = false
	}
	walk = func(c *cobra.Command) {
		c.SilenceUsage = false
		c.Flags().VisitAll(reset)
		c.PersistentFlags().VisitAll(reset)
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(rootCmd)
}

// cliResult is what one in-process run of the gosqlx command line produced.
type cliResult struct {
	stdout, stderr string
	err            error
}

// runCLI runs the command line in process with stdin as standard input.
// stdin is only wired up when non-nil.
func runCLI(t *testing.T, stdin *string, args ...string) cliResult {
	t.Helper()
	resetCLIFlags()
	t.Cleanup(resetCLIFlags)

	if stdin != nil {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("pipe: %v", err)
		}
		old := os.Stdin
		os.Stdin = r
		t.Cleanup(func() { os.Stdin = old; _ = r.Close() })
		go func() {
			_, _ = w.WriteString(*stdin)
			_ = w.Close()
		}()
	}

	var out, errOut bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errOut)
	rootCmd.SetArgs(args)
	err := rootCmd.Execute()
	rootCmd.SetOut(nil)
	rootCmd.SetErr(nil)
	return cliResult{stdout: out.String(), stderr: errOut.String(), err: err}
}

func str(s string) *string { return &s }

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCLI_LintExitsNonZeroOnSyntaxErrors(t *testing.T) {
	bad := writeTemp(t, "bad.sql", "SELEC FROM\n")
	good := writeTemp(t, "good.sql", "SELECT id FROM users WHERE id = 1;\n")

	tests := []struct {
		name    string
		stdin   *string
		args    []string
		wantErr bool
	}{
		{"stdin syntax error", str("SELEC FROM"), []string{"lint"}, true},
		{"stdin valid", str("SELECT id FROM users"), []string{"lint"}, false},
		{"file syntax error", nil, []string{"lint", bad}, true},
		{"file valid", nil, []string{"lint", good}, false},
		{"inline syntax error", nil, []string{"lint", "SELECT FROM WHERE ("}, true},
		{"inline valid", nil, []string{"lint", "SELECT id FROM users"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := runCLI(t, tt.stdin, tt.args...)
			if (res.err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v\nstdout: %s", res.err, tt.wantErr, res.stdout)
			}
			if tt.wantErr && strings.Contains(res.stdout, "No violations found") {
				t.Fatalf("invalid SQL reported as clean:\n%s", res.stdout)
			}
		})
	}
}

func TestCLI_LintAutoFixJudgesTheFixedText(t *testing.T) {
	path := writeTemp(t, "ws.sql", "SELECT id FROM users  \n")
	res := runCLI(t, nil, "lint", "--auto-fix", path)
	if res.err != nil {
		t.Fatalf("lint --auto-fix left %v after fixing everything\n%s", res.err, res.stdout)
	}
	if !strings.Contains(res.stdout, "0 violation(s) remain after auto-fix") {
		t.Fatalf("missing remaining-violation count:\n%s", res.stdout)
	}
	got, _ := os.ReadFile(path)
	if strings.Contains(string(got), "  \n") {
		t.Fatalf("file not fixed: %q", got)
	}

	res = runCLI(t, str("SELECT id FROM users  \n"), "lint", "--auto-fix")
	if res.err != nil {
		t.Fatalf("stdin lint --auto-fix: %v\n%s", res.err, res.stdout)
	}
}

func TestCLI_NoStatementsIsNotAnError(t *testing.T) {
	for _, content := range []string{"", "  \n", "-- just a comment\n", "/* a */ -- b\n"} {
		path := writeTemp(t, "empty.sql", content)
		for _, cmd := range []string{"validate", "lint", "format"} {
			if cmd == "lint" && strings.TrimSpace(content) == "" && content != "" {
				continue // whitespace-only text legitimately breaks the whitespace rules
			}
			res := runCLI(t, nil, cmd, path)
			if res.err != nil {
				t.Errorf("%s %q: %v\n%s%s", cmd, content, res.err, res.stdout, res.stderr)
			}
		}
	}
	// Comment-only stdin is the same: valid, and format echoes it.
	res := runCLI(t, str("-- keep me\n"), "format")
	if res.err != nil || strings.TrimSpace(res.stdout) != "-- keep me" {
		t.Fatalf("format of a comment-only stdin = %q, %v", res.stdout, res.err)
	}
	if res = runCLI(t, str("-- keep me\n"), "validate"); res.err != nil {
		t.Fatalf("validate of a comment-only stdin: %v", res.err)
	}
	// parse and analyze need a statement to show; they say so.
	path := writeTemp(t, "c.sql", "-- only a comment\n")
	for _, cmd := range []string{"parse", "analyze"} {
		res := runCLI(t, nil, cmd, path)
		if res.err == nil || !strings.Contains(res.err.Error(), "no SQL statements") {
			t.Errorf("%s of a comment-only file: err = %v, want a 'no SQL statements' error", cmd, res.err)
		}
	}
}

func TestCLI_DialectAliases(t *testing.T) {
	for _, alias := range []string{"postgres", "pg", "mssql", "tsql", "sqlite3", "postgresql", "sqlserver"} {
		for _, cmd := range []string{"validate", "format", "lint", "parse", "analyze"} {
			t.Run(cmd+"/"+alias, func(t *testing.T) {
				res := runCLI(t, nil, cmd, "--dialect", alias, "SELECT id FROM users")
				if res.err != nil && strings.Contains(res.err.Error(), "unknown SQL dialect") {
					t.Fatalf("--dialect %s rejected: %v", alias, res.err)
				}
			})
		}
	}
	res := runCLI(t, nil, "validate", "--dialect", "nosuchsql", "SELECT 1")
	if res.err == nil || !strings.Contains(res.err.Error(), "unknown SQL dialect") {
		t.Fatalf("unknown dialect: err = %v", res.err)
	}
	// Case handling for canonical names is unchanged.
	if res = runCLI(t, nil, "validate", "--dialect", "MySQL", "SELECT 1"); res.err == nil {
		t.Fatal(`--dialect MySQL accepted; names are case-sensitive`)
	}
}

func TestCLI_FormatNoUppercase(t *testing.T) {
	res := runCLI(t, str("SELECT a FROM t"), "format", "--no-uppercase")
	if res.err != nil {
		t.Fatal(res.err)
	}
	if got := strings.ToLower(res.stdout); got != res.stdout {
		t.Fatalf("--no-uppercase output has upper-case keywords: %q", res.stdout)
	}
	res = runCLI(t, str("select a from t"), "format")
	if !strings.Contains(res.stdout, "SELECT") {
		t.Fatalf("default output is not upper case: %q", res.stdout)
	}
	res = runCLI(t, str("select a from t"), "format", "--uppercase", "--no-uppercase")
	if res.err == nil {
		t.Fatal("--uppercase together with --no-uppercase was accepted")
	}
}

func TestCLI_FormatKeepsCommentsAndHints(t *testing.T) {
	res := runCLI(t, str("SELECT /*+ hint */ a FROM t -- note\n"), "format")
	if res.err != nil {
		t.Fatal(res.err)
	}
	for _, want := range []string{"SELECT /*+ hint */ a", "-- note"} {
		if !strings.Contains(res.stdout, want) {
			t.Fatalf("output %q lost %q", res.stdout, want)
		}
	}

	// A hint that cannot be put back refuses the file and leaves it alone.
	original := "SELECT a FROM /*+ FULL(t) */ t -- keep\n"
	path := writeTemp(t, "hint.sql", original)
	res = runCLI(t, nil, "format", "-i", path)
	if res.err == nil {
		t.Fatalf("format -i accepted a hint it cannot place\n%s%s", res.stdout, res.stderr)
	}
	if got, _ := os.ReadFile(path); string(got) != original {
		t.Fatalf("file was rewritten despite the refusal: %q", got)
	}
}

func TestCLI_FormatInPlaceNeverDropsComments(t *testing.T) {
	original := "-- header\nselect a, /* inline */ b from t; -- after\n-- next\nselect 2\n-- tail\n"
	path := writeTemp(t, "c.sql", original)
	res := runCLI(t, nil, "format", "-i", path)
	if res.err != nil {
		t.Fatalf("%v\n%s%s", res.err, res.stdout, res.stderr)
	}
	got, _ := os.ReadFile(path)
	for _, c := range []string{"-- header", "/* inline */", "-- after", "-- next", "-- tail"} {
		if !strings.Contains(string(got), c) {
			t.Errorf("formatted file lost %q:\n%s", c, got)
		}
	}
}

func TestCLI_FormatKeepsByteOrderMark(t *testing.T) {
	path := writeTemp(t, "bom.sql", "\uFEFFselect a from t\n")
	if res := runCLI(t, nil, "format", "-i", path); res.err != nil {
		t.Fatal(res.err)
	}
	got, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(got), "\uFEFFSELECT") {
		t.Fatalf("byte order mark lost or output wrong: %q", got)
	}
	if res := runCLI(t, nil, "validate", path); res.err != nil {
		t.Fatalf("validate of a BOM file: %v", res.err)
	}
}

func TestCLI_ValidateStdinIsNamedStdin(t *testing.T) {
	res := runCLI(t, str("SELECT 1"), "validate")
	if res.err != nil {
		t.Fatal(res.err)
	}
	if !strings.Contains(res.stdout, "<stdin>") || strings.Contains(res.stdout, os.TempDir()) {
		t.Fatalf("stdin result is not labelled <stdin>:\n%s", res.stdout)
	}
	res = runCLI(t, str("SELEC"), "validate")
	if res.err == nil || !strings.Contains(res.stderr+res.stdout, "<stdin>") {
		t.Fatalf("invalid stdin not reported under <stdin>: err=%v\n%s%s", res.err, res.stdout, res.stderr)
	}
}

func TestCLI_ErrorsAreNotPrintedByCobraAndUsageIsSilent(t *testing.T) {
	res := runCLI(t, str("SELEC"), "validate")
	if res.err == nil {
		t.Fatal("expected a validation failure")
	}
	if strings.Contains(res.stderr, "Usage:") || strings.Contains(res.stdout, "Usage:") {
		t.Fatalf("usage printed for a syntax error:\n%s%s", res.stdout, res.stderr)
	}
	if strings.Contains(res.stderr, "Error:") {
		t.Fatalf("cobra printed the error that main prints:\n%s", res.stderr)
	}
	// Argument errors still show usage.
	res = runCLI(t, nil, "parse", "a", "b")
	if res.err == nil || !strings.Contains(res.stderr+res.stdout, "Usage:") {
		t.Fatalf("argument error without usage: err=%v\n%s%s", res.err, res.stdout, res.stderr)
	}
}

func TestCLI_ValidateQuietFailsSilently(t *testing.T) {
	res := runCLI(t, str("SELEC"), "validate", "--quiet")
	if res.err == nil || !IsSilentError(res.err) {
		t.Fatalf("quiet validation failure: err = %v, want a silent error", res.err)
	}
	if res.stdout != "" || res.stderr != "" {
		t.Fatalf("quiet mode printed output: %q %q", res.stdout, res.stderr)
	}
	// Non-validation errors are still reported.
	res = runCLI(t, nil, "validate", "--quiet", "--dialect", "bogus", "SELECT 1")
	if res.err == nil || IsSilentError(res.err) {
		t.Fatalf("bad dialect under --quiet: err = %v, want a visible error", res.err)
	}
}

func TestCLI_ValidateAcceptsBatchScripts(t *testing.T) {
	tsql := writeTemp(t, "batches.sql", "CREATE TABLE a (id INT)\nGO\nSELECT id FROM a\nGO\n")
	res := runCLI(t, nil, "validate", "--dialect", "sqlserver", tsql)
	if res.err != nil {
		t.Fatalf("T-SQL GO script: %v\n%s%s", res.err, res.stdout, res.stderr)
	}
	// Without the dialect, GO is not a separator and the file is invalid.
	if res = runCLI(t, nil, "validate", "--dialect", "postgresql", tsql); res.err == nil {
		t.Fatal("GO script accepted for postgresql")
	}

	mysql := writeTemp(t, "delim.sql", "DELIMITER //\nSELECT 1//\nSELECT 2//\nDELIMITER ;\nSELECT 3;\n")
	if res = runCLI(t, nil, "validate", "--dialect", "mysql", mysql); res.err != nil {
		t.Fatalf("DELIMITER script: %v\n%s%s", res.err, res.stdout, res.stderr)
	}

	// A genuinely broken statement is still reported, with the whole-file
	// position.
	broken := writeTemp(t, "broken.sql", "SELECT 1;\nSELEC 2;\n")
	res = runCLI(t, nil, "validate", broken)
	if res.err == nil || !strings.Contains(res.stderr+res.stdout, "line 2") {
		t.Fatalf("broken file: err=%v\n%s%s", res.err, res.stdout, res.stderr)
	}
}

func TestCLI_GlobalFlagsAreHonouredOrRejected(t *testing.T) {
	// -f is rejected where there is only one output format.
	for _, args := range [][]string{
		{"lint", "-f", "json", "SELECT 1"},
		{"format", "-f", "json", "SELECT 1"},
		{"transpile", "-f", "yaml", "SELECT 1"},
	} {
		res := runCLI(t, nil, args...)
		if res.err == nil || !strings.Contains(res.err.Error(), "-f/--format") {
			t.Errorf("%v: err = %v, want a -f/--format rejection", args, res.err)
		}
	}
	// "-f auto" is the default and is fine.
	if res := runCLI(t, nil, "format", "-f", "auto", "SELECT 1"); res.err != nil {
		t.Errorf("format -f auto: %v", res.err)
	}

	// -o is honoured by parse and transpile.
	dir := t.TempDir()
	out := filepath.Join(dir, "ast.txt")
	if res := runCLI(t, nil, "parse", "-o", out, "SELECT 1"); res.err != nil {
		t.Fatal(res.err)
	} else if res.stdout != "" {
		t.Fatalf("parse -o still wrote to stdout: %q", res.stdout)
	}
	if b, err := os.ReadFile(out); err != nil || len(b) == 0 {
		t.Fatalf("parse -o produced no file: %v", err)
	}
	out = filepath.Join(dir, "t.sql")
	if res := runCLI(t, nil, "transpile", "--from", "mysql", "--to", "postgres", "-o", out, "SELECT 1"); res.err != nil {
		t.Fatal(res.err)
	}
	if b, err := os.ReadFile(out); err != nil || !strings.Contains(string(b), "SELECT 1") {
		t.Fatalf("transpile -o file = %q, %v", b, err)
	}

	// format -o with several inputs would overwrite the file repeatedly.
	a := writeTemp(t, "a.sql", "SELECT 1")
	b := writeTemp(t, "b.sql", "SELECT 2")
	if res := runCLI(t, nil, "format", "-o", filepath.Join(dir, "o.sql"), a, b); res.err == nil {
		t.Fatal("format -o with two inputs accepted")
	}

	// validate maps -f json / -o onto its own output flags.
	res := runCLI(t, nil, "validate", "-f", "json", "SELECT 1")
	if res.err != nil || !strings.Contains(res.stdout, "{") {
		t.Fatalf("validate -f json: %v\n%s", res.err, res.stdout)
	}
	if res = runCLI(t, nil, "validate", "-f", "yaml", "SELECT 1"); res.err == nil {
		t.Fatal("validate -f yaml accepted")
	}
	jsonOut := filepath.Join(dir, "v.json")
	if res = runCLI(t, nil, "validate", "-f", "json", "-o", jsonOut, "SELECT 1"); res.err != nil {
		t.Fatalf("validate -f json -o: %v", res.err)
	}
	if b, err := os.ReadFile(jsonOut); err != nil || !strings.Contains(string(b), "{") {
		t.Fatalf("validate -o file = %q, %v", b, err)
	}
	if res = runCLI(t, nil, "validate", "-o", filepath.Join(dir, "x"), "SELECT 1"); res.err == nil {
		t.Fatal("validate -o without a machine-readable format accepted")
	}
}
