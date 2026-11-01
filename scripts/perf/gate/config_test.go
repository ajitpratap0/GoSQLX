// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package main

// Tests of the perf tooling's configuration (W0-15): the toolchain pin of the
// perf workflows, GOMEMLIMIT next to every GOGC=off measurement, the shell
// helpers in scripts/perf/lib.sh and the full-matrix suite. They read the
// repository files, so they run from scripts/perf/gate.

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

const repoRoot = "../../.."

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var perfWorkflows = []string{".github/workflows/perf-gate.yml", ".github/workflows/bench-compare.yml"}

// TestPerfWorkflowsPinOneGoToolchain: perf numbers from the gate and from the
// competitor harness are only comparable when both are built by the same Go
// release (C0 found the gate on 1.26.1 from go.mod and the harness on 1.26.9).
// Each workflow pins PERF_GO_VERSION to the same exact release, every
// setup-go step uses it without check-latest, and GOTOOLCHAIN=local stops a
// go.mod from switching toolchains behind the pin.
func TestPerfWorkflowsPinOneGoToolchain(t *testing.T) {
	pinRe := regexp.MustCompile(`(?m)^\s+PERF_GO_VERSION:\s*'?([0-9]+\.[0-9]+\.[0-9]+)'?\s*$`)
	pins := map[string]string{}
	for _, wf := range perfWorkflows {
		src := readRepoFile(t, wf)
		m := pinRe.FindAllStringSubmatch(src, -1)
		if len(m) != 1 {
			t.Fatalf("%s: want exactly one PERF_GO_VERSION: 'X.Y.Z' in the workflow env, found %d", wf, len(m))
		}
		pins[wf] = m[0][1]
		if !regexp.MustCompile(`(?m)^\s+GOTOOLCHAIN:\s*local\s*$`).MatchString(src) {
			t.Errorf("%s: GOTOOLCHAIN must be local so go.mod cannot switch toolchains", wf)
		}
		if strings.Contains(src, "go-version-file") {
			t.Errorf("%s: setup-go must use the pinned PERF_GO_VERSION, not go-version-file", wf)
		}
		steps := strings.Split(src, "uses: actions/setup-go@")[1:]
		if len(steps) == 0 {
			t.Fatalf("%s: no setup-go step", wf)
		}
		for i, step := range steps {
			with := step
			if j := strings.Index(with, "- name:"); j >= 0 {
				with = with[:j]
			}
			if !strings.Contains(with, "go-version: ${{ env.PERF_GO_VERSION }}") {
				t.Errorf("%s: setup-go step %d does not use go-version: ${{ env.PERF_GO_VERSION }}", wf, i+1)
			}
			if !strings.Contains(with, "check-latest: false") {
				t.Errorf("%s: setup-go step %d must set check-latest: false", wf, i+1)
			}
		}
	}
	if a, b := pins[perfWorkflows[0]], pins[perfWorkflows[1]]; a != b {
		t.Errorf("perf workflows pin different toolchains: %s=%s, %s=%s", perfWorkflows[0], a, perfWorkflows[1], b)
	}
}

// TestGCOffMeasurementsSetGOMEMLIMIT: every place a perf script or workflow
// turns the collector off also bounds the heap, so first-touch page faults do
// not pollute timings and profiles (C0 methodology finding 2).
func TestGCOffMeasurementsSetGOMEMLIMIT(t *testing.T) {
	files := []string{"scripts/perf/ab.sh", "scripts/perf/profile.sh", "Taskfile.yml"}
	files = append(files, perfWorkflows...)
	gcoff := regexp.MustCompile(`GOGC[=:]\s*'?off`)
	for _, f := range files {
		sc := bufio.NewScanner(strings.NewReader(readRepoFile(t, f)))
		for n := 1; sc.Scan(); n++ {
			line := strings.TrimSpace(sc.Text())
			// Comments and Taskfile descriptions only talk about GOGC=off.
			if strings.HasPrefix(line, "#") || strings.HasPrefix(line, "desc:") || !gcoff.MatchString(line) {
				continue
			}
			// gcoff_env is the array scripts fill from perf_gcoff_env.
			if !strings.Contains(line, "GOMEMLIMIT") && !strings.Contains(line, "gcoff_env") {
				t.Errorf("%s:%d sets GOGC=off without GOMEMLIMIT (use perf_gcoff_env from scripts/perf/lib.sh): %s", f, n, line)
			}
		}
	}
	// The competitor harness lives in its own module; its default must match.
	lib := readRepoFile(t, "scripts/perf/lib.sh")
	m := regexp.MustCompile(`(?m)^PERF_GOMEMLIMIT_DEFAULT=(\S+)$`).FindStringSubmatch(lib)
	if m == nil {
		t.Fatal("scripts/perf/lib.sh: no PERF_GOMEMLIMIT_DEFAULT")
	}
	pub := readRepoFile(t, "benchmarks/compare/cmd/publish/main.go")
	if want := `defaultGOMEMLIMIT = "` + m[1] + `"`; !strings.Contains(pub, want) {
		t.Errorf("benchmarks/compare/cmd/publish: want %s, the scripts/perf/lib.sh default", want)
	}
}

// bashLib runs a snippet with scripts/perf/lib.sh sourced.
func bashLib(t *testing.T, env []string, script string) string {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	cmd := exec.Command("bash", "-c", `set -euo pipefail; . "$1"; `+script, "bash", filepath.Join(repoRoot, "scripts", "perf", "lib.sh"))
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash: %v\n%s", err, out)
	}
	return string(out)
}

func TestGCOffEnvSetsTheMemoryLimit(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  []string
		want string
	}{
		{"default", []string{"PERF_GOMEMLIMIT="}, "GOGC=off\nGOMEMLIMIT=64MiB\n"},
		{"override", []string{"PERF_GOMEMLIMIT=1GiB"}, "GOGC=off\nGOMEMLIMIT=1GiB\n"},
		{"off unsets an inherited limit", []string{"PERF_GOMEMLIMIT=off"}, "-u\nGOMEMLIMIT\nGOGC=off\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := bashLib(t, tc.env, "perf_gcoff_env"); got != tc.want {
				t.Errorf("perf_gcoff_env = %q, want %q", got, tc.want)
			}
			// The arguments must work as given: env(1) applies them.
			got := bashLib(t, append(tc.env, "GOMEMLIMIT=inherited"), `a=(); while IFS= read -r kv; do a+=("$kv"); done < <(perf_gcoff_env); env "${a[@]}" sh -c 'echo "GOGC=$GOGC GOMEMLIMIT=${GOMEMLIMIT:-unset}"'`)
			wantLimit := strings.TrimPrefix(strings.Split(strings.TrimSpace(tc.want), "\n")[1], "GOMEMLIMIT=")
			if strings.HasPrefix(tc.want, "-u") {
				wantLimit = "unset"
			}
			if want := "GOGC=off GOMEMLIMIT=" + wantLimit + "\n"; got != want {
				t.Errorf("env with perf_gcoff_env: got %q, want %q", got, want)
			}
		})
	}
}

func TestCPUModelIsRecorded(t *testing.T) {
	got := strings.TrimSpace(bashLib(t, nil, "perf_cpu_model"))
	if got == "" || strings.HasPrefix(got, "unknown") && runtime.GOOS == "linux" {
		t.Fatalf("perf_cpu_model = %q, want a model name", got)
	}
	if !strings.HasSuffix(got, ")") {
		t.Errorf("perf_cpu_model = %q, want the architecture in parentheses", got)
	}
}

// valgrindSummary is cachegrind's stderr summary with --cache-sim=yes
// (valgrind 3.22, as installed on ubuntu-24.04 runners).
const valgrindSummary = `==4242== Cachegrind, a high-precision tracing profiler
==4242== 
==4242== I refs:        2,149,394
==4242== I1  misses:        1,276
==4242== LLi misses:        1,232
==4242== I1  miss rate:      0.06%
==4242== LLi miss rate:      0.06%
==4242== 
==4242== D refs:          758,433  (542,105 rd   + 216,328 wr)
==4242== D1  misses:       14,357  ( 12,198 rd   +   2,159 wr)
==4242== LLd misses:        9,032  (  7,920 rd   +   1,112 wr)
==4242== D1  miss rate:       1.9% (    2.3%     +     1.0%  )
==4242== LLd miss rate:       1.2% (    1.5%     +     0.5%  )
==4242== 
==4242== LL refs:          15,633  ( 13,474 rd   +   2,159 wr)
==4242== LL misses:        10,264  (  9,152 rd   +   1,112 wr)
==4242== LL miss rate:        0.4% (    0.3%     +     0.5%  )
`

func TestCachegrindCountsParseTheSummary(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	full := write("full.log", valgrindSummary)
	if got := bashLib(t, nil, `perf_cachegrind_counts "`+full+`"`); got != "2149394 1276 1232 758433 14357 9032\n" {
		t.Errorf("cache-sim summary: got %q", got)
	}
	// --cache-sim=no (the perf gate's instruction counts): only I refs.
	irOnly := write("ir.log", "==7== I refs:        123,456,789\n")
	if got := bashLib(t, nil, `perf_cachegrind_counts "`+irOnly+`"`); got != "123456789 0 0 0 0 0\n" {
		t.Errorf("Ir-only summary: got %q", got)
	}
	empty := write("empty.log", "valgrind: failed to start tool\n")
	if got := bashLib(t, nil, `if perf_cachegrind_counts "`+empty+`"; then echo parsed; else echo failed; fi`); got != "failed\n" {
		t.Errorf("a log without I refs must fail, got %q", got)
	}
}

// TestMatrixSuiteCoversEveryBenchmarkPackage: the full-matrix mode of the
// perf gate runs the suite scripts/perf/matrix-suite.sh prints, which must
// name every package with benchmarks that `task bench:matrix` runs (./pkg/...
// and ./wasm/internal/... except the CGO-only cbinding), each once, with the
// regex ".". The expected set is computed here independently of the script.
func TestMatrixSuiteCoversEveryBenchmarkPackage(t *testing.T) {
	want := map[string]bool{}
	benchRe := regexp.MustCompile(`(?m)^func Benchmark\w*\(`)
	for _, top := range []string{"pkg", "wasm/internal"} {
		err := filepath.WalkDir(filepath.Join(repoRoot, top), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, "_test.go") {
				return err
			}
			src, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if benchRe.Match(src) {
				rel, err := filepath.Rel(repoRoot, filepath.Dir(p))
				if err != nil {
					return err
				}
				if rel = filepath.ToSlash(rel); rel != "pkg/cbinding" {
					want["./"+rel] = true
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if !want["./pkg/gosqlx"] || !want["./pkg/sql/tokenizer"] {
		t.Fatalf("benchmark package walk found %v, which lacks pkg/gosqlx or pkg/sql/tokenizer", want)
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not installed")
	}
	out, err := exec.Command("bash", filepath.Join(repoRoot, "scripts", "perf", "matrix-suite.sh"), repoRoot).CombinedOutput()
	if err != nil {
		t.Fatalf("matrix-suite.sh: %v\n%s", err, out)
	}
	got := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if len(f) != 2 || f[1] != "." {
			t.Errorf("matrix suite: want \"<package> .\", got %q", sc.Text())
			continue
		}
		if got[f[0]] {
			t.Errorf("matrix suite: %s listed twice", f[0])
		}
		got[f[0]] = true
	}
	var missing, extra []string
	for p := range want {
		if !got[p] {
			missing = append(missing, p)
		}
	}
	for p := range got {
		if !want[p] {
			extra = append(extra, p)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("matrix suite misses benchmark packages: %v", missing)
	}
	if len(extra) > 0 {
		t.Errorf("matrix suite lists packages without benchmarks: %v", extra)
	}
}
