// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package benchcorpus

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

var updateManifest = flag.Bool("update-manifest", false, "rewrite testdata/bench/MANIFEST.sha256 from the files on disk")

// TestManifest fails when any pinned corpus file is added, removed or edited
// without regenerating the manifest, so benchmark inputs cannot drift silently.
func TestManifest(t *testing.T) {
	root, err := FindRoot()
	if err != nil {
		t.Fatal(err)
	}
	if *updateManifest {
		got, err := BuildManifest(root)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, "testdata", filepath.FromSlash(ManifestFile))
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %d entries", strings.Count(got, "\n"))
		return
	}
	if err := Verify(root); err != nil {
		t.Fatal(err)
	}
}

// TestVerifyDetectsDrift proves Verify reports edited, added and removed
// files, using a scratch copy of the tree.
func TestVerifyDetectsDrift(t *testing.T) {
	root, err := FindRoot()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	paths, err := ManifestPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	copyTo := func(rel string) {
		data, err := os.ReadFile(filepath.Join(root, "testdata", filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(tmp, "testdata", filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range append(paths, ManifestFile) {
		copyTo(p)
	}
	if err := Verify(tmp); err != nil {
		t.Fatalf("pristine copy must verify: %v", err)
	}

	victim := filepath.Join(tmp, "testdata", "realworld", "mysql", "01_app_crud.sql")
	if err := os.WriteFile(victim, []byte("SELECT 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Verify(tmp); err == nil || !strings.Contains(err.Error(), "content changed: realworld/mysql/01_app_crud.sql") {
		t.Errorf("edited file not reported: %v", err)
	}
	copyTo("realworld/mysql/01_app_crud.sql")

	extra := filepath.Join(tmp, "testdata", "realworld", "mysql", "99_new.sql")
	if err := os.WriteFile(extra, []byte("SELECT 2;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Verify(tmp); err == nil || !strings.Contains(err.Error(), "not in manifest: realworld/mysql/99_new.sql") {
		t.Errorf("added file not reported: %v", err)
	}
	if err := os.Remove(extra); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(victim); err != nil {
		t.Fatal(err)
	}
	if err := Verify(tmp); err == nil || !strings.Contains(err.Error(), "realworld/mysql/01_app_crud.sql") {
		t.Errorf("removed file not reported: %v", err)
	}
}

// TestLoadDeterministic checks two independent loads agree exactly.
func TestLoadDeterministic(t *testing.T) {
	root, err := FindRoot()
	if err != nil {
		t.Fatal(err)
	}
	a, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a.All(), b.All()) {
		t.Fatal("two loads of the same tree produced different statements")
	}
	if len(a.All()) == 0 {
		t.Fatal("corpus is empty")
	}
	keys := map[string]bool{}
	for _, st := range a.All() {
		if keys[st.Key()] {
			t.Fatalf("duplicate statement key %s", st.Key())
		}
		keys[st.Key()] = true
	}
}

func TestBucketBoundaries(t *testing.T) {
	for _, tc := range []struct {
		n    int
		want Bucket
	}{
		{0, Small}, {255, Small}, {256, Medium}, {LargeMin - 1, Medium}, {LargeMin, Large}, {LargeMin * 4, Large},
	} {
		if got := BucketOf(tc.n); got != tc.want {
			t.Errorf("BucketOf(%d) = %v, want %v", tc.n, got, tc.want)
		}
	}
}

func TestStatementsAreBucketedConsistently(t *testing.T) {
	set, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	counts := map[Bucket]int{}
	for _, st := range set.All() {
		if want := BucketOf(len(st.SQL)); st.Bucket != want {
			t.Errorf("%s: bucket %v but %d bytes belongs in %v", st.Key(), st.Bucket, len(st.SQL), want)
		}
		counts[st.Bucket]++
	}
	// The medium and small buckets must be populated for every RW dialect.
	for _, c := range Corpora {
		if c.Kind != KindRealWorld {
			continue
		}
		rw := set.RealWorld(c.Dialect)
		for _, b := range []Bucket{Small, Medium} {
			if len(InBucket(rw, b)) == 0 {
				t.Errorf("realworld/%s has no %v statements", c.Dialect, b)
			}
		}
	}
	t.Logf("statements per bucket: small=%d medium=%d large=%d", counts[Small], counts[Medium], counts[Large])
}

// TestScriptBuildsLargeInput covers the Large bucket, which no single corpus
// statement reaches.
func TestScriptBuildsLargeInput(t *testing.T) {
	set, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	rw := set.RealWorld("postgresql")
	s1, s2 := Script(rw, LargeMin), Script(rw, LargeMin)
	if s1.Bucket != Large || len(s1.SQL) < LargeMin {
		t.Fatalf("script is %d bytes in bucket %v, want Large", len(s1.SQL), s1.Bucket)
	}
	if s1.SQL != s2.SQL {
		t.Error("Script is not deterministic")
	}
	if s1.Dialect != "postgresql" {
		t.Errorf("script dialect = %q", s1.Dialect)
	}
	if got := Script(nil, LargeMin); got.SQL != "" {
		t.Errorf("Script(nil) = %q, want empty", got.SQL)
	}
}

func TestKnownFailuresExcluded(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, "testdata", filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A minimal tree: every listed corpus gets one file with two statements.
	for _, c := range Corpora {
		write(c.Dir+"/01.sql", "SELECT 1;\nSELECT 2;\n")
	}
	write(PortableQueriesFile, "q\tQ\tSELECT 1\n")
	write(KnownFailuresFile, "# header\nmysql/01.sql#1 parse\n")

	set, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range set.RealWorld("mysql") {
		if st.File == "realworld/mysql/01.sql" && st.Index == 1 {
			t.Errorf("known failure %s was not excluded", st.Key())
		}
	}
	if ex := set.Excluded(); len(ex) != 1 || ex[0].Key() != "realworld/mysql/01.sql#1" {
		t.Errorf("Excluded() = %+v, want exactly mysql/01.sql#1", ex)
	}
	// The feature/mysql corpus has the same basename but is not realworld, so it is kept.
	if n := len(set.ByCorpus("feature/mysql")); n != 2 {
		t.Errorf("feature/mysql kept %d statements, want 2", n)
	}

	write(KnownFailuresFile, "garbage\n")
	if _, err := Load(root); err == nil {
		t.Error("malformed known_failures.txt must be an error")
	}
}

// TestCorporaCoverRealworld stops a new testdata/realworld folder from being
// silently left out of (or an unknown one silently added to) the benchmarks.
func TestCorporaCoverRealworld(t *testing.T) {
	root, err := FindRoot()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "testdata", "realworld"))
	if err != nil {
		t.Fatal(err)
	}
	var onDisk, listed []string
	for _, e := range entries {
		if e.IsDir() {
			onDisk = append(onDisk, e.Name())
		}
	}
	for _, c := range Corpora {
		if c.Kind == KindRealWorld {
			listed = append(listed, strings.TrimPrefix(c.Dir, "realworld/"))
		}
	}
	sort.Strings(onDisk)
	sort.Strings(listed)
	if !reflect.DeepEqual(onDisk, listed) {
		t.Errorf("testdata/realworld folders %v differ from Corpora %v", onDisk, listed)
	}
}

// TestDialectCoverage requires a decision for every dialect the library
// accepts: it has a corpus, or it is on the documented no-corpus list.
func TestDialectCoverage(t *testing.T) {
	set, err := Default()
	if err != nil {
		t.Fatal(err)
	}
	wantNone := []string{"bigquery", "redshift"}
	if got := DialectsWithoutCorpus(); !reflect.DeepEqual(got, wantNone) {
		t.Errorf("dialects without a corpus = %v, want %v (add a corpus or update this list deliberately)", got, wantNone)
	}
	for _, d := range Dialects() {
		none := d == "bigquery" || d == "redshift"
		if n := len(set.ByDialect(d)); none == (n > 0) {
			t.Errorf("dialect %s: %d statements, no-corpus=%v", d, n, none)
		}
	}
	for _, d := range []string{"clickhouse", "mariadb", "mysql", "oracle", "postgresql", "snowflake", "sqlite", "sqlserver"} {
		if len(set.RealWorld(d)) == 0 {
			t.Errorf("no realworld statements for %s", d)
		}
	}
}
