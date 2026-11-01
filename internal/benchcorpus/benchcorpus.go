// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

// Package benchcorpus is the single source of benchmark and golden inputs.
//
// It loads an explicit, reviewed list of corpus folders under testdata/ (never
// a glob over testdata/**), splits every file into statements with the public
// gosqlx.SplitStatements splitter, drops statements listed in
// testdata/realworld/known_failures.txt, and tags each statement with a size
// bucket. Output order is fully determined by the sorted file names and the
// splitter, so two loads of the same tree are identical.
//
// The tree is pinned by testdata/bench/MANIFEST.sha256 (see Verify). The
// separate benchmarks/compare module cannot import this internal package; it
// reads the same files by relative path, and a test here asserts that its
// portable query list equals testdata/bench/portable_queries.txt.
package benchcorpus

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/ajitpratap0/GoSQLX/internal/dialectaudit"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// Bucket classifies a statement by size in bytes.
type Bucket int

const (
	// Small statements are shorter than SmallLimit bytes.
	Small Bucket = iota
	// Medium statements are at least SmallLimit and shorter than LargeMin bytes.
	Medium
	// Large statements are at least LargeMin bytes.
	Large
)

const (
	// SmallLimit is the exclusive upper bound of the Small bucket (256 B).
	SmallLimit = 256
	// LargeMin is the inclusive lower bound of the Large bucket (64 KB).
	LargeMin = 64 << 10
)

// Buckets lists every bucket in ascending size order.
var Buckets = []Bucket{Small, Medium, Large}

// BucketOf returns the bucket for a statement of n bytes.
func BucketOf(n int) Bucket {
	switch {
	case n < SmallLimit:
		return Small
	case n >= LargeMin:
		return Large
	default:
		return Medium
	}
}

// String returns the bucket name used in benchmark names.
func (b Bucket) String() string {
	switch b {
	case Small:
		return "small"
	case Medium:
		return "medium"
	case Large:
		return "large"
	}
	return fmt.Sprintf("bucket(%d)", int(b))
}

// Kind groups corpora by origin.
type Kind string

const (
	// KindRealWorld is testdata/realworld/<dialect>, one folder per dialect.
	KindRealWorld Kind = "realworld"
	// KindFeature is the small per-feature dialect samples (testdata/mssql, ...).
	KindFeature Kind = "feature"
	// KindGeneric is dialect-neutral SQL (TPC, ORM, real_world).
	KindGeneric Kind = "generic"
)

// GenericDialect is the dialect name for dialect-neutral corpora.
const GenericDialect = "generic"

// Corpus is one explicitly listed corpus folder.
type Corpus struct {
	// Name is the stable identifier, e.g. "realworld/mysql".
	Name string
	// Dir is the folder relative to testdata/, slash separated.
	Dir string
	// Dialect is the keywords.SQLDialect value the folder is written in.
	Dialect string
	Kind    Kind
}

// Corpora is the explicit list of benchmark corpus folders. Adding a folder
// here is the only way it enters the benchmark set; TestCorporaCoverRealworld
// fails if testdata/realworld gains a folder that is not listed.
var Corpora = []Corpus{
	{"realworld/clickhouse", "realworld/clickhouse", "clickhouse", KindRealWorld},
	{"realworld/mariadb", "realworld/mariadb", "mariadb", KindRealWorld},
	{"realworld/mysql", "realworld/mysql", "mysql", KindRealWorld},
	{"realworld/oracle", "realworld/oracle", "oracle", KindRealWorld},
	{"realworld/postgresql", "realworld/postgresql", "postgresql", KindRealWorld},
	{"realworld/snowflake", "realworld/snowflake", "snowflake", KindRealWorld},
	{"realworld/sqlite", "realworld/sqlite", "sqlite", KindRealWorld},
	{"realworld/sqlserver", "realworld/sqlserver", "sqlserver", KindRealWorld},
	{"feature/mssql", "mssql", "sqlserver", KindFeature},
	{"feature/mysql", "mysql", "mysql", KindFeature},
	{"feature/oracle", "oracle", "oracle", KindFeature},
	{"feature/postgresql", "postgresql", "postgresql", KindFeature},
	{"generic/real_world", "real_world", GenericDialect, KindGeneric},
	{"generic/tpch", "corpus/tpch", GenericDialect, KindGeneric},
	{"generic/tpcds", "corpus/tpcds", GenericDialect, KindGeneric},
	{"generic/orm", "corpus/orm", GenericDialect, KindGeneric},
}

// Paths of the non-corpus files inside testdata/, relative to testdata/.
const (
	KnownFailuresFile   = "realworld/known_failures.txt"
	PortableQueriesFile = "bench/portable_queries.txt"
	ManifestFile        = "bench/MANIFEST.sha256"
)

// Statement is one split statement of one corpus file.
type Statement struct {
	Corpus  string // Corpus.Name
	Dialect string
	// File is the source path relative to testdata/, slash separated.
	File string
	// Index is the 0-based position among all splitter segments of File
	// (comment-only segments count), matching known_failures.txt numbering.
	Index  int
	SQL    string
	Bucket Bucket
}

// Key is "<File>#<Index>".
func (s Statement) Key() string { return fmt.Sprintf("%s#%d", s.File, s.Index) }

// Query is one of the portable queries shared with benchmarks/compare.
type Query struct {
	ID, Name, SQL string
}

// Set is an immutable loaded corpus. Each accessor returns a fresh slice that
// the caller may modify without affecting the Set.
type Set struct {
	all      []Statement
	excluded []Statement
	portable []Query
}

// Load reads the corpus under root (the repository root).
func Load(root string) (*Set, error) {
	td := filepath.Join(root, "testdata")
	known, err := loadKnownFailures(filepath.Join(td, filepath.FromSlash(KnownFailuresFile)))
	if err != nil {
		return nil, err
	}
	s := &Set{}
	for _, c := range Corpora {
		files, err := CorpusFiles(root, c)
		if err != nil {
			return nil, err
		}
		for _, rel := range files {
			data, err := os.ReadFile(filepath.Join(td, filepath.FromSlash(rel)))
			if err != nil {
				return nil, fmt.Errorf("benchcorpus: read %s: %w", rel, err)
			}
			for i, sql := range gosqlx.SplitStatements(string(data), c.Dialect) {
				if dialectaudit.Empty(sql) {
					continue
				}
				st := Statement{Corpus: c.Name, Dialect: c.Dialect, File: rel, Index: i, SQL: sql, Bucket: BucketOf(len(sql))}
				if c.Kind == KindRealWorld {
					if _, bad := known[strings.TrimPrefix(st.Key(), "realworld/")]; bad {
						s.excluded = append(s.excluded, st)
						continue
					}
				}
				s.all = append(s.all, st)
			}
		}
	}
	s.portable, err = loadPortable(filepath.Join(td, filepath.FromSlash(PortableQueriesFile)))
	if err != nil {
		return nil, err
	}
	return s, nil
}

var (
	defaultOnce sync.Once
	defaultSet  *Set
	defaultErr  error
)

// Default loads the corpus of the enclosing repository once per process.
func Default() (*Set, error) {
	defaultOnce.Do(func() {
		root, err := FindRoot()
		if err != nil {
			defaultErr = err
			return
		}
		defaultSet, defaultErr = Load(root)
	})
	return defaultSet, defaultErr
}

// FindRoot walks up from the working directory to the repository root, the
// first directory that holds both go.mod and testdata/bench (the manifest
// itself is not required, so it can be generated from a clean checkout).
func FindRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("benchcorpus: getwd: %w", err)
	}
	for {
		_, modErr := os.Stat(filepath.Join(dir, "go.mod"))
		_, benchErr := os.Stat(filepath.Join(dir, "testdata", "bench"))
		if modErr == nil && benchErr == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("benchcorpus: no go.mod with testdata/bench above the working directory")
		}
		dir = parent
	}
}

// CorpusFiles returns the *.sql files of c relative to testdata/, sorted.
func CorpusFiles(root string, c Corpus) ([]string, error) {
	dir := filepath.Join(root, "testdata", filepath.FromSlash(c.Dir))
	matches, err := filepath.Glob(filepath.Join(dir, "*.sql"))
	if err != nil {
		return nil, fmt.Errorf("benchcorpus: glob %s: %w", c.Dir, err)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("benchcorpus: corpus %s: no .sql files in testdata/%s", c.Name, c.Dir)
	}
	sort.Strings(matches)
	out := make([]string, len(matches))
	for i, m := range matches {
		out[i] = c.Dir + "/" + filepath.Base(m)
	}
	return out, nil
}

// All returns every non-excluded statement in corpus order.
func (s *Set) All() []Statement { return append([]Statement(nil), s.all...) }

// Excluded returns the statements dropped because known_failures.txt lists them.
func (s *Set) Excluded() []Statement { return append([]Statement(nil), s.excluded...) }

// Portable returns the portable queries shared with benchmarks/compare.
func (s *Set) Portable() []Query { return append([]Query(nil), s.portable...) }

// ByDialect returns the statements of every corpus written in dialect.
func (s *Set) ByDialect(dialect string) []Statement {
	return s.filter(func(st Statement) bool { return st.Dialect == dialect })
}

// RealWorld returns the testdata/realworld statements of one dialect, the
// input of the RW/<dialect>/<bucket> benchmarks.
func (s *Set) RealWorld(dialect string) []Statement {
	return s.filter(func(st Statement) bool { return st.Dialect == dialect && strings.HasPrefix(st.Corpus, "realworld/") })
}

// ByCorpus returns the statements of the corpus with the given Name.
func (s *Set) ByCorpus(name string) []Statement {
	return s.filter(func(st Statement) bool { return st.Corpus == name })
}

func (s *Set) filter(keep func(Statement) bool) []Statement {
	var out []Statement
	for _, st := range s.all {
		if keep(st) {
			out = append(out, st)
		}
	}
	return out
}

// InBucket returns the statements of stmts that fall in b.
func InBucket(stmts []Statement, b Bucket) []Statement {
	var out []Statement
	for _, st := range stmts {
		if st.Bucket == b {
			out = append(out, st)
		}
	}
	return out
}

// Dialects returns every dialect the library accepts, in keywords.AllDialects order.
func Dialects() []string {
	all := keywords.AllDialects()
	out := make([]string, len(all))
	for i, d := range all {
		out[i] = string(d)
	}
	return out
}

// DialectsWithoutCorpus lists accepted dialects that no corpus is written in
// (generic is covered by the generic corpora).
func DialectsWithoutCorpus() []string {
	have := map[string]bool{}
	for _, c := range Corpora {
		have[c.Dialect] = true
	}
	var out []string
	for _, d := range Dialects() {
		if !have[d] {
			out = append(out, d)
		}
	}
	return out
}

// Script joins statements, cycling through them in order, into one
// semicolon-separated script of at least minBytes. No corpus statement
// reaches the Large bucket on its own, so large-input benchmarks build their
// input with Script(stmts, LargeMin). The result is deterministic.
func Script(stmts []Statement, minBytes int) Statement {
	if len(stmts) == 0 {
		return Statement{}
	}
	var b strings.Builder
	for i := 0; b.Len() < minBytes; i++ {
		sql := strings.TrimRight(stmts[i%len(stmts)].SQL, " \t\r\n")
		b.WriteString(sql)
		// The separator goes on its own line: a statement may end in a
		// line comment (-- or #) that would otherwise swallow the ';'.
		b.WriteString("\n;\n")
	}
	out := stmts[0]
	out.File, out.Index = "", 0
	out.Corpus += "+script"
	out.SQL = b.String()
	out.Bucket = BucketOf(len(out.SQL))
	return out
}

func loadKnownFailures(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("benchcorpus: open known failures: %w", err)
	}
	defer func() { _ = f.Close() }()
	known, err := dialectaudit.ParseKnownFailures(f)
	if err != nil {
		return nil, fmt.Errorf("benchcorpus: %w", err)
	}
	return known, nil
}

func loadPortable(path string) ([]Query, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("benchcorpus: open portable queries: %w", err)
	}
	defer func() { _ = f.Close() }()
	var out []Query
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			return nil, fmt.Errorf("benchcorpus: portable_queries.txt: want id<TAB>name<TAB>sql, got %q", line)
		}
		out = append(out, Query{ID: parts[0], Name: parts[1], SQL: parts[2]})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("benchcorpus: scan portable queries: %w", err)
	}
	return out, nil
}
