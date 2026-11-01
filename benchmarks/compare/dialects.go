package compare

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

// Dialects lists the corpus dialects, one per testdata/realworld folder.
var Dialects = []string{
	"clickhouse", "mariadb", "mysql", "oracle", "postgresql", "snowflake", "sqlite", "sqlserver",
}

// RepoRoot returns the repository root: the first directory above the working
// directory that holds testdata/realworld. The harness is a separate module,
// so it reads the shared corpus by path instead of importing it.
func RepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("compare: getwd: %w", err)
	}
	for {
		if st, err := os.Stat(filepath.Join(dir, "testdata", "realworld")); err == nil && st.IsDir() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("compare: testdata/realworld not found above the working directory")
		}
		dir = parent
	}
}

// DialectStatements returns the statements of testdata/realworld/<dialect>,
// split with the public gosqlx splitter, in sorted file order. Empty and
// comment-only segments are dropped.
func DialectStatements(dialect string) ([]string, error) {
	root, err := RepoRoot()
	if err != nil {
		return nil, err
	}
	files, err := filepath.Glob(filepath.Join(root, "testdata", "realworld", dialect, "*.sql"))
	if err != nil {
		return nil, fmt.Errorf("compare: glob %s: %w", dialect, err)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("compare: no corpus files for dialect %q", dialect)
	}
	sort.Strings(files)
	var out []string
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("compare: read %s: %w", f, err)
		}
		for _, seg := range gosqlx.SplitStatements(string(b), dialect) {
			if hasCode(seg) {
				out = append(out, seg)
			}
		}
	}
	return out, nil
}

// hasCode reports whether seg holds anything besides whitespace and comments.
func hasCode(seg string) bool {
	sc := bufio.NewScanner(strings.NewReader(seg))
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	inBlock := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		for line != "" {
			if inBlock {
				_, rest, ok := strings.Cut(line, "*/")
				if !ok {
					line = ""
					break
				}
				inBlock = false
				line = strings.TrimSpace(rest)
				continue
			}
			switch {
			case strings.HasPrefix(line, "--"), strings.HasPrefix(line, "#"):
				line = ""
			case strings.HasPrefix(line, "/*"):
				inBlock = true
				line = line[2:]
			default:
				return true
			}
		}
	}
	return false
}

// StatementHash is the hex SHA-256 of a statement's text.
func StatementHash(sql string) string {
	sum := sha256.Sum256([]byte(sql))
	return hex.EncodeToString(sum[:])
}

// PeersFor returns the parsers that are like-for-like peers for dialect:
// GoSQLX first, then every library whose PeerDialects lists it. Legacy
// libraries are included only when withLegacy is set.
func PeersFor(dialect string, withLegacy bool) []Parser {
	var out []Parser
	for _, p := range Parsers {
		if p.ID == "gosqlx" {
			out = append(out, p)
			continue
		}
		if p.Legacy && !withLegacy {
			continue
		}
		for _, d := range p.PeerDialects {
			if d == dialect {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// DialectParse returns the parse function p uses for dialect: GoSQLX is
// parsed with its dialect-specific entry point, peers with their only grammar.
func DialectParse(p Parser, dialect string) (ParseFunc, error) {
	if p.NewDialect != nil {
		return p.NewDialect(dialect)
	}
	return p.New()
}

// safeParse runs parse and turns a panic (some peers panic on input they do
// not support) into a rejection.
func safeParse(parse ParseFunc, sql string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return parse(sql)
}

// AcceptRow is one row of the acceptance table.
type AcceptRow struct {
	Dialect  string  `json:"dialect"`
	Parser   string  `json:"parser"`
	Accepted int     `json:"accepted"`
	Total    int     `json:"total"`
	Rate     float64 `json:"rate"`
}

// Acceptance returns the statements of dialect that each peer accepts,
// indexed like DialectStatements, keyed by parser ID.
func Acceptance(dialect string) (stmts []string, accepted map[string][]bool, err error) {
	stmts, err = DialectStatements(dialect)
	if err != nil {
		return nil, nil, err
	}
	accepted = map[string][]bool{}
	for _, p := range PeersFor(dialect, true) {
		parse, err := DialectParse(p, dialect)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", p.Name, err)
		}
		ok := make([]bool, len(stmts))
		for i, s := range stmts {
			ok[i] = safeParse(parse, s) == nil
		}
		accepted[p.ID] = ok
	}
	return stmts, accepted, nil
}

// AcceptanceTable computes the acceptance rate of every (parser, dialect)
// pair over the whole dialect corpus. Dialects without a peer list GoSQLX
// alone.
func AcceptanceTable() ([]AcceptRow, error) {
	var rows []AcceptRow
	for _, d := range Dialects {
		stmts, acc, err := Acceptance(d)
		if err != nil {
			return nil, err
		}
		for _, p := range PeersFor(d, true) {
			n := 0
			for _, ok := range acc[p.ID] {
				if ok {
					n++
				}
			}
			rate := 0.0
			if len(stmts) > 0 {
				rate = float64(n) / float64(len(stmts))
			}
			rows = append(rows, AcceptRow{Dialect: d, Parser: p.ID, Accepted: n, Total: len(stmts), Rate: rate})
		}
	}
	return rows, nil
}

// CommonAccept is the set of statements every gating parser of a dialect
// accepts. Timing a parser on statements another parser rejects would compare
// a full parse against an early exit.
type CommonAccept struct {
	Dialect string
	// Parsers are the IDs that gated the set (GoSQLX plus non-legacy peers).
	Parsers []string
	// Total is the number of statements in the dialect corpus, counting
	// repeated statements each time.
	Total int
	// Statements are the accepted statements, in corpus order.
	Statements []string
}

// Hashes returns the sorted statement hashes.
func (c CommonAccept) Hashes() []string {
	h := make([]string, len(c.Statements))
	for i, s := range c.Statements {
		h[i] = StatementHash(s)
	}
	sort.Strings(h)
	return h
}

// SetHash is the SHA-256 over the sorted statement hashes, one per line.
func (c CommonAccept) SetHash() string {
	sum := sha256.Sum256([]byte(strings.Join(c.Hashes(), "\n")))
	return hex.EncodeToString(sum[:])
}

// ComputeCommonAccept computes the common-accept set of dialect.
func ComputeCommonAccept(dialect string) (CommonAccept, error) {
	stmts, acc, err := Acceptance(dialect)
	if err != nil {
		return CommonAccept{}, err
	}
	c := CommonAccept{Dialect: dialect, Total: len(stmts)}
	for _, p := range PeersFor(dialect, false) {
		c.Parsers = append(c.Parsers, p.ID)
	}
	seen := map[string]bool{}
	for i, s := range stmts {
		// Corpus files repeat some statements; the set holds each once.
		h := StatementHash(s)
		if seen[h] {
			continue
		}
		seen[h] = true
		all := true
		for _, id := range c.Parsers {
			if !acc[id][i] {
				all = false
				break
			}
		}
		if all {
			c.Statements = append(c.Statements, s)
		}
	}
	return c, nil
}

// CommonAcceptDir is where the checked-in sets live, relative to the harness
// module directory.
const CommonAcceptDir = "commonaccept"

// Encode renders the checked-in file for c.
func (c CommonAccept) Encode() string {
	var b strings.Builder
	b.WriteString("# GoSQLX compare harness: common-accept set (format 1)\n")
	b.WriteString("# Statements of testdata/realworld/" + c.Dialect + " that every gating parser accepts.\n")
	b.WriteString("# One SHA-256 per statement, sorted. Regenerate: go test -run TestCommonAcceptSets -update\n")
	fmt.Fprintf(&b, "# dialect: %s\n", c.Dialect)
	fmt.Fprintf(&b, "# parsers: %s\n", strings.Join(c.Parsers, ","))
	fmt.Fprintf(&b, "# total: %d\n", c.Total)
	fmt.Fprintf(&b, "# accepted: %d\n", len(c.Statements))
	fmt.Fprintf(&b, "# set-sha256: %s\n", c.SetHash())
	for _, h := range c.Hashes() {
		b.WriteString(h + "\n")
	}
	return b.String()
}

// LoadCommonAccept returns the statements of the checked-in common-accept set
// of dialect. It does not re-run any parser; TestCommonAcceptSets keeps the
// file in step with the pinned libraries.
func LoadCommonAccept(dialect string) ([]string, error) {
	path := filepath.Join(CommonAcceptDir, dialect+".txt")
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("compare: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	want := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		want[line] = true
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("compare: read %s: %w", path, err)
	}
	stmts, err := DialectStatements(dialect)
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, s := range stmts {
		h := StatementHash(s)
		if want[h] && !seen[h] {
			seen[h] = true
			out = append(out, s)
		}
	}
	if len(out) != len(want) {
		return nil, fmt.Errorf("compare: %s lists %d hashes but the corpus has %d matching statements; the corpus changed, regenerate the set", path, len(want), len(out))
	}
	return out, nil
}
