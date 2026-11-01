package compare

// W0-14b scratch: per-statement cost breakdown of the common-accept sets and
// focused benchmarks for profiling. Not for merge.

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ajitpratap0/GoSQLX/internal/tokscratch"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	gosqlxast "github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
	rqlite "github.com/rqlite/sql"
	vitess "vitess.io/vitess/go/vt/sqlparser"
)

// stmtKind classifies a statement by its first keyword(s), skipping comments.
func stmtKind(s string) string {
	t := strings.TrimSpace(s)
	for {
		switch {
		case strings.HasPrefix(t, "--"), strings.HasPrefix(t, "#"):
			if i := strings.IndexByte(t, '\n'); i >= 0 {
				t = strings.TrimSpace(t[i+1:])
				continue
			}
			return "comment"
		case strings.HasPrefix(t, "/*"):
			if i := strings.Index(t, "*/"); i >= 0 {
				t = strings.TrimSpace(t[i+2:])
				continue
			}
			return "comment"
		}
		break
	}
	f := strings.Fields(strings.ToUpper(t))
	if len(f) == 0 {
		return "empty"
	}
	k := strings.Trim(f[0], "(;")
	switch k {
	case "CREATE", "ALTER", "DROP":
		i := 1
		for i < len(f) && (f[i] == "OR" || f[i] == "REPLACE" || f[i] == "UNIQUE" || f[i] == "TEMPORARY" || f[i] == "TEMP" || f[i] == "IF" || f[i] == "NOT" || f[i] == "EXISTS" || f[i] == "DEFINER") {
			i++
		}
		if i < len(f) {
			k += " " + f[i]
		}
	}
	return k
}

func timeOne(parse ParseFunc, s string, iters int) time.Duration {
	start := time.Now()
	for i := 0; i < iters; i++ {
		if err := parse(s); err != nil {
			panic(err)
		}
	}
	return time.Since(start) / time.Duration(iters)
}

func median(d []time.Duration) time.Duration {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return d[len(d)/2]
}

// TestW014bPerStmt writes a TSV of per-statement GoSQLX and peer cost for the
// dialects in W014B_DIALECTS (default "mysql sqlite") to W014B_OUT.
func TestW014bPerStmt(t *testing.T) {
	out := os.Getenv("W014B_OUT")
	if out == "" {
		t.Skip("set W014B_OUT")
	}
	ds := strings.Fields(os.Getenv("W014B_DIALECTS"))
	if len(ds) == 0 {
		ds = []string{"mysql", "sqlite"}
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fmt.Fprintln(f, "dialect\tidx\tkind\tbytes\ttokens\tparser\tns\tgosqlx_ns\tratio")
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)
	for _, d := range ds {
		stmts, err := LoadCommonAccept(d)
		if err != nil {
			t.Fatal(err)
		}
		peers := PeersFor(d, false)
		fns := make([]ParseFunc, len(peers))
		for i, p := range peers {
			fns[i], err = DialectParse(p, d)
			if err != nil {
				t.Fatal(err)
			}
		}
		for idx, s := range stmts {
			toks, _ := tkz.TokenizeString(s)
			ntok := len(toks)
			tkz.Reset()
			// calibrate iterations to ~1ms per sample on gosqlx
			base := timeOne(fns[0], s, 20)
			iters := int(time.Millisecond / (base + 1))
			if iters < 5 {
				iters = 5
			}
			samples := make([][]time.Duration, len(peers))
			for r := 0; r < 7; r++ {
				for i := range peers {
					j := (i + r) % len(peers)
					samples[j] = append(samples[j], timeOne(fns[j], s, iters))
				}
			}
			g := median(samples[0])
			for i, p := range peers {
				m := median(samples[i])
				fmt.Fprintf(f, "%s\t%d\t%s\t%d\t%d\t%s\t%d\t%d\t%.3f\n", d, idx, stmtKind(s), len(s), ntok, p.ID, m.Nanoseconds(), g.Nanoseconds(), float64(g)/float64(m))
			}
		}
	}
}

// TestW014bDump writes the common-accept statements of a dialect, one per
// block, so they can be inspected.
func TestW014bDump(t *testing.T) {
	out := os.Getenv("W014B_DUMP")
	if out == "" {
		t.Skip("set W014B_DUMP")
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, d := range []string{"mysql", "sqlite", "mariadb"} {
		stmts, err := LoadCommonAccept(d)
		if err != nil {
			t.Fatal(err)
		}
		for i, s := range stmts {
			fmt.Fprintf(f, "=== %s %d %s\n%s\n", d, i, stmtKind(s), s)
		}
	}
}

// BenchmarkW014bKind parses only the common-accept statements of one kind,
// for profiling: BenchmarkW014bKind/<dialect>/<kind>/<parser>.
func BenchmarkW014bKind(b *testing.B) {
	for _, d := range []string{"mysql", "sqlite"} {
		stmts, err := LoadCommonAccept(d)
		if err != nil {
			b.Fatal(err)
		}
		byKind := map[string][]string{}
		for _, s := range stmts {
			k := strings.ReplaceAll(stmtKind(s), " ", "_")
			byKind[k] = append(byKind[k], s)
		}
		kinds := make([]string, 0, len(byKind))
		for k := range byKind {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		for _, k := range kinds {
			set := byKind[k]
			for _, p := range PeersFor(d, false) {
				b.Run(d+"/"+k+"/"+p.ID, func(b *testing.B) {
					parse, err := DialectParse(p, d)
					if err != nil {
						b.Fatal(err)
					}
					b.ReportAllocs()
					for b.Loop() {
						for _, s := range set {
							if err := parse(s); err != nil {
								b.Fatal(err)
							}
						}
					}
				})
			}
		}
	}
}

// BenchmarkW014bLexSet lexes a whole common-accept set: GoSQLX scratch path
// (tokenizer dialect set) against the peer's scanner.
func BenchmarkW014bLexSet(b *testing.B) {
	for _, d := range []string{"mysql", "sqlite"} {
		stmts, err := LoadCommonAccept(d)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(d+"/gosqlx_scratch", func(b *testing.B) {
			tkz := tokenizer.GetTokenizer()
			defer tokenizer.PutTokenizer(tkz)
			b.ReportAllocs()
			for b.Loop() {
				for _, s := range stmts {
					tkz.SetDialect(keywords.SQLDialect(d))
					if _, err := tokscratch.String(tkz, s); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
		switch d {
		case "mysql":
			b.Run(d+"/vitess_scan", func(b *testing.B) {
				p, err := vitess.New(vitess.Options{})
				if err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				for b.Loop() {
					for _, s := range stmts {
						tkn := p.NewStringTokenizer(s)
						for {
							if typ, _ := tkn.Scan(); typ == 0 {
								break
							}
						}
					}
				}
			})
		case "sqlite":
			b.Run(d+"/rqlite_scan", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					for _, s := range stmts {
						sc := rqlite.NewScanner(strings.NewReader(s))
						for {
							if _, tok, _ := sc.Scan(); tok == rqlite.EOF {
								break
							}
						}
					}
				}
			})
		}
	}
}

var w014bQuoteSQL = map[string]string{
	"plain": "SELECT users.id, users.name, profiles.bio FROM users LEFT JOIN profiles ON profiles.user_id = users.id " +
		"WHERE users.deleted_at IS NULL AND users.age > 21 ORDER BY users.created_at DESC LIMIT 20",
	"backtick": "SELECT `users`.`id`, `users`.`name`, `profiles`.`bio` FROM `users` LEFT JOIN `profiles` ON `profiles`.`user_id` = `users`.`id` " +
		"WHERE `users`.`deleted_at` IS NULL AND `users`.`age` > 21 ORDER BY `users`.`created_at` DESC LIMIT 20",
	"ddl_create": "CREATE TABLE users (id BIGINT NOT NULL, name VARCHAR(255) NOT NULL, email VARCHAR(255) NOT NULL, age INT, " +
		"created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, deleted_at TIMESTAMP NULL, PRIMARY KEY (id), UNIQUE (email))",
	"ddl_index": "CREATE INDEX idx_users_deleted_at ON users (deleted_at)",
	"commit":    "COMMIT",
	"show":      "SHOW TABLES",
	"select1":   "SELECT 1",
	"set":       "SET NAMES utf8mb4",
}

// BenchmarkW014bShape: one query, several GoSQLX entry points and Vitess.
// gosqlx = gosqlx.Parse, gosqlx_mysql = ParseWithDialect(mysql), lex =
// tokscratch only (default dialect), lex_mysql = tokscratch with mysql.
func BenchmarkW014bShape(b *testing.B) {
	names := make([]string, 0, len(w014bQuoteSQL))
	for k := range w014bQuoteSQL {
		names = append(names, k)
	}
	sort.Strings(names)
	vp, err := vitess.New(vitess.Options{})
	if err != nil {
		b.Fatal(err)
	}
	for _, n := range names {
		sql := w014bQuoteSQL[n]
		run := func(id string, f func() error) {
			b.Run(n+"/"+id, func(b *testing.B) {
				if err := f(); err != nil {
					b.Skip(err)
				}
				b.ReportAllocs()
				for b.Loop() {
					if err := f(); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
		run("gosqlx", func() error {
			t, err := gosqlx.Parse(sql)
			if err == nil {
				gosqlxast.ReleaseAST(t)
			}
			return err
		})
		run("gosqlx_mysql", func() error {
			t, err := gosqlx.ParseWithDialect(sql, keywords.DialectMySQL)
			if err == nil {
				gosqlxast.ReleaseAST(t)
			}
			return err
		})
		run("gosqlx_sqlite", func() error {
			t, err := gosqlx.ParseWithDialect(sql, keywords.DialectSQLite)
			if err == nil {
				gosqlxast.ReleaseAST(t)
			}
			return err
		})
		tkz := tokenizer.GetTokenizer()
		run("lex", func() error {
			tkz.SetDialect(keywords.DialectPostgreSQL)
			_, err := tokscratch.String(tkz, sql)
			return err
		})
		run("lex_mysql", func() error {
			tkz.SetDialect(keywords.DialectMySQL)
			_, err := tokscratch.String(tkz, sql)
			return err
		})
		run("vitess", func() error { _, err := vp.ParseStrictDDL(sql); return err })
		run("vitess_scan", func() error {
			tkn := vp.NewStringTokenizer(sql)
			for {
				if typ, _ := tkn.Scan(); typ == 0 {
					return nil
				}
			}
		})
		run("rqlite_sql", func() error {
			_, err := rqlite.NewParser(strings.NewReader(sql)).ParseStatements()
			return err
		})
	}
}
