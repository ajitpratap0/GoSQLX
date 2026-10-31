package compare

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/metrics"
)

var update = flag.Bool("update", false, "rewrite the checked-in common-accept sets")

// TestGoSQLXAcceptsCorpus guards the corpus: GoSQLX must parse every query,
// otherwise a published comparison would silently drop rows.
func TestGoSQLXAcceptsCorpus(t *testing.T) {
	p, ok := ParserByID("gosqlx")
	if !ok {
		t.Fatal("gosqlx parser not registered")
	}
	for _, q := range Corpus {
		t.Run(q.ID, func(t *testing.T) {
			if err := Supports(p, q); err != nil {
				t.Fatalf("GoSQLX rejected %q: %v", q.SQL, err)
			}
		})
	}
}

// TestEveryParserAcceptsBaseline ensures each competitor is wired correctly:
// all of them must parse the portable baseline statements.
func TestEveryParserAcceptsBaseline(t *testing.T) {
	baseline := map[string]bool{
		"simple_select": true, "select_where": true, "join": true,
		"aggregate": true, "subquery": true, "insert": true,
		"update": true, "delete": true,
	}
	// Peers added after v1 may implement a narrower grammar (the ClickHouse
	// parser has no UPDATE statement), so they only have to parse SELECTs.
	selectOnly := map[string]bool{"simple_select": true, "select_where": true, "aggregate": true}
	for _, p := range Parsers {
		for _, q := range Corpus {
			if !baseline[q.ID] || (!p.Schema1 && p.ID != "gosqlx_norelease" && !selectOnly[q.ID]) {
				continue
			}
			t.Run(p.ID+"/"+q.ID, func(t *testing.T) {
				if err := Supports(p, q); err != nil {
					t.Fatalf("%s rejected %q: %v", p.Name, q.SQL, err)
				}
			})
		}
	}
}

// TestCorpusIDsUnique keeps benchmark names and JSON keys unambiguous.
func TestCorpusIDsUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, q := range Corpus {
		if seen[q.ID] {
			t.Fatalf("duplicate corpus ID %q", q.ID)
		}
		seen[q.ID] = true
	}
	seen = map[string]bool{}
	for _, p := range Parsers {
		if seen[p.ID] {
			t.Fatalf("duplicate parser ID %q", p.ID)
		}
		seen[p.ID] = true
	}
}

// BenchmarkParse measures the end-to-end stage (SQL text to AST) for every
// parser on every corpus query. Benchmark names are
// BenchmarkParse/<query-id>/<parser-id>. Queries a parser rejects are skipped.
func BenchmarkParse(b *testing.B) {
	for _, q := range Corpus {
		b.Run(q.ID, func(b *testing.B) {
			for _, p := range Parsers {
				b.Run(p.ID, func(b *testing.B) {
					parse, err := p.New()
					if err != nil {
						b.Fatalf("%s: %v", p.Name, err)
					}
					if err := parse(q.SQL); err != nil {
						b.Skipf("%s does not accept this query: %v", p.Name, err)
					}
					b.ReportAllocs()
					b.SetBytes(int64(len(q.SQL)))
					b.ResetTimer()
					for b.Loop() {
						if err := parse(q.SQL); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

// parseFor returns the parse function for p or skips the benchmark.
func mustParse(b *testing.B, p Parser) ParseFunc {
	b.Helper()
	parse, err := p.New()
	if err != nil {
		b.Fatalf("%s: %v", p.Name, err)
	}
	return parse
}

// BenchmarkParseORM measures the end-to-end stage on the ORM-style corpus.
// Names are BenchmarkParseORM/<query-id>/<parser-id>. Queries a parser
// rejects are skipped; TestORMAcceptanceTable prints who accepts what.
func BenchmarkParseORM(b *testing.B) {
	for _, q := range ORMCorpus {
		b.Run(q.ID, func(b *testing.B) {
			for _, p := range Parsers {
				b.Run(p.ID, func(b *testing.B) {
					parse := mustParse(b, p)
					if err := safeParse(parse, q.SQL); err != nil {
						b.Skipf("%s does not accept this query: %v", p.Name, err)
					}
					b.ReportAllocs()
					b.SetBytes(int64(len(q.SQL)))
					b.ResetTimer()
					for b.Loop() {
						if err := parse(q.SQL); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

// benchImpls runs one non-parse cell: BenchmarkX/<query-id>/<impl-id>.
func benchImpls(b *testing.B, impls []Impl) {
	for _, q := range Corpus {
		b.Run(q.ID, func(b *testing.B) {
			for _, im := range impls {
				b.Run(im.ID, func(b *testing.B) {
					op, cleanup, err := im.New(q.SQL)
					if cleanup != nil {
						b.Cleanup(cleanup)
					}
					if err != nil {
						b.Skipf("%s cannot handle this query: %v", im.Name, err)
					}
					b.ReportAllocs()
					b.SetBytes(int64(len(q.SQL)))
					b.ResetTimer()
					for b.Loop() {
						if err := op(); err != nil {
							b.Fatal(err)
						}
					}
				})
			}
		})
	}
}

// BenchmarkLex measures tokenisation only: GoSQLX's scratch and public paths
// against Vitess Tokenizer.Scan and pg_query_go Scan.
func BenchmarkLex(b *testing.B) { benchImpls(b, LexImpls) }

// BenchmarkNormalize measures literal normalisation and fingerprinting.
func BenchmarkNormalize(b *testing.B) { benchImpls(b, NormalizeImpls) }

// BenchmarkRender measures AST-to-SQL rendering of a pre-parsed statement.
func BenchmarkRender(b *testing.B) { benchImpls(b, RenderImpls) }

// concurrencyVariant is one row of the ParseFresh and ParseParallel cells: a
// parser, optionally with GoSQLX's global metrics collection switched on.
type concurrencyVariant struct {
	id      string
	parser  Parser
	metrics bool
}

// concurrencyVariants lists every parser plus gosqlx_metricson. Metrics are
// off by default, so the plain gosqlx row is the metrics-off measurement;
// the metrics-on row shows the cost of the shared atomic counters under
// concurrency (CRITIQUE item 10).
func concurrencyVariants() []concurrencyVariant {
	var out []concurrencyVariant
	for _, p := range Parsers {
		out = append(out, concurrencyVariant{id: p.ID, parser: p})
	}
	if g, ok := ParserByID("gosqlx"); ok {
		out = append(out, concurrencyVariant{id: "gosqlx_metricson", parser: g, metrics: true})
	}
	return out
}

// enableMetrics turns global metrics on for the benchmark and restores the
// previous state when it ends.
func enableMetrics(b *testing.B) {
	b.Helper()
	was := metrics.IsEnabled()
	metrics.Enable()
	b.Cleanup(func() {
		if !was {
			metrics.Disable()
		}
	})
}

// BenchmarkParseFresh measures one parse on a brand-new goroutine per op, the
// shape of a server that handles each request on its own goroutine. It
// exposes stack growth and cold per-goroutine state that a long-lived loop
// hides.
func BenchmarkParseFresh(b *testing.B) {
	for _, q := range Corpus {
		b.Run(q.ID, func(b *testing.B) {
			for _, v := range concurrencyVariants() {
				p := v.parser
				b.Run(v.id, func(b *testing.B) {
					if v.metrics {
						enableMetrics(b)
					}
					parse := mustParse(b, p)
					if err := safeParse(parse, q.SQL); err != nil {
						b.Skipf("%s does not accept this query: %v", p.Name, err)
					}
					b.ReportAllocs()
					b.SetBytes(int64(len(q.SQL)))
					b.ResetTimer()
					for b.Loop() {
						var wg sync.WaitGroup
						var perr error
						wg.Add(1)
						go func() {
							defer wg.Done()
							perr = parse(q.SQL)
						}()
						wg.Wait()
						if perr != nil {
							b.Fatal(perr)
						}
					}
				})
			}
		})
	}
}

// BenchmarkParseParallel measures throughput with every P parsing at once
// (b.RunParallel); run it with -cpu 1,4,10 (or wider on a large box, see
// README) to see scaling and shared-state contention. gosqlx_metricson
// repeats the GoSQLX cell with global metrics enabled. Each worker builds its own parse function, since parse
// functions are not safe for concurrent use.
func BenchmarkParseParallel(b *testing.B) {
	for _, q := range Corpus {
		b.Run(q.ID, func(b *testing.B) {
			for _, v := range concurrencyVariants() {
				p := v.parser
				b.Run(v.id, func(b *testing.B) {
					if v.metrics {
						enableMetrics(b)
					}
					if err := safeParse(mustParse(b, p), q.SQL); err != nil {
						b.Skipf("%s does not accept this query: %v", p.Name, err)
					}
					b.ReportAllocs()
					b.SetBytes(int64(len(q.SQL)))
					b.ResetTimer()
					b.RunParallel(func(pb *testing.PB) {
						parse, err := p.New()
						if err != nil {
							b.Error(err)
							return
						}
						for pb.Next() {
							if err := parse(q.SQL); err != nil {
								b.Error(err)
								return
							}
						}
					})
				})
			}
		})
	}
}

// BenchmarkParseDialect parses the whole common-accept set of a dialect per
// op. Names are BenchmarkParseDialect/<dialect>/<parser-id>. Only parsers
// that gate the set (GoSQLX and the non-legacy peers) run, so every parser
// does identical, fully accepted work.
func BenchmarkParseDialect(b *testing.B) {
	for _, d := range Dialects {
		b.Run(d, func(b *testing.B) {
			stmts, err := LoadCommonAccept(d)
			if err != nil {
				b.Fatal(err)
			}
			if len(stmts) == 0 {
				b.Skipf("empty common-accept set for %s", d)
			}
			total := 0
			for _, s := range stmts {
				total += len(s)
			}
			for _, p := range PeersFor(d, false) {
				b.Run(p.ID, func(b *testing.B) {
					parse, err := DialectParse(p, d)
					if err != nil {
						b.Fatalf("%s: %v", p.Name, err)
					}
					b.ReportAllocs()
					b.SetBytes(int64(total))
					b.ResetTimer()
					for b.Loop() {
						for _, s := range stmts {
							if err := parse(s); err != nil {
								b.Fatalf("%s rejected a common-accept statement: %v", p.Name, err)
							}
						}
					}
				})
			}
		})
	}
}

// TestGoSQLXNoReleaseMatchesGoSQLX guards the norelease variant: it must
// accept exactly what the releasing variant accepts, or the two cells would
// not isolate the release step.
func TestGoSQLXNoReleaseMatchesGoSQLX(t *testing.T) {
	a, _ := ParserByID("gosqlx")
	b, ok := ParserByID("gosqlx_norelease")
	if !ok {
		t.Fatal("gosqlx_norelease parser not registered")
	}
	all := append([]string(nil), "SELECT FROM WHERE", "")
	for _, q := range Corpus {
		all = append(all, q.SQL)
	}
	for _, q := range ORMCorpus {
		all = append(all, q.SQL)
	}
	pa, _ := a.New()
	pb, _ := b.New()
	for _, sql := range all {
		if (safeParse(pa, sql) == nil) != (safeParse(pb, sql) == nil) {
			t.Errorf("variants disagree on %q", sql)
		}
	}
}

// TestParserMetadata checks every parser records a license, and that peers
// declare the dialects they are peers for.
func TestParserMetadata(t *testing.T) {
	for _, p := range Parsers {
		if strings.TrimSpace(p.License) == "" {
			t.Errorf("%s: license not recorded", p.ID)
		}
		if p.ID != "gosqlx" && p.ID != "gosqlx_norelease" && len(p.PeerDialects) == 0 {
			t.Errorf("%s: no PeerDialects", p.ID)
		}
		for _, d := range p.PeerDialects {
			found := false
			for _, known := range Dialects {
				found = found || known == d
			}
			if !found {
				t.Errorf("%s: unknown peer dialect %q", p.ID, d)
			}
		}
	}
}

// knownGoSQLXORMRejects lists the ORM queries GoSQLX does not parse today.
// They stay in the corpus: dropping them would hide the gap from the
// acceptance table.
var knownGoSQLXORMRejects = map[string]string{
	"orm_placeholder_qmark": "the '?' placeholder is not parsed (E2001)",
	"orm_placeholder_named": "the ':name' placeholder is not parsed (E2001/E2004)",
}

// TestORMCorpus checks that the ORM corpus is well formed, that GoSQLX
// handles it, and prints which parser accepts which query. Rejections by
// peers are information, not failures.
func TestORMCorpus(t *testing.T) {
	seen := map[string]bool{}
	for _, q := range ORMCorpus {
		if seen[q.ID] {
			t.Fatalf("duplicate ORM query ID %q", q.ID)
		}
		seen[q.ID] = true
		if _, dup := ORMQueryByID(q.ID); !dup {
			t.Fatalf("ORMQueryByID(%q) not found", q.ID)
		}
	}
	shapes := map[string]bool{}
	for _, q := range ORMCorpus {
		shapes[q.Shape] = true
	}
	for _, want := range []string{"quoted", "placeholders", "lowercase", "ddl", "nesting", "multistatement"} {
		if !shapes[want] {
			t.Errorf("ORM corpus has no %q query", want)
		}
	}

	g, _ := ParserByID("gosqlx")
	gp, _ := g.New()
	var tab strings.Builder
	tab.WriteString("ORM acceptance (Y = accepted, . = rejected)\n")
	tab.WriteString(strings.Repeat(" ", 22))
	for _, p := range Parsers {
		tab.WriteString(" " + p.ID)
	}
	tab.WriteString("\n")
	for _, q := range ORMCorpus {
		tab.WriteString(q.ID + strings.Repeat(" ", max(1, 22-len(q.ID))))
		for _, p := range Parsers {
			parse, err := p.New()
			if err != nil {
				t.Fatalf("%s: %v", p.ID, err)
			}
			mark := "."
			if safeParse(parse, q.SQL) == nil {
				mark = "Y"
			}
			tab.WriteString(" " + mark + strings.Repeat(" ", max(0, len(p.ID)-1)))
		}
		tab.WriteString("\n")
		// A rejection by GoSQLX is allowed only when it is documented in
		// knownGoSQLXORMRejects; an undocumented rejection would silently
		// drop a row, and a documented one that starts passing means the
		// list is stale.
		err := safeParse(gp, q.SQL)
		reason, known := knownGoSQLXORMRejects[q.ID]
		switch {
		case err != nil && !known:
			t.Errorf("GoSQLX rejected ORM query %s: %v", q.ID, err)
		case err == nil && known:
			t.Errorf("GoSQLX now accepts %s; remove it from knownGoSQLXORMRejects (%s)", q.ID, reason)
		}
	}
	t.Log("\n" + tab.String())
}

// TestImplsRunOnPortableQueries makes sure each Lex/Normalize/Render
// implementation works on at least the simplest portable query, so a wiring
// mistake fails a test instead of producing an all-skipped benchmark.
func TestImplsRunOnPortableQueries(t *testing.T) {
	groups := map[string][]Impl{"lex": LexImpls, "normalize": NormalizeImpls, "render": RenderImpls}
	for name, impls := range groups {
		for _, im := range impls {
			t.Run(name+"/"+im.ID, func(t *testing.T) {
				if _, ok := ParserByID(im.Parser); !ok {
					t.Fatalf("impl references unknown parser %q", im.Parser)
				}
				ran := 0
				for _, q := range Corpus {
					op, cleanup, err := im.New(q.SQL)
					if cleanup != nil {
						t.Cleanup(cleanup)
					}
					if err != nil {
						continue
					}
					if err := op(); err != nil {
						t.Fatalf("%s failed on %s: %v", im.Name, q.ID, err)
					}
					ran++
				}
				if ran == 0 {
					t.Fatalf("%s handled none of the %d corpus queries", im.Name, len(Corpus))
				}
			})
		}
	}
}

// TestRenderOutputsParse checks GoSQLX's render cells produce SQL that GoSQLX
// parses again, so the render benchmark measures real output. It re-parses
// the output of both AST.SQL() and the compact formatter path.
func TestRenderOutputsParse(t *testing.T) {
	for _, q := range Corpus {
		t.Run(q.ID, func(t *testing.T) {
			tree, err := parseTree(q.SQL)
			if err != nil {
				t.Fatal(err)
			}
			outs := map[string]string{"sql": tree.SQL()}
			compact, err := formatCompact(tree)
			if err != nil {
				t.Fatalf("compact format: %v", err)
			}
			outs["compact"] = compact
			for name, out := range outs {
				if strings.TrimSpace(out) == "" {
					t.Errorf("%s output is empty", name)
					continue
				}
				if _, err := gosqlx.Parse(out); err != nil {
					t.Errorf("%s output does not parse again: %v\n%s", name, err, out)
				}
			}
		})
	}
}

// TestPartialDDLIsRejected guards the strict-DDL wiring: the lenient Parse of
// Vitess and xwb1989 logs and returns nil for DDL they only partly parsed,
// which would count a rejection as an acceptance.
func TestPartialDDLIsRejected(t *testing.T) {
	for id, partial := range map[string]string{
		"vitess":  "ALTER TABLE users DROP COLUMN IF EXISTS mobile",
		"xwb1989": "CREATE TABLE decs (a DEC(4,1))",
	} {
		t.Run(id, func(t *testing.T) {
			p, ok := ParserByID(id)
			if !ok {
				t.Fatalf("%s not registered", id)
			}
			parse, err := p.New()
			if err != nil {
				t.Fatal(err)
			}
			if safeParse(parse, partial) == nil {
				t.Errorf("%s accepted partially parsed DDL %q", id, partial)
			}
		})
	}
}

// TestAcceptanceTable prints the acceptance rate of every (parser, dialect)
// pair and checks its invariants. Run with -v to see the table.
func TestAcceptanceTable(t *testing.T) {
	if testing.Short() {
		t.Skip("parses the whole realworld corpus with every peer")
	}
	rows, err := AcceptanceTable()
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("dialect      parser                 accepted/total  rate\n")
	for _, r := range rows {
		b.WriteString(formatRow(r))
		if r.Accepted > r.Total || r.Total == 0 {
			t.Errorf("inconsistent row %+v", r)
		}
	}
	t.Log("\n" + b.String())
	for _, d := range Dialects {
		found := false
		for _, r := range rows {
			found = found || (r.Dialect == d && r.Parser == "gosqlx")
		}
		if !found {
			t.Errorf("no GoSQLX row for dialect %s", d)
		}
	}
}

// TestCommonAcceptSets keeps the checked-in sets in step with the pinned
// libraries and the corpus. A dependency bump or corpus edit that changes
// what a parser accepts fails here until the sets are regenerated with
// -update and reviewed.
func TestCommonAcceptSets(t *testing.T) {
	if testing.Short() && !*update {
		t.Skip("parses the whole realworld corpus with every peer")
	}
	for _, d := range Dialects {
		t.Run(d, func(t *testing.T) {
			c, err := ComputeCommonAccept(d)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(CommonAcceptDir, d+".txt")
			got := c.Encode()
			if *update {
				if err := os.MkdirAll(CommonAcceptDir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v (run go test -run TestCommonAcceptSets -update)", path, err)
			}
			if string(want) != got {
				t.Fatalf("%s is stale: recomputed set has %d of %d statements (set hash %s); rerun with -update and review the diff",
					path, len(c.Statements), c.Total, c.SetHash())
			}
			if len(c.Statements) == 0 {
				t.Errorf("common-accept set for %s is empty", d)
			}
			loaded, err := LoadCommonAccept(d)
			if err != nil {
				t.Fatal(err)
			}
			if len(loaded) != len(c.Statements) {
				t.Errorf("LoadCommonAccept returned %d statements, want %d", len(loaded), len(c.Statements))
			}
		})
	}
}

func TestStatementHashStable(t *testing.T) {
	// SHA-256("abc"), a published test vector.
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := StatementHash("abc"); got != want {
		t.Fatalf("StatementHash(abc) = %s", got)
	}
}

func TestHasCode(t *testing.T) {
	for sql, want := range map[string]bool{
		"":                         false,
		"-- only a comment":        false,
		"/* block */":              false,
		"/* a\n b */ -- c\n":       false,
		"# mysql comment":          false,
		"/* c */ SELECT 1":         true,
		"SELECT 1 -- trailing":     true,
		"  \n\t SELECT 1":          true,
		"/* unterminated SELECT 1": false,
	} {
		if got := hasCode(sql); got != want {
			t.Errorf("hasCode(%q) = %v, want %v", sql, got, want)
		}
	}
}
