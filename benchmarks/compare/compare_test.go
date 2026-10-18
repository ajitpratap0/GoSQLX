package compare

import (
	"testing"
)

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
	for _, p := range Parsers {
		for _, q := range Corpus {
			if !baseline[q.ID] {
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
