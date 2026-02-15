package parser

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func buildWideSelect(n int) string {
	var sb strings.Builder
	sb.WriteString("SELECT ")
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteString(", ")
		}
		fmt.Fprintf(&sb, "col%d", i)
	}
	sb.WriteString(" FROM t")
	return sb.String()
}

func benchmarkWideSelect(b *testing.B, numCols int) {
	sql := buildWideSelect(numCols)
	sqlBytes := []byte(sql)

	// Pre-tokenize to measure parser only
	tkz := tokenizer.GetTokenizer()
	tokens, err := tkz.Tokenize(sqlBytes)
	tokenizer.PutTokenizer(tkz)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		p := NewParser()
		_, err := p.ParseFromModelTokens(tokens)
		if err != nil {
			b.Fatal(err)
		}
		p.Release()
	}
}

func BenchmarkWideSelect100(b *testing.B)  { benchmarkWideSelect(b, 100) }
func BenchmarkWideSelect500(b *testing.B)  { benchmarkWideSelect(b, 500) }
func BenchmarkWideSelect1000(b *testing.B) { benchmarkWideSelect(b, 1000) }
func BenchmarkWideSelect5000(b *testing.B) { benchmarkWideSelect(b, 5000) }
