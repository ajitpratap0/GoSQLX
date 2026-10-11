package tokenizer

import (
	"strconv"
	"strings"
	"testing"
)

// Fixtures for the position-tracking regression benchmarks (#544). They are
// built once so benchmark iterations measure tokenization only.
var (
	singleLineInList1k  = generateSingleLineInList(1000)
	singleLineInList10k = generateSingleLineInList(10000)
	multiLineStatements = generateMultiLineStatements(2500)
)

// generateSingleLineInList builds a single-line query (no newlines) with an
// n-element IN list. Long single-line input used to make position tracking
// quadratic, because every token re-counted the whole line prefix.
func generateSingleLineInList(n int) []byte {
	var sb strings.Builder
	sb.Grow(n*6 + 80)
	sb.WriteString("SELECT id, name FROM users WHERE id IN (")
	for i := 1; i <= n; i++ {
		if i > 1 {
			sb.WriteByte(',')
		}
		sb.WriteString(strconv.Itoa(i))
	}
	sb.WriteString(") AND active = true")
	return []byte(sb.String())
}

// generateMultiLineStatements builds n short statements, one per line.
func generateMultiLineStatements(n int) []byte {
	var sb strings.Builder
	sb.Grow(n * 40)
	for i := 0; i < n; i++ {
		sb.WriteString("SELECT a, b FROM t WHERE x = ")
		sb.WriteString(strconv.Itoa(i))
		sb.WriteString(";\n")
	}
	return []byte(sb.String())
}

// BenchmarkTokenizerSingleLine guards against quadratic position tracking.
// InList_10k has 10x the input of InList_1k and should cost roughly 10x the time.
func BenchmarkTokenizerSingleLine(b *testing.B) {
	cases := []struct {
		name  string
		input []byte
	}{
		{"InList_1k", singleLineInList1k},
		{"InList_10k", singleLineInList10k},
		{"MultiLine_2500", multiLineStatements},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			tkz := GetTokenizer()
			defer PutTokenizer(tkz)

			b.ReportAllocs()
			b.SetBytes(int64(len(tc.input)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				tokens, err := tkz.Tokenize(tc.input)
				if err != nil {
					b.Fatal(err)
				}
				if len(tokens) == 0 {
					b.Fatal("no tokens produced")
				}
			}
		})
	}
}
