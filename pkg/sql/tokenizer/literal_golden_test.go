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

package tokenizer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	gerrors "github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// updateLiteralGolden regenerates testdata/tokenizer_literal_golden.json.
// Run it only on a tree whose quoted-literal behaviour is the accepted
// reference: go test -run TestLiteralGolden ./pkg/sql/tokenizer/ -args -update-literal-golden
var updateLiteralGolden = flag.Bool("update-literal-golden", false, "regenerate testdata/tokenizer_literal_golden.json from the current tree")

const literalGoldenPath = "testdata/tokenizer_literal_golden.json"

// literalGoldenDialects are the dialects every golden input is tokenized
// under. The empty dialect is reachable only in-package and is the zero
// value a hand-built Tokenizer has; it enables backslash escapes.
var literalGoldenDialects = []keywords.SQLDialect{
	"",
	keywords.DialectPostgreSQL,
	keywords.DialectMySQL,
	keywords.DialectMariaDB,
	keywords.DialectSQLServer,
	keywords.DialectOracle,
	keywords.DialectSQLite,
	keywords.DialectSnowflake,
	keywords.DialectClickHouse,
}

// quotedLiteralEdgeInputs covers every quoted reader (strings, N'...',
// double-quoted and backtick identifiers, triple-quoted strings) and every
// case where the scanned value differs from the source bytes: doubled
// quotes, backslash escapes, Unicode quote normalization, invalid UTF-8,
// newlines and unterminated input.
var quotedLiteralEdgeInputs = []string{
	// Single-quoted strings.
	`'abc'`,
	`''`,
	`'it''s'`,
	`'a'''`,
	`''''`,
	`'''`,
	`'''''`,
	`''''''`,
	`'a\nb'`,
	`'a\\'`,
	`'a\\' 'b'`,
	`'\\'`,
	`'a\q'`,
	`'a\'b'`,
	`'a\"b'`,
	"'a\\`b'",
	`'a\tb\rc'`,
	`'abc\`,
	`'\`,
	"'a\nb'",
	"'a\r\nb'",
	"'a\tb'",
	"'abc",
	"'abc\n",
	"'héllo 世界'",
	"‘abc’",
	"‘abc'",
	"'abc’",
	"«abc»",
	"»abc«",
	"'x’’y'",
	"'x'’y'",
	"'a“b'",
	"'a”b'",
	"'a\"b'",
	"'a\xffb'",
	"'a\xe2\x80b'",
	"'a�b'",
	"'é''é'",
	"'\xff",
	// SQL Server national strings (an identifier N under other dialects).
	"N'abc'",
	"N'it''s'",
	"N''",
	"n'x'",
	"N'a\\b'",
	"N'abc",
	// Double-quoted identifiers.
	`"Col"`,
	`""`,
	`"a""b"`,
	`"a"""`,
	"“Smart”",
	"“Smart\"",
	"\"Smart”",
	"“a\"\"b”",
	"\"a‘b\"",
	"\"a«b\"",
	"\"a'b\"",
	"\"a\\b\"",
	"\"a\nb\"",
	"\"abc",
	"\"héllo 世界\"",
	"\"a\xffb\"",
	"\"a�b\"",
	// Backtick identifiers.
	"`col`",
	"``",
	"`a``b`",
	"`a```",
	"`a\nb`",
	"`a\nb` x",
	"`héllo` x",
	"`a\xffb`",
	"`abc",
	"`a\\b`",
	"`a'b\"c`",
	// Triple-quoted strings.
	"'''abc'''",
	"'''a'b'''",
	"'''a''b'''",
	"'''a\nb''' x",
	"'''abc",
	"'''a\xffb'''",
	"'''héllo'''",
	"'''a\\nb'''",
	"\"\"\"a'b\"\"\"",
	// Literals in statement context, so later token spans are checked.
	"SELECT 'a', \"b\", `c` FROM t WHERE x = 'it''s' AND y = 'p\\nq'",
	"SELECT 'a'\n, 'b\nc', \"d\" FROM t -- tail",
	"SELECT “Name”, ‘v’ FROM “T” WHERE «k» = 'x'",
	"INSERT INTO t (a, b) VALUES ('alpha', 'beta'), ('it''s', 'a\\tb')",
	"SELECT N'abc', N'x''y' FROM [dbo].[T] WHERE \"c\" = 'v'",
	"SELECT '''triple''' AS t, `bt``x` FROM t",
	"SELECT 'é', \"é\", `é` FROM t\nWHERE a = 'z'",
	// Multi-line or multibyte quoted literals followed by an error that reads
	// the tokenizer's internal position (invalid escape, newline inside a
	// quoted identifier). Spans come from byte offsets, so only these errors
	// expose drift in the internal line/column tracking.
	"'a\nb' 'c\\q'",
	"'a\nb' \"c\nd\"",
	"`é\nx` 'y\\q'",
	"'é€𝄞' \"c\nd\"",
	"\"é\" 'a\\q'",
	"'''a\nb''' \"c\nd\"",
	"'''a\nb''' 'c\\q'",
	"'''é€𝄞''' 'c\\q'",
	"N'é\nx' 'c\\q'",
	"N'é€𝄞' \"c\nd\"",
	"‘a\nb’ 'c\\q'",
	"‘é€𝄞’ \"c\nd\"",
	"“é\nx” 'c\\q'",
	"“é€” \"c\nd\"",
	"'a''\nb''c' 'c\\q'",
	"'a\\\nb' 'c\\q'",
	"`a``\nb` \"c\nd\"",
	"\"a\"\"é\" 'c\\q'",
	"'a\r\nb' 'c\\q'",
	"'é'\n'é' \"c\nd\"",
	"SELECT 'a\nb', 'é€' FROM t WHERE x = 'c\\q'",
	"SELECT 'a\nb',\n 'é€𝄞', \"c\nd\" FROM t",
}

// literalGoldenEntry is one corpus input. Digests holds one digest per
// dialect, in the order of the file's Dialects list. A file: entry is read
// from disk and fails the test when its content no longer matches ContentSHA.
type literalGoldenEntry struct {
	ID         string   `json:"id"`
	Input      string   `json:"input,omitempty"`
	InputBytes []byte   `json:"input_b64,omitempty"` // used when Input would not be valid UTF-8 (JSON cannot carry it)
	ContentSHA string   `json:"content_sha,omitempty"`
	Digests    []string `json:"digests"`
}

type literalGoldenFile struct {
	Comment  string               `json:"comment"`
	Dialects []string             `json:"dialects"`
	Entries  []literalGoldenEntry `json:"entries"`
}

// TestLiteralGolden is a differential test of quoted-literal scanning against
// the reference tree that generated the golden file. Each input is tokenized
// under every dialect through Tokenize and TokenizeString, and a digest of
// the semantic result (tokens, words, spans, comments, structured errors) must
// match the stored one. Optional U& identifier spelling metadata is tested
// separately and excluded, preserving the reference's decoded-name contract.
func TestLiteralGolden(t *testing.T) {
	if *updateLiteralGolden {
		writeLiteralGolden(t)
		return
	}
	raw, err := os.ReadFile(literalGoldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var golden literalGoldenFile
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	if len(golden.Entries) == 0 {
		t.Fatal("golden file has no entries")
	}
	if len(golden.Dialects) != len(literalGoldenDialects) {
		t.Fatalf("golden dialects %q, want %d dialects", golden.Dialects, len(literalGoldenDialects))
	}
	for i, d := range literalGoldenDialects {
		if golden.Dialects[i] != string(d) {
			t.Fatalf("golden dialect %d is %q, want %q", i, golden.Dialects[i], d)
		}
	}
	tkzs := literalGoldenTokenizers(t)
	checked := 0
	for _, e := range golden.Entries {
		input := e.Input
		if e.InputBytes != nil {
			input = string(e.InputBytes)
		}
		if strings.HasPrefix(e.ID, "file:") {
			data, err := readCorpusFile(filepath.FromSlash(strings.TrimPrefix(e.ID, "file:")))
			if err != nil {
				t.Errorf("%s: cannot read corpus file: %v; regenerate the golden on the reference tree with -args -update-literal-golden", e.ID, err)
				continue
			}
			if sha256Hex(string(data)) != e.ContentSHA {
				t.Errorf("%s: content changed since the golden was generated, so its coverage would be lost; regenerate the golden on the reference tree with -args -update-literal-golden", e.ID)
				continue
			}
			input = string(data)
		}
		if len(e.Digests) != len(literalGoldenDialects) {
			t.Errorf("%s: %d digests, want %d", e.ID, len(e.Digests), len(literalGoldenDialects))
			continue
		}
		for i, d := range literalGoldenDialects {
			want := e.Digests[i]
			if got := literalGoldenDigest(t, tkzs[d], input); got != want {
				t.Errorf("%s dialect %q: digest %s, golden %s\ninput: %q", e.ID, d, got, want, input)
			}
			checked++
		}
	}
	t.Logf("checked %d (input, dialect) digests", checked)
}

// literalGoldenTokenizers returns one tokenizer per golden dialect; reusing
// them across inputs also exercises Reset.
func literalGoldenTokenizers(t *testing.T) map[keywords.SQLDialect]*Tokenizer {
	t.Helper()
	out := make(map[keywords.SQLDialect]*Tokenizer, len(literalGoldenDialects))
	for _, d := range literalGoldenDialects {
		tkz, err := New()
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if d == "" {
			tkz.dialect = ""
		} else {
			tkz.SetDialect(d)
		}
		out[d] = tkz
	}
	return out
}

// literalGoldenDigest serializes Tokenize and TokenizeString results and
// returns a truncated SHA-256 of both.
func literalGoldenDigest(t *testing.T, tkz *Tokenizer, input string) string {
	t.Helper()
	var sb strings.Builder
	tokens, err := tkz.Tokenize([]byte(input))
	sb.WriteString("B:")
	serializeLiteralResult(&sb, tokens, tkz.Comments, err)
	tokens, err = tkz.TokenizeString(input)
	sb.WriteString("S:")
	serializeLiteralResult(&sb, tokens, tkz.Comments, err)
	return sha256Hex(sb.String())[:16]
}

func serializeLiteralResult(sb *strings.Builder, tokens []models.TokenWithSpan, comments []models.Comment, err error) {
	if err != nil {
		fmt.Fprintf(sb, "err=%q", err.Error())
		var se *gerrors.Error
		if errors.As(err, &se) {
			fmt.Fprintf(sb, " code=%s loc=%d:%d", se.Code, se.Location.Line, se.Location.Column)
		}
		sb.WriteByte('\n')
		return
	}
	for _, tw := range tokens {
		tok := tw.Token
		// U& identifiers gained optional source spelling without changing the
		// reference token's decoded value, delimiter, kind or span. Normalize
		// only that new metadata; all ordinary Word metadata remains pinned.
		if tok.Type == models.TokenTypeIdentifier && tok.Quote == '"' &&
			tok.Word != nil && tok.Word.QuoteStyle == 'U' && tok.Word.Keyword == nil {
			tok.Word = nil
		}
		fmt.Fprintf(sb, "%d|%q|%d|%t|", tok.Type, tok.Value, tok.Quote, tok.Long)
		if tok.Word == nil {
			sb.WriteString("nil")
		} else {
			fmt.Fprintf(sb, "w(%q,%d", tok.Word.Value, tok.Word.QuoteStyle)
			if tok.Word.Keyword != nil {
				fmt.Fprintf(sb, ",%q,%t", tok.Word.Keyword.Word, tok.Word.Keyword.Reserved)
			}
			sb.WriteByte(')')
		}
		fmt.Fprintf(sb, "|%d:%d-%d:%d\n", tw.Start.Line, tw.Start.Column, tw.End.Line, tw.End.Column)
	}
	for _, c := range comments {
		fmt.Fprintf(sb, "c%+v\n", c)
	}
}

// readCorpusFile reads a corpus .sql file with CRLF normalized to LF. Git on
// the windows-latest CI runner checks text files out with CRLF
// (core.autocrlf; the repo has no .gitattributes), which would otherwise
// change both the content hash and the tokenizer output for every file
// entry. None of the corpus files contain carriage returns, so this is
// lossless on LF checkouts.
func readCorpusFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")), nil
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// writeLiteralGolden rebuilds the corpus from the sources and records the
// current digests.
func writeLiteralGolden(t *testing.T) {
	t.Helper()
	tkzs := literalGoldenTokenizers(t)
	hashesFor := func(input string) []string {
		h := make([]string, 0, len(literalGoldenDialects))
		for _, d := range literalGoldenDialects {
			h = append(h, literalGoldenDigest(t, tkzs[d], input))
		}
		return h
	}

	var out literalGoldenFile
	out.Comment = "Generated by: go test -run TestLiteralGolden ./pkg/sql/tokenizer/ -args -update-literal-golden (see literal_golden_test.go)"
	for _, d := range literalGoldenDialects {
		out.Dialects = append(out.Dialects, string(d))
	}

	for _, path := range literalGoldenSQLFiles(t) {
		data, err := readCorpusFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		out.Entries = append(out.Entries, literalGoldenEntry{
			ID:         "file:" + filepath.ToSlash(path),
			ContentSHA: sha256Hex(string(data)),
			Digests:    hashesFor(string(data)),
		})
	}

	seen := map[string]bool{}
	addLiteral := func(id, s string) {
		if seen[s] {
			return
		}
		seen[s] = true
		e := literalGoldenEntry{ID: id, Digests: hashesFor(s)}
		if utf8.ValidString(s) {
			e.Input = s
		} else {
			e.InputBytes = []byte(s)
		}
		out.Entries = append(out.Entries, e)
	}
	for i, s := range quotedLiteralEdgeInputs {
		addLiteral(fmt.Sprintf("edge:%d", i), s)
		addLiteral(fmt.Sprintf("edge-ctx:%d", i), "SELECT "+s+", z\nFROM t")
	}
	for _, lit := range literalGoldenTestLiterals(t) {
		addLiteral(lit.id, lit.value)
	}

	// One entry per line keeps the file compact and its diffs readable.
	header, err := json.Marshal(struct {
		Comment  string   `json:"comment"`
		Dialects []string `json:"dialects"`
	}{out.Comment, out.Dialects})
	if err != nil {
		t.Fatalf("encode golden header: %v", err)
	}
	var sb strings.Builder
	sb.Write(header[:len(header)-1])
	sb.WriteString(`,"entries":[`)
	for i, e := range out.Entries {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatalf("encode golden entry %s: %v", e.ID, err)
		}
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString("\n")
		sb.Write(line)
	}
	sb.WriteString("\n]}\n")
	data := []byte(sb.String())
	if err := os.MkdirAll(filepath.Dir(literalGoldenPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(literalGoldenPath, data, 0o644); err != nil {
		t.Fatalf("write golden: %v", err)
	}
	t.Logf("wrote %d entries to %s", len(out.Entries), literalGoldenPath)
}

// literalGoldenSQLFiles lists the .sql corpus under the repository testdata
// and the parser testdata, sorted for a stable golden file.
func literalGoldenSQLFiles(t *testing.T) []string {
	t.Helper()
	var paths []string
	for _, root := range []string{
		filepath.Join("..", "..", "..", "testdata"),
		filepath.Join("..", "parser", "testdata"),
	} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(path, ".sql") {
				paths = append(paths, path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	sort.Strings(paths)
	return paths
}

type goldenLiteral struct {
	id    string
	value string
}

// literalGoldenTestLiterals extracts every Go string literal containing a
// quote character from the parser and tokenizer test files.
func literalGoldenTestLiterals(t *testing.T) []goldenLiteral {
	t.Helper()
	var files []string
	for _, pattern := range []string{
		filepath.Join("..", "parser", "*_test.go"),
		"*_test.go",
	} {
		m, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}
		files = append(files, m...)
	}
	sort.Strings(files)

	var out []goldenLiteral
	fset := token.NewFileSet()
	for _, f := range files {
		file, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil || len(s) > 64<<10 || !strings.ContainsAny(s, "'\"`‘’“”«»") {
				return true
			}
			out = append(out, goldenLiteral{
				id:    fmt.Sprintf("lit:%s:%d", filepath.ToSlash(f), fset.Position(lit.Pos()).Line),
				value: s,
			})
			return true
		})
	}
	return out
}
