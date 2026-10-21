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

package lsp

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/highlight"
)

// semTok is a decoded semantic token with absolute 0-based position.
// Char and Len are in UTF-16 code units.
type semTok struct {
	Line, Char, Len int
	Type            string
	Mods            string // comma-separated modifier names, "" for none
}

// decodeSemanticTokens turns the relative LSP encoding back into absolute
// tokens using the advertised legend, failing on any malformed entry.
func decodeSemanticTokens(t *testing.T, data []uint32) []semTok {
	t.Helper()
	if len(data)%5 != 0 {
		t.Fatalf("semantic token data length %d is not a multiple of 5", len(data))
	}
	legend := semanticTokensLegend()
	var out []semTok
	line, char := 0, 0
	for i := 0; i < len(data); i += 5 {
		dl, dc, length, typ, mods := data[i], data[i+1], data[i+2], data[i+3], data[i+4]
		if dl > 0 {
			line += int(dl)
			char = int(dc)
		} else {
			char += int(dc)
		}
		if length == 0 {
			t.Errorf("token %d at %d:%d has zero length", i/5, line, char)
		}
		if int(typ) >= len(legend.TokenTypes) {
			t.Fatalf("token %d type index %d out of legend range %d", i/5, typ, len(legend.TokenTypes))
		}
		if mods>>uint(len(legend.TokenModifiers)) != 0 {
			t.Fatalf("token %d modifier bits %b exceed legend %v", i/5, mods, legend.TokenModifiers)
		}
		var names []string
		for b, name := range legend.TokenModifiers {
			if mods&(1<<uint(b)) != 0 {
				names = append(names, name)
			}
		}
		out = append(out, semTok{
			Line: line, Char: char, Len: int(length),
			Type: legend.TokenTypes[typ], Mods: strings.Join(names, ","),
		})
	}
	return out
}

// requestSemanticTokens opens content (when non-empty uri) and issues a
// textDocument/semanticTokens/full request through HandleRequest.
func requestSemanticTokens(t *testing.T, server *Server, uri string) *SemanticTokens {
	t.Helper()
	params, err := json.Marshal(SemanticTokensParams{TextDocument: TextDocumentIdentifier{URI: uri}})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	result, err := server.handler.HandleRequest("textDocument/semanticTokens/full", params)
	if err != nil {
		t.Fatalf("semanticTokens/full: %v", err)
	}
	toks, ok := result.(*SemanticTokens)
	if !ok {
		t.Fatalf("expected *SemanticTokens, got %T", result)
	}
	if toks.Data == nil {
		t.Fatal("semantic token data is nil; must encode as [] not null")
	}
	return toks
}

// semanticTokensFor opens content as a document and returns its decoded tokens.
func semanticTokensFor(t *testing.T, content string) []semTok {
	t.Helper()
	server := setupTestServer()
	const uri = "file:///semantic.sql"
	server.Documents().Open(uri, "sql", 1, content)
	return decodeSemanticTokens(t, requestSemanticTokens(t, server, uri).Data)
}

func assertTokens(t *testing.T, got, want []semTok) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("semantic tokens mismatch\n got: %+v\nwant: %+v", got, want)
	}
}

func TestSemanticTokens_Legend(t *testing.T) {
	legend := semanticTokensLegend()
	wantTypes := []string{"keyword", "function", "type", "variable", "string", "number", "operator", "comment", "parameter"}
	if !reflect.DeepEqual(legend.TokenTypes, wantTypes) {
		t.Errorf("TokenTypes = %v, want %v", legend.TokenTypes, wantTypes)
	}
	if want := []string{"readonly"}; !reflect.DeepEqual(legend.TokenModifiers, want) {
		t.Errorf("TokenModifiers = %v, want %v", legend.TokenModifiers, want)
	}

	// Every mapped category encodes to the legend entries its spec names.
	usedTypes := make(map[string]bool)
	for _, cat := range highlight.Categories() {
		spec, mapped := semanticTokenSpecs[cat]
		enc := semanticEncodings[cat]
		if mapped != enc.ok {
			t.Errorf("%s: mapped=%v but encoding ok=%v", cat, mapped, enc.ok)
			continue
		}
		if !mapped {
			continue
		}
		if got := legend.TokenTypes[enc.tokenType]; got != spec.tokenType {
			t.Errorf("%s: legend type %q, want %q", cat, got, spec.tokenType)
		}
		usedTypes[spec.tokenType] = true
		var mods []string
		for b, name := range legend.TokenModifiers {
			if enc.modifiers&(1<<uint(b)) != 0 {
				mods = append(mods, name)
			}
		}
		if len(mods) != len(spec.modifiers) || (len(mods) > 0 && !reflect.DeepEqual(mods, spec.modifiers)) {
			t.Errorf("%s: modifiers %v, want %v", cat, mods, spec.modifiers)
		}
	}
	for _, typ := range legend.TokenTypes {
		if !usedTypes[typ] {
			t.Errorf("legend type %q is not used by any category", typ)
		}
	}
	for _, cat := range []highlight.Category{highlight.Punctuation, highlight.Error, highlight.Plain} {
		if semanticEncodings[cat].ok {
			t.Errorf("%s must be omitted from the token stream", cat)
		}
	}

	// The copy must not alias the shared legend.
	legend.TokenTypes[0] = "mutated"
	if semanticTokensLegend().TokenTypes[0] != "keyword" {
		t.Error("semanticTokensLegend returned an aliased slice")
	}
}

func TestSemanticTokens_InitializeAdvertisesLegend(t *testing.T) {
	server := setupTestServer()
	result, err := server.handler.HandleRequest("initialize", json.RawMessage(`{"processId":1,"rootUri":"file:///"}`))
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	init, ok := result.(*InitializeResult)
	if !ok {
		t.Fatalf("expected *InitializeResult, got %T", result)
	}
	provider := init.Capabilities.SemanticTokensProvider
	if provider == nil {
		t.Fatal("semanticTokensProvider not advertised")
	}
	if !provider.Full {
		t.Error("full semantic tokens not advertised")
	}
	if !reflect.DeepEqual(provider.Legend, semanticTokensLegend()) {
		t.Errorf("advertised legend %+v differs from encoder legend %+v", provider.Legend, semanticTokensLegend())
	}
}

func TestSemanticTokens_Categories(t *testing.T) {
	sql := "SELECT COUNT(*), CAST(a AS INT) FROM t WHERE b = $1 AND c IS NULL -- c\n" +
		"SELECT 'x', 42"
	assertTokens(t, semanticTokensFor(t, sql), []semTok{
		{0, 0, 6, "keyword", ""},
		{0, 7, 5, "function", ""},
		{0, 13, 1, "operator", ""},
		{0, 17, 4, "function", ""},
		{0, 22, 1, "variable", ""},
		{0, 24, 2, "keyword", ""},
		{0, 27, 3, "type", ""},
		{0, 32, 4, "keyword", ""},
		{0, 37, 1, "variable", ""},
		{0, 39, 5, "keyword", ""},
		{0, 45, 1, "variable", ""},
		{0, 47, 1, "operator", ""},
		{0, 49, 2, "parameter", ""},
		{0, 52, 3, "keyword", ""},
		{0, 56, 1, "variable", ""},
		{0, 58, 2, "keyword", ""},
		{0, 61, 4, "keyword", "readonly"},
		{0, 66, 4, "comment", ""},
		{1, 0, 6, "keyword", ""},
		{1, 7, 3, "string", ""},
		{1, 12, 2, "number", ""},
	})
}

func TestSemanticTokens_QuotedIdentifier(t *testing.T) {
	assertTokens(t, semanticTokensFor(t, `SELECT "Name" FROM t`), []semTok{
		{0, 0, 6, "keyword", ""},
		{0, 7, 6, "variable", ""},
		{0, 14, 4, "keyword", ""},
		{0, 19, 1, "variable", ""},
	})
}

// TestSemanticTokens_InitializationDialect verifies that the dialect sent in
// initializationOptions (as the VS Code extension does) drives highlighting:
// MySQL treats "..." as a string, the default dialect as a quoted identifier.
func TestSemanticTokens_InitializationDialect(t *testing.T) {
	const content = `SELECT "x" FROM t`
	tests := []struct {
		name     string
		initOpts string
		wantType string
	}{
		{"no options", `null`, "variable"},
		{"mysql", `{"dialect":"mysql"}`, "string"},
		{"mysql mixed case", `{"dialect":" MySQL "}`, "string"},
		{"postgresql", `{"dialect":"postgresql"}`, "variable"},
		{"unknown dialect falls back", `{"dialect":"fakesql"}`, "variable"},
		{"non-string dialect ignored", `{"dialect":42}`, "variable"},
		{"non-object options ignored", `"mysql"`, "variable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := setupTestServer()
			params := `{"processId":1,"rootUri":"file:///","initializationOptions":` + tt.initOpts + `}`
			if _, err := server.handler.HandleRequest("initialize", json.RawMessage(params)); err != nil {
				t.Fatalf("initialize: %v", err)
			}
			const uri = "file:///dialect.sql"
			server.Documents().Open(uri, "sql", 1, content)
			got := decodeSemanticTokens(t, requestSemanticTokens(t, server, uri).Data)
			if len(got) < 2 {
				t.Fatalf("expected at least 2 tokens, got %+v", got)
			}
			if got[1].Type != tt.wantType {
				t.Errorf(`"x" token type = %q, want %q (tokens %+v)`, got[1].Type, tt.wantType, got)
			}
		})
	}
}

func TestSemanticTokens_MultiLineSplitting(t *testing.T) {
	t.Run("block comment", func(t *testing.T) {
		// The blank middle line yields no zero-length token.
		assertTokens(t, semanticTokensFor(t, "SELECT 1 /* a\n\n  bb */ x"), []semTok{
			{0, 0, 6, "keyword", ""},
			{0, 7, 1, "number", ""},
			{0, 9, 4, "comment", ""},
			{2, 0, 7, "comment", ""},
			{2, 8, 1, "variable", ""},
		})
	})
	t.Run("string", func(t *testing.T) {
		assertTokens(t, semanticTokensFor(t, "SELECT 'a\nbc', TRUE"), []semTok{
			{0, 0, 6, "keyword", ""},
			{0, 7, 2, "string", ""},
			{1, 0, 3, "string", ""},
			{1, 5, 4, "keyword", "readonly"},
		})
	})
}

func TestSemanticTokens_UTF16Columns(t *testing.T) {
	t.Run("string with BMP and astral chars", func(t *testing.T) {
		// 'é😀' is 8 bytes but 5 UTF-16 code units (é=1, 😀=2 surrogates).
		assertTokens(t, semanticTokensFor(t, "SELECT 'é😀', x FROM t"), []semTok{
			{0, 0, 6, "keyword", ""},
			{0, 7, 5, "string", ""},
			{0, 14, 1, "variable", ""},
			{0, 16, 4, "keyword", ""},
			{0, 21, 1, "variable", ""},
		})
	})
	t.Run("comment before token", func(t *testing.T) {
		// "/* é😀 */" is 9 UTF-16 units (12 bytes); SELECT starts at 10, not 13.
		assertTokens(t, semanticTokensFor(t, "/* é😀 */ SELECT 1"), []semTok{
			{0, 0, 9, "comment", ""},
			{0, 10, 6, "keyword", ""},
			{0, 17, 1, "number", ""},
		})
	})
	t.Run("multi-line comment with astral char", func(t *testing.T) {
		assertTokens(t, semanticTokensFor(t, "/* 😀\n😀 */ x"), []semTok{
			{0, 0, 5, "comment", ""},
			{1, 0, 5, "comment", ""},
			{1, 6, 1, "variable", ""},
		})
	})
}

func TestSemanticTokens_LineEndings(t *testing.T) {
	t.Run("CRLF", func(t *testing.T) {
		// "\r" is a line terminator, never part of a token's length.
		assertTokens(t, semanticTokensFor(t, "SELECT a\r\nFROM t\r\n/* x\r\ny */ 1 -- z\r\n"), []semTok{
			{0, 0, 6, "keyword", ""},
			{0, 7, 1, "variable", ""},
			{1, 0, 4, "keyword", ""},
			{1, 5, 1, "variable", ""},
			{2, 0, 4, "comment", ""},
			{3, 0, 4, "comment", ""},
			{3, 5, 1, "number", ""},
			{3, 7, 4, "comment", ""},
		})
	})
	t.Run("CR only", func(t *testing.T) {
		assertTokens(t, semanticTokensFor(t, "SELECT a\rFROM t"), []semTok{
			{0, 0, 6, "keyword", ""},
			{0, 7, 1, "variable", ""},
			{1, 0, 4, "keyword", ""},
			{1, 5, 1, "variable", ""},
		})
	})
}

func TestSemanticTokens_EmptyAndUnknown(t *testing.T) {
	server := setupTestServer()
	server.Documents().Open("file:///empty.sql", "sql", 1, "")
	server.Documents().Open("file:///blank.sql", "sql", 1, "  \n\t\r\n")
	for _, uri := range []string{"file:///empty.sql", "file:///blank.sql", "file:///missing.sql"} {
		toks := requestSemanticTokens(t, server, uri)
		if len(toks.Data) != 0 {
			t.Errorf("%s: expected no tokens, got %v", uri, toks.Data)
		}
		b, err := json.Marshal(toks)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(b) != `{"data":[]}` {
			t.Errorf("%s: JSON = %s, want {\"data\":[]}", uri, b)
		}
	}
}

func TestSemanticTokens_InvalidSQL(t *testing.T) {
	// Tokens before the lexical error are reported; the Error span is not.
	assertTokens(t, semanticTokensFor(t, "SELECT a FROM t WHERE x = 'unterminated\nmore"), []semTok{
		{0, 0, 6, "keyword", ""},
		{0, 7, 1, "variable", ""},
		{0, 9, 4, "keyword", ""},
		{0, 14, 1, "variable", ""},
		{0, 16, 5, "keyword", ""},
		{0, 22, 1, "variable", ""},
		{0, 24, 1, "operator", ""},
	})
}

func TestSemanticTokens_RejectsMalformedSpans(t *testing.T) {
	// encodeSemanticTokens must tolerate out-of-range or empty spans rather
	// than panic; they are simply skipped.
	content := "SELECT 1"
	spans := []highlight.Span{
		{Start: 0, End: 6, Category: highlight.Keyword},
		{Start: 7, End: 7, Category: highlight.Number},
		{Start: 7, End: 99, Category: highlight.Number},
	}
	assertTokens(t, decodeSemanticTokens(t, encodeSemanticTokens(content, spans)), []semTok{
		{0, 0, 6, "keyword", ""},
	})
}

// FuzzEncodeSemanticTokens checks encoder invariants on arbitrary input:
// no panic, no zero-length tokens, positions strictly increasing, and each
// token stays within its line's UTF-16 length.
func FuzzEncodeSemanticTokens(f *testing.F) {
	for _, s := range []string{
		"SELECT 1", "/* a\r\n😀 */ x", "SELECT 'é\r\n' -- c\r", "SELECT \"unterminated",
		"\r\r\n\n", "SELECT $1, :name, @v FROM t WHERE a::int > 2",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, content string) {
		data := encodeSemanticTokens(content, highlight.Spans(content))
		toks := decodeSemanticTokens(t, data)
		lineLens := utf16LineLengths(content)
		prevLine, prevEnd := -1, 0
		for _, tok := range toks {
			if tok.Line >= len(lineLens) {
				t.Fatalf("token %+v beyond last line %d", tok, len(lineLens)-1)
			}
			if tok.Char+tok.Len > lineLens[tok.Line] {
				t.Fatalf("token %+v exceeds line length %d", tok, lineLens[tok.Line])
			}
			if tok.Line == prevLine && tok.Char < prevEnd {
				t.Fatalf("token %+v overlaps previous token ending at %d", tok, prevEnd)
			}
			if tok.Line < prevLine {
				t.Fatalf("token %+v goes backwards from line %d", tok, prevLine)
			}
			prevLine, prevEnd = tok.Line, tok.Char+tok.Len
		}
	})
}

// utf16LineLengths splits on \n, \r\n and \r and returns each line's length in
// UTF-16 code units, independently of the encoder under test.
func utf16LineLengths(s string) []int {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	var out []int
	for _, line := range strings.Split(s, "\n") {
		n := 0
		for _, r := range line {
			if r >= 0x10000 {
				n += 2
			} else {
				n++
			}
		}
		out = append(out, n)
	}
	return out
}
