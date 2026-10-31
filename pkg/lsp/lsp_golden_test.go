// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package lsp_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/internal/goldens"
	"github.com/ajitpratap0/GoSQLX/pkg/lsp"
)

// lspDoc is one document of the fixed LSP golden set, opened under each of
// its dialects.
type lspDoc struct {
	name     string
	text     string
	dialects []string
}

// lspGoldenDocs builds the fixed document set from the benchmark corpus:
//   - rw-<dialect>: about 30 KB of that dialect's realworld statements, under
//     its own dialect and under generic (which reports the dialect-only
//     syntax as diagnostics);
//   - generic: about 30 KB of the dialect-neutral corpora, under generic,
//     bigquery and redshift (which have no corpus of their own);
//   - feature-<dialect>: every feature sample of the dialect, under it;
//   - errors: hand-written multi-error input with non-ASCII text, tabs and
//     CRLF line ends, which exercises UTF-16 column conversion.
func lspGoldenDocs(t *testing.T) []lspDoc {
	t.Helper()
	goldens.Corpus(t) // manifest check
	set, err := benchcorpus.Default()
	if err != nil {
		t.Fatal(err)
	}
	const size = 30 << 10
	var docs []lspDoc
	for _, c := range benchcorpus.Corpora {
		if c.Kind != benchcorpus.KindRealWorld {
			continue
		}
		docs = append(docs, lspDoc{
			name:     "rw-" + c.Dialect,
			text:     benchcorpus.Script(set.ByCorpus(c.Name), size).SQL,
			dialects: []string{c.Dialect, benchcorpus.GenericDialect},
		})
	}
	var generic []benchcorpus.Statement
	for _, c := range benchcorpus.Corpora {
		switch c.Kind {
		case benchcorpus.KindGeneric:
			generic = append(generic, set.ByCorpus(c.Name)...)
		case benchcorpus.KindFeature:
			docs = append(docs, lspDoc{
				name:     strings.ReplaceAll(c.Name, "/", "-"),
				text:     joinSQL(set.ByCorpus(c.Name)),
				dialects: []string{c.Dialect},
			})
		}
	}
	docs = append(docs, lspDoc{
		name:     "generic",
		text:     benchcorpus.Script(generic, size).SQL,
		dialects: []string{"generic", "bigquery", "redshift"},
	})
	docs = append(docs, lspDoc{
		name: "errors",
		text: "-- naïve “quotes” before errors\r\nSELECT * FROM 表 WHERE x = 'é' AND;\r\n" +
			"SELECT\tname, FROM users;\n" +
			"INSERT INTO t (a, b VALUES (1, 2);\n" +
			"UPDATE t SET a = WHERE id = 1;\n" +
			"SELECT 'ünïcödé' AS s, ) FROM dual;\n" +
			"CREATE TABLE x (id INT PRIMARY KEY, name VARCHAR(10)\n" +
			"WITH c AS (SELECT 1) SELECT * FROM c;\n",
		dialects: []string{"generic", "postgresql", "sqlserver"},
	})
	return docs
}

func joinSQL(stmts []benchcorpus.Statement) string {
	var b strings.Builder
	for _, st := range stmts {
		b.WriteString(strings.TrimRight(st.SQL, " \t\r\n"))
		b.WriteString("\n;\n")
	}
	return b.String()
}

// TestGoldenLSP pins the published diagnostics, the full semantic tokens
// (decoded with the advertised legend) and the document symbols the LSP
// handler produces for a fixed document set. Regenerate with
// task goldens:update; inspect a mismatch with task goldens:diff.
func TestGoldenLSP(t *testing.T) {
	type job struct {
		doc     lspDoc
		dialect string
	}
	var jobs []job
	for _, d := range lspGoldenDocs(t) {
		for _, dialect := range d.dialects {
			jobs = append(jobs, job{d, dialect})
		}
	}
	cols := []string{"diagnostics", "semantic_tokens", "document_symbols"}
	g := goldens.New("lsp", "LSP publishDiagnostics, semanticTokens/full and documentSymbol per fixed document and dialect", cols...)
	goldens.Parallel(len(jobs), func(i int) {
		j := jobs[i]
		row := j.doc.name + "@" + j.dialect
		res := lspRun(j.doc.text, j.dialect)
		for ci, c := range cols {
			g.Add(row, c, 0, j.doc.text, res[ci])
		}
	})
	g.Check(t)
}

// lspRun opens text in a fresh server configured for dialect and returns the
// diagnostics, semantic tokens and document symbols, each rendered as text.
func lspRun(text, dialect string) (out [3]string) {
	var buf bytes.Buffer
	srv := lsp.NewServer(strings.NewReader(""), &buf, log.New(io.Discard, "", 0))
	h := lsp.NewHandler(srv)
	const uri = "file:///golden.sql"

	var legend lsp.SemanticTokensLegend
	out[0] = goldens.Safe(func() string {
		init, err := h.HandleRequest("initialize", mustJSON(lsp.InitializeParams{
			InitializationOptions: map[string]interface{}{"dialect": dialect},
		}))
		if err != nil {
			return "initialize: " + err.Error()
		}
		if r, ok := init.(*lsp.InitializeResult); ok && r.Capabilities.SemanticTokensProvider != nil {
			legend = r.Capabilities.SemanticTokensProvider.Legend
		}
		h.HandleNotification("textDocument/didOpen", mustJSON(lsp.DidOpenTextDocumentParams{
			TextDocument: lsp.TextDocumentItem{URI: uri, LanguageID: "sql", Version: 1, Text: text},
		}))
		return publishedDiagnostics(buf.Bytes())
	})
	doc := mustJSON(lsp.SemanticTokensParams{TextDocument: lsp.TextDocumentIdentifier{URI: uri}})
	out[1] = goldens.Safe(func() string {
		res, err := h.HandleRequest("textDocument/semanticTokens/full", doc)
		if err != nil {
			return "error: " + err.Error()
		}
		st, ok := res.(*lsp.SemanticTokens)
		if !ok || st == nil {
			return fmt.Sprintf("unexpected result %T", res)
		}
		return decodeSemanticTokens(st.Data, legend)
	})
	out[2] = goldens.Safe(func() string {
		res, err := h.HandleRequest("textDocument/documentSymbol", mustJSON(lsp.DocumentSymbolParams{TextDocument: lsp.TextDocumentIdentifier{URI: uri}}))
		if err != nil {
			return "error: " + err.Error()
		}
		syms, ok := res.([]lsp.DocumentSymbol)
		if !ok {
			return fmt.Sprintf("unexpected result %T", res)
		}
		return jsonLines(syms)
	})
	return out
}

func mustJSON(v interface{}) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// jsonLines renders one compact JSON value per element and line, so a diff
// points at the element that changed.
func jsonLines[T any](items []T) string {
	var b strings.Builder
	for _, it := range items {
		j, err := json.Marshal(it)
		if err != nil {
			return "marshal: " + err.Error()
		}
		b.Write(j)
		b.WriteByte('\n')
	}
	return b.String()
}

// publishedDiagnostics extracts every textDocument/publishDiagnostics
// notification from the server's framed output.
func publishedDiagnostics(raw []byte) string {
	var b strings.Builder
	rd := bufio.NewReader(bytes.NewReader(raw))
	for {
		hdr, err := rd.ReadString('\n')
		if err != nil {
			break
		}
		n, ok := strings.CutPrefix(strings.TrimSpace(hdr), "Content-Length: ")
		if !ok {
			continue
		}
		size, err := strconv.Atoi(n)
		if err != nil {
			return "bad frame: " + hdr
		}
		if _, err := rd.ReadString('\n'); err != nil { // blank line
			return "truncated frame"
		}
		body := make([]byte, size)
		if _, err := io.ReadFull(rd, body); err != nil {
			return "truncated frame"
		}
		var msg struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(body, &msg); err != nil {
			return "bad message: " + err.Error()
		}
		if msg.Method != "textDocument/publishDiagnostics" {
			continue
		}
		var p lsp.PublishDiagnosticsParams
		if err := json.Unmarshal(msg.Params, &p); err != nil {
			return "bad diagnostics: " + err.Error()
		}
		fmt.Fprintf(&b, "publish uri=%s version=%d diagnostics=%d\n", p.URI, p.Version, len(p.Diagnostics))
		b.WriteString(jsonLines(p.Diagnostics))
	}
	return b.String()
}

// decodeSemanticTokens turns the relative LSP encoding into one absolute
// "line:char len type modifiers" line per token (0-based, UTF-16 units).
func decodeSemanticTokens(data []uint32, legend lsp.SemanticTokensLegend) string {
	var b strings.Builder
	if len(data)%5 != 0 {
		fmt.Fprintf(&b, "malformed: %d values\n", len(data))
	}
	line, char := 0, 0
	for i := 0; i+4 < len(data); i += 5 {
		if data[i] > 0 {
			line += int(data[i])
			char = int(data[i+1])
		} else {
			char += int(data[i+1])
		}
		typ := strconv.Itoa(int(data[i+3]))
		if int(data[i+3]) < len(legend.TokenTypes) {
			typ = legend.TokenTypes[data[i+3]]
		}
		var mods []string
		for bit, name := range legend.TokenModifiers {
			if data[i+4]&(1<<uint(bit)) != 0 {
				mods = append(mods, name)
			}
		}
		fmt.Fprintf(&b, "%d:%d %d %s %s\n", line, char, data[i+2], typ, strings.Join(mods, ","))
	}
	return b.String()
}
