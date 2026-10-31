// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package lsp

// LSP benchmark matrix (PLAN.md 2.2, W0-06).
//
//	BenchmarkLSP/<op>/<size>/<dialect>
//	  op      semanticTokens | documentSymbol | diagnostics | editCycle | didChangeIncremental
//	  size    1KB | 30KB | 300KB
//	  dialect postgresql | mysql | sqlserver
//
// The document is a script of the dialect's real-world statements (see
// benchcorpus.Script), so it is at least the named size and at most one
// statement larger.
//
//	semanticTokens        textDocument/semanticTokens/full request
//	documentSymbol        textDocument/documentSymbol request
//	diagnostics           validateDocument: what the debounce timer runs, including the publishDiagnostics send
//	didChangeIncremental  one textDocument/didChange notification with a one-character range edit (the
//	                      debounce timer is cancelled so no validation runs in the background)
//	editCycle             a keystroke followed by what an editor asks for once typing pauses: didChange,
//	                      validateDocument, semanticTokens
//
// Edits alternate insert and delete of one character so the size stays fixed.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

const benchURI = "file:///bench.sql"

var lspBenchDialects = []string{"postgresql", "mysql", "sqlserver"}

var lspBenchSizes = []struct {
	name  string
	bytes int
}{{"1KB", 1 << 10}, {"30KB", 30 << 10}, {"300KB", 300 << 10}}

// lspBenchDoc builds the document for a dialect and size.
func lspBenchDoc(tb testing.TB, dialect string, minBytes int) string {
	tb.Helper()
	set, err := benchcorpus.Default()
	if err != nil {
		tb.Fatalf("benchcorpus.Default: %v", err)
	}
	var stmts []benchcorpus.Statement
	for _, st := range set.RealWorld(dialect) {
		if st.Bucket != benchcorpus.Large {
			stmts = append(stmts, st)
		}
	}
	if len(stmts) == 0 {
		tb.Fatalf("no real-world statements for %s", dialect)
	}
	return benchcorpus.Script(stmts, minBytes).SQL
}

// lspBenchHandler returns a handler with doc open under benchURI and the
// dialect configured, plus a one-character edit pair that keeps the size
// fixed.
func lspBenchHandler(tb testing.TB, dialect, doc string) (h *Handler, insert, remove func(version int) json.RawMessage) {
	tb.Helper()
	srv := setupTestServer()
	h = srv.handler
	h.setDialect(keywords.SQLDialect(dialect))
	srv.Documents().Open(benchURI, "sql", 1, doc)

	// Edit in the middle of the document, at the start of a line.
	line := strings.Count(doc, "\n") / 2
	pos := Position{Line: line, Character: 0}
	mk := func(r Range, text string) func(int) json.RawMessage {
		return func(version int) json.RawMessage {
			p := DidChangeTextDocumentParams{
				TextDocument:   VersionedTextDocumentIdentifier{TextDocumentIdentifier: TextDocumentIdentifier{URI: benchURI}, Version: version},
				ContentChanges: []TextDocumentContentChangeEvent{{Range: &r, Text: text}},
			}
			raw, err := json.Marshal(p)
			if err != nil {
				tb.Fatalf("marshal didChange: %v", err)
			}
			return raw
		}
	}
	insert = mk(Range{Start: pos, End: pos}, " ")
	remove = mk(Range{Start: pos, End: Position{Line: line, Character: 1}}, "")
	return h, insert, remove
}

// cancelDebounce stops the validation timer didChange arms, so a benchmark
// op never spawns background validation that would run during a later op.
func cancelDebounce(h *Handler) {
	h.debounceMu.Lock()
	for uri, t := range h.debounceTimers {
		t.Stop()
		delete(h.debounceTimers, uri)
	}
	h.debounceMu.Unlock()
}

func mustMarshal(tb testing.TB, v interface{}) json.RawMessage {
	tb.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		tb.Fatalf("marshal: %v", err)
	}
	return raw
}

func BenchmarkLSP(b *testing.B) {
	ops := []string{"semanticTokens", "documentSymbol", "diagnostics", "editCycle", "didChangeIncremental"}
	for _, op := range ops {
		for _, sz := range lspBenchSizes {
			for _, d := range lspBenchDialects {
				doc := lspBenchDoc(b, d, sz.bytes)
				b.Run(op+"/"+sz.name+"/"+d, func(b *testing.B) {
					h, insert, remove := lspBenchHandler(b, d, doc)
					defer cancelDebounce(h)
					symParams := mustMarshal(b, DocumentSymbolParams{TextDocument: TextDocumentIdentifier{URI: benchURI}})
					semParams := mustMarshal(b, SemanticTokensParams{TextDocument: TextDocumentIdentifier{URI: benchURI}})
					edit := func(i int) {
						if i&1 == 0 {
							h.HandleNotification("textDocument/didChange", insert(i+2))
						} else {
							h.HandleNotification("textDocument/didChange", remove(i+2))
						}
						cancelDebounce(h)
					}

					b.ReportAllocs()
					b.SetBytes(int64(len(doc)))
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						switch op {
						case "semanticTokens":
							if _, err := h.HandleRequest("textDocument/semanticTokens/full", semParams); err != nil {
								b.Fatal(err)
							}
						case "documentSymbol":
							if _, err := h.HandleRequest("textDocument/documentSymbol", symParams); err != nil {
								b.Fatal(err)
							}
						case "diagnostics":
							h.validateDocument(benchURI, doc, 1)
						case "didChangeIncremental":
							edit(i)
						case "editCycle":
							edit(i)
							content, _ := h.server.Documents().GetContent(benchURI)
							h.validateDocument(benchURI, content, i+2)
							if _, err := h.HandleRequest("textDocument/semanticTokens/full", semParams); err != nil {
								b.Fatal(err)
							}
						}
					}
				})
			}
		}
	}
}

// TestLSPBenchDocuments pins what the benchmarks run on: each document is at
// least the named size, deterministic, valid in its dialect (so diagnostics
// publishes an empty list rather than timing an error path), and yields
// symbols and semantic tokens.
func TestLSPBenchDocuments(t *testing.T) {
	for _, d := range lspBenchDialects {
		for _, sz := range lspBenchSizes {
			doc := lspBenchDoc(t, d, sz.bytes)
			if len(doc) < sz.bytes {
				t.Fatalf("%s/%s: document is %d bytes", d, sz.name, len(doc))
			}
			if doc != lspBenchDoc(t, d, sz.bytes) {
				t.Errorf("%s/%s: document is not deterministic", d, sz.name)
			}
			if sz.bytes > 30<<10 && testing.Short() {
				continue
			}
			_, errs := parseWithRecoveryForDialect(doc, keywords.SQLDialect(d))
			if len(errs) != 0 {
				t.Errorf("%s/%s: %d parse errors, first: %v", d, sz.name, len(errs), errs[0])
			}
		}
	}
}

// TestLSPBenchOps runs every benchmarked operation once on the 1KB document
// and checks its observable effect, so a benchmark cannot silently time a
// no-op (unknown URI, wrong method, dropped edit).
func TestLSPBenchOps(t *testing.T) {
	for _, d := range lspBenchDialects {
		t.Run(d, func(t *testing.T) {
			doc := lspBenchDoc(t, d, 1<<10)
			h, insert, remove := lspBenchHandler(t, d, doc)
			defer cancelDebounce(h)

			res, err := h.HandleRequest("textDocument/semanticTokens/full",
				mustMarshal(t, SemanticTokensParams{TextDocument: TextDocumentIdentifier{URI: benchURI}}))
			if err != nil {
				t.Fatalf("semanticTokens: %v", err)
			}
			if st, ok := res.(*SemanticTokens); !ok || len(st.Data) == 0 || len(st.Data)%5 != 0 {
				t.Errorf("semanticTokens result = %#v, want non-empty data in groups of 5", res)
			}

			res, err = h.HandleRequest("textDocument/documentSymbol",
				mustMarshal(t, DocumentSymbolParams{TextDocument: TextDocumentIdentifier{URI: benchURI}}))
			if err != nil {
				t.Fatalf("documentSymbol: %v", err)
			}
			if syms, ok := res.([]DocumentSymbol); ok && len(syms) == 0 {
				t.Errorf("documentSymbol returned no symbols for %d bytes of SQL", len(doc))
			}

			// A one-character insert changes the document by exactly one
			// byte, and the delete restores it.
			h.HandleNotification("textDocument/didChange", insert(2))
			cancelDebounce(h)
			got, _ := h.server.Documents().GetContent(benchURI)
			if len(got) != len(doc)+1 {
				t.Fatalf("after insert: %d bytes, want %d", len(got), len(doc)+1)
			}
			h.HandleNotification("textDocument/didChange", remove(3))
			cancelDebounce(h)
			if got, _ = h.server.Documents().GetContent(benchURI); got != doc {
				t.Errorf("after delete the document differs from the original (%d vs %d bytes)", len(got), len(doc))
			}

			h.validateDocument(benchURI, doc, 1) // must not panic or block
		})
	}
}
