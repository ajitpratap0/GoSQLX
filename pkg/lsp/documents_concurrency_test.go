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
	"fmt"
	"strings"
	"sync"
	"testing"
)

// checkSnapshotConsistent verifies that a Get snapshot is internally
// consistent: Lines is exactly the line split of Content.
func checkSnapshotConsistent(doc *Document) error {
	if joined := strings.Join(doc.Lines, "\n"); joined != doc.Content {
		return fmt.Errorf("Lines/Content mismatch: join(Lines)=%q Content=%q", joined, doc.Content)
	}
	if want := strings.Count(doc.Content, "\n") + 1; len(doc.Lines) != want {
		return fmt.Errorf("len(Lines)=%d, want %d", len(doc.Lines), want)
	}
	return nil
}

// TestDocumentManager_ConcurrentUpdateAndRead exercises Update against
// concurrent readers (Get, GetWordAtPosition and the request handlers) on the
// same URI. Run with -race. Get shares the manager's immutable Lines slice, so
// this proves that sharing is safe and that snapshots stay consistent.
func TestDocumentManager_ConcurrentUpdateAndRead(t *testing.T) {
	iterations := 300
	if testing.Short() {
		iterations = 50
	}
	const uri = "file:///concurrent.sql"

	server := setupTestServer()
	server.Documents().Open(uri, "sql", 1, "SELECT COUNT(a, b) FROM users WHERE id = 1")

	posParams, err := json.Marshal(TextDocumentPositionParams{
		TextDocument: TextDocumentIdentifier{URI: uri},
		Position:     Position{Line: 0, Character: 14},
	})
	if err != nil {
		t.Fatalf("marshal position params: %v", err)
	}
	docParams, err := json.Marshal(DocumentSymbolParams{TextDocument: TextDocumentIdentifier{URI: uri}})
	if err != nil {
		t.Fatalf("marshal document params: %v", err)
	}
	methods := []struct {
		name   string
		params json.RawMessage
	}{
		{"textDocument/hover", posParams},
		{"textDocument/completion", posParams},
		{"textDocument/signatureHelp", posParams},
		{"textDocument/documentSymbol", docParams},
		{"textDocument/semanticTokens/full", docParams},
	}

	errCh := make(chan error, 16)
	report := func(err error) {
		select {
		case errCh <- err:
		default:
		}
	}

	var readers sync.WaitGroup
	for r := 0; r < 4; r++ {
		readers.Add(1)
		go func(r int) {
			defer readers.Done()
			for i := 0; i < iterations; i++ {
				doc, ok := server.Documents().Get(uri)
				if !ok {
					report(fmt.Errorf("document disappeared"))
					return
				}
				if err := checkSnapshotConsistent(doc); err != nil {
					report(err)
					return
				}
				_ = doc.GetWordAtPosition(Position{Line: 0, Character: 3})
				m := methods[(i+r)%len(methods)]
				if _, err := server.handler.HandleRequest(m.name, m.params); err != nil {
					report(fmt.Errorf("%s: %w", m.name, err))
					return
				}
			}
		}(r)
	}

	for i := 0; i < iterations; i++ {
		if i%2 == 0 {
			text := "SELECT COUNT(a, b) FROM users" + strings.Repeat("\n  WHERE id = 1", i%7)
			server.Documents().Update(uri, i+2, []TextDocumentContentChangeEvent{{Text: text}})
		} else {
			server.Documents().Update(uri, i+2, []TextDocumentContentChangeEvent{{
				Range: &Range{Start: Position{Line: 0, Character: 0}, End: Position{Line: 0, Character: 0}},
				Text:  "-- note\n",
			}})
		}
	}
	readers.Wait()

	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
}

// TestDocumentManager_GetSnapshotSurvivesUpdate pins the "replace, never
// mutate" contract: a snapshot obtained from Get is unaffected by later
// Updates because Update publishes fresh Content and Lines.
func TestDocumentManager_GetSnapshotSurvivesUpdate(t *testing.T) {
	const uri = "file:///snap.sql"
	dm := NewDocumentManager()
	dm.Open(uri, "sql", 1, "SELECT 1\nFROM t")

	snap, ok := dm.Get(uri)
	if !ok {
		t.Fatal("document not found")
	}
	wantContent := snap.Content
	wantLines := append([]string(nil), snap.Lines...)

	dm.Update(uri, 2, []TextDocumentContentChangeEvent{{Text: "SELECT 2\nFROM u\nWHERE x = 1"}})
	dm.Update(uri, 3, []TextDocumentContentChangeEvent{{
		Range: &Range{Start: Position{Line: 0, Character: 7}, End: Position{Line: 0, Character: 8}},
		Text:  "99",
	}})

	if snap.Content != wantContent {
		t.Errorf("snapshot Content changed: %q", snap.Content)
	}
	if strings.Join(snap.Lines, "\n") != strings.Join(wantLines, "\n") || len(snap.Lines) != len(wantLines) {
		t.Errorf("snapshot Lines changed: %q", snap.Lines)
	}

	cur, ok := dm.Get(uri)
	if !ok {
		t.Fatal("document not found after update")
	}
	if cur.Content != "SELECT 99\nFROM u\nWHERE x = 1" {
		t.Errorf("unexpected current content %q", cur.Content)
	}
	if err := checkSnapshotConsistent(cur); err != nil {
		t.Error(err)
	}
	if cur.Version != 3 {
		t.Errorf("version = %d, want 3", cur.Version)
	}
}
