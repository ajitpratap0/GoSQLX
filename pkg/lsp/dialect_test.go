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
	"io"
	"log"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// SQL the parser treats differently per dialect:
//   - mysqlLimit: LIMIT offset, count is MySQL syntax, rejected by the
//     default pipeline and by PostgreSQL.
//   - ilikeQuery: ILIKE is accepted by the default pipeline and PostgreSQL
//     but rejected by MySQL.
const (
	mysqlLimit = "SELECT id FROM users LIMIT 5, 10"
	ilikeQuery = "SELECT id FROM users WHERE name ILIKE 'a%'"
)

// dialectTestServer is a server whose output can be read while handlers run
// on other goroutines.
type dialectTestServer struct {
	*Server
	out *countingWriter
}

// newDialectServer creates a server and sends initialize. initOpts is the raw
// initializationOptions JSON ("" omits it); refresh advertises
// workspace.semanticTokens.refreshSupport.
func newDialectServer(t *testing.T, initOpts string, refresh bool) *dialectTestServer {
	t.Helper()
	out := &countingWriter{}
	server := NewServer(strings.NewReader(""), out, log.New(io.Discard, "", 0))
	params := `{"processId":1,"rootUri":"file:///"`
	if initOpts != "" {
		params += `,"initializationOptions":` + initOpts
	}
	if refresh {
		params += `,"capabilities":{"workspace":{"semanticTokens":{"refreshSupport":true}}}`
	}
	params += `}`
	if _, err := server.handler.HandleRequest("initialize", json.RawMessage(params)); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	return &dialectTestServer{Server: server, out: out}
}

func dialectOpts(d string) string {
	if d == "" {
		return ""
	}
	return fmt.Sprintf(`{"dialect":%q}`, d)
}

// frames decodes every message the server has written so far.
func (s *dialectTestServer) frames(t *testing.T) []map[string]json.RawMessage {
	t.Helper()
	data, _ := s.out.snapshot()
	var msgs []map[string]json.RawMessage
	for _, f := range parseStrictFrames(t, data) {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(f, &m); err != nil {
			t.Fatalf("unmarshal frame %s: %v", f, err)
		}
		msgs = append(msgs, m)
	}
	return msgs
}

// methodFrames returns the messages with the given method, in order.
func (s *dialectTestServer) methodFrames(t *testing.T, method string) []map[string]json.RawMessage {
	t.Helper()
	var out []map[string]json.RawMessage
	for _, m := range s.frames(t) {
		var got string
		if raw, ok := m["method"]; ok && json.Unmarshal(raw, &got) == nil && got == method {
			out = append(out, m)
		}
	}
	return out
}

// lastDiagnostics returns the diagnostics of the last publishDiagnostics
// notification for uri.
func (s *dialectTestServer) lastDiagnostics(t *testing.T, uri string) []Diagnostic {
	t.Helper()
	var last []Diagnostic
	found := false
	for _, m := range s.methodFrames(t, "textDocument/publishDiagnostics") {
		var p PublishDiagnosticsParams
		if err := json.Unmarshal(m["params"], &p); err != nil {
			t.Fatalf("unmarshal diagnostics: %v", err)
		}
		if p.URI == uri {
			last, found = p.Diagnostics, true
		}
	}
	if !found {
		t.Fatalf("no publishDiagnostics for %s", uri)
	}
	return last
}

func (s *dialectTestServer) open(t *testing.T, uri, text string) {
	t.Helper()
	raw, err := json.Marshal(DidOpenTextDocumentParams{
		TextDocument: TextDocumentItem{URI: uri, LanguageID: "sql", Version: 1, Text: text},
	})
	if err != nil {
		t.Fatalf("marshal didOpen: %v", err)
	}
	s.handler.HandleNotification("textDocument/didOpen", raw)
}

func (s *dialectTestServer) changeConfig(settings string) {
	s.handler.HandleNotification("workspace/didChangeConfiguration",
		json.RawMessage(`{"settings":`+settings+`}`))
}

func (s *dialectTestServer) request(t *testing.T, method string, params interface{}) interface{} {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatalf("marshal %s params: %v", method, err)
	}
	result, err := s.handler.HandleRequest(method, raw)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	return result
}

func (s *dialectTestServer) formatting(t *testing.T, uri string) []TextEdit {
	t.Helper()
	result := s.request(t, "textDocument/formatting", DocumentFormattingParams{
		TextDocument: TextDocumentIdentifier{URI: uri},
		Options:      FormattingOptions{TabSize: 2, InsertSpaces: true},
	})
	edits, ok := result.([]TextEdit)
	if !ok {
		t.Fatalf("expected []TextEdit, got %T", result)
	}
	return edits
}

func (s *dialectTestServer) symbols(t *testing.T, uri string) []DocumentSymbol {
	t.Helper()
	result := s.request(t, "textDocument/documentSymbol", DocumentSymbolParams{
		TextDocument: TextDocumentIdentifier{URI: uri},
	})
	syms, ok := result.([]DocumentSymbol)
	if !ok {
		t.Fatalf("expected []DocumentSymbol, got %T", result)
	}
	return syms
}

func (s *dialectTestServer) completionLabels(t *testing.T, uri string, pos Position) map[string]bool {
	t.Helper()
	result := s.request(t, "textDocument/completion", CompletionParams{
		TextDocumentPositionParams: TextDocumentPositionParams{
			TextDocument: TextDocumentIdentifier{URI: uri},
			Position:     pos,
		},
	})
	list, ok := result.(*CompletionList)
	if !ok {
		t.Fatalf("expected *CompletionList, got %T", result)
	}
	labels := make(map[string]bool, len(list.Items))
	for _, item := range list.Items {
		labels[item.Label] = true
	}
	return labels
}

func (s *dialectTestServer) hover(t *testing.T, uri string, pos Position) string {
	t.Helper()
	result := s.request(t, "textDocument/hover", TextDocumentPositionParams{
		TextDocument: TextDocumentIdentifier{URI: uri},
		Position:     pos,
	})
	h, ok := result.(*Hover)
	if !ok {
		t.Fatalf("expected *Hover, got %T", result)
	}
	return h.Contents.Value
}

func TestDialect_Diagnostics(t *testing.T) {
	tests := []struct {
		dialect   string // "" = no initializationOptions
		sql       string
		wantDiags bool
	}{
		{"", mysqlLimit, true},
		{"generic", mysqlLimit, true},
		{"postgresql", mysqlLimit, true},
		{"mysql", mysqlLimit, false},
		{"", ilikeQuery, false},
		{"generic", ilikeQuery, false},
		{"postgresql", ilikeQuery, false},
		{"mysql", ilikeQuery, true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s/%s", tt.dialect, tt.sql), func(t *testing.T) {
			s := newDialectServer(t, dialectOpts(tt.dialect), false)
			const uri = "file:///diag.sql"
			s.open(t, uri, tt.sql)
			diags := s.lastDiagnostics(t, uri)
			if got := len(diags) > 0; got != tt.wantDiags {
				t.Errorf("diagnostics present = %v, want %v (%+v)", got, tt.wantDiags, diags)
			}
		})
	}
}

// TestDialect_DefaultMatchesLegacy pins the unset/generic behaviour to the
// dialect-less pipeline the server used before it became dialect-aware.
func TestDialect_DefaultMatchesLegacy(t *testing.T) {
	inputs := []string{
		mysqlLimit,
		ilikeQuery,
		"SELECT * FROM",
		"SELECT * FROM; DELETE FROM",
		"SELECT `id` FROM `users`",
		"SELECT data->>'name' FROM users",
		"SELECT TOP 10 id FROM users",
		"select  id,name from users where id=1",
	}
	for _, d := range []string{"", "generic", "GENERIC", "fakesql"} {
		for _, sql := range inputs {
			t.Run(d+"/"+sql, func(t *testing.T) {
				s := newDialectServer(t, dialectOpts(d), false)
				const uri = "file:///legacy.sql"
				s.open(t, uri, sql)

				_, errs := gosqlx.ParseWithRecovery(sql)
				wantDiags := buildDiagnostics(sql, errs)
				if wantDiags == nil {
					wantDiags = []Diagnostic{}
				}
				if got := s.lastDiagnostics(t, uri); !reflect.DeepEqual(got, wantDiags) {
					t.Errorf("diagnostics\n got: %+v\nwant: %+v", got, wantDiags)
				}

				wantFormatted, err := gosqlx.Format(sql, gosqlx.DefaultFormatOptions())
				if err != nil {
					wantFormatted = formatSQL(sql, FormattingOptions{TabSize: 2, InsertSpaces: true})
				}
				edits := s.formatting(t, uri)
				gotFormatted := sql
				if len(edits) == 1 {
					gotFormatted = edits[0].NewText
				}
				if gotFormatted != wantFormatted {
					t.Errorf("formatting = %q, want %q", gotFormatted, wantFormatted)
				}

				_, parseErr := gosqlx.Parse(sql)
				if got, want := len(s.symbols(t, uri)) > 0, parseErr == nil; got != want {
					t.Errorf("symbols present = %v, want %v", got, want)
				}
			})
		}
	}
}

func TestDialect_Formatting(t *testing.T) {
	const sql = "select id from users limit 5, 10"
	const uri = "file:///fmt.sql"
	fallback := formatSQL(sql, FormattingOptions{TabSize: 2, InsertSpaces: true})

	parsed, err := gosqlx.ParseWithDialect(sql, keywords.DialectMySQL)
	if err != nil {
		t.Fatalf("ParseWithDialect: %v", err)
	}
	wantMySQL := gosqlx.FormatAST(parsed, gosqlx.WithIndent(2))
	if wantMySQL == fallback {
		t.Fatalf("test needs AST and fallback formatting to differ; both %q", fallback)
	}

	for _, tt := range []struct{ dialect, want string }{
		{"", fallback},
		{"postgresql", fallback},
		{"mysql", wantMySQL},
	} {
		t.Run(tt.dialect, func(t *testing.T) {
			s := newDialectServer(t, dialectOpts(tt.dialect), false)
			s.Documents().Open(uri, "sql", 1, sql)
			got := sql
			if edits := s.formatting(t, uri); len(edits) == 1 {
				got = edits[0].NewText
			}
			if got != tt.want {
				t.Errorf("formatted = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDialect_DocumentSymbols(t *testing.T) {
	const uri = "file:///sym.sql"
	for _, tt := range []struct {
		dialect, sql string
		want         int
	}{
		{"", mysqlLimit, 0},
		{"postgresql", mysqlLimit, 0},
		{"mysql", mysqlLimit, 1},
		{"", ilikeQuery, 1},
		{"mysql", ilikeQuery, 0},
	} {
		t.Run(tt.dialect+"/"+tt.sql, func(t *testing.T) {
			s := newDialectServer(t, dialectOpts(tt.dialect), false)
			s.Documents().Open(uri, "sql", 1, tt.sql)
			if got := len(s.symbols(t, uri)); got != tt.want {
				t.Errorf("symbols = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestDialect_CompletionAndHover(t *testing.T) {
	const uri = "file:///kw.sql"
	for _, tt := range []struct {
		dialect  string
		wantKW   bool
		wantText string
	}{
		{"", false, ""},
		{"generic", false, ""},
		{"postgresql", false, ""},
		{"mysql", true, "MySQL-specific"},
		{"mariadb", true, "MariaDB-specific"},
	} {
		t.Run(tt.dialect, func(t *testing.T) {
			s := newDialectServer(t, dialectOpts(tt.dialect), false)

			// GetWordAtPosition needs the cursor inside the word.
			s.Documents().Open(uri, "sql", 1, "SELECT ZEROF")
			labels := s.completionLabels(t, uri, Position{Line: 0, Character: 10})
			if labels["ZEROFILL"] != tt.wantKW {
				t.Errorf("ZEROFILL offered = %v, want %v (%v)", labels["ZEROFILL"], tt.wantKW, labels)
			}

			// Generic keywords are still offered first for every dialect.
			s.Documents().Open(uri, "sql", 1, "SEL")
			if !s.completionLabels(t, uri, Position{Line: 0, Character: 1})["SELECT"] {
				t.Error("SELECT missing from completion")
			}

			s.Documents().Open(uri, "sql", 1, "CREATE TABLE t (id INT ZEROFILL)")
			text := s.hover(t, uri, Position{Line: 0, Character: 26})
			if tt.wantText == "" && text != "" {
				t.Errorf("hover = %q, want none", text)
			}
			if tt.wantText != "" && !strings.Contains(text, tt.wantText) {
				t.Errorf("hover = %q, want it to contain %q", text, tt.wantText)
			}

			// Documented generic keywords keep their documentation.
			if text := s.hover(t, uri, Position{Line: 0, Character: 2}); !strings.Contains(text, "CREATE") {
				t.Errorf("CREATE hover = %q", text)
			}
		})
	}
}

func TestDialect_DidChangeConfiguration(t *testing.T) {
	tests := []struct {
		name     string
		settings string
		want     keywords.SQLDialect
	}{
		{"mysql", `{"gosqlx":{"dialect":"mysql"}}`, keywords.DialectMySQL},
		{"mixed case", `{"gosqlx":{"dialect":" MySQL "}}`, keywords.DialectMySQL},
		{"other settings kept", `{"gosqlx":{"dialect":"sqlserver","format":{"indentSize":4}}}`, keywords.DialectSQLServer},
		{"generic", `{"gosqlx":{"dialect":"generic"}}`, keywords.DialectGeneric},
		{"unknown falls back to generic", `{"gosqlx":{"dialect":"fakesql"}}`, keywords.DialectGeneric},
		{"empty falls back to generic", `{"gosqlx":{"dialect":""}}`, keywords.DialectGeneric},
		{"non-string falls back to generic", `{"gosqlx":{"dialect":42}}`, keywords.DialectGeneric},
		{"null settings keep current", `null`, keywords.DialectPostgreSQL},
		{"no gosqlx section keeps current", `{"editor":{"tabSize":2}}`, keywords.DialectPostgreSQL},
		{"no dialect key keeps current", `{"gosqlx":{"enable":true}}`, keywords.DialectPostgreSQL},
		{"non-object section keeps current", `{"gosqlx":"mysql"}`, keywords.DialectPostgreSQL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newDialectServer(t, dialectOpts("postgresql"), false)
			s.changeConfig(tt.settings)
			if got := s.handler.currentDialect(); got != tt.want {
				t.Errorf("dialect = %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("malformed params keep current", func(t *testing.T) {
		s := newDialectServer(t, dialectOpts("postgresql"), false)
		s.handler.HandleNotification("workspace/didChangeConfiguration", json.RawMessage(`{"settings":`))
		if got := s.handler.currentDialect(); got != keywords.DialectPostgreSQL {
			t.Errorf("dialect = %q, want postgresql", got)
		}
		if len(s.methodFrames(t, "window/showMessage")) != 1 {
			t.Error("expected a showMessage warning for malformed params")
		}
	})
}

func TestDialect_DidChangeConfiguration_RepublishesAndRefreshes(t *testing.T) {
	const uriA, uriB = "file:///a.sql", "file:///b.sql"

	s := newDialectServer(t, "", true)
	s.open(t, uriA, mysqlLimit)
	s.open(t, uriB, ilikeQuery)
	if len(s.lastDiagnostics(t, uriA)) == 0 || len(s.lastDiagnostics(t, uriB)) != 0 {
		t.Fatal("unexpected diagnostics before the dialect change")
	}

	s.changeConfig(`{"gosqlx":{"dialect":"mysql"}}`)
	if d := s.lastDiagnostics(t, uriA); len(d) != 0 {
		t.Errorf("a.sql under mysql: want no diagnostics, got %+v", d)
	}
	if len(s.lastDiagnostics(t, uriB)) == 0 {
		t.Error("b.sql under mysql: want ILIKE diagnosed")
	}
	refreshes := s.methodFrames(t, "workspace/semanticTokens/refresh")
	if len(refreshes) != 1 {
		t.Fatalf("expected 1 semantic token refresh request, got %d", len(refreshes))
	}
	if _, ok := refreshes[0]["id"]; !ok {
		t.Error("refresh must be a request (with an id)")
	}

	// Semantic tokens follow the new dialect: MySQL treats "x" as a string.
	const semURI = "file:///sem.sql"
	s.Documents().Open(semURI, "sql", 1, `SELECT "x" FROM t`)
	toks := decodeSemanticTokens(t, requestSemanticTokens(t, s.Server, semURI).Data)
	if len(toks) < 2 || toks[1].Type != "string" {
		t.Errorf(`"x" under mysql: tokens %+v, want string`, toks)
	}

	// Re-sending the same dialect is a no-op: no re-publish, no refresh.
	before := len(s.frames(t))
	s.changeConfig(`{"gosqlx":{"dialect":"mysql"}}`)
	if after := len(s.frames(t)); after != before {
		t.Errorf("unchanged dialect wrote %d messages", after-before)
	}

	// The client's response to the refresh request is accepted silently.
	before = len(s.frames(t))
	s.handleMessage(json.RawMessage(`{"jsonrpc":"2.0","id":1,"result":null}`))
	if after := len(s.frames(t)); after != before {
		t.Errorf("response to server request produced %d messages", after-before)
	}
}

func TestDialect_DidChangeConfiguration_NoRefreshWithoutSupport(t *testing.T) {
	s := newDialectServer(t, "", false)
	s.open(t, "file:///a.sql", mysqlLimit)
	s.changeConfig(`{"gosqlx":{"dialect":"mysql"}}`)
	if n := len(s.methodFrames(t, "workspace/semanticTokens/refresh")); n != 0 {
		t.Errorf("sent %d refresh requests to a client without refreshSupport", n)
	}
	if d := s.lastDiagnostics(t, "file:///a.sql"); len(d) != 0 {
		t.Errorf("want diagnostics re-published without errors, got %+v", d)
	}
}

// TestDialect_DidChangeConfiguration_PendingChange checks that a dialect
// change re-validates the document's current version and cancels a pending
// debounced didChange validation instead of letting it publish afterwards.
func TestDialect_DidChangeConfiguration_PendingChange(t *testing.T) {
	const uri = "file:///pending.sql"
	s := newDialectServer(t, "", false)
	s.open(t, uri, ilikeQuery)

	raw, err := json.Marshal(DidChangeTextDocumentParams{
		TextDocument:   VersionedTextDocumentIdentifier{TextDocumentIdentifier: TextDocumentIdentifier{URI: uri}, Version: 2},
		ContentChanges: []TextDocumentContentChangeEvent{{Text: mysqlLimit}},
	})
	if err != nil {
		t.Fatalf("marshal didChange: %v", err)
	}
	s.handler.HandleNotification("textDocument/didChange", raw)
	s.changeConfig(`{"gosqlx":{"dialect":"mysql"}}`)

	s.handler.debounceMu.Lock()
	pending := len(s.handler.debounceTimers)
	s.handler.debounceMu.Unlock()
	if pending != 0 {
		t.Errorf("dialect change left %d debounce timers pending", pending)
	}

	publishes := func() []PublishDiagnosticsParams {
		var out []PublishDiagnosticsParams
		for _, m := range s.methodFrames(t, "textDocument/publishDiagnostics") {
			var p PublishDiagnosticsParams
			if err := json.Unmarshal(m["params"], &p); err != nil {
				t.Fatalf("unmarshal diagnostics: %v", err)
			}
			if p.URI == uri {
				out = append(out, p)
			}
		}
		return out
	}
	got := publishes()
	if len(got) == 0 {
		t.Fatal("no diagnostics published")
	}
	if last := got[len(got)-1]; last.Version != 2 || len(last.Diagnostics) != 0 {
		t.Errorf("after dialect change: version %d diagnostics %+v, want version 2 with none", last.Version, last.Diagnostics)
	}

	// The cancelled debounce (300ms) must not publish again.
	time.Sleep(400 * time.Millisecond)
	if after := publishes(); len(after) != len(got) {
		t.Errorf("cancelled debounce published %d more diagnostics", len(after)-len(got))
	}
}

// TestDialect_ConcurrentConfigurationChange runs every dialect-aware feature
// while the dialect flips; run with -race.
func TestDialect_ConcurrentConfigurationChange(t *testing.T) {
	s := newDialectServer(t, "", true)
	const uri = "file:///concurrent.sql"
	s.open(t, uri, mysqlLimit+";\n"+ilikeQuery)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		dialects := []string{"mysql", "postgresql", "generic", "sqlserver", "fakesql"}
		for i := 0; i < 200; i++ {
			s.changeConfig(fmt.Sprintf(`{"gosqlx":{"dialect":%q}}`, dialects[i%len(dialects)]))
		}
		close(stop)
	}()

	worker := func(fn func()) {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				fn()
			}
		}
	}
	pos := Position{Line: 0, Character: 2}
	wg.Add(5)
	go worker(func() { s.formatting(t, uri) })
	go worker(func() { s.symbols(t, uri) })
	go worker(func() { s.completionLabels(t, uri, pos) })
	go worker(func() { s.hover(t, uri, pos) })
	go worker(func() { requestSemanticTokens(t, s.Server, uri) })
	wg.Wait()

	// Every message written concurrently is still a well-formed frame.
	s.frames(t)
}

// TestDialect_DocumentSymbolsWithGO checks the SQL Server outline of a script
// with GO batch separators: the separators get no symbol, and each statement
// ends before the GO line that follows it instead of running to the end of
// the file.
func TestDialect_DocumentSymbolsWithGO(t *testing.T) {
	const uri = "file:///batches.sql"
	const sql = "SELECT a FROM t\nGO\nUPDATE u SET b = 1\nGO 2\nDELETE FROM v WHERE c = 1"
	s := newDialectServer(t, dialectOpts("sqlserver"), false)
	s.Documents().Open(uri, "sql", 1, sql)
	symbols := s.symbols(t, uri)
	if len(symbols) != 3 {
		t.Fatalf("symbols = %d (%+v), want 3", len(symbols), symbols)
	}
	wantLines := [][2]int{{0, 0}, {2, 2}, {4, 4}} // start and end line of each statement
	for i, sym := range symbols {
		if strings.HasPrefix(sym.Name, "GO") || strings.HasPrefix(sym.Name, "Statement #") {
			t.Errorf("symbol %d is %q, want a statement symbol", i, sym.Name)
		}
		if sym.Range.Start.Line != wantLines[i][0] || sym.Range.End.Line != wantLines[i][1] {
			t.Errorf("symbol %d (%s) spans lines %d-%d, want %d-%d", i, sym.Name,
				sym.Range.Start.Line, sym.Range.End.Line, wantLines[i][0], wantLines[i][1])
		}
	}
}
