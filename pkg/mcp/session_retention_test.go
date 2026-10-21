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

package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	mcpserver "github.com/mark3labs/mcp-go/server"
)

// syncBuffer is a goroutine-safe bytes.Buffer for capturing log output
// written from HTTP handler goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// mcpRequest sends method to url with an optional Mcp-Session-Id header and
// returns the status code and body.
func mcpRequest(t *testing.T, method, url, sessionID, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(data)
}

func TestNewSessionIdManager_KeepsNoTerminatedSet(t *testing.T) {
	mgr := newSessionIdManager()
	if _, ok := mgr.(*mcpserver.StatelessGeneratingSessionIdManager); !ok {
		t.Fatalf("newSessionIdManager() = %T, want *StatelessGeneratingSessionIdManager "+
			"(InsecureStatefulSessionIdManager never prunes terminated IDs)", mgr)
	}
	id := mgr.Generate()
	if !strings.HasPrefix(id, "mcp-session-") {
		t.Fatalf("Generate() = %q, want an mcp-session- ID", id)
	}
	if notAllowed, err := mgr.Terminate(id); notAllowed || err != nil {
		t.Fatalf("Terminate() = (%v, %v), want (false, nil)", notAllowed, err)
	}
	// A manager that remembered terminated IDs would report this one as
	// terminated; a stateless one has nothing to remember.
	if terminated, err := mgr.Validate(id); terminated || err != nil {
		t.Errorf("Validate(terminated ID) = (%v, %v), want (false, nil): manager must not track terminations", terminated, err)
	}
}

// TestServer_CreateTerminateCyclesRetainNothing opens and DELETEs many
// sessions over HTTP. If the transport tracked terminated IDs, the first
// session would be rejected with "Session terminated" afterwards; instead it
// is still accepted, proving no per-ID record is kept.
func TestServer_CreateTerminateCyclesRetainNothing(t *testing.T) {
	srv := New(DefaultConfig())
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	url := ts.URL + "/mcp"

	const cycles = 500
	var first string
	for i := 0; i < cycles; i++ {
		status, sid := postInitialize(t, url)
		if status != http.StatusOK || sid == "" {
			t.Fatalf("cycle %d initialize: status %d, session %q", i, status, sid)
		}
		if first == "" {
			first = sid
		}
		if status, body := mcpRequest(t, http.MethodDelete, url, sid, ""); status != http.StatusOK {
			t.Fatalf("cycle %d DELETE: status %d, body %q", i, status, body)
		}
	}

	status, body := mcpRequest(t, http.MethodPost, url, first, `{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	if status != http.StatusOK {
		t.Errorf("ping with terminated session ID: status %d, body %q; want 200 "+
			"(a 404 means the transport records terminated IDs, which grows without bound)", status, body)
	}
}

func TestTransportLogger_RedactsSessionIDsInErrors(t *testing.T) {
	const sid = "mcp-session-8c3e0a7e-58a4-4f43-9e1b-5d1b2c3f4a5b"
	tests := []struct {
		name     string
		format   string
		args     []any
		want     string
		mustSkip []string
	}{
		{
			name:     "unknown format arguments are withheld",
			format:   "Failed to handle sampling response: %v",
			args:     []any{errors.New("invalid session id: attacker-chosen-value")},
			want:     "Failed to handle sampling response: [redacted]",
			mustSkip: []string{"attacker-chosen-value"},
		},
		{
			name:     "deliver error with generated ID",
			format:   "Failed to deliver sampling response: %v",
			args:     []any{fmt.Errorf("no active session found for session %s", sid)},
			want:     "Failed to deliver sampling response: [redacted]",
			mustSkip: []string{sid, "8c3e0a7e"},
		},
		{
			name:     "safe format keeps its error detail",
			format:   "Failed to write response: %v",
			args:     []any{errors.New("write: broken pipe")},
			want:     "Failed to write response: write: broken pipe",
			mustSkip: nil,
		},
		{
			name:     "generated ID is scrubbed even from a safe format",
			format:   "Failed to write response: %v",
			args:     []any{fmt.Errorf("stream for %s closed", sid)},
			want:     "stream for mcp-session-[redacted] closed",
			mustSkip: []string{sid, "8c3e0a7e"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			l := transportLogger{logger: log.New(&buf, "", 0)}
			l.Errorf(tt.format, tt.args...)
			got := buf.String()
			if !strings.Contains(got, tt.want) {
				t.Errorf("Errorf output = %q, want it to contain %q", got, tt.want)
			}
			for _, s := range tt.mustSkip {
				if strings.Contains(got, s) {
					t.Errorf("Errorf output = %q leaks %q", got, s)
				}
			}
		})
	}
}

// TestServer_SessionIDsNotLoggedEndToEnd drives the mcp-go error paths that
// embed the client's Mcp-Session-Id (a response-shaped JSON-RPC POST with no
// pending sampling request) through the real transport and checks that the
// log carries the error but not the ID.
func TestServer_SessionIDsNotLoggedEndToEnd(t *testing.T) {
	logBuf := &syncBuffer{}
	srv := New(DefaultConfig())
	srv.transportLogger = transportLogger{logger: log.New(logBuf, "", 0)}
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	url := ts.URL + "/mcp"

	status, sid := postInitialize(t, url)
	if status != http.StatusOK || sid == "" {
		t.Fatalf("initialize: status %d, session %q", status, sid)
	}
	const forged = "client-forged-session-id"
	samplingResponse := `{"jsonrpc":"2.0","id":7,"result":{"role":"assistant"}}`
	for _, id := range []string{sid, forged} {
		if status, _ := mcpRequest(t, http.MethodPost, url, id, samplingResponse); status == http.StatusOK {
			t.Fatalf("sampling response for %q unexpectedly accepted", id)
		}
	}
	if status, _ := mcpRequest(t, http.MethodDelete, url, sid, ""); status != http.StatusOK {
		t.Fatalf("DELETE: status %d", status)
	}

	got := logBuf.String()
	if !strings.Contains(got, "sampling response") {
		t.Fatalf("expected the sampling error path to be logged, got %q", got)
	}
	uuidPart := strings.TrimPrefix(sid, "mcp-session-")
	for _, leak := range []string{sid, uuidPart, forged} {
		if strings.Contains(got, leak) {
			t.Errorf("transport log leaks session ID %q:\n%s", leak, got)
		}
	}
}
