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
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// initializeBody is a minimal MCP initialize request.
const initializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"lifecycle-test","version":"0"}}}`

// postInitialize sends initialize to url and returns the response status and
// the Mcp-Session-Id header.
func postInitialize(t *testing.T, url string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(initializeBody))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST initialize: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Mcp-Session-Id")
}

// recordingLogger captures transport log lines.
type recordingLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *recordingLogger) Infof(format string, v ...any) { l.add("INFO: " + fmt.Sprintf(format, v...)) }
func (l *recordingLogger) Errorf(format string, v ...any) {
	l.add("ERROR: " + fmt.Sprintf(format, v...))
}
func (l *recordingLogger) add(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, s)
}
func (l *recordingLogger) contains(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.lines {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// waitGoroutines polls until the goroutine count is at most limit, so that
// goroutines which are already exiting are not counted as leaks.
func waitGoroutines(limit int) int {
	n := runtime.NumGoroutine()
	for deadline := time.Now().Add(3 * time.Second); n > limit && time.Now().Before(deadline); {
		time.Sleep(20 * time.Millisecond)
		runtime.GC()
		n = runtime.NumGoroutine()
	}
	return n
}

func TestSessionIdleTTL_Value(t *testing.T) {
	// The privacy policy and docs cite 30 minutes (state removed 30-45
	// minutes after the last request, since the sweep runs every TTL/2).
	if SessionIdleTTL != 30*time.Minute {
		t.Errorf("SessionIdleTTL = %v, want 30m", SessionIdleTTL)
	}
	srv := New(DefaultConfig())
	if srv.sessionIdleTTL != SessionIdleTTL {
		t.Errorf("New() sessionIdleTTL = %v, want SessionIdleTTL", srv.sessionIdleTTL)
	}
	if _, ok := srv.transportLogger.(transportLogger); !ok {
		t.Errorf("New() transportLogger is %T, want transportLogger", srv.transportLogger)
	}
}

// TestServer_SessionSweeperWired proves the TTL reaches the transport: with a
// tiny TTL the sweeper removes the session's state and says so through the
// configured logger.
func TestServer_SessionSweeperWired(t *testing.T) {
	srv := New(DefaultConfig())
	srv.sessionIdleTTL = 50 * time.Millisecond
	rec := &recordingLogger{}
	srv.transportLogger = rec
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	status, sid := postInitialize(t, ts.URL+"/mcp")
	if status != http.StatusOK || sid == "" {
		t.Fatalf("initialize: status %d, session %q", status, sid)
	}
	want := "Sweeping expired session: " + sid
	for deadline := time.Now().Add(5 * time.Second); !rec.contains(want); {
		if time.Now().After(deadline) {
			t.Fatalf("session %s was not swept; transport log: %v", sid, rec.lines)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestTransportLogger_DropsInfoKeepsErrors(t *testing.T) {
	var buf bytes.Buffer
	l := transportLogger{logger: log.New(&buf, "", 0)}

	l.Infof("Sweeping expired session: %s", "mcp-session-0123")
	if buf.Len() != 0 {
		t.Errorf("Infof wrote %q; info messages carry session IDs and must be dropped", buf.String())
	}
	l.Errorf("Failed to write response: %v", "broken pipe")
	if got := buf.String(); !strings.Contains(got, "Failed to write response: broken pipe") {
		t.Errorf("Errorf output = %q, want the error message", got)
	}
}

func TestServer_HandlerReusesOneTransport(t *testing.T) {
	srv := New(DefaultConfig())
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	_ = srv.Handler()
	first := srv.streamSrv
	_ = srv.Handler()
	if first == nil || srv.streamSrv != first {
		t.Error("Handler() must build the streamable HTTP transport once and reuse it")
	}
}

// TestServer_NoSweeperLeak checks that Handler, Start and Shutdown do not
// leave a session-sweeper goroutine behind.
func TestServer_NoSweeperLeak(t *testing.T) {
	before := waitGoroutines(runtime.NumGoroutine())

	for i := 0; i < 20; i++ {
		srv := New(DefaultConfig())
		_ = srv.Handler()
		_ = srv.Handler()
		if err := srv.Shutdown(context.Background()); err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
	}
	for i := 0; i < 5; i++ {
		srv := New(&Config{Host: "127.0.0.1", Port: freePort(t)})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- srv.Start(ctx) }()
		time.Sleep(20 * time.Millisecond)
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Start did not return after cancel")
		}
	}

	if after := waitGoroutines(before + 2); after > before+2 {
		t.Errorf("goroutines grew from %d to %d: session sweeper not stopped", before, after)
	}
}

func TestServer_Shutdown_Idempotent(t *testing.T) {
	srv := New(DefaultConfig())
	// Never built: nothing to stop.
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown before Handler: %v", err)
	}
	h := srv.Handler()
	for i := 0; i < 2; i++ {
		if err := srv.Shutdown(context.Background()); err != nil {
			t.Fatalf("Shutdown #%d: %v", i+1, err)
		}
	}
	// A handler obtained before Shutdown keeps serving.
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	if status, sid := postInitialize(t, ts.URL+"/mcp"); status != http.StatusOK || sid == "" {
		t.Errorf("initialize after Shutdown: status %d, session %q", status, sid)
	}
}

func TestServer_Start_PortInUse_ReturnsAndCleansUp(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	tcpAddr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is %T", l.Addr())
	}

	before := waitGoroutines(runtime.NumGoroutine())
	srv := New(&Config{Host: "127.0.0.1", Port: tcpAddr.Port})
	done := make(chan error, 1)
	// The context is never cancelled: Start must still return and stop the sweeper.
	go func() { done <- srv.Start(context.Background()) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected an error when the port is in use")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return on a listen error")
	}
	if after := waitGoroutines(before + 1); after > before+1 {
		t.Errorf("goroutines grew from %d to %d after a failed Start", before, after)
	}
}
