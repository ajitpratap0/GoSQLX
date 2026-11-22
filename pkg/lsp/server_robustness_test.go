// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package lsp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"testing"
)

// Diagnostics may be published asynchronously after Run returns.
type robustnessBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *robustnessBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *robustnessBuffer) snapshot() *bytes.Buffer {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.NewBuffer(bytes.Clone(b.buffer.Bytes()))
}

func robustnessFrame(body string) string {
	return fmt.Sprintf("Content-Length: %d\r\n\r\n%s", len(body), body)
}

func robustnessResponses(t *testing.T, output *bytes.Buffer) map[int]map[string]any {
	t.Helper()
	responses := make(map[int]map[string]any)
	reader := bufio.NewReader(output)
	for {
		var size int
		header, err := reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Sscanf(header, "Content-Length: %d", &size); err != nil {
			t.Fatal(err)
		}
		if line, err := reader.ReadString('\n'); err != nil || line != "\r\n" {
			t.Fatalf("invalid separator %q: %v", line, err)
		}
		body := make([]byte, size)
		if _, err := io.ReadFull(reader, body); err != nil {
			t.Fatal(err)
		}
		var response map[string]any
		if err := json.Unmarshal(body, &response); err != nil {
			t.Fatal(err)
		}
		if id, ok := response["id"].(float64); ok {
			responses[int(id)] = response
		}
	}
	return responses
}

func TestRobustnessInitializeCapabilities(t *testing.T) {
	var output bytes.Buffer
	server := NewServer(strings.NewReader(robustnessFrame(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)), &output, nil)
	if err := server.Run(); err != nil {
		t.Fatal(err)
	}
	response := robustnessResponses(t, &output)[1]
	result, ok := response["result"].(map[string]any)
	if !ok {
		t.Fatalf("missing result: %v", response)
	}
	caps, ok := result["capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("missing capabilities: %v", result)
	}
	syncOptions, ok := caps["textDocumentSync"].(map[string]any)
	if !ok || syncOptions["openClose"] != true || syncOptions["change"] != float64(2) {
		t.Fatalf("invalid sync capability: %v", caps)
	}
	if _, exists := caps["textDocumentSyncOptions"]; exists {
		t.Fatal("obsolete capability key")
	}
}

func TestRobustnessContentLength(t *testing.T) {
	for _, value := range []string{"-5", "0", "abc"} {
		t.Run(value, func(t *testing.T) {
			var output bytes.Buffer
			input := "Content-Length: " + value + "\r\n\r\n" + robustnessFrame(`{"jsonrpc":"2.0","id":7,"method":"shutdown"}`)
			if err := NewServer(strings.NewReader(input), &output, nil).Run(); err != nil {
				t.Fatal(err)
			}
			if robustnessResponses(t, &output)[7] == nil {
				t.Fatal("next request not served")
			}
		})
	}
}

func TestRobustnessOversizedMessage(t *testing.T) {
	var output bytes.Buffer
	input := fmt.Sprintf("Content-Length: %d\r\n\r\n", MaxContentLength+1) + strings.Repeat("x", MaxContentLength+1) + robustnessFrame(`{"jsonrpc":"2.0","id":8,"method":"shutdown"}`)
	if err := NewServer(strings.NewReader(input), &output, nil).Run(); err != nil {
		t.Fatal(err)
	}
	if robustnessResponses(t, &output)[8] == nil {
		t.Fatal("stream not resynchronized")
	}
}

func TestRobustnessTruncatedOversizedMessage(t *testing.T) {
	for _, body := range []string{"", "short"} {
		t.Run(fmt.Sprint(len(body)), func(t *testing.T) {
			var output bytes.Buffer
			input := fmt.Sprintf("Content-Length: %d\r\n\r\n%s", MaxContentLength+1, body)
			if err := NewServer(strings.NewReader(input), &output, nil).Run(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRobustnessDocumentChanges(t *testing.T) {
	tests := []struct {
		name, content string
		start, end    Position
		text, want    string
	}{
		{"past last line", "SELECT 1", Position{5, 0}, Position{5, 3}, "x", "SELECT 1x"},
		{"negative line", "SELECT 1", Position{-1, 0}, Position{0, 3}, "x", "SELECT 1"},
		{"negative character", "SELECT 1", Position{0, 0}, Position{0, -1}, "x", "SELECT 1"},
		{"reversed", "SELECT 1", Position{0, 8}, Position{0, 0}, "", ""},
		{"UTF16", "SELECT 'é😀' x", Position{0, 11}, Position{0, 12}, `"`, "SELECT 'é😀\" x"},
		{"surrogate midpoint rounds up", "a😀b", Position{0, 2}, Position{0, 3}, "X", "a😀Xb"},
		{"CRLF", "SELECT 1\r\nFROM t", Position{0, 100}, Position{0, 100}, "X", "SELECT 1X\r\nFROM t"},
		{"trailing newline", "SELECT 1\n", Position{5, 0}, Position{5, 3}, "x", "SELECT 1\nx"},
		{"empty", "", Position{5, 0}, Position{5, 3}, "x", "x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			open, err := json.Marshal(DidOpenTextDocumentParams{TextDocument: TextDocumentItem{URI: "file:///test.sql", LanguageID: "sql", Version: 1, Text: tt.content}})
			if err != nil {
				t.Fatal(err)
			}
			change, err := json.Marshal(DidChangeTextDocumentParams{TextDocument: VersionedTextDocumentIdentifier{TextDocumentIdentifier: TextDocumentIdentifier{URI: "file:///test.sql"}, Version: 2}, ContentChanges: []TextDocumentContentChangeEvent{{Range: &Range{Start: tt.start, End: tt.end}, Text: tt.text}}})
			if err != nil {
				t.Fatal(err)
			}
			input := robustnessFrame(fmt.Sprintf(`{"jsonrpc":"2.0","method":"textDocument/didOpen","params":%s}`, open)) + robustnessFrame(fmt.Sprintf(`{"jsonrpc":"2.0","method":"textDocument/didChange","params":%s}`, change)) + robustnessFrame(`{"jsonrpc":"2.0","id":9,"method":"shutdown"}`)
			var output, logs robustnessBuffer
			server := NewServer(strings.NewReader(input), &output, log.New(&logs, "", 0))
			if err := server.Run(); err != nil {
				t.Fatal(err)
			}
			server.handler.debounceMu.Lock()
			for _, timer := range server.handler.debounceTimers {
				timer.Stop()
			}
			server.handler.debounceMu.Unlock()
			got, ok := server.documents.GetContent("file:///test.sql")
			if !ok || got != tt.want {
				t.Fatalf("content = %q, want %q", got, tt.want)
			}
			if robustnessResponses(t, output.snapshot())[9] == nil {
				t.Fatal("next request not served")
			}
			if strings.HasPrefix(tt.name, "negative") && !strings.Contains(logs.snapshot().String(), "negative") {
				t.Fatal("rejected range not logged")
			}
		})
	}
}

func TestRobustnessRecovery(t *testing.T) {
	for _, request := range []bool{true, false} {
		t.Run(fmt.Sprint(request), func(t *testing.T) {
			var output, logs bytes.Buffer
			input := robustnessFrame(`{"jsonrpc":"2.0","id":11,"method":"shutdown"}`)
			server := NewServer(strings.NewReader(input), &output, log.New(&logs, "", 0))
			msg := json.RawMessage(`{"jsonrpc":"2.0","id":10,"method":"test/panic"}`)
			if !request {
				msg = json.RawMessage(`{"jsonrpc":"2.0","method":"test/panic"}`)
			}
			server.handleMessageWithRecovery(msg, func(json.RawMessage) {
				panic("test handler failure /private/internal.go")
			})
			if err := server.Run(); err != nil {
				t.Fatal(err)
			}
			responses := robustnessResponses(t, &output)
			if request {
				responseError, ok := responses[10]["error"].(map[string]any)
				if !ok || responseError["code"] != float64(InternalError) {
					t.Fatalf("missing internal error: %v", responses)
				}
				message, ok := responseError["message"].(string)
				if !ok || strings.Contains(message, "goroutine") || strings.ContainsAny(message, "/\\") {
					t.Fatalf("unsafe error message: %v", responseError)
				}
			} else if len(responses) != 1 {
				t.Fatalf("notification generated response: %v", responses)
			}
			if responses[11] == nil {
				t.Fatal("next request not served")
			}
			if !strings.Contains(logs.String(), "goroutine") || !strings.Contains(logs.String(), "test handler failure") {
				t.Fatal("panic and stack not logged")
			}
		})
	}
}
