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
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestNew_CreatesServer(t *testing.T) {
	cfg := DefaultConfig()
	srv := New(cfg)
	if srv == nil {
		t.Fatal("New() returned nil")
	}
	if srv.cfg != cfg {
		t.Error("cfg not stored on server")
	}
	if srv.mcpSrv == nil {
		t.Error("mcpSrv is nil after New()")
	}
}

func TestServer_AuthDisabled(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.AuthEnabled() {
		t.Error("DefaultConfig should have auth disabled")
	}
	srv := New(cfg)
	if srv == nil {
		t.Fatal("New() returned nil")
	}
}

func TestServer_AuthEnabled(t *testing.T) {
	cfg := &Config{Host: "127.0.0.1", Port: 8080, AuthToken: "testtoken"}
	if !cfg.AuthEnabled() {
		t.Error("Config with AuthToken should have auth enabled")
	}
	srv := New(cfg)
	if srv == nil {
		t.Fatal("New() returned nil")
	}
}

// freePort asks the OS for an available TCP port on localhost.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func TestServer_Start_And_Shutdown(t *testing.T) {
	port := freePort(t)
	cfg := &Config{Host: "127.0.0.1", Port: port}
	srv := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Poll until the server is accepting connections.
	addr := fmt.Sprintf("http://127.0.0.1:%d/mcp", port)
	ready := false
	for i := 0; i < 50; i++ {
		resp, err := http.Post(addr, "application/json", nil)
		if err == nil {
			resp.Body.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("server did not become ready within timeout")
	}

	// Cancel context to trigger graceful shutdown.
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Start returned unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down within 5s")
	}
}

func TestServer_Start_PortInUse(t *testing.T) {
	// Occupy a port.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port

	cfg := &Config{Host: "127.0.0.1", Port: port}
	srv := New(cfg)

	// Start should fail immediately because the port is occupied.
	err = srv.Start(context.Background())
	if err == nil {
		t.Fatal("expected error when port is in use, got nil")
	}
}

func TestServer_Start_WithAuth(t *testing.T) {
	port := freePort(t)
	token := "secret-test-token"
	cfg := &Config{Host: "127.0.0.1", Port: port, AuthToken: token}
	srv := New(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Wait for server to be ready.
	addr := fmt.Sprintf("http://127.0.0.1:%d/mcp", port)
	ready := false
	for i := 0; i < 50; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("server did not become ready within timeout")
	}

	// Request without auth token should get 401.
	resp, err := http.Get(addr)
	if err != nil {
		t.Fatalf("GET request failed: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", resp.StatusCode)
	}

	// Clean up.
	cancel()
	select {
	case <-errCh:
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down within 5s")
	}
}
