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
	"testing"
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
