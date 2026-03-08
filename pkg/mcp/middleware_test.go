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
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBearerAuthMiddleware_AuthDisabled(t *testing.T) {
	cfg := DefaultConfig() // no auth token
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := BearerAuthMiddleware(cfg, next)
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("next handler was not called when auth is disabled")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

func TestBearerAuthMiddleware_ValidToken(t *testing.T) {
	cfg := &Config{Host: "127.0.0.1", Port: 8080, AuthToken: "secret"}
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	handler := BearerAuthMiddleware(cfg, next)
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !called {
		t.Error("next handler was not called with valid token")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}

func TestBearerAuthMiddleware_InvalidToken(t *testing.T) {
	cfg := &Config{Host: "127.0.0.1", Port: 8080, AuthToken: "secret"}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called with invalid token")
	})

	handler := BearerAuthMiddleware(cfg, next)
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer wrongtoken")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Error("WWW-Authenticate header missing on 401")
	}
}

func TestBearerAuthMiddleware_MissingHeader(t *testing.T) {
	cfg := &Config{Host: "127.0.0.1", Port: 8080, AuthToken: "secret"}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called with missing header")
	})

	handler := BearerAuthMiddleware(cfg, next)
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rr.Code)
	}
}

func TestBearerAuthMiddleware_MalformedHeader(t *testing.T) {
	cfg := &Config{Host: "127.0.0.1", Port: 8080, AuthToken: "secret"}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called with malformed header")
	})

	tests := []struct {
		name   string
		header string
	}{
		{"Token prefix", "Token secret"},
		{"Basic prefix", "Basic secret"},
		{"no prefix", "secret"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := BearerAuthMiddleware(cfg, next)
			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			req.Header.Set("Authorization", tc.header)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", rr.Code)
			}
		})
	}
}

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name      string
		header    string
		wantToken string
	}{
		{"valid", "Bearer mytoken", "mytoken"},
		{"empty", "", ""},
		{"no bearer", "Token mytoken", ""},
		{"basic", "Basic dXNlcjpwYXNz", ""},
		{"bearer no token", "Bearer ", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			got := extractBearerToken(req)
			if got != tc.wantToken {
				t.Errorf("extractBearerToken() = %q, want %q", got, tc.wantToken)
			}
		})
	}
}
