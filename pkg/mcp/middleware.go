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
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
)

// BearerAuthMiddleware returns an http.Handler that enforces bearer token
// authentication when cfg.AuthEnabled() is true. When auth is disabled it
// passes all requests through unchanged. On failure it responds 401 with a
// WWW-Authenticate header.
//
// Tokens are compared as SHA-256 digests with crypto/subtle, so the
// comparison time reveals neither the token's content nor its length.
func BearerAuthMiddleware(cfg *Config, next http.Handler) http.Handler {
	if !cfg.AuthEnabled() {
		return next
	}
	want := sha256.Sum256([]byte(cfg.AuthToken))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := sha256.Sum256([]byte(extractBearerToken(r)))
		if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="gosqlx-mcp"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// extractBearerToken parses the "Authorization: Bearer <token>" header. The
// scheme is matched case-insensitively (RFC 9110 §11.1) and surrounding
// whitespace is trimmed. Returns an empty string if the header is absent or
// malformed.
func extractBearerToken(r *http.Request) string {
	scheme, token, ok := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}
