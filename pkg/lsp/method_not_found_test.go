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
	"bytes"
	"encoding/json"
	"io"
	"log"
	"strings"
	"testing"
)

func TestUnknownMethodDispatch(t *testing.T) {
	for _, tt := range []struct {
		name     string
		message  string
		wantCode int
	}{
		{"request", `{"jsonrpc":"2.0","id":7,"method":"textDocument/definition","params":{}}`, MethodNotFound},
		{"notification", `{"jsonrpc":"2.0","method":"textDocument/definition","params":{}}`, 0},
		{"handler error", `{"jsonrpc":"2.0","id":7,"method":"initialize","params":true}`, InternalError},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			server := NewServer(strings.NewReader(""), &output, log.New(io.Discard, "", 0))
			server.handleMessage(json.RawMessage(tt.message))
			if tt.wantCode == 0 {
				if output.Len() != 0 {
					t.Fatalf("notification produced a response: %s", output.String())
				}
				return
			}
			responses := robustnessResponses(t, &output)
			responseError, ok := responses[7]["error"].(map[string]any)
			if !ok || responseError["code"] != float64(tt.wantCode) {
				t.Fatalf("response = %v, want error code %d", responses, tt.wantCode)
			}
		})
	}
}
