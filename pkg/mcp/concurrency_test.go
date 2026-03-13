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
	"sync"
	"testing"

	mcpmcp "github.com/mark3labs/mcp-go/mcp"
)

func TestConcurrent_ValidateSQL(t *testing.T) {
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := makeReq(map[string]any{"sql": "SELECT id FROM users WHERE id = 1"})
			res, err := handleValidateSQL(ctx, req)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			data := unmarshalResult(t, res)
			if data["valid"] != true {
				t.Errorf("expected valid=true")
			}
		}()
	}
	wg.Wait()
}

func TestConcurrent_AnalyzeSQL(t *testing.T) {
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := makeReq(map[string]any{"sql": "SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.user_id"})
			res, err := handleAnalyzeSQL(ctx, req)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			data := unmarshalResult(t, res)
			for _, key := range []string{"validate", "parse", "metadata", "security", "lint", "format"} {
				if _, ok := data[key]; !ok {
					t.Errorf("missing key %q in concurrent analyze result", key)
				}
			}
		}()
	}
	wg.Wait()
}

func TestConcurrent_MixedTools(t *testing.T) {
	ctx := context.Background()
	var wg sync.WaitGroup

	type handlerFunc = func(context.Context, mcpmcp.CallToolRequest) (*mcpmcp.CallToolResult, error)

	tools := []struct {
		name string
		fn   handlerFunc
		args map[string]any
	}{
		{"validate", handleValidateSQL, map[string]any{"sql": "SELECT 1"}},
		{"format", handleFormatSQL, map[string]any{"sql": "select id from users"}},
		{"parse", handleParseSQL, map[string]any{"sql": "SELECT id FROM users"}},
		{"metadata", handleExtractMetadata, map[string]any{"sql": "SELECT u.id FROM users u"}},
		{"security", handleSecurityScan, map[string]any{"sql": "SELECT id FROM users WHERE id = 1"}},
		{"lint", handleLintSQL, map[string]any{"sql": "SELECT id FROM users"}},
	}

	for i := 0; i < 20; i++ {
		for _, tool := range tools {
			wg.Add(1)
			go func(name string, fn handlerFunc, args map[string]any) {
				defer wg.Done()
				req := makeReq(args)
				_, err := fn(ctx, req)
				if err != nil {
					t.Errorf("%s: unexpected error: %v", name, err)
				}
			}(tool.name, tool.fn, tool.args)
		}
	}
	wg.Wait()
}
