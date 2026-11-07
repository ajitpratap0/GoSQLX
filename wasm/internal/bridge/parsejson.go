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

package bridge

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/ajitpratap0/GoSQLX/internal/astjson"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// ASTJSONLegacy selects the original indented encoding/json representation.
//
// Deprecated: removed when the site switches to AST JSON v1.
const ASTJSONLegacy = 0

var parseJSONBuffers = sync.Pool{New: func() any {
	buf := make([]byte, 0, 4<<10)
	return &buf
}}

func putParseJSONBuffer(buf *[]byte) {
	if cap(*buf) <= 1<<20 {
		*buf = (*buf)[:0]
		parseJSONBuffers.Put(buf)
	}
}

// ParseJSON parses sql with the playground dialect and returns the AST JSON
// of the requested version. Version zero preserves the legacy indented output.
func ParseJSON(sql, dialect string, version int) (string, error) {
	if version != ASTJSONLegacy && version != astjson.Version {
		return "", fmt.Errorf("unsupported AST JSON version %d (supported: %d)", version, astjson.Version)
	}
	tree, err := Parse(sql, dialect)
	if err != nil {
		return "", err
	}
	defer ast.ReleaseAST(tree)
	if version == ASTJSONLegacy {
		out, err := json.MarshalIndent(tree, "", "  ")
		if err != nil {
			return "", fmt.Errorf("bridge: encode legacy AST JSON: %w", err)
		}
		return string(out), nil
	}
	buf, ok := parseJSONBuffers.Get().(*[]byte)
	if !ok {
		return "", fmt.Errorf("bridge: invalid AST JSON buffer pool value")
	}
	defer putParseJSONBuffer(buf)
	*buf, err = astjson.Append((*buf)[:0], tree)
	if err != nil {
		return "", fmt.Errorf("bridge: encode AST JSON v1: %w", err)
	}
	// string(*buf) copies before the deferred pool put; this order matters
	// because the returned string must survive subsequent buffer reuse.
	return string(*buf), nil
}
