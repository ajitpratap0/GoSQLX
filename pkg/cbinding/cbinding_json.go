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

package main

// #include <stdlib.h>
import "C"
import (
	"bytes"
	"encoding/json"
	"sync"
)

const (
	maxPooledJSONBuf   = 64 << 10
	maxPooledStmtTypes = 1024
)

type exportScratch struct {
	buf       bytes.Buffer
	enc       *json.Encoder
	parse     ParseResult
	valid     ValidationResult
	format    FormatResult
	stmtTypes []string
}

var scratchPool = sync.Pool{New: func() any {
	sc := &exportScratch{stmtTypes: make([]string, 0, 8)}
	sc.enc = json.NewEncoder(&sc.buf)
	return sc
}}

func getScratch() *exportScratch {
	sc, ok := scratchPool.Get().(*exportScratch)
	if !ok {
		// The pool only stores exportScratch pointers; retain a safe fallback.
		sc = &exportScratch{stmtTypes: make([]string, 0, 8)}
		sc.enc = json.NewEncoder(&sc.buf)
	}
	sc.buf.Reset()
	return sc
}

func keepScratch(bufCap, stmtCap int) bool {
	return bufCap <= maxPooledJSONBuf && stmtCap <= maxPooledStmtTypes
}

func putScratch(sc *exportScratch) {
	sc.parse = ParseResult{}
	sc.valid = ValidationResult{}
	sc.format = FormatResult{}
	sc.stmtTypes = sc.stmtTypes[:0]
	if keepScratch(sc.buf.Cap(), cap(sc.stmtTypes)) {
		scratchPool.Put(sc)
	}
}

func (sc *exportScratch) encode(v any) *C.char {
	if err := sc.enc.Encode(v); err != nil {
		return fallbackJSON(err)
	}
	b := sc.buf.Bytes()
	// Encode appends a newline; replace it with the C string terminator.
	b[len(b)-1] = 0
	// The copy completes before the caller's deferred putScratch runs.
	return (*C.char)(C.CBytes(b))
}

func fallbackJSON(err error) *C.char {
	errMsg, marshalErr := json.Marshal("json marshal failed: " + err.Error())
	if marshalErr != nil {
		return C.CString(`{"error":"json marshal failed"}`)
	}
	return C.CString(`{"error":` + string(errMsg) + `}`)
}
