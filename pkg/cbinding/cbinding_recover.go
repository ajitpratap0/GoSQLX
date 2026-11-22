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

import "sync/atomic"

const (
	panicErrorJSON      = `{"error":"internal error"}`
	panicSuccessJSON    = `{"success":false,"error":"internal error"}`
	panicValidationJSON = `{"valid":false,"error":"internal error"}`
)

// exportPanicHook injects a panic at a selected ABI boundary for regression tests.
// Atomic access also keeps concurrent calls safe while the hook is installed.
var exportPanicHook atomic.Pointer[string]

func checkExportPanic(name string) {
	if target := exportPanicHook.Load(); target != nil && *target == name {
		panic("injected C binding panic")
	}
}

// recoverExport is deferred directly by every C export. Static error messages
// avoid exposing panic values, which can contain internal paths or SQL input.
// Version has no JSON error channel and returns NULL; free has no return value.
func recoverExport(result **C.char, failure string) {
	if recover() != nil && result != nil {
		if failure == "" {
			*result = nil
		} else {
			*result = C.CString(failure)
		}
	}
}
