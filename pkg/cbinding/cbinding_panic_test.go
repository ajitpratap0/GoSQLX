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

import "testing"

func TestExportsRecoverPanics(t *testing.T) {
	sql, dialect := strPtr("SELECT 1"), strPtr("postgresql")
	type panicCase struct {
		name string
		call func() string
		flag string
	}
	var cases []panicCase
	for _, e := range allExports {
		flag := ""
		if e == exportValidate {
			flag = "valid"
		} else if e == exportParse || e == exportFormat {
			flag = "success"
		}
		cases = append(cases,
			panicCase{"gosqlx_" + e.String(), func() string { return callLegacyRaw(e, sql) }, flag},
			panicCase{"gosqlx_" + e.String() + "_dialect", func() string { return callDialectRaw(e, sql, dialect) }, flag})
	}
	cases = append(cases,
		panicCase{"gosqlx_lint", func() string { return lintRaw(*sql, nil) }, "success"},
		panicCase{"gosqlx_security_scan", func() string { return securityScanRaw(sql) }, "success"},
		panicCase{"gosqlx_transpile", func() string { return transpileRaw(sql, dialect, dialect) }, "success"},
		panicCase{"gosqlx_dialects", dialectsRaw, ""})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exportPanicHook.Store(&tc.name)
			defer exportPanicHook.Store(nil)
			result := decodeMap(t, tc.call())
			if got := errorOf(result); got != "internal error" {
				t.Errorf("error = %q, want sanitized internal error", got)
			}
			if tc.flag != "" && result[tc.flag] != false {
				t.Errorf("%s = %v, want false", tc.flag, result[tc.flag])
			}
		})
	}
	t.Run("gosqlx_version", func(t *testing.T) {
		name := "gosqlx_version"
		exportPanicHook.Store(&name)
		defer exportPanicHook.Store(nil)
		if !versionIsNull() {
			t.Fatal("version panic must return NULL")
		}
	})
	t.Run("gosqlx_free", func(t *testing.T) {
		name := "gosqlx_free"
		exportPanicHook.Store(&name)
		defer exportPanicHook.Store(nil)
		freeNil()
	})
}

func TestExportRecoveryDoesNotAllocate(t *testing.T) {
	if got := testing.AllocsPerRun(100, freeNil); got != 0 {
		t.Fatalf("normal free boundary allocates: %v", got)
	}
}
