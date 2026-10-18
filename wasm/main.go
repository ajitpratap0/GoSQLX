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

//go:build js && wasm

package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/wasm/internal/bridge"
)

// dialectArg extracts the optional playground dialect string from the second
// JS argument. Returns "" when absent.
func dialectArg(args []js.Value) string {
	if len(args) > 1 && args[1].Type() == js.TypeString {
		return args[1].String()
	}
	return ""
}

func parse(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return jsonError("no SQL provided")
	}
	astObj, err := bridge.Parse(args[0].String(), dialectArg(args))
	if err != nil {
		return jsonError(err.Error())
	}
	b, err := json.MarshalIndent(astObj, "", "  ")
	if err != nil {
		return jsonError(err.Error())
	}
	return string(b)
}

func format(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return jsonError("no SQL provided")
	}
	sql := args[0].String()
	// dialect is accepted but formatter currently uses generic formatting

	result, err := formatter.FormatString(sql)
	if err != nil {
		return jsonError(err.Error())
	}
	return result
}

// lint runs the full built-in rule set (L001-L030, the same rules as
// gosqlx.Lint) and reports a parse error when the SQL does not parse.
func lint(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return jsonError("no SQL provided")
	}
	return jsonResult(bridge.Lint(args[0].String(), dialectArg(args)))
}

func validate(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return jsonError("no SQL provided")
	}
	sql := args[0].String()
	// dialect is accepted for API consistency

	err := gosqlx.Validate(sql)
	if err != nil {
		return jsonResult(map[string]any{"valid": false, "error": err.Error()})
	}
	return jsonResult(map[string]any{"valid": true})
}

// analyze runs the security scanner and the optimization advisor. SQL that
// fails to parse yields only a parse_error and is never scored.
func analyze(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return jsonError("no SQL provided")
	}
	return jsonResult(bridge.Analyze(args[0].String(), dialectArg(args)))
}

func jsonError(msg string) string {
	b, _ := json.Marshal(map[string]any{"error": msg})
	return string(b)
}

func jsonResult(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func main() {
	js.Global().Set("gosqlxParse", js.FuncOf(parse))
	js.Global().Set("gosqlxFormat", js.FuncOf(format))
	js.Global().Set("gosqlxLint", js.FuncOf(lint))
	js.Global().Set("gosqlxValidate", js.FuncOf(validate))
	js.Global().Set("gosqlxAnalyze", js.FuncOf(analyze))

	// Keep the Go program running
	select {}
}
