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

// format formats the SQL for the selected dialect, keeping comments and
// optimizer hints. It returns {"result": "..."} or {"error": "...",
// "error_span": {...}} (bridge.TextResponse).
func format(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return jsonError("no SQL provided")
	}
	return jsonResult(bridge.Format(args[0].String(), dialectArg(args)))
}

// transpile rewrites the SQL from the dialect in the second argument to the
// one in the third. It returns the same envelope as format.
func transpile(_ js.Value, args []js.Value) any {
	if len(args) < 3 {
		return jsonError("transpile needs SQL, a source dialect and a target dialect")
	}
	for _, a := range args[:3] {
		if a.Type() != js.TypeString {
			return jsonError("transpile arguments must be strings")
		}
	}
	return jsonResult(bridge.Transpile(args[0].String(), args[1].String(), args[2].String()))
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

// highlight classifies the SQL for syntax highlighting. It returns
// {"spans":[{"start":0,"end":6,"category":"keyword"}, ...]} where start and
// end are 0-based, end-exclusive offsets in UTF-16 code units (JavaScript
// string indices), not bytes. Invalid SQL is still highlighted; the text from
// the first lexical error on is one "error" span.
func highlight(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return jsonError("no SQL provided")
	}
	// Compact JSON: this runs on every edit and a span is five lines indented.
	b, err := json.Marshal(bridge.Highlight(args[0].String(), dialectArg(args)))
	if err != nil {
		return jsonError(err.Error())
	}
	return string(b)
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
	js.Global().Set("gosqlxHighlight", js.FuncOf(highlight))
	js.Global().Set("gosqlxTranspile", js.FuncOf(transpile))

	// Keep the Go program running
	select {}
}
