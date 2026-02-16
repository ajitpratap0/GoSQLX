//go:build js && wasm

package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/whitespace"
)

func parse(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return jsonError("no SQL provided")
	}
	sql := args[0].String()
	astObj, err := gosqlx.Parse(sql)
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
	result, err := formatter.FormatString(sql)
	if err != nil {
		return jsonError(err.Error())
	}
	return result
}

func lint(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return jsonError("no SQL provided")
	}
	sql := args[0].String()

	l := linter.New(
		whitespace.NewTrailingWhitespaceRule(),
		whitespace.NewMixedIndentationRule(),
		keywords.NewKeywordCaseRule(keywords.CaseUpper),
	)
	result := l.LintString(sql, "<playground>")

	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return jsonError(err.Error())
	}
	return string(b)
}

func validate(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return jsonError("no SQL provided")
	}
	sql := args[0].String()
	err := gosqlx.Validate(sql)
	if err != nil {
		return jsonResult(map[string]any{"valid": false, "error": err.Error()})
	}
	return jsonResult(map[string]any{"valid": true})
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

	// Keep the Go program running
	select {}
}
