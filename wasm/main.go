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

	"github.com/ajitpratap0/GoSQLX/pkg/advisor"
	"github.com/ajitpratap0/GoSQLX/pkg/formatter"
	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/linter"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/keywords"
	"github.com/ajitpratap0/GoSQLX/pkg/linter/rules/whitespace"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/security"

	sqlkeywords "github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// dialectMap maps JS-friendly dialect strings to keywords.SQLDialect constants.
var dialectMap = map[string]sqlkeywords.SQLDialect{
	"generic":    sqlkeywords.DialectGeneric,
	"postgresql": sqlkeywords.DialectPostgreSQL,
	"mysql":      sqlkeywords.DialectMySQL,
	"mariadb":    sqlkeywords.DialectMariaDB,
	"sqlite":     sqlkeywords.DialectSQLite,
	"sqlserver":  sqlkeywords.DialectSQLServer,
	"oracle":     sqlkeywords.DialectOracle,
	"snowflake":  sqlkeywords.DialectSnowflake,
}

// getDialect extracts an optional dialect from the second JS argument.
// Returns empty string if not provided or unrecognized.
func getDialect(args []js.Value) sqlkeywords.SQLDialect {
	if len(args) > 1 && args[1].Type() == js.TypeString {
		d := args[1].String()
		if mapped, ok := dialectMap[d]; ok {
			return mapped
		}
	}
	return ""
}

func parse(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return jsonError("no SQL provided")
	}
	sql := args[0].String()
	dialect := getDialect(args)

	var (
		astObj any
		err    error
	)
	if dialect != "" {
		astObj, err = gosqlx.ParseWithDialect(sql, dialect)
	} else {
		astObj, err = gosqlx.Parse(sql)
	}
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
	_ = getDialect(args)

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
	// dialect is accepted for API consistency
	_ = getDialect(args)

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
	// dialect is accepted for API consistency
	_ = getDialect(args)

	err := gosqlx.Validate(sql)
	if err != nil {
		return jsonResult(map[string]any{"valid": false, "error": err.Error()})
	}
	return jsonResult(map[string]any{"valid": true})
}

func analyze(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return jsonError("no SQL provided")
	}
	sql := args[0].String()
	// dialect is accepted for API consistency
	_ = getDialect(args)

	// Run security scan
	scanner := security.NewScanner()
	securityResult := scanner.ScanSQL(sql)

	// Run optimization analysis
	opt := advisor.New()
	optResult, err := opt.AnalyzeSQL(sql)
	if err != nil {
		// If parsing fails, still return security results with an optimization error
		combined := map[string]any{
			"security":     securityResult,
			"optimization": map[string]any{"error": err.Error()},
		}
		return jsonResult(combined)
	}

	combined := map[string]any{
		"security":     securityResult,
		"optimization": optResult,
	}
	return jsonResult(combined)
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
