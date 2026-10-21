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

// Package highlight provides dialect-aware SQL syntax highlighting built on
// the GoSQLX tokenizer.
//
// Spans classifies SQL into byte-offset ranges tagged with a Category
// (keyword, function, type, identifier, string, comment, ...). The
// classification is lexical with light context: function names are detected
// in call position, type names in type position (column definitions, x::int,
// CAST(x AS DATE)), and prefixed literals such as N'...' or 0x1F are kept
// whole. Spans never fails; invalid SQL is highlighted up to the first
// lexical error and the remainder is marked Error, which makes it suitable
// for editors where input is incomplete most of the time.
//
// Renderers turn spans into output:
//
//   - ANSI / WriteANSI: terminal escape sequences (256-color, true color, or
//     attributes only).
//   - HTML / WriteHTML: escaped HTML with class="gsx-<category>" spans, or
//     inline styles; CSS generates the matching stylesheet.
//
// Spans also marshal to JSON ({"start":0,"end":6,"category":"keyword"}) for
// browser and editor integrations.
//
// Example:
//
//	sql := "SELECT id, name FROM users WHERE active = TRUE"
//	spans := highlight.Spans(sql, highlight.WithDialect(keywords.DialectPostgreSQL))
//	fmt.Print(highlight.ANSI(sql, spans, highlight.ANSIOptions{}))
//
//	html := highlight.HTML(sql, spans, highlight.HTMLOptions{Wrap: true})
//	css := highlight.CSS(highlight.DarkTheme(), "")
package highlight
