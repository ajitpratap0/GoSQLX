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

package highlight_test

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/highlight"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func ExampleSpans() {
	sql := "SELECT name FROM users WHERE id = $1 -- by id"
	for _, s := range highlight.Spans(sql, highlight.WithDialect(keywords.DialectPostgreSQL)) {
		fmt.Printf("%-11s %s\n", s.Category, s.Text(sql))
	}
	// Output:
	// keyword     SELECT
	// identifier  name
	// keyword     FROM
	// identifier  users
	// keyword     WHERE
	// identifier  id
	// operator    =
	// placeholder $1
	// comment     -- by id
}

func ExampleHTML() {
	sql := "SELECT 'a' AS x"
	fmt.Println(highlight.HTML(sql, highlight.Spans(sql), highlight.HTMLOptions{}))
	// Output:
	// <span class="gsx-keyword">SELECT</span> <span class="gsx-string">&#39;a&#39;</span> <span class="gsx-keyword">AS</span> <span class="gsx-identifier">x</span>
}

func ExampleANSI() {
	sql := "SELECT 1"
	out := highlight.ANSI(sql, highlight.Spans(sql), highlight.ANSIOptions{
		Theme: highlight.MonoTheme(),
		Mode:  highlight.NoColor,
	})
	fmt.Printf("%q\n", out)
	// Output:
	// "\x1b[1mSELECT\x1b[0m 1"
}
