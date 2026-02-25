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

// Hello World - The simplest GoSQLX example
//
// This example shows the absolute minimum code needed to parse SQL with GoSQLX.
// Perfect for beginners!
//
// Run: go run main.go

package main

import "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"

func main() {
	ast, _ := gosqlx.Parse("SELECT * FROM users")
	println("Parsed successfully!")

	// Let's also print the number of statements
	println("Statements parsed:", len(ast.Statements))
}
