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

// Package token defines the Token struct and object pool for SQL lexical analysis.
//
// A Token is the fundamental unit produced by the GoSQLX tokenizer: it pairs a
// models.TokenType integer constant (e.g., models.TokenTypeSelect, models.TokenTypeIdent)
// with the raw literal string from the source SQL. The integer-based TokenType taxonomy
// covers all SQL token categories — DML keywords (SELECT, INSERT, UPDATE, DELETE),
// DDL keywords (CREATE, ALTER, DROP), punctuation, operators, literals, and identifiers.
// The legacy string-based token.Type was removed in #215; all code should use models.TokenType.
//
// The package also provides an object pool (Get / Put) for zero-allocation token reuse in
// hot paths such as batch parsing or high-throughput server workloads. Every token obtained
// with Get must be returned with a deferred Put to avoid memory leaks.
//
// # Token Structure
//
//	type Token struct {
//	    Type    models.TokenType // Integer token type constant (primary, O(1) comparison)
//	    Literal string           // Raw literal value from the SQL source
//	}
//
// # Basic Usage
//
//	import (
//	    "github.com/ajitpratap0/GoSQLX/pkg/sql/token"
//	    "github.com/ajitpratap0/GoSQLX/pkg/models"
//	)
//
//	tok := token.Token{Type: models.TokenTypeSelect, Literal: "SELECT"}
//
//	if tok.IsType(models.TokenTypeSelect) {
//	    fmt.Println("This is a SELECT token")
//	}
//
//	if tok.IsAnyType(models.TokenTypeSelect, models.TokenTypeInsert) {
//	    fmt.Println("This is a DML statement")
//	}
//
// # Token Pool
//
// The package provides an object pool for zero-allocation token reuse:
//
//	tok := token.Get()
//	defer token.Put(tok)  // MANDATORY — return to pool when done
//
//	tok.Type = models.TokenTypeSelect
//	tok.Literal = "SELECT"
//
// # See Also
//
//   - pkg/models: Core TokenType constants and the TokenTypeUnknown sentinel
//   - pkg/sql/keywords: Keyword-to-TokenType mapping for all SQL dialects
//   - pkg/sql/tokenizer: SQL lexical analysis that produces Token values
//   - pkg/sql/parser: Recursive descent parser that consumes Token values
package token
