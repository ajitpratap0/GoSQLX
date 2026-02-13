// Copyright 2024 GoSQLX Contributors
//
// Licensed under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License. You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. See the License for the
// specific language governing permissions and limitations
// under the License.

package ast

import "fmt"

// FunctionDesc represents a function descriptor used in SQL statements
type FunctionDesc struct {
	Name      ObjectName
	Schema    string // Optional schema qualifier
	Arguments []string
}

func (f FunctionDesc) String() string {
	if len(f.Arguments) == 0 {
		if f.Schema != "" {
			return fmt.Sprintf("%s.%s", f.Schema, f.Name)
		}
		return f.Name.String()
	}

	if f.Schema != "" {
		return fmt.Sprintf("%s.%s(%s)", f.Schema, f.Name, f.Arguments)
	}
	return fmt.Sprintf("%s(%s)", f.Name, f.Arguments)
}

// Implement Node interface
func (f FunctionDesc) Children() []Node     { return nil }
func (f FunctionDesc) TokenLiteral() string { return f.String() }
