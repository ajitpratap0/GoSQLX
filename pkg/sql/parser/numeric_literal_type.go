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

package parser

import "strings"

// numericLiteralType returns the ast.LiteralValue Type of a number token:
// "float" when it has a decimal point or an exponent, otherwise "int". A hex
// literal (0x1E) is always "int": its E is a digit, not an exponent.
func numericLiteralType(value string) string {
	if len(value) > 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X') {
		return "int"
	}
	if strings.ContainsAny(value, ".eE") {
		return "float"
	}
	return "int"
}
