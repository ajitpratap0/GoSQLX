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

package highlight

import "fmt"

// Category is the syntactic class assigned to a highlighted span of SQL.
//
// Category values and their String names are part of the public contract:
// the names are used as JSON values, HTML class suffixes and theme keys, and
// will not change. New categories may be appended in future releases.
type Category uint8

const (
	// Plain is unclassified text. Spans never carry Plain; it is the implicit
	// category of whitespace and any gap between spans.
	Plain Category = iota
	// Keyword is a SQL keyword such as SELECT, FROM, RETURNING or LATERAL.
	Keyword
	// Function is a function name in call position, such as COUNT or now.
	Function
	// DataType is a type name in type position, such as VARCHAR in a column
	// definition or INT in x::int.
	DataType
	// Identifier is an unquoted table, column, alias or schema name.
	Identifier
	// QuotedIdentifier is a delimited identifier: "name", `name` or [name].
	QuotedIdentifier
	// String is a string literal, including prefixed (N'', E'', X'') and
	// dollar-quoted forms.
	String
	// Number is a numeric literal.
	Number
	// Constant is a literal keyword value: TRUE, FALSE or NULL.
	Constant
	// Operator is an operator such as =, <>, ||, ->> or ::.
	Operator
	// Punctuation is a structural character: comma, period, semicolon,
	// parenthesis, bracket or brace.
	Punctuation
	// Comment is a line (--) or block (/* */) comment.
	Comment
	// Placeholder is a bind parameter or variable: $1, ?, :name, @var, @@var.
	Placeholder
	// Error marks input the tokenizer rejected, such as an unterminated
	// string or comment. It always extends to the end of the input.
	Error

	numCategories
)

var categoryNames = [numCategories]string{
	Plain:            "plain",
	Keyword:          "keyword",
	Function:         "function",
	DataType:         "type",
	Identifier:       "identifier",
	QuotedIdentifier: "quoted-identifier",
	String:           "string",
	Number:           "number",
	Constant:         "constant",
	Operator:         "operator",
	Punctuation:      "punctuation",
	Comment:          "comment",
	Placeholder:      "placeholder",
	Error:            "error",
}

// String returns the stable lowercase name of the category, for example
// "keyword" or "quoted-identifier".
func (c Category) String() string {
	if c < numCategories {
		return categoryNames[c]
	}
	return fmt.Sprintf("category(%d)", uint8(c))
}

// MarshalText encodes the category as its stable name, so spans serialize
// to JSON as {"category":"keyword"}.
func (c Category) MarshalText() ([]byte, error) {
	if c >= numCategories {
		return nil, fmt.Errorf("highlight: invalid category %d", uint8(c))
	}
	return []byte(categoryNames[c]), nil
}

// UnmarshalText decodes a category from its stable name.
func (c *Category) UnmarshalText(text []byte) error {
	cat, ok := ParseCategory(string(text))
	if !ok {
		return fmt.Errorf("highlight: unknown category %q", text)
	}
	*c = cat
	return nil
}

// ParseCategory returns the category with the given stable name.
func ParseCategory(name string) (Category, bool) {
	for i, n := range categoryNames {
		if n == name {
			return Category(i), true
		}
	}
	return Plain, false
}

// Categories returns every category that can appear on a Span, in
// declaration order. Plain is excluded. The result is a fresh slice.
func Categories() []Category {
	out := make([]Category, 0, numCategories-1)
	for c := Keyword; c < numCategories; c++ {
		out = append(out, c)
	}
	return out
}
