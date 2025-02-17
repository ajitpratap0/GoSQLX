// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package ast

import (
	"testing"
)

func TestValueString(t *testing.T) {
	tests := []struct {
		name     string
		value    Value
		expected string
	}{
		{
			name: "Number without L",
			value: Value{
				Type:  NumberValue,
				Value: Number{Value: "123", Long: false},
			},
			expected: "123",
		},
		{
			name: "Number with L",
			value: Value{
				Type:  NumberValue,
				Value: Number{Value: "123", Long: true},
			},
			expected: "123L",
		},
		{
			name: "SingleQuotedString",
			value: Value{
				Type:  SingleQuotedStringValue,
				Value: "hello",
			},
			expected: "'hello'",
		},
		{
			name: "SingleQuotedString with quotes",
			value: Value{
				Type:  SingleQuotedStringValue,
				Value: "O'Reilly",
			},
			expected: "'O''Reilly'",
		},
		{
			name: "DollarQuotedString without tag",
			value: Value{
				Type: DollarQuotedStringValue,
				Value: DollarQuotedString{
					Value: "hello",
					Tag:   "",
				},
			},
			expected: "$$hello$$",
		},
		{
			name: "DollarQuotedString with tag",
			value: Value{
				Type: DollarQuotedStringValue,
				Value: DollarQuotedString{
					Value: "hello",
					Tag:   "tag",
				},
			},
			expected: "$tag$hello$tag$",
		},
		{
			name: "TripleSingleQuotedString",
			value: Value{
				Type:  TripleSingleQuotedStringValue,
				Value: "hello",
			},
			expected: "'''hello'''",
		},
		{
			name: "TripleDoubleQuotedString",
			value: Value{
				Type:  TripleDoubleQuotedStringValue,
				Value: "hello",
			},
			expected: `"""hello"""`,
		},
		{
			name: "EscapedStringLiteral",
			value: Value{
				Type:  EscapedStringLiteralValue,
				Value: "hello\nworld",
			},
			expected: "E'hello\\nworld'",
		},
		{
			name: "UnicodeStringLiteral ASCII",
			value: Value{
				Type:  UnicodeStringLiteralValue,
				Value: "hello",
			},
			expected: "U&'hello'",
		},
		{
			name: "UnicodeStringLiteral with Unicode",
			value: Value{
				Type:  UnicodeStringLiteralValue,
				Value: "hello世界",
			},
			expected: "U&'hello\\4E16\\754C'",
		},
		{
			name: "Boolean true",
			value: Value{
				Type:  BooleanValue,
				Value: true,
			},
			expected: "true",
		},
		{
			name: "Boolean false",
			value: Value{
				Type:  BooleanValue,
				Value: false,
			},
			expected: "false",
		},
		{
			name: "Null",
			value: Value{
				Type: NullValue,
			},
			expected: "NULL",
		},
		{
			name: "Placeholder",
			value: Value{
				Type:  PlaceholderValue,
				Value: "$1",
			},
			expected: "$1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.value.String()
			if got != tt.expected {
				t.Errorf("Value.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDateTimeFieldString(t *testing.T) {
	tests := []struct {
		field    DateTimeField
		expected string
	}{
		{Year, "YEAR"},
		{Month, "MONTH"},
		{Day, "DAY"},
		{Hour, "HOUR"},
		{Minute, "MINUTE"},
		{Second, "SECOND"},
		{Millisecond, "MILLISECOND"},
		{Microsecond, "MICROSECOND"},
		{Nanosecond, "NANOSECOND"},
		{Quarter, "QUARTER"},
		{Week, "WEEK"},
		{DayOfWeek, "DAYOFWEEK"},
		{DayOfYear, "DAYOFYEAR"},
		{IsoWeek, "ISOWEEK"},
		{Timezone, "TIMEZONE"},
		{NoDateTime, "NODATETIME"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.field.String()
			if got != tt.expected {
				t.Errorf("DateTimeField.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestNormalizationFormString(t *testing.T) {
	tests := []struct {
		form     NormalizationForm
		expected string
	}{
		{NFC, "NFC"},
		{NFD, "NFD"},
		{NFKC, "NFKC"},
		{NFKD, "NFKD"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.form.String()
			if got != tt.expected {
				t.Errorf("NormalizationForm.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTrimWhereFieldString(t *testing.T) {
	tests := []struct {
		field    TrimWhereField
		expected string
	}{
		{Both, "BOTH"},
		{Leading, "LEADING"},
		{Trailing, "TRAILING"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := tt.field.String()
			if got != tt.expected {
				t.Errorf("TrimWhereField.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEscapeUnicodeString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "hello"},
		{"hello'world", "hello''world"},
		{"hello\\world", "hello\\\\world"},
		{"hello世界", "hello\\4E16\\754C"},
		{"hello\U0001F600", "hello\\+01F600"}, // Emoji (requires >16 bits)
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := escapeUnicodeString(tt.input)
			if got != tt.expected {
				t.Errorf("escapeUnicodeString() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEscapeEscapedString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hello", "hello"},
		{"hello'world", "hello\\'world"},
		{"hello\\world", "hello\\\\world"},
		{"hello\nworld", "hello\\nworld"},
		{"hello\tworld", "hello\\tworld"},
		{"hello\rworld", "hello\\rworld"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := escapeEscapedString(tt.input)
			if got != tt.expected {
				t.Errorf("escapeEscapedString() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEscapeQuotedString(t *testing.T) {
	tests := []struct {
		input    string
		quote    rune
		expected string
	}{
		{"hello", '\'', "hello"},
		{"O'Reilly", '\'', "O''Reilly"},
		{`"quoted"`, '"', `""quoted""`},
		{"mixed'\"quotes", '\'', "mixed''\"quotes"},
		{"mixed'\"quotes", '"', "mixed'\"\"quotes"},
		{`escaped\'quote`, '\'', `escaped\'quote`},
		{`escaped\"quote`, '"', `escaped\"quote`},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := escapeQuotedString(tt.input, tt.quote)
			if got != tt.expected {
				t.Errorf("escapeQuotedString() with quote %c = %v, want %v", tt.quote, got, tt.expected)
			}
		})
	}
}
