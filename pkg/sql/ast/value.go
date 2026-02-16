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

import (
	"fmt"
	"strings"
)

// Value represents primitive SQL values such as number and string
type Value struct {
	Type  ValueType
	Value interface{}
}

// ValueType represents the type of a SQL value
type ValueType int

const (
	NumberValue ValueType = iota
	SingleQuotedStringValue
	DollarQuotedStringValue
	TripleSingleQuotedStringValue
	TripleDoubleQuotedStringValue
	EscapedStringLiteralValue
	UnicodeStringLiteralValue
	SingleQuotedByteStringLiteralValue
	DoubleQuotedByteStringLiteralValue
	TripleSingleQuotedByteStringLiteralValue
	TripleDoubleQuotedByteStringLiteralValue
	SingleQuotedRawStringLiteralValue
	DoubleQuotedRawStringLiteralValue
	TripleSingleQuotedRawStringLiteralValue
	TripleDoubleQuotedRawStringLiteralValue
	NationalStringLiteralValue
	HexStringLiteralValue
	DoubleQuotedStringValue
	BooleanValue
	NullValue
	PlaceholderValue
)

// DollarQuotedString represents a dollar-quoted string with an optional tag
type DollarQuotedString struct {
	Value string
	Tag   string
}

func (v Value) String() string {
	switch v.Type {
	case NumberValue:
		if n, ok := v.Value.(Number); ok {
			if n.Long {
				return fmt.Sprintf("%sL", n.Value)
			}
			return n.Value
		}
		return fmt.Sprintf("%v", v.Value)
	case SingleQuotedStringValue:
		if s, ok := v.Value.(string); ok {
			return fmt.Sprintf("'%s'", escapeSingleQuoteString(s))
		}
		return fmt.Sprintf("'%v'", v.Value)
	case DollarQuotedStringValue:
		if dq, ok := v.Value.(DollarQuotedString); ok {
			if dq.Tag != "" {
				return fmt.Sprintf("$%s$%s$%s$", dq.Tag, dq.Value, dq.Tag)
			}
			return fmt.Sprintf("$$%s$$", dq.Value)
		}
		return fmt.Sprintf("$$%v$$", v.Value)
	case TripleSingleQuotedStringValue:
		return fmt.Sprintf("'''%s'''", v.Value)
	case TripleDoubleQuotedStringValue:
		return fmt.Sprintf(`"""%s"""`, v.Value)
	case EscapedStringLiteralValue:
		if s, ok := v.Value.(string); ok {
			return fmt.Sprintf("E'%s'", escapeEscapedString(s))
		}
		return fmt.Sprintf("E'%v'", v.Value)
	case UnicodeStringLiteralValue:
		if s, ok := v.Value.(string); ok {
			return fmt.Sprintf("U&'%s'", escapeUnicodeString(s))
		}
		return fmt.Sprintf("U&'%v'", v.Value)
	case SingleQuotedByteStringLiteralValue:
		return fmt.Sprintf("B'%s'", v.Value)
	case DoubleQuotedByteStringLiteralValue:
		return fmt.Sprintf(`B"%s"`, v.Value)
	case TripleSingleQuotedByteStringLiteralValue:
		return fmt.Sprintf("B'''%s'''", v.Value)
	case TripleDoubleQuotedByteStringLiteralValue:
		return fmt.Sprintf(`B"""%s"""`, v.Value)
	case SingleQuotedRawStringLiteralValue:
		return fmt.Sprintf("R'%s'", v.Value)
	case DoubleQuotedRawStringLiteralValue:
		return fmt.Sprintf(`R"%s"`, v.Value)
	case TripleSingleQuotedRawStringLiteralValue:
		return fmt.Sprintf("R'''%s'''", v.Value)
	case TripleDoubleQuotedRawStringLiteralValue:
		return fmt.Sprintf(`R"""%s"""`, v.Value)
	case NationalStringLiteralValue:
		return fmt.Sprintf("N'%s'", v.Value)
	case HexStringLiteralValue:
		return fmt.Sprintf("X'%s'", v.Value)
	case DoubleQuotedStringValue:
		if s, ok := v.Value.(string); ok {
			return fmt.Sprintf(`"%s"`, escapeDoubleQuoteString(s))
		}
		return fmt.Sprintf(`"%v"`, v.Value)
	case BooleanValue:
		return fmt.Sprintf("%v", v.Value)
	case NullValue:
		return "NULL"
	case PlaceholderValue:
		if s, ok := v.Value.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v.Value)
	default:
		return fmt.Sprintf("%v", v.Value)
	}
}

// Number represents a numeric value with a flag indicating if it's a long
type Number struct {
	Value string
	Long  bool
}

func (v Value) Children() []Node {
	return nil
}

func (v Value) TokenLiteral() string {
	return v.String()
}

func escapeSingleQuoteString(s string) string {
	return escapeQuotedString(s, '\'')
}

func escapeDoubleQuoteString(s string) string {
	return escapeQuotedString(s, '"')
}

func escapeQuotedString(s string, quote rune) string {
	var result strings.Builder
	prevChar := rune(0)
	chars := []rune(s)
	for i := 0; i < len(chars); i++ {
		ch := chars[i]
		if ch == quote {
			if prevChar == '\\' {
				result.WriteRune(ch)
				continue
			}
			result.WriteRune(ch)
			result.WriteRune(ch)
		} else {
			result.WriteRune(ch)
		}
		prevChar = ch
	}
	return result.String()
}

func escapeEscapedString(s string) string {
	var result strings.Builder
	for _, ch := range s {
		switch ch {
		case '\'':
			result.WriteString(`\'`)
		case '\\':
			result.WriteString(`\\`)
		case '\n':
			result.WriteString(`\n`)
		case '\t':
			result.WriteString(`\t`)
		case '\r':
			result.WriteString(`\r`)
		default:
			result.WriteRune(ch)
		}
	}
	return result.String()
}

func escapeUnicodeString(s string) string {
	var result strings.Builder
	for _, ch := range s {
		switch ch {
		case '\'':
			result.WriteString("''")
		case '\\':
			result.WriteString(`\\`)
		default:
			if ch <= 127 { // ASCII
				result.WriteRune(ch)
			} else {
				codepoint := int(ch)
				if codepoint <= 0xFFFF {
					result.WriteString(fmt.Sprintf("\\%04X", codepoint))
				} else {
					result.WriteString(fmt.Sprintf("\\+%06X", codepoint))
				}
			}
		}
	}
	return result.String()
}

// DateTimeField represents date/time fields that can be extracted or used in operations
type DateTimeField int

const (
	Year DateTimeField = iota
	Years
	Month
	Months
	Week
	Weeks
	Day
	DayOfWeek
	DayOfYear
	Days
	Date
	Datetime
	Hour
	Hours
	Minute
	Minutes
	Second
	Seconds
	Century
	Decade
	Dow
	Doy
	Epoch
	Isodow
	IsoWeek
	Isoyear
	Julian
	Microsecond
	Microseconds
	Millenium //nolint:misspell // intentional: SQL accepts both spellings
	Millennium
	Millisecond
	Milliseconds
	Nanosecond
	Nanoseconds
	Quarter
	Time
	Timezone
	TimezoneAbbr
	TimezoneHour
	TimezoneMinute
	TimezoneRegion
	NoDateTime
	CustomDateTime
)

func (d DateTimeField) String() string {
	switch d {
	case Year:
		return "YEAR"
	case Years:
		return "YEARS"
	case Month:
		return "MONTH"
	case Months:
		return "MONTHS"
	case Week:
		return "WEEK"
	case Weeks:
		return "WEEKS"
	case Day:
		return "DAY"
	case DayOfWeek:
		return "DAYOFWEEK"
	case DayOfYear:
		return "DAYOFYEAR"
	case Days:
		return "DAYS"
	case Date:
		return "DATE"
	case Datetime:
		return "DATETIME"
	case Hour:
		return "HOUR"
	case Hours:
		return "HOURS"
	case Minute:
		return "MINUTE"
	case Minutes:
		return "MINUTES"
	case Second:
		return "SECOND"
	case Seconds:
		return "SECONDS"
	case Century:
		return "CENTURY"
	case Decade:
		return "DECADE"
	case Dow:
		return "DOW"
	case Doy:
		return "DOY"
	case Epoch:
		return "EPOCH"
	case Isodow:
		return "ISODOW"
	case IsoWeek:
		return "ISOWEEK"
	case Isoyear:
		return "ISOYEAR"
	case Julian:
		return "JULIAN"
	case Microsecond:
		return "MICROSECOND"
	case Microseconds:
		return "MICROSECONDS"
	case Millenium: //nolint:misspell // intentional: SQL accepts both spellings
		return "MILLENIUM" //nolint:misspell // intentional: matches SQL keyword
	case Millennium:
		return "MILLENNIUM"
	case Millisecond:
		return "MILLISECOND"
	case Milliseconds:
		return "MILLISECONDS"
	case Nanosecond:
		return "NANOSECOND"
	case Nanoseconds:
		return "NANOSECONDS"
	case Quarter:
		return "QUARTER"
	case Time:
		return "TIME"
	case Timezone:
		return "TIMEZONE"
	case TimezoneAbbr:
		return "TIMEZONE_ABBR"
	case TimezoneHour:
		return "TIMEZONE_HOUR"
	case TimezoneMinute:
		return "TIMEZONE_MINUTE"
	case TimezoneRegion:
		return "TIMEZONE_REGION"
	case NoDateTime:
		return "NODATETIME"
	default:
		return "UNKNOWN"
	}
}

// NormalizationForm represents Unicode normalization forms
type NormalizationForm int

const (
	NFC NormalizationForm = iota
	NFD
	NFKC
	NFKD
)

func (n NormalizationForm) String() string {
	switch n {
	case NFC:
		return "NFC"
	case NFD:
		return "NFD"
	case NFKC:
		return "NFKC"
	case NFKD:
		return "NFKD"
	default:
		return "UNKNOWN"
	}
}

// TrimWhereField represents the type of trimming operation
type TrimWhereField int

const (
	Both TrimWhereField = iota
	Leading
	Trailing
)

func (t TrimWhereField) String() string {
	switch t {
	case Both:
		return "BOTH"
	case Leading:
		return "LEADING"
	case Trailing:
		return "TRAILING"
	default:
		return "UNKNOWN"
	}
}
