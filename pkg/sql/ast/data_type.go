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

// EnumMember represents a member of an ENUM type
type EnumMember struct {
	Name  string
	Value Expression
}

func (e *EnumMember) String() string {
	if e.Value != nil {
		return fmt.Sprintf("'%s' = %s", escapeString(e.Name), e.Value.TokenLiteral())
	}
	return fmt.Sprintf("'%s'", escapeString(e.Name))
}

// DataType represents SQL data types
type DataType struct {
	Type DataTypeVariant
}

// DataTypeVariant represents the different variants of SQL data types
type DataTypeVariant interface {
	fmt.Stringer
	isDataType()
}

// CharacterLength represents character length information
type CharacterLength struct {
	Length uint64
	Unit   *CharLengthUnits
}

func (c *CharacterLength) String() string {
	if c.Unit != nil {
		return fmt.Sprintf("%d %s", c.Length, c.Unit)
	}
	return fmt.Sprintf("%d", c.Length)
}

// CharLengthUnits represents possible units for characters
type CharLengthUnits int

const (
	Characters CharLengthUnits = iota
	Octets
)

func (u CharLengthUnits) String() string {
	switch u {
	case Characters:
		return "CHARACTERS"
	case Octets:
		return "OCTETS"
	default:
		return "UNKNOWN"
	}
}

// BinaryLength represents binary length information
type BinaryLength struct {
	Length uint64
	IsMax  bool
}

func (b *BinaryLength) String() string {
	if b.IsMax {
		return "MAX"
	}
	return fmt.Sprintf("%d", b.Length)
}

// TimezoneInfo represents timezone information for temporal types
type TimezoneInfo int

const (
	NoTimezone TimezoneInfo = iota
	WithTimeZone
	WithoutTimeZone
	Tz
)

func (t TimezoneInfo) String() string {
	switch t {
	case NoTimezone:
		return ""
	case WithTimeZone:
		return " WITH TIME ZONE"
	case WithoutTimeZone:
		return " WITHOUT TIME ZONE"
	case Tz:
		return "TZ"
	default:
		return "UNKNOWN"
	}
}

// ExactNumberInfo represents precision and scale information
type ExactNumberInfo struct {
	Precision *uint64
	Scale     *uint64
}

func (e *ExactNumberInfo) String() string {
	if e.Precision == nil {
		return ""
	}
	if e.Scale == nil {
		return fmt.Sprintf("(%d)", *e.Precision)
	}
	return fmt.Sprintf("(%d,%d)", *e.Precision, *e.Scale)
}

// ArrayElemTypeDef represents array element type definition
type ArrayElemTypeDef struct {
	Type     *DataType
	Size     *uint64
	Brackets ArrayBracketType
}

type ArrayBracketType int

const (
	NoBrackets ArrayBracketType = iota
	AngleBrackets
	SquareBrackets
	Parentheses
)

func (a *ArrayElemTypeDef) String() string {
	if a.Type == nil {
		return "ARRAY"
	}

	switch a.Brackets {
	case AngleBrackets:
		return fmt.Sprintf("ARRAY<%s>", a.Type)
	case SquareBrackets:
		if a.Size != nil {
			return fmt.Sprintf("%s[%d]", a.Type, *a.Size)
		}
		return fmt.Sprintf("%s[]", a.Type)
	case Parentheses:
		return fmt.Sprintf("Array(%s)", a.Type)
	default:
		return "ARRAY"
	}
}

// StructBracketKind represents the type of brackets used in STRUCT type
type StructBracketKind int

const (
	ParenthesesBrackets StructBracketKind = iota
	AngleBracketsBrackets
)

// Helper function to escape strings
func escapeString(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// Basic data types
type (
	TableType struct {
		Columns []*ColumnDef
	}

	CharacterType struct {
		Length *CharacterLength
	}

	VarcharType struct {
		Length *CharacterLength
	}

	NumericType struct {
		Info *ExactNumberInfo
	}

	IntegerType struct {
		Length   *uint64
		Unsigned bool
	}

	FloatType struct {
		Length *uint64
	}

	BooleanType struct{}

	DateType struct{}

	TimeType struct {
		Precision *uint64
		Timezone  TimezoneInfo
	}

	TimestampType struct {
		Precision *uint64
		Timezone  TimezoneInfo
	}

	ArrayType struct {
		ElementType *ArrayElemTypeDef
	}

	EnumType struct {
		Values []EnumMember
		Bits   *uint8
	}

	SetType struct {
		Values []string
	}

	JsonType struct{}

	BinaryType struct {
		Length *BinaryLength
	}

	CustomType struct {
		Name      ObjectName
		Modifiers []string
	}
)

// Implement DataTypeVariant interface
func (*TableType) isDataType()     {}
func (*CharacterType) isDataType() {}
func (*VarcharType) isDataType()   {}
func (*NumericType) isDataType()   {}
func (*IntegerType) isDataType()   {}
func (*FloatType) isDataType()     {}
func (*BooleanType) isDataType()   {}
func (*DateType) isDataType()      {}
func (*TimeType) isDataType()      {}
func (*TimestampType) isDataType() {}
func (*ArrayType) isDataType()     {}
func (*EnumType) isDataType()      {}
func (*SetType) isDataType()       {}
func (*JsonType) isDataType()      {}
func (*BinaryType) isDataType()    {}
func (*CustomType) isDataType()    {}

// String implementations for data types
func (t *TableType) String() string {
	var cols []string
	for _, col := range t.Columns {
		cols = append(cols, col.String())
	}
	return fmt.Sprintf("TABLE(%s)", strings.Join(cols, ", "))
}

func (t *CharacterType) String() string {
	if t.Length == nil {
		return "CHARACTER"
	}
	return fmt.Sprintf("CHARACTER(%s)", t.Length)
}

func (t *VarcharType) String() string {
	if t.Length == nil {
		return "VARCHAR"
	}
	return fmt.Sprintf("VARCHAR(%s)", t.Length)
}

func (t *NumericType) String() string {
	if t.Info == nil {
		return "NUMERIC"
	}
	return fmt.Sprintf("NUMERIC%s", t.Info)
}

func (t *IntegerType) String() string {
	var result string
	if t.Length == nil {
		result = "INTEGER"
	} else {
		result = fmt.Sprintf("INTEGER(%d)", *t.Length)
	}
	if t.Unsigned {
		result += " UNSIGNED"
	}
	return result
}

func (t *FloatType) String() string {
	if t.Length == nil {
		return "FLOAT"
	}
	return fmt.Sprintf("FLOAT(%d)", *t.Length)
}

func (*BooleanType) String() string { return "BOOLEAN" }
func (*DateType) String() string    { return "DATE" }

func (t *TimeType) String() string {
	var result string
	if t.Precision == nil {
		result = "TIME"
	} else {
		result = fmt.Sprintf("TIME(%d)", *t.Precision)
	}
	if t.Timezone != NoTimezone {
		result += t.Timezone.String()
	}
	return result
}

func (t *TimestampType) String() string {
	var result string
	if t.Precision == nil {
		result = "TIMESTAMP"
	} else {
		result = fmt.Sprintf("TIMESTAMP(%d)", *t.Precision)
	}
	if t.Timezone != NoTimezone {
		result += t.Timezone.String()
	}
	return result
}

func (t *ArrayType) String() string {
	if t.ElementType == nil {
		return "ARRAY"
	}
	return t.ElementType.String()
}

func (t *EnumType) String() string {
	var values []string
	for _, v := range t.Values {
		values = append(values, v.String())
	}
	var result string
	if t.Bits != nil {
		result = fmt.Sprintf("ENUM%d", *t.Bits)
	} else {
		result = "ENUM"
	}
	return fmt.Sprintf("%s(%s)", result, strings.Join(values, ", "))
}

func (t *SetType) String() string {
	var values []string
	for _, v := range t.Values {
		values = append(values, fmt.Sprintf("'%s'", escapeString(v)))
	}
	return fmt.Sprintf("SET(%s)", strings.Join(values, ", "))
}

func (*JsonType) String() string { return "JSON" }

func (t *BinaryType) String() string {
	if t.Length == nil {
		return "BINARY"
	}
	return fmt.Sprintf("BINARY(%s)", t.Length)
}

func (t *CustomType) String() string {
	if len(t.Modifiers) == 0 {
		return t.Name.String()
	}
	return fmt.Sprintf("%s(%s)", t.Name, strings.Join(t.Modifiers, ", "))
}
