package ast

import "testing"

// Test EnumMember node
func TestEnumMember(t *testing.T) {
	tests := []struct {
		name       string
		enumMember *EnumMember
		wantString string
	}{
		{
			name:       "simple enum member",
			enumMember: &EnumMember{Name: "active"},
			wantString: "'active'",
		},
		{
			name:       "enum member with value",
			enumMember: &EnumMember{Name: "pending", Value: &LiteralValue{Value: "1"}},
			wantString: "'pending' = 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test String method
			if got := tt.enumMember.String(); got != tt.wantString {
				t.Errorf("EnumMember.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

// Test CharacterLength node
func TestCharacterLength(t *testing.T) {
	tests := []struct {
		name       string
		charLen    *CharacterLength
		wantString string
	}{
		{
			name:       "simple length",
			charLen:    &CharacterLength{Length: 255},
			wantString: "255",
		},
		{
			name: "length with CHARACTERS unit",
			charLen: &CharacterLength{
				Length: 100,
				Unit:   func() *CharLengthUnits { u := Characters; return &u }(),
			},
			wantString: "100 CHARACTERS",
		},
		{
			name: "length with OCTETS unit",
			charLen: &CharacterLength{
				Length: 1024,
				Unit:   func() *CharLengthUnits { u := Octets; return &u }(),
			},
			wantString: "1024 OCTETS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test String method
			if got := tt.charLen.String(); got != tt.wantString {
				t.Errorf("CharacterLength.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

// Test CharLengthUnits
func TestCharLengthUnits(t *testing.T) {
	tests := []struct {
		name       string
		unit       CharLengthUnits
		wantString string
	}{
		{
			name:       "CHARACTERS unit",
			unit:       Characters,
			wantString: "CHARACTERS",
		},
		{
			name:       "OCTETS unit",
			unit:       Octets,
			wantString: "OCTETS",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test String method
			if got := tt.unit.String(); got != tt.wantString {
				t.Errorf("CharLengthUnits.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

// Test BinaryLength node
func TestBinaryLength(t *testing.T) {
	tests := []struct {
		name       string
		binLen     *BinaryLength
		wantString string
	}{
		{
			name:       "simple binary length",
			binLen:     &BinaryLength{Length: 1024},
			wantString: "1024",
		},
		{
			name:       "MAX binary length",
			binLen:     &BinaryLength{IsMax: true},
			wantString: "MAX",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test String method
			if got := tt.binLen.String(); got != tt.wantString {
				t.Errorf("BinaryLength.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

// Test TimezoneInfo
func TestTimezoneInfo(t *testing.T) {
	tests := []struct {
		name       string
		tz         TimezoneInfo
		wantString string
	}{
		{
			name:       "NoTimezone",
			tz:         NoTimezone,
			wantString: "",
		},
		{
			name:       "WithTimeZone",
			tz:         WithTimeZone,
			wantString: " WITH TIME ZONE",
		},
		{
			name:       "WithoutTimeZone",
			tz:         WithoutTimeZone,
			wantString: " WITHOUT TIME ZONE",
		},
		{
			name:       "Tz",
			tz:         Tz,
			wantString: "TZ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test String method
			if got := tt.tz.String(); got != tt.wantString {
				t.Errorf("TimezoneInfo.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

// Test ExactNumberInfo
func TestExactNumberInfo(t *testing.T) {
	precision := uint64(10)
	scale := uint64(2)

	tests := []struct {
		name       string
		info       *ExactNumberInfo
		wantString string
	}{
		{
			name:       "no precision or scale",
			info:       &ExactNumberInfo{},
			wantString: "",
		},
		{
			name:       "precision only",
			info:       &ExactNumberInfo{Precision: &precision},
			wantString: "(10)",
		},
		{
			name:       "precision and scale",
			info:       &ExactNumberInfo{Precision: &precision, Scale: &scale},
			wantString: "(10,2)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.info.String(); got != tt.wantString {
				t.Errorf("ExactNumberInfo.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

// Test ArrayElemTypeDef
func TestArrayElemTypeDef(t *testing.T) {
	size := uint64(10)

	tests := []struct {
		name       string
		arrDef     *ArrayElemTypeDef
		wantString string
	}{
		{
			name:       "no type",
			arrDef:     &ArrayElemTypeDef{},
			wantString: "ARRAY",
		},
		{
			name: "angle brackets",
			arrDef: &ArrayElemTypeDef{
				Type: &DataType{
					Type: &IntegerType{},
				},
				Brackets: AngleBrackets,
			},
			wantString: "ARRAY<&{INTEGER}>",
		},
		{
			name: "square brackets without size",
			arrDef: &ArrayElemTypeDef{
				Type: &DataType{
					Type: &VarcharType{},
				},
				Brackets: SquareBrackets,
			},
			wantString: "&{VARCHAR}[]",
		},
		{
			name: "square brackets with size",
			arrDef: &ArrayElemTypeDef{
				Type: &DataType{
					Type: &IntegerType{},
				},
				Size:     &size,
				Brackets: SquareBrackets,
			},
			wantString: "&{INTEGER}[10]",
		},
		{
			name: "parentheses",
			arrDef: &ArrayElemTypeDef{
				Type: &DataType{
					Type: &IntegerType{},
				},
				Brackets: Parentheses,
			},
			wantString: "Array(&{INTEGER})",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.arrDef.String(); got != tt.wantString {
				t.Errorf("ArrayElemTypeDef.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

// Test data type String() methods
func TestCharacterType(t *testing.T) {
	tests := []struct {
		name       string
		charType   *CharacterType
		wantString string
	}{
		{
			name:       "without length",
			charType:   &CharacterType{},
			wantString: "CHARACTER",
		},
		{
			name: "with length",
			charType: &CharacterType{
				Length: &CharacterLength{Length: 50},
			},
			wantString: "CHARACTER(50)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.charType.String(); got != tt.wantString {
				t.Errorf("CharacterType.String() = %v, want %v", got, tt.wantString)
			}
			// Test isDataType marker
			tt.charType.isDataType()
		})
	}
}

func TestVarcharType(t *testing.T) {
	tests := []struct {
		name       string
		varType    *VarcharType
		wantString string
	}{
		{
			name:       "without length",
			varType:    &VarcharType{},
			wantString: "VARCHAR",
		},
		{
			name: "with length",
			varType: &VarcharType{
				Length: &CharacterLength{Length: 255},
			},
			wantString: "VARCHAR(255)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.varType.String(); got != tt.wantString {
				t.Errorf("VarcharType.String() = %v, want %v", got, tt.wantString)
			}
			// Test isDataType marker
			tt.varType.isDataType()
		})
	}
}

func TestNumericType(t *testing.T) {
	precision := uint64(10)
	scale := uint64(2)

	tests := []struct {
		name       string
		numType    *NumericType
		wantString string
	}{
		{
			name:       "without info",
			numType:    &NumericType{},
			wantString: "NUMERIC",
		},
		{
			name: "with precision",
			numType: &NumericType{
				Info: &ExactNumberInfo{Precision: &precision},
			},
			wantString: "NUMERIC(10)",
		},
		{
			name: "with precision and scale",
			numType: &NumericType{
				Info: &ExactNumberInfo{Precision: &precision, Scale: &scale},
			},
			wantString: "NUMERIC(10,2)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.numType.String(); got != tt.wantString {
				t.Errorf("NumericType.String() = %v, want %v", got, tt.wantString)
			}
			// Test isDataType marker
			tt.numType.isDataType()
		})
	}
}

func TestIntegerType(t *testing.T) {
	length := uint64(11)

	tests := []struct {
		name       string
		intType    *IntegerType
		wantString string
	}{
		{
			name:       "simple integer",
			intType:    &IntegerType{},
			wantString: "INTEGER",
		},
		{
			name: "integer with length",
			intType: &IntegerType{
				Length: &length,
			},
			wantString: "INTEGER(11)",
		},
		{
			name: "unsigned integer",
			intType: &IntegerType{
				Unsigned: true,
			},
			wantString: "INTEGER UNSIGNED",
		},
		{
			name: "unsigned integer with length",
			intType: &IntegerType{
				Length:   &length,
				Unsigned: true,
			},
			wantString: "INTEGER(11) UNSIGNED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.intType.String(); got != tt.wantString {
				t.Errorf("IntegerType.String() = %v, want %v", got, tt.wantString)
			}
			// Test isDataType marker
			tt.intType.isDataType()
		})
	}
}

func TestFloatType(t *testing.T) {
	length := uint64(7)

	tests := []struct {
		name       string
		floatType  *FloatType
		wantString string
	}{
		{
			name:       "simple float",
			floatType:  &FloatType{},
			wantString: "FLOAT",
		},
		{
			name: "float with length",
			floatType: &FloatType{
				Length: &length,
			},
			wantString: "FLOAT(7)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.floatType.String(); got != tt.wantString {
				t.Errorf("FloatType.String() = %v, want %v", got, tt.wantString)
			}
			// Test isDataType marker
			tt.floatType.isDataType()
		})
	}
}

func TestBooleanType(t *testing.T) {
	boolType := &BooleanType{}

	if got := boolType.String(); got != "BOOLEAN" {
		t.Errorf("BooleanType.String() = %v, want BOOLEAN", got)
	}

	// Test isDataType marker
	boolType.isDataType()
}

func TestDateType(t *testing.T) {
	dateType := &DateType{}

	if got := dateType.String(); got != "DATE" {
		t.Errorf("DateType.String() = %v, want DATE", got)
	}

	// Test isDataType marker
	dateType.isDataType()
}

func TestTimeType(t *testing.T) {
	precision := uint64(6)

	tests := []struct {
		name       string
		timeType   *TimeType
		wantString string
	}{
		{
			name:       "simple time",
			timeType:   &TimeType{},
			wantString: "TIME",
		},
		{
			name: "time with precision",
			timeType: &TimeType{
				Precision: &precision,
			},
			wantString: "TIME(6)",
		},
		{
			name: "time with timezone",
			timeType: &TimeType{
				Timezone: WithTimeZone,
			},
			wantString: "TIME WITH TIME ZONE",
		},
		{
			name: "time with precision and timezone",
			timeType: &TimeType{
				Precision: &precision,
				Timezone:  WithTimeZone,
			},
			wantString: "TIME(6) WITH TIME ZONE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.timeType.String(); got != tt.wantString {
				t.Errorf("TimeType.String() = %v, want %v", got, tt.wantString)
			}
			// Test isDataType marker
			tt.timeType.isDataType()
		})
	}
}

func TestTimestampType(t *testing.T) {
	precision := uint64(6)

	tests := []struct {
		name       string
		tsType     *TimestampType
		wantString string
	}{
		{
			name:       "simple timestamp",
			tsType:     &TimestampType{},
			wantString: "TIMESTAMP",
		},
		{
			name: "timestamp with precision",
			tsType: &TimestampType{
				Precision: &precision,
			},
			wantString: "TIMESTAMP(6)",
		},
		{
			name: "timestamp without timezone",
			tsType: &TimestampType{
				Timezone: WithoutTimeZone,
			},
			wantString: "TIMESTAMP WITHOUT TIME ZONE",
		},
		{
			name: "timestamp with precision and timezone",
			tsType: &TimestampType{
				Precision: &precision,
				Timezone:  WithTimeZone,
			},
			wantString: "TIMESTAMP(6) WITH TIME ZONE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tsType.String(); got != tt.wantString {
				t.Errorf("TimestampType.String() = %v, want %v", got, tt.wantString)
			}
			// Test isDataType marker
			tt.tsType.isDataType()
		})
	}
}

func TestArrayType(t *testing.T) {
	tests := []struct {
		name       string
		arrType    *ArrayType
		wantString string
	}{
		{
			name:       "array without element type",
			arrType:    &ArrayType{},
			wantString: "ARRAY",
		},
		{
			name: "array with element type",
			arrType: &ArrayType{
				ElementType: &ArrayElemTypeDef{
					Type: &DataType{
						Type: &IntegerType{},
					},
					Brackets: AngleBrackets,
				},
			},
			wantString: "ARRAY<&{INTEGER}>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.arrType.String(); got != tt.wantString {
				t.Errorf("ArrayType.String() = %v, want %v", got, tt.wantString)
			}
			// Test isDataType marker
			tt.arrType.isDataType()
		})
	}
}

func TestEnumType(t *testing.T) {
	bits := uint8(8)

	tests := []struct {
		name       string
		enumType   *EnumType
		wantString string
	}{
		{
			name: "simple enum",
			enumType: &EnumType{
				Values: []EnumMember{
					{Name: "active"},
					{Name: "inactive"},
				},
			},
			wantString: "ENUM('active', 'inactive')",
		},
		{
			name: "enum with bits",
			enumType: &EnumType{
				Values: []EnumMember{
					{Name: "red"},
					{Name: "green"},
				},
				Bits: &bits,
			},
			wantString: "ENUM8('red', 'green')",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.enumType.String(); got != tt.wantString {
				t.Errorf("EnumType.String() = %v, want %v", got, tt.wantString)
			}
			// Test isDataType marker
			tt.enumType.isDataType()
		})
	}
}

func TestSetType(t *testing.T) {
	tests := []struct {
		name       string
		setType    *SetType
		wantString string
	}{
		{
			name: "simple set",
			setType: &SetType{
				Values: []string{"red", "green", "blue"},
			},
			wantString: "SET('red', 'green', 'blue')",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.setType.String(); got != tt.wantString {
				t.Errorf("SetType.String() = %v, want %v", got, tt.wantString)
			}
			// Test isDataType marker
			tt.setType.isDataType()
		})
	}
}

func TestJsonType(t *testing.T) {
	jsonType := &JsonType{}

	if got := jsonType.String(); got != "JSON" {
		t.Errorf("JsonType.String() = %v, want JSON", got)
	}

	// Test isDataType marker
	jsonType.isDataType()
}

func TestBinaryType(t *testing.T) {
	tests := []struct {
		name       string
		binType    *BinaryType
		wantString string
	}{
		{
			name:       "binary without length",
			binType:    &BinaryType{},
			wantString: "BINARY",
		},
		{
			name: "binary with length",
			binType: &BinaryType{
				Length: &BinaryLength{Length: 16},
			},
			wantString: "BINARY(16)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.binType.String(); got != tt.wantString {
				t.Errorf("BinaryType.String() = %v, want %v", got, tt.wantString)
			}
			// Test isDataType marker
			tt.binType.isDataType()
		})
	}
}

func TestCustomType(t *testing.T) {
	tests := []struct {
		name       string
		custType   *CustomType
		wantString string
	}{
		{
			name: "custom type without modifiers",
			custType: &CustomType{
				Name: ObjectName{Name: "my_type"},
			},
			wantString: "my_type",
		},
		{
			name: "custom type with modifiers",
			custType: &CustomType{
				Name:      ObjectName{Name: "geo_point"},
				Modifiers: []string{"srid=4326"},
			},
			wantString: "geo_point(srid=4326)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.custType.String(); got != tt.wantString {
				t.Errorf("CustomType.String() = %v, want %v", got, tt.wantString)
			}
			// Test isDataType marker
			tt.custType.isDataType()
		})
	}
}

func TestTableType(t *testing.T) {
	tests := []struct {
		name       string
		tableType  *TableType
		wantString string
	}{
		{
			name: "table type with columns",
			tableType: &TableType{
				Columns: []*ColumnDef{
					{Name: "id", Type: "INTEGER"},
					{Name: "name", Type: "VARCHAR"},
				},
			},
			wantString: "TABLE(id INTEGER, name VARCHAR)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.tableType.String(); got != tt.wantString {
				t.Errorf("TableType.String() = %v, want %v", got, tt.wantString)
			}
			// Test isDataType marker
			tt.tableType.isDataType()
		})
	}
}
