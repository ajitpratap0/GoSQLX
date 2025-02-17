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
	"fmt"
	"strings"
)

// StageParamsObject represents parameters for stage operations in data loading
type StageParamsObject struct {
	URL                *string
	Encryption         DataLoadingOptions
	Endpoint           *string
	StorageIntegration *string
	Credentials        DataLoadingOptions
}

// String implements the Stringer interface for StageParamsObject
func (s *StageParamsObject) String() string {
	var parts []string

	if s.URL != nil {
		parts = append(parts, fmt.Sprintf("URL='%s'", *s.URL))
	}
	if s.StorageIntegration != nil {
		parts = append(parts, fmt.Sprintf("STORAGE_INTEGRATION=%s", *s.StorageIntegration))
	}
	if s.Endpoint != nil {
		parts = append(parts, fmt.Sprintf("ENDPOINT='%s'", *s.Endpoint))
	}
	if len(s.Credentials.Options) > 0 {
		parts = append(parts, fmt.Sprintf("CREDENTIALS=(%s)", s.Credentials.String()))
	}
	if len(s.Encryption.Options) > 0 {
		parts = append(parts, fmt.Sprintf("ENCRYPTION=(%s)", s.Encryption.String()))
	}

	return strings.Join(parts, " ")
}

// DataLoadingOptions represents a collection of data loading options
type DataLoadingOptions struct {
	Options []DataLoadingOption
}

// String implements the Stringer interface for DataLoadingOptions
func (d *DataLoadingOptions) String() string {
	var parts []string
	for _, opt := range d.Options {
		parts = append(parts, opt.String())
	}
	return strings.Join(parts, " ")
}

// DataLoadingOptionType represents the type of a data loading option
type DataLoadingOptionType int

const (
	DataLoadingOptionTypeString DataLoadingOptionType = iota
	DataLoadingOptionTypeBoolean
	DataLoadingOptionTypeEnum
	DataLoadingOptionTypeNumber
)

// DataLoadingOption represents a single data loading option
type DataLoadingOption struct {
	OptionName string
	OptionType DataLoadingOptionType
	Value      string
}

// String implements the Stringer interface for DataLoadingOption
func (d *DataLoadingOption) String() string {
	switch d.OptionType {
	case DataLoadingOptionTypeString:
		return fmt.Sprintf("%s='%s'", d.OptionName, d.Value)
	case DataLoadingOptionTypeEnum,
		DataLoadingOptionTypeBoolean,
		DataLoadingOptionTypeNumber:
		return fmt.Sprintf("%s=%s", d.OptionName, d.Value)
	default:
		return fmt.Sprintf("%s=%s", d.OptionName, d.Value)
	}
}

// StageLoadSelectItem represents a select item in stage loading operations
type StageLoadSelectItem struct {
	Alias      *Ident
	FileColNum int32
	Element    *Ident
	ItemAs     *Ident
}

// String implements the Stringer interface for StageLoadSelectItem
func (s *StageLoadSelectItem) String() string {
	var result strings.Builder

	if s.Alias != nil {
		result.WriteString(s.Alias.String())
		result.WriteString(".")
	}
	result.WriteString(fmt.Sprintf("$%d", s.FileColNum))
	if s.Element != nil {
		result.WriteString(":")
		result.WriteString(s.Element.String())
	}
	if s.ItemAs != nil {
		result.WriteString(" AS ")
		result.WriteString(s.ItemAs.String())
	}

	return result.String()
}

// FileStagingCommand represents a file staging command
type FileStagingCommand struct {
	Stage   ObjectName
	Pattern *string
}

// String implements the Stringer interface for FileStagingCommand
func (f *FileStagingCommand) String() string {
	var result strings.Builder

	result.WriteString(f.Stage.String())
	if f.Pattern != nil {
		result.WriteString(fmt.Sprintf(" PATTERN='%s'", *f.Pattern))
	}

	return result.String()
}

// Helper functions for creating options

// NewStringOption creates a new string-type DataLoadingOption
func NewStringOption(name, value string) DataLoadingOption {
	return DataLoadingOption{
		OptionName: name,
		OptionType: DataLoadingOptionTypeString,
		Value:      value,
	}
}

// NewBooleanOption creates a new boolean-type DataLoadingOption
func NewBooleanOption(name string, value bool) DataLoadingOption {
	return DataLoadingOption{
		OptionName: name,
		OptionType: DataLoadingOptionTypeBoolean,
		Value:      fmt.Sprintf("%v", value),
	}
}

// NewEnumOption creates a new enum-type DataLoadingOption
func NewEnumOption(name, value string) DataLoadingOption {
	return DataLoadingOption{
		OptionName: name,
		OptionType: DataLoadingOptionTypeEnum,
		Value:      value,
	}
}

// NewNumberOption creates a new number-type DataLoadingOption
func NewNumberOption(name string, value interface{}) DataLoadingOption {
	return DataLoadingOption{
		OptionName: name,
		OptionType: DataLoadingOptionTypeNumber,
		Value:      fmt.Sprintf("%v", value),
	}
}
