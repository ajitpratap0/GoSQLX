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

// TriggerObject specifies whether the trigger function should be fired once for every row
// affected by the trigger event, or just once per SQL statement.
type TriggerObject int

const (
	TriggerObjectRow TriggerObject = iota
	TriggerObjectStatement
)

func (t TriggerObject) String() string {
	switch t {
	case TriggerObjectRow:
		return "ROW"
	case TriggerObjectStatement:
		return "STATEMENT"
	default:
		return "UNKNOWN"
	}
}

// TriggerReferencingType indicates whether the following relation name is for
// the before-image transition relation or the after-image transition relation
type TriggerReferencingType int

const (
	TriggerReferencingOldTable TriggerReferencingType = iota
	TriggerReferencingNewTable
)

func (t TriggerReferencingType) String() string {
	switch t {
	case TriggerReferencingOldTable:
		return "OLD TABLE"
	case TriggerReferencingNewTable:
		return "NEW TABLE"
	default:
		return "UNKNOWN"
	}
}

// TriggerReferencing represents a declaration of relation names that provide access
// to the transition relations of the triggering statement
type TriggerReferencing struct {
	ReferType              TriggerReferencingType
	IsAs                   bool
	TransitionRelationName ObjectName
}

func (t TriggerReferencing) String() string {
	var as string
	if t.IsAs {
		as = " AS"
	}
	return fmt.Sprintf("%s%s %s", t.ReferType, as, t.TransitionRelationName)
}

// TriggerEvent describes trigger events
type TriggerEvent struct {
	Type    TriggerEventType
	Columns []Identifier // Only used for UPDATE events
}

type TriggerEventType int

const (
	TriggerEventInsert TriggerEventType = iota
	TriggerEventUpdate
	TriggerEventDelete
	TriggerEventTruncate
)

func (t TriggerEvent) String() string {
	switch t.Type {
	case TriggerEventInsert:
		return "INSERT"
	case TriggerEventUpdate:
		if len(t.Columns) == 0 {
			return "UPDATE"
		}
		cols := make([]string, len(t.Columns))
		for i, col := range t.Columns {
			cols[i] = col.TokenLiteral()
		}
		return fmt.Sprintf("UPDATE OF %s", strings.Join(cols, ", "))
	case TriggerEventDelete:
		return "DELETE"
	case TriggerEventTruncate:
		return "TRUNCATE"
	default:
		return "UNKNOWN"
	}
}

// TriggerPeriod represents when the trigger should be executed
type TriggerPeriod int

const (
	TriggerPeriodAfter TriggerPeriod = iota
	TriggerPeriodBefore
	TriggerPeriodInsteadOf
)

func (t TriggerPeriod) String() string {
	switch t {
	case TriggerPeriodAfter:
		return "AFTER"
	case TriggerPeriodBefore:
		return "BEFORE"
	case TriggerPeriodInsteadOf:
		return "INSTEAD OF"
	default:
		return "UNKNOWN"
	}
}

// TriggerExecBodyType represents types of trigger body execution
type TriggerExecBodyType int

const (
	TriggerExecBodyFunction TriggerExecBodyType = iota
	TriggerExecBodyProcedure
)

func (t TriggerExecBodyType) String() string {
	switch t {
	case TriggerExecBodyFunction:
		return "FUNCTION"
	case TriggerExecBodyProcedure:
		return "PROCEDURE"
	default:
		return "UNKNOWN"
	}
}

// TriggerExecBody represents the execution body of a trigger
type TriggerExecBody struct {
	ExecType TriggerExecBodyType
	FuncDesc FunctionDesc
}

func (t TriggerExecBody) String() string {
	return fmt.Sprintf("%s %s", t.ExecType, t.FuncDesc)
}

// Implement Node interface for trigger types
func (t TriggerObject) Children() []Node          { return nil }
func (t TriggerObject) TokenLiteral() string      { return t.String() }
func (t TriggerReferencing) Children() []Node     { return nil }
func (t TriggerReferencing) TokenLiteral() string { return t.String() }
func (t TriggerEvent) Children() []Node           { return nil }
func (t TriggerEvent) TokenLiteral() string       { return t.String() }
func (t TriggerPeriod) Children() []Node          { return nil }
func (t TriggerPeriod) TokenLiteral() string      { return t.String() }
func (t TriggerExecBody) Children() []Node        { return nil }
func (t TriggerExecBody) TokenLiteral() string    { return t.String() }
