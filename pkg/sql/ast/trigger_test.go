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

func TestTriggerObjectString(t *testing.T) {
	tests := []struct {
		obj      TriggerObject
		expected string
	}{
		{TriggerObjectRow, "ROW"},
		{TriggerObjectStatement, "STATEMENT"},
		{TriggerObject(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.obj.String(); got != tt.expected {
				t.Errorf("TriggerObject.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTriggerReferencingTypeString(t *testing.T) {
	tests := []struct {
		refType  TriggerReferencingType
		expected string
	}{
		{TriggerReferencingOldTable, "OLD TABLE"},
		{TriggerReferencingNewTable, "NEW TABLE"},
		{TriggerReferencingType(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.refType.String(); got != tt.expected {
				t.Errorf("TriggerReferencingType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTriggerReferencingString(t *testing.T) {
	tests := []struct {
		ref      TriggerReferencing
		expected string
	}{
		{
			TriggerReferencing{
				ReferType:              TriggerReferencingOldTable,
				IsAs:                   false,
				TransitionRelationName: ObjectName{Name: "old_rows"},
			},
			"OLD TABLE old_rows",
		},
		{
			TriggerReferencing{
				ReferType:              TriggerReferencingNewTable,
				IsAs:                   true,
				TransitionRelationName: ObjectName{Name: "new_rows"},
			},
			"NEW TABLE AS new_rows",
		},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.ref.String(); got != tt.expected {
				t.Errorf("TriggerReferencing.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTriggerEventString(t *testing.T) {
	tests := []struct {
		event    TriggerEvent
		expected string
	}{
		{
			TriggerEvent{Type: TriggerEventInsert},
			"INSERT",
		},
		{
			TriggerEvent{Type: TriggerEventUpdate},
			"UPDATE",
		},
		{
			TriggerEvent{
				Type: TriggerEventUpdate,
				Columns: []Identifier{
					{Name: "col1"},
					{Name: "col2"},
				},
			},
			"UPDATE OF col1, col2",
		},
		{
			TriggerEvent{Type: TriggerEventDelete},
			"DELETE",
		},
		{
			TriggerEvent{Type: TriggerEventTruncate},
			"TRUNCATE",
		},
		{
			TriggerEvent{Type: TriggerEventType(999)},
			"UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.event.String(); got != tt.expected {
				t.Errorf("TriggerEvent.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTriggerPeriodString(t *testing.T) {
	tests := []struct {
		period   TriggerPeriod
		expected string
	}{
		{TriggerPeriodAfter, "AFTER"},
		{TriggerPeriodBefore, "BEFORE"},
		{TriggerPeriodInsteadOf, "INSTEAD OF"},
		{TriggerPeriod(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.period.String(); got != tt.expected {
				t.Errorf("TriggerPeriod.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTriggerExecBodyTypeString(t *testing.T) {
	tests := []struct {
		execType TriggerExecBodyType
		expected string
	}{
		{TriggerExecBodyFunction, "FUNCTION"},
		{TriggerExecBodyProcedure, "PROCEDURE"},
		{TriggerExecBodyType(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.execType.String(); got != tt.expected {
				t.Errorf("TriggerExecBodyType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestTriggerExecBodyString(t *testing.T) {
	tests := []struct {
		body     TriggerExecBody
		expected string
	}{
		{
			TriggerExecBody{
				ExecType: TriggerExecBodyFunction,
				FuncDesc: FunctionDesc{
					Name:      ObjectName{Name: "update_timestamp"},
					Arguments: []string{},
				},
			},
			"FUNCTION update_timestamp",
		},
		{
			TriggerExecBody{
				ExecType: TriggerExecBodyProcedure,
				FuncDesc: FunctionDesc{
					Name:      ObjectName{Name: "audit_changes"},
					Arguments: []string{},
				},
			},
			"PROCEDURE audit_changes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.body.String(); got != tt.expected {
				t.Errorf("TriggerExecBody.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}
