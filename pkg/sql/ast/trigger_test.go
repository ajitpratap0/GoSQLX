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

package ast

import "testing"

// Test TriggerObject
func TestTriggerObject(t *testing.T) {
	tests := []struct {
		name       string
		trigObj    TriggerObject
		wantString string
	}{
		{
			name:       "ROW trigger object",
			trigObj:    TriggerObjectRow,
			wantString: "ROW",
		},
		{
			name:       "STATEMENT trigger object",
			trigObj:    TriggerObjectStatement,
			wantString: "STATEMENT",
		},
		{
			name:       "Unknown trigger object",
			trigObj:    TriggerObject(999),
			wantString: "UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test String
			if got := tt.trigObj.String(); got != tt.wantString {
				t.Errorf("TriggerObject.String() = %v, want %v", got, tt.wantString)
			}

			// Test TokenLiteral
			if got := tt.trigObj.TokenLiteral(); got != tt.wantString {
				t.Errorf("TriggerObject.TokenLiteral() = %v, want %v", got, tt.wantString)
			}

			// Test Children (should be nil)
			if children := tt.trigObj.Children(); children != nil {
				t.Errorf("TriggerObject.Children() = %v, want nil", children)
			}
		})
	}
}

// Test TriggerReferencingType
func TestTriggerReferencingType(t *testing.T) {
	tests := []struct {
		name       string
		refType    TriggerReferencingType
		wantString string
	}{
		{
			name:       "OLD TABLE",
			refType:    TriggerReferencingOldTable,
			wantString: "OLD TABLE",
		},
		{
			name:       "NEW TABLE",
			refType:    TriggerReferencingNewTable,
			wantString: "NEW TABLE",
		},
		{
			name:       "Unknown referencing type",
			refType:    TriggerReferencingType(999),
			wantString: "UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.refType.String(); got != tt.wantString {
				t.Errorf("TriggerReferencingType.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

// Test TriggerReferencing
func TestTriggerReferencing(t *testing.T) {
	tests := []struct {
		name       string
		trigRef    TriggerReferencing
		wantString string
	}{
		{
			name: "OLD TABLE without AS",
			trigRef: TriggerReferencing{
				ReferType:              TriggerReferencingOldTable,
				IsAs:                   false,
				TransitionRelationName: ObjectName{Name: "old_data"},
			},
			wantString: "OLD TABLE old_data",
		},
		{
			name: "NEW TABLE with AS",
			trigRef: TriggerReferencing{
				ReferType:              TriggerReferencingNewTable,
				IsAs:                   true,
				TransitionRelationName: ObjectName{Name: "new_data"},
			},
			wantString: "NEW TABLE AS new_data",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test String
			if got := tt.trigRef.String(); got != tt.wantString {
				t.Errorf("TriggerReferencing.String() = %v, want %v", got, tt.wantString)
			}

			// Test TokenLiteral
			if got := tt.trigRef.TokenLiteral(); got != tt.wantString {
				t.Errorf("TriggerReferencing.TokenLiteral() = %v, want %v", got, tt.wantString)
			}

			// Test Children: visitor contract (C6) — TransitionRelationName
			// is exposed as the single child so Walk/Inspect reach it.
			children := tt.trigRef.Children()
			if len(children) != 1 {
				t.Fatalf("TriggerReferencing.Children() = %v (len %d), want 1 child", children, len(children))
			}
			if on, ok := children[0].(ObjectName); !ok || on != tt.trigRef.TransitionRelationName {
				t.Errorf("TriggerReferencing.Children()[0] = %v, want %v", children[0], tt.trigRef.TransitionRelationName)
			}
		})
	}
}

// Test TriggerEvent
func TestTriggerEvent(t *testing.T) {
	tests := []struct {
		name       string
		trigEvent  TriggerEvent
		wantString string
	}{
		{
			name: "INSERT event",
			trigEvent: TriggerEvent{
				Type: TriggerEventInsert,
			},
			wantString: "INSERT",
		},
		{
			name: "UPDATE event without columns",
			trigEvent: TriggerEvent{
				Type: TriggerEventUpdate,
			},
			wantString: "UPDATE",
		},
		{
			name: "UPDATE event with columns",
			trigEvent: TriggerEvent{
				Type: TriggerEventUpdate,
				Columns: []Identifier{
					{Name: "email"},
					{Name: "updated_at"},
				},
			},
			wantString: "UPDATE OF email, updated_at",
		},
		{
			name: "DELETE event",
			trigEvent: TriggerEvent{
				Type: TriggerEventDelete,
			},
			wantString: "DELETE",
		},
		{
			name: "TRUNCATE event",
			trigEvent: TriggerEvent{
				Type: TriggerEventTruncate,
			},
			wantString: "TRUNCATE",
		},
		{
			name: "Unknown event type",
			trigEvent: TriggerEvent{
				Type: TriggerEventType(999),
			},
			wantString: "UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test String
			if got := tt.trigEvent.String(); got != tt.wantString {
				t.Errorf("TriggerEvent.String() = %v, want %v", got, tt.wantString)
			}

			// Test TokenLiteral
			if got := tt.trigEvent.TokenLiteral(); got != tt.wantString {
				t.Errorf("TriggerEvent.TokenLiteral() = %v, want %v", got, tt.wantString)
			}

			// Test Children: visitor contract (C6) — UPDATE OF ... columns
			// are exposed for Walk/Inspect traversal. Other event types have
			// no child nodes.
			children := tt.trigEvent.Children()
			if len(tt.trigEvent.Columns) == 0 {
				if children != nil {
					t.Errorf("TriggerEvent.Children() = %v, want nil", children)
				}
			} else {
				if len(children) != len(tt.trigEvent.Columns) {
					t.Errorf("TriggerEvent.Children() len = %d, want %d", len(children), len(tt.trigEvent.Columns))
				}
			}
		})
	}
}

// Test TriggerPeriod
func TestTriggerPeriod(t *testing.T) {
	tests := []struct {
		name       string
		period     TriggerPeriod
		wantString string
	}{
		{
			name:       "AFTER",
			period:     TriggerPeriodAfter,
			wantString: "AFTER",
		},
		{
			name:       "BEFORE",
			period:     TriggerPeriodBefore,
			wantString: "BEFORE",
		},
		{
			name:       "INSTEAD OF",
			period:     TriggerPeriodInsteadOf,
			wantString: "INSTEAD OF",
		},
		{
			name:       "Unknown period",
			period:     TriggerPeriod(999),
			wantString: "UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test String
			if got := tt.period.String(); got != tt.wantString {
				t.Errorf("TriggerPeriod.String() = %v, want %v", got, tt.wantString)
			}

			// Test TokenLiteral
			if got := tt.period.TokenLiteral(); got != tt.wantString {
				t.Errorf("TriggerPeriod.TokenLiteral() = %v, want %v", got, tt.wantString)
			}

			// Test Children (should be nil)
			if children := tt.period.Children(); children != nil {
				t.Errorf("TriggerPeriod.Children() = %v, want nil", children)
			}
		})
	}
}

// Test TriggerExecBodyType
func TestTriggerExecBodyType(t *testing.T) {
	tests := []struct {
		name       string
		execType   TriggerExecBodyType
		wantString string
	}{
		{
			name:       "FUNCTION",
			execType:   TriggerExecBodyFunction,
			wantString: "FUNCTION",
		},
		{
			name:       "PROCEDURE",
			execType:   TriggerExecBodyProcedure,
			wantString: "PROCEDURE",
		},
		{
			name:       "Unknown exec type",
			execType:   TriggerExecBodyType(999),
			wantString: "UNKNOWN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.execType.String(); got != tt.wantString {
				t.Errorf("TriggerExecBodyType.String() = %v, want %v", got, tt.wantString)
			}
		})
	}
}

// Test TriggerExecBody
func TestTriggerExecBody(t *testing.T) {
	tests := []struct {
		name       string
		execBody   TriggerExecBody
		wantString string
	}{
		{
			name: "FUNCTION execution",
			execBody: TriggerExecBody{
				ExecType: TriggerExecBodyFunction,
				FuncDesc: FunctionDesc{
					Name: ObjectName{Name: "process_audit"},
				},
			},
			wantString: "FUNCTION process_audit",
		},
		{
			name: "PROCEDURE execution",
			execBody: TriggerExecBody{
				ExecType: TriggerExecBodyProcedure,
				FuncDesc: FunctionDesc{
					Name:   ObjectName{Name: "handle_trigger"},
					Schema: "public",
				},
			},
			wantString: "PROCEDURE public.handle_trigger",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test String
			if got := tt.execBody.String(); got != tt.wantString {
				t.Errorf("TriggerExecBody.String() = %v, want %v", got, tt.wantString)
			}

			// Test TokenLiteral
			if got := tt.execBody.TokenLiteral(); got != tt.wantString {
				t.Errorf("TriggerExecBody.TokenLiteral() = %v, want %v", got, tt.wantString)
			}

			// Test Children: visitor contract (C6) — FuncDesc exposed as a child.
			children := tt.execBody.Children()
			if len(children) != 1 {
				t.Fatalf("TriggerExecBody.Children() = %v (len %d), want 1 child", children, len(children))
			}
			fd, ok := children[0].(FunctionDesc)
			if !ok {
				t.Fatalf("TriggerExecBody.Children()[0] type = %T, want FunctionDesc", children[0])
			}
			if fd.String() != tt.execBody.FuncDesc.String() {
				t.Errorf("FuncDesc child = %v, want %v", fd, tt.execBody.FuncDesc)
			}
		})
	}
}
