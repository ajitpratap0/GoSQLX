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

			// Test Children (should be nil)
			if children := tt.trigRef.Children(); children != nil {
				t.Errorf("TriggerReferencing.Children() = %v, want nil", children)
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

			// Test Children (should be nil)
			if children := tt.trigEvent.Children(); children != nil {
				t.Errorf("TriggerEvent.Children() = %v, want nil", children)
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

			// Test Children (should be nil)
			if children := tt.execBody.Children(); children != nil {
				t.Errorf("TriggerExecBody.Children() = %v, want nil", children)
			}
		})
	}
}
