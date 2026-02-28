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

// TriggerObject specifies whether the trigger function should be fired once for every row
// affected by the trigger event, or just once per SQL statement.
type TriggerObject int

const (
	TriggerObjectRow TriggerObject = iota
	TriggerObjectStatement
)

// String returns the SQL keyword for this trigger object: "ROW" or "STATEMENT".
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

// String returns the SQL phrase for this referencing type: "OLD TABLE" or "NEW TABLE".
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

// String returns the SQL representation of this transition relation declaration,
// e.g. "OLD TABLE AS old_rows" or "NEW TABLE new_rows".
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

// TriggerEventType identifies which DML event fires the trigger.
type TriggerEventType int

const (
	// TriggerEventInsert fires the trigger on INSERT.
	TriggerEventInsert TriggerEventType = iota
	// TriggerEventUpdate fires the trigger on UPDATE (optionally of specific columns).
	TriggerEventUpdate
	// TriggerEventDelete fires the trigger on DELETE.
	TriggerEventDelete
	// TriggerEventTruncate fires the trigger on TRUNCATE.
	TriggerEventTruncate
)

// String returns the SQL representation of this trigger event: "INSERT",
// "UPDATE", "UPDATE OF col1, col2", "DELETE", or "TRUNCATE".
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

// String returns the SQL keyword for this trigger period: "AFTER", "BEFORE",
// or "INSTEAD OF".
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

// String returns the SQL keyword for this execution body type: "FUNCTION" or "PROCEDURE".
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

// String returns the SQL representation of this trigger execution body,
// e.g. "FUNCTION schema.my_func()" or "PROCEDURE my_proc()".
func (t TriggerExecBody) String() string {
	return fmt.Sprintf("%s %s", t.ExecType, t.FuncDesc)
}

// Children implements Node and returns nil — TriggerObject has no child nodes.
func (t TriggerObject) Children() []Node { return nil }

// TokenLiteral implements Node and returns the SQL keyword for this trigger object.
func (t TriggerObject) TokenLiteral() string { return t.String() }

// Children implements Node and returns nil — TriggerReferencing has no child nodes.
func (t TriggerReferencing) Children() []Node { return nil }

// TokenLiteral implements Node and returns the SQL representation of this
// transition relation declaration.
func (t TriggerReferencing) TokenLiteral() string { return t.String() }

// Children implements Node and returns nil — TriggerEvent has no child nodes.
func (t TriggerEvent) Children() []Node { return nil }

// TokenLiteral implements Node and returns the SQL representation of this
// trigger event (e.g. "INSERT", "UPDATE OF col", "DELETE").
func (t TriggerEvent) TokenLiteral() string { return t.String() }

// Children implements Node and returns nil — TriggerPeriod has no child nodes.
func (t TriggerPeriod) Children() []Node { return nil }

// TokenLiteral implements Node and returns the SQL keyword for this trigger
// period ("AFTER", "BEFORE", or "INSTEAD OF").
func (t TriggerPeriod) TokenLiteral() string { return t.String() }

// Children implements Node and returns nil — TriggerExecBody has no child nodes.
func (t TriggerExecBody) Children() []Node { return nil }

// TokenLiteral implements Node and returns the SQL representation of this
// trigger execution body.
func (t TriggerExecBody) TokenLiteral() string { return t.String() }
