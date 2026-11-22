// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package ast

import (
	"encoding/json"
	"fmt"
)

// literalJSON preserves the branch's exported literal JSON fields while the
// in-memory representation keeps the string metadata in cold storage.
type literalJSON struct {
	Value        interface{}
	Type         string
	Prefix       string
	RawBackslash bool
}

// MarshalJSON includes string metadata for AST consumers such as the WASM
// parse endpoint, without exposing the private shared raw-string marker.
func (l LiteralValue) MarshalJSON() ([]byte, error) {
	x := l.DialectExtras()
	return json.Marshal(literalJSON{Value: l.Value, Type: l.Type, Prefix: x.Prefix, RawBackslash: x.RawBackslash})
}

// UnmarshalJSON restores literal metadata, preserving fields absent from the
// input just as the default decoder did before the metadata moved.
func (l *LiteralValue) UnmarshalJSON(data []byte) error {
	x := l.DialectExtras()
	fields := literalJSON{Value: l.Value, Type: l.Type, Prefix: x.Prefix, RawBackslash: x.RawBackslash}
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("decode literal: %w", err)
	}
	*l = LiteralValue{Value: fields.Value, Type: fields.Type}
	if fields.Prefix != "" {
		l.EnsureExtras().Prefix = fields.Prefix
	}
	l.SetRawBackslash(fields.RawBackslash)
	return nil
}
