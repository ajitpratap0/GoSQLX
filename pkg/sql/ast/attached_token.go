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
	"hash"
)

// AttachedToken is a wrapper over TokenWithSpan that ignores the token and source
// location in comparisons and hashing.
//
// This type is used when the token and location is not relevant for semantics,
// but is still needed for accurate source location tracking.
//
// Note: ALL AttachedTokens are equal.
//
// Examples:
//
// Same token, different location are equal:
//
//	// commas @ line 1, column 10
//	tok1 := NewTokenWithSpan(
//	    Token{Type: Comma},
//	    Span{Start: Location{Line: 1, Column: 10}, End: Location{Line: 1, Column: 11}},
//	)
//	// commas @ line 2, column 20
//	tok2 := NewTokenWithSpan(
//	    Token{Type: Comma},
//	    Span{Start: Location{Line: 2, Column: 20}, End: Location{Line: 2, Column: 21}},
//	)
//
//	// token with locations are *not* equal
//	fmt.Println(tok1 != tok2) // true
//	// attached tokens are equal
//	fmt.Println(AttachedToken{tok1} == AttachedToken{tok2}) // true
//
// Different token, different location are equal:
//
//	// commas @ line 1, column 10
//	tok1 := NewTokenWithSpan(
//	    Token{Type: Comma},
//	    Span{Start: Location{Line: 1, Column: 10}, End: Location{Line: 1, Column: 11}},
//	)
//	// period @ line 2, column 20
//	tok2 := NewTokenWithSpan(
//	    Token{Type: Period},
//	    Span{Start: Location{Line: 2, Column: 20}, End: Location{Line: 2, Column: 21}},
//	)
//
//	// token with locations are *not* equal
//	fmt.Println(tok1 != tok2) // true
//	// attached tokens are equal
//	fmt.Println(AttachedToken{tok1} == AttachedToken{tok2}) // true
type AttachedToken struct {
	Token TokenWithSpan
}

// NewAttachedToken creates a new AttachedToken from a TokenWithSpan
func NewAttachedToken(token TokenWithSpan) AttachedToken {
	return AttachedToken{Token: token}
}

// Empty returns a new Empty AttachedToken
func (a AttachedToken) Empty() AttachedToken {
	return AttachedToken{Token: NewTokenWithSpanEOF()}
}

// String implements fmt.Stringer
func (a AttachedToken) String() string {
	return a.Token.String()
}

// GoString implements fmt.GoStringer
func (a AttachedToken) GoString() string {
	return fmt.Sprintf("AttachedToken{%#v}", a.Token)
}

// Equal implements equality comparison
// Note: ALL AttachedTokens are equal
func (a AttachedToken) Equal(other AttachedToken) bool {
	return true
}

// Compare implements comparison
// Note: ALL AttachedTokens are equal
func (a AttachedToken) Compare(other AttachedToken) int {
	return 0
}

// Hash implements hashing
// Note: ALL AttachedTokens have the same hash
func (a AttachedToken) Hash(h hash.Hash) {
	// Do nothing - all AttachedTokens have the same hash
}

// UnwrapToken returns the underlying TokenWithSpan
func (a AttachedToken) UnwrapToken() TokenWithSpan {
	return a.Token
}

// WrapToken wraps a TokenWithSpan in an AttachedToken
func WrapToken(token TokenWithSpan) AttachedToken {
	return AttachedToken{Token: token}
}

// TokenWithSpan represents a token with its source location span
type TokenWithSpan struct {
	Token Token
	Span  Span
}

// NewTokenWithSpan creates a new TokenWithSpan
func NewTokenWithSpan(token Token, span Span) TokenWithSpan {
	return TokenWithSpan{
		Token: token,
		Span:  span,
	}
}

// NewTokenWithSpanEOF creates a new EOF TokenWithSpan
func NewTokenWithSpanEOF() TokenWithSpan {
	return TokenWithSpan{
		Token: Token{Type: EOF},
		Span:  Span{},
	}
}

// String implements fmt.Stringer
func (t TokenWithSpan) String() string {
	return fmt.Sprintf("%v @ %v", t.Token, t.Span)
}

// GoString implements fmt.GoStringer
func (t TokenWithSpan) GoString() string {
	return fmt.Sprintf("TokenWithSpan{Token: %#v, Span: %#v}", t.Token, t.Span)
}

// Token represents a lexical token
type Token struct {
	Type TokenType
	// Add other token fields as needed
}

// TokenType represents the type of a token
type TokenType int

// Token types
const (
	EOF TokenType = iota
	Comma
	Period
	// Add other token types as needed
)

// String implements fmt.Stringer
func (t Token) String() string {
	switch t.Type {
	case EOF:
		return "EOF"
	case Comma:
		return ","
	case Period:
		return "."
	default:
		return fmt.Sprintf("TokenType(%d)", t.Type)
	}
}

// Span represents a source location span
type Span struct {
	Start Location
	End   Location
}

// String implements fmt.Stringer
func (s Span) String() string {
	return fmt.Sprintf("%v-%v", s.Start, s.End)
}

// Location represents a source location
type Location struct {
	Line   int
	Column int
}

// String implements fmt.Stringer
func (l Location) String() string {
	return fmt.Sprintf("%d:%d", l.Line, l.Column)
}
