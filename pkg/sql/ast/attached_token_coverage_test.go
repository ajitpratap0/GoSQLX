package ast

import (
	"fmt"
	"hash/fnv"
	"strings"
	"testing"
)

func TestNewAttachedToken(t *testing.T) {
	tws := NewTokenWithSpan(Token{Type: Comma}, Span{Start: Location{1, 10}, End: Location{1, 11}})
	at := NewAttachedToken(tws)
	if at.Token != tws {
		t.Error("NewAttachedToken should store token")
	}
}

func TestAttachedToken_Empty(t *testing.T) {
	at := AttachedToken{}
	empty := at.Empty()
	if empty.Token.Token.Type != EOF {
		t.Error("Empty should return EOF token")
	}
}

func TestAttachedToken_String(t *testing.T) {
	tws := NewTokenWithSpan(Token{Type: Comma}, Span{Start: Location{1, 10}, End: Location{1, 11}})
	at := NewAttachedToken(tws)
	s := at.String()
	if !strings.Contains(s, ",") {
		t.Errorf("String should contain comma token representation, got: %s", s)
	}
}

func TestAttachedToken_GoString(t *testing.T) {
	tws := NewTokenWithSpan(Token{Type: Period}, Span{})
	at := NewAttachedToken(tws)
	gs := at.GoString()
	if !strings.Contains(gs, "AttachedToken") {
		t.Errorf("GoString should contain AttachedToken, got: %s", gs)
	}
}

func TestAttachedToken_Equal(t *testing.T) {
	a := NewAttachedToken(NewTokenWithSpan(Token{Type: Comma}, Span{}))
	b := NewAttachedToken(NewTokenWithSpan(Token{Type: Period}, Span{Start: Location{5, 5}}))
	// AttachedToken.Equal() intentionally returns true for all comparisons
	// (see attached_token.go) — tokens are compared by AST structure, not position
	if !a.Equal(b) {
		t.Error("ALL AttachedTokens should be equal (by design)")
	}
}

func TestAttachedToken_Compare(t *testing.T) {
	a := NewAttachedToken(NewTokenWithSpan(Token{Type: Comma}, Span{}))
	b := NewAttachedToken(NewTokenWithSpan(Token{Type: Period}, Span{}))
	if a.Compare(b) != 0 {
		t.Error("ALL AttachedTokens should compare to 0")
	}
}

func TestAttachedToken_Hash(t *testing.T) {
	a := NewAttachedToken(NewTokenWithSpan(Token{Type: Comma}, Span{}))
	h := fnv.New64()
	a.Hash(h) // should not panic
}

func TestAttachedToken_UnwrapToken(t *testing.T) {
	tws := NewTokenWithSpan(Token{Type: Comma}, Span{Start: Location{1, 1}})
	at := NewAttachedToken(tws)
	unwrapped := at.UnwrapToken()
	if unwrapped != tws {
		t.Error("UnwrapToken should return original")
	}
}

func TestWrapToken(t *testing.T) {
	tws := NewTokenWithSpan(Token{Type: Period}, Span{})
	at := WrapToken(tws)
	if at.Token != tws {
		t.Error("WrapToken should wrap token")
	}
}

func TestNewTokenWithSpan(t *testing.T) {
	tok := Token{Type: Comma}
	span := Span{Start: Location{1, 1}, End: Location{1, 2}}
	tws := NewTokenWithSpan(tok, span)
	if tws.Token != tok || tws.Span != span {
		t.Error("NewTokenWithSpan should store both")
	}
}

func TestNewTokenWithSpanEOF(t *testing.T) {
	tws := NewTokenWithSpanEOF()
	if tws.Token.Type != EOF {
		t.Error("should be EOF")
	}
}

func TestTokenWithSpan_String(t *testing.T) {
	tws := NewTokenWithSpan(Token{Type: Comma}, Span{Start: Location{1, 10}, End: Location{1, 11}})
	s := tws.String()
	if !strings.Contains(s, ",") {
		t.Errorf("should contain comma representation, got: %s", s)
	}
}

func TestTokenWithSpan_GoString(t *testing.T) {
	tws := NewTokenWithSpan(Token{Type: EOF}, Span{})
	gs := tws.GoString()
	if !strings.Contains(gs, "TokenWithSpan") {
		t.Errorf("should contain TokenWithSpan, got: %s", gs)
	}
}

func TestToken_String(t *testing.T) {
	tests := []struct {
		typ  TokenType
		want string
	}{
		{EOF, "EOF"},
		{Comma, ","},
		{Period, "."},
		{TokenType(999), fmt.Sprintf("TokenType(%d)", 999)},
	}
	for _, tt := range tests {
		tok := Token{Type: tt.typ}
		if got := tok.String(); got != tt.want {
			t.Errorf("Token{%d}.String() = %q, want %q", tt.typ, got, tt.want)
		}
	}
}

func TestSpan_String(t *testing.T) {
	s := Span{Start: Location{1, 2}, End: Location{3, 4}}
	if got := s.String(); got != "1:2-3:4" {
		t.Errorf("Span.String() = %q", got)
	}
}

func TestLocation_String(t *testing.T) {
	l := Location{Line: 5, Column: 10}
	if got := l.String(); got != "5:10" {
		t.Errorf("Location.String() = %q", got)
	}
}
