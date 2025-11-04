package models

import "testing"

func TestTokenWithSpan(t *testing.T) {
	tests := []struct {
		name      string
		tws       TokenWithSpan
		wantToken Token
		wantStart Location
		wantEnd   Location
	}{
		{
			name: "identifier with span",
			tws: TokenWithSpan{
				Token: Token{Type: TokenTypeIdentifier, Value: "users"},
				Start: Location{Line: 1, Column: 10},
				End:   Location{Line: 1, Column: 15},
			},
			wantToken: Token{Type: TokenTypeIdentifier, Value: "users"},
			wantStart: Location{Line: 1, Column: 10},
			wantEnd:   Location{Line: 1, Column: 15},
		},
		{
			name: "keyword with span",
			tws: TokenWithSpan{
				Token: Token{Type: TokenTypeSelect, Value: "SELECT"},
				Start: Location{Line: 1, Column: 1},
				End:   Location{Line: 1, Column: 7},
			},
			wantToken: Token{Type: TokenTypeSelect, Value: "SELECT"},
			wantStart: Location{Line: 1, Column: 1},
			wantEnd:   Location{Line: 1, Column: 7},
		},
		{
			name: "operator with span",
			tws: TokenWithSpan{
				Token: Token{Type: TokenTypeEq, Value: "="},
				Start: Location{Line: 2, Column: 5},
				End:   Location{Line: 2, Column: 6},
			},
			wantToken: Token{Type: TokenTypeEq, Value: "="},
			wantStart: Location{Line: 2, Column: 5},
			wantEnd:   Location{Line: 2, Column: 6},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.tws.Token.Type != tt.wantToken.Type {
				t.Errorf("TokenWithSpan.Token.Type = %v, want %v", tt.tws.Token.Type, tt.wantToken.Type)
			}
			if tt.tws.Token.Value != tt.wantToken.Value {
				t.Errorf("TokenWithSpan.Token.Value = %v, want %v", tt.tws.Token.Value, tt.wantToken.Value)
			}
			if tt.tws.Start != tt.wantStart {
				t.Errorf("TokenWithSpan.Start = %v, want %v", tt.tws.Start, tt.wantStart)
			}
			if tt.tws.End != tt.wantEnd {
				t.Errorf("TokenWithSpan.End = %v, want %v", tt.tws.End, tt.wantEnd)
			}
		})
	}
}

func TestWrapToken(t *testing.T) {
	tests := []struct {
		name      string
		token     Token
		wantToken Token
		wantStart Location
		wantEnd   Location
	}{
		{
			name:      "wrap identifier",
			token:     Token{Type: TokenTypeIdentifier, Value: "users"},
			wantToken: Token{Type: TokenTypeIdentifier, Value: "users"},
			wantStart: Location{Line: 0, Column: 0},
			wantEnd:   Location{Line: 0, Column: 0},
		},
		{
			name:      "wrap keyword",
			token:     Token{Type: TokenTypeSelect, Value: "SELECT"},
			wantToken: Token{Type: TokenTypeSelect, Value: "SELECT"},
			wantStart: Location{Line: 0, Column: 0},
			wantEnd:   Location{Line: 0, Column: 0},
		},
		{
			name:      "wrap operator",
			token:     Token{Type: TokenTypeEq, Value: "="},
			wantToken: Token{Type: TokenTypeEq, Value: "="},
			wantStart: Location{Line: 0, Column: 0},
			wantEnd:   Location{Line: 0, Column: 0},
		},
		{
			name:      "wrap EOF",
			token:     Token{Type: TokenTypeEOF, Value: ""},
			wantToken: Token{Type: TokenTypeEOF, Value: ""},
			wantStart: Location{Line: 0, Column: 0},
			wantEnd:   Location{Line: 0, Column: 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WrapToken(tt.token)

			if got.Token.Type != tt.wantToken.Type {
				t.Errorf("WrapToken().Token.Type = %v, want %v", got.Token.Type, tt.wantToken.Type)
			}
			if got.Token.Value != tt.wantToken.Value {
				t.Errorf("WrapToken().Token.Value = %v, want %v", got.Token.Value, tt.wantToken.Value)
			}
			if got.Start != tt.wantStart {
				t.Errorf("WrapToken().Start = %v, want %v", got.Start, tt.wantStart)
			}
			if got.End != tt.wantEnd {
				t.Errorf("WrapToken().End = %v, want %v", got.End, tt.wantEnd)
			}
		})
	}
}

func TestWrapTokenPreservesTokenProperties(t *testing.T) {
	// Test that WrapToken preserves all token properties
	token := Token{
		Type:  TokenTypeSingleQuotedString,
		Value: "hello",
		Quote: '\'',
		Long:  false,
		Word:  &Word{Value: "hello"},
	}

	wrapped := WrapToken(token)

	if wrapped.Token.Type != token.Type {
		t.Errorf("WrapToken did not preserve Token.Type")
	}
	if wrapped.Token.Value != token.Value {
		t.Errorf("WrapToken did not preserve Token.Value")
	}
	if wrapped.Token.Quote != token.Quote {
		t.Errorf("WrapToken did not preserve Token.Quote")
	}
	if wrapped.Token.Long != token.Long {
		t.Errorf("WrapToken did not preserve Token.Long")
	}
	if wrapped.Token.Word != token.Word {
		t.Errorf("WrapToken did not preserve Token.Word pointer")
	}
}

func TestTokenWithSpanSlice(t *testing.T) {
	// Test working with slices of TokenWithSpan
	tokens := []TokenWithSpan{
		NewTokenWithSpan(TokenTypeSelect, "SELECT", Location{Line: 1, Column: 1}, Location{Line: 1, Column: 7}),
		NewTokenWithSpan(TokenTypeMul, "*", Location{Line: 1, Column: 8}, Location{Line: 1, Column: 9}),
		NewTokenWithSpan(TokenTypeFrom, "FROM", Location{Line: 1, Column: 10}, Location{Line: 1, Column: 14}),
		NewTokenWithSpan(TokenTypeIdentifier, "users", Location{Line: 1, Column: 15}, Location{Line: 1, Column: 20}),
	}

	if len(tokens) != 4 {
		t.Errorf("Expected 4 tokens, got %d", len(tokens))
	}

	// Verify first token
	if tokens[0].Token.Type != TokenTypeSelect {
		t.Errorf("First token type = %v, want TokenTypeSelect", tokens[0].Token.Type)
	}

	// Verify last token
	if tokens[3].Token.Value != "users" {
		t.Errorf("Last token value = %v, want 'users'", tokens[3].Token.Value)
	}
}

func BenchmarkTokenWithSpan(b *testing.B) {
	token := Token{Type: TokenTypeIdentifier, Value: "users"}
	start := Location{Line: 1, Column: 10}
	end := Location{Line: 1, Column: 15}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = TokenWithSpan{Token: token, Start: start, End: end}
	}
}

func BenchmarkWrapToken(b *testing.B) {
	token := Token{Type: TokenTypeIdentifier, Value: "users"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = WrapToken(token)
	}
}
