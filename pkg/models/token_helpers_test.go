package models

import "testing"

func TestNewToken(t *testing.T) {
	tests := []struct {
		name      string
		tokenType TokenType
		value     string
		wantType  TokenType
		wantValue string
	}{
		{
			name:      "identifier token",
			tokenType: TokenTypeIdentifier,
			value:     "users",
			wantType:  TokenTypeIdentifier,
			wantValue: "users",
		},
		{
			name:      "SELECT keyword",
			tokenType: TokenTypeSelect,
			value:     "SELECT",
			wantType:  TokenTypeSelect,
			wantValue: "SELECT",
		},
		{
			name:      "number token",
			tokenType: TokenTypeNumber,
			value:     "42",
			wantType:  TokenTypeNumber,
			wantValue: "42",
		},
		{
			name:      "EOF token",
			tokenType: TokenTypeEOF,
			value:     "",
			wantType:  TokenTypeEOF,
			wantValue: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewToken(tt.tokenType, tt.value)

			if got.Type != tt.wantType {
				t.Errorf("NewToken().Type = %v, want %v", got.Type, tt.wantType)
			}
			if got.Value != tt.wantValue {
				t.Errorf("NewToken().Value = %v, want %v", got.Value, tt.wantValue)
			}
		})
	}
}

func TestNewTokenWithSpan(t *testing.T) {
	tests := []struct {
		name      string
		tokenType TokenType
		value     string
		start     Location
		end       Location
		wantType  TokenType
		wantValue string
		wantStart Location
		wantEnd   Location
	}{
		{
			name:      "simple token with span",
			tokenType: TokenTypeIdentifier,
			value:     "users",
			start:     Location{Line: 1, Column: 10},
			end:       Location{Line: 1, Column: 15},
			wantType:  TokenTypeIdentifier,
			wantValue: "users",
			wantStart: Location{Line: 1, Column: 10},
			wantEnd:   Location{Line: 1, Column: 15},
		},
		{
			name:      "keyword with span",
			tokenType: TokenTypeSelect,
			value:     "SELECT",
			start:     Location{Line: 1, Column: 1},
			end:       Location{Line: 1, Column: 7},
			wantType:  TokenTypeSelect,
			wantValue: "SELECT",
			wantStart: Location{Line: 1, Column: 1},
			wantEnd:   Location{Line: 1, Column: 7},
		},
		{
			name:      "multi-line token",
			tokenType: TokenTypeSingleQuotedString,
			value:     "hello\nworld",
			start:     Location{Line: 1, Column: 10},
			end:       Location{Line: 2, Column: 6},
			wantType:  TokenTypeSingleQuotedString,
			wantValue: "hello\nworld",
			wantStart: Location{Line: 1, Column: 10},
			wantEnd:   Location{Line: 2, Column: 6},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewTokenWithSpan(tt.tokenType, tt.value, tt.start, tt.end)

			if got.Token.Type != tt.wantType {
				t.Errorf("NewTokenWithSpan().Token.Type = %v, want %v", got.Token.Type, tt.wantType)
			}
			if got.Token.Value != tt.wantValue {
				t.Errorf("NewTokenWithSpan().Token.Value = %v, want %v", got.Token.Value, tt.wantValue)
			}
			if got.Start != tt.wantStart {
				t.Errorf("NewTokenWithSpan().Start = %v, want %v", got.Start, tt.wantStart)
			}
			if got.End != tt.wantEnd {
				t.Errorf("NewTokenWithSpan().End = %v, want %v", got.End, tt.wantEnd)
			}
		})
	}
}

func TestNewEOFToken(t *testing.T) {
	tests := []struct {
		name     string
		pos      Location
		wantPos  Location
		wantType TokenType
	}{
		{
			name:     "EOF at start",
			pos:      Location{Line: 1, Column: 1},
			wantPos:  Location{Line: 1, Column: 1},
			wantType: TokenTypeEOF,
		},
		{
			name:     "EOF at end of file",
			pos:      Location{Line: 100, Column: 50},
			wantPos:  Location{Line: 100, Column: 50},
			wantType: TokenTypeEOF,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewEOFToken(tt.pos)

			if got.Token.Type != tt.wantType {
				t.Errorf("NewEOFToken().Token.Type = %v, want %v", got.Token.Type, tt.wantType)
			}
			if got.Token.Value != "" {
				t.Errorf("NewEOFToken().Token.Value = %v, want empty string", got.Token.Value)
			}
			if got.Start != tt.wantPos {
				t.Errorf("NewEOFToken().Start = %v, want %v", got.Start, tt.wantPos)
			}
			if got.End != tt.wantPos {
				t.Errorf("NewEOFToken().End = %v, want %v", got.End, tt.wantPos)
			}
		})
	}
}

func TestTokenAtLocation(t *testing.T) {
	tests := []struct {
		name      string
		token     Token
		start     Location
		end       Location
		wantStart Location
		wantEnd   Location
	}{
		{
			name:      "identifier at location",
			token:     Token{Type: TokenTypeIdentifier, Value: "users"},
			start:     Location{Line: 1, Column: 15},
			end:       Location{Line: 1, Column: 20},
			wantStart: Location{Line: 1, Column: 15},
			wantEnd:   Location{Line: 1, Column: 20},
		},
		{
			name:      "operator at location",
			token:     Token{Type: TokenTypeEq, Value: "="},
			start:     Location{Line: 2, Column: 10},
			end:       Location{Line: 2, Column: 11},
			wantStart: Location{Line: 2, Column: 10},
			wantEnd:   Location{Line: 2, Column: 11},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TokenAtLocation(tt.token, tt.start, tt.end)

			if got.Token.Type != tt.token.Type {
				t.Errorf("TokenAtLocation().Token.Type = %v, want %v", got.Token.Type, tt.token.Type)
			}
			if got.Token.Value != tt.token.Value {
				t.Errorf("TokenAtLocation().Token.Value = %v, want %v", got.Token.Value, tt.token.Value)
			}
			if got.Start != tt.wantStart {
				t.Errorf("TokenAtLocation().Start = %v, want %v", got.Start, tt.wantStart)
			}
			if got.End != tt.wantEnd {
				t.Errorf("TokenAtLocation().End = %v, want %v", got.End, tt.wantEnd)
			}
		})
	}
}

func BenchmarkNewToken(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewToken(TokenTypeIdentifier, "users")
	}
}

func BenchmarkNewTokenWithSpan(b *testing.B) {
	start := Location{Line: 1, Column: 10}
	end := Location{Line: 1, Column: 15}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewTokenWithSpan(TokenTypeIdentifier, "users", start, end)
	}
}

func BenchmarkNewEOFToken(b *testing.B) {
	pos := Location{Line: 1, Column: 1}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewEOFToken(pos)
	}
}

func BenchmarkTokenAtLocation(b *testing.B) {
	token := Token{Type: TokenTypeIdentifier, Value: "users"}
	start := Location{Line: 1, Column: 10}
	end := Location{Line: 1, Column: 15}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = TokenAtLocation(token, start, end)
	}
}
