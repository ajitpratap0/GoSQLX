package models

import "testing"

func TestToken(t *testing.T) {
	tests := []struct {
		name      string
		token     Token
		wantType  TokenType
		wantValue string
		wantQuote rune
		wantLong  bool
	}{
		{
			name:      "simple token",
			token:     Token{Type: TokenTypeIdentifier, Value: "users"},
			wantType:  TokenTypeIdentifier,
			wantValue: "users",
			wantQuote: 0,
			wantLong:  false,
		},
		{
			name:      "quoted string token",
			token:     Token{Type: TokenTypeSingleQuotedString, Value: "John", Quote: '\''},
			wantType:  TokenTypeSingleQuotedString,
			wantValue: "John",
			wantQuote: '\'',
			wantLong:  false,
		},
		{
			name:      "long number token",
			token:     Token{Type: TokenTypeNumber, Value: "1234567890", Long: true},
			wantType:  TokenTypeNumber,
			wantValue: "1234567890",
			wantQuote: 0,
			wantLong:  true,
		},
		{
			name:      "EOF token",
			token:     Token{Type: TokenTypeEOF, Value: ""},
			wantType:  TokenTypeEOF,
			wantValue: "",
			wantQuote: 0,
			wantLong:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.token.Type != tt.wantType {
				t.Errorf("Token.Type = %v, want %v", tt.token.Type, tt.wantType)
			}
			if tt.token.Value != tt.wantValue {
				t.Errorf("Token.Value = %v, want %v", tt.token.Value, tt.wantValue)
			}
			if tt.token.Quote != tt.wantQuote {
				t.Errorf("Token.Quote = %v, want %v", tt.token.Quote, tt.wantQuote)
			}
			if tt.token.Long != tt.wantLong {
				t.Errorf("Token.Long = %v, want %v", tt.token.Long, tt.wantLong)
			}
		})
	}
}

func TestWord(t *testing.T) {
	tests := []struct {
		name           string
		word           Word
		wantValue      string
		wantQuoteStyle rune
		wantKeyword    bool
	}{
		{
			name:           "simple identifier",
			word:           Word{Value: "users", QuoteStyle: 0, Keyword: nil},
			wantValue:      "users",
			wantQuoteStyle: 0,
			wantKeyword:    false,
		},
		{
			name:           "quoted identifier",
			word:           Word{Value: "my-table", QuoteStyle: '"', Keyword: nil},
			wantValue:      "my-table",
			wantQuoteStyle: '"',
			wantKeyword:    false,
		},
		{
			name: "keyword",
			word: Word{
				Value:      "SELECT",
				QuoteStyle: 0,
				Keyword:    &Keyword{Word: "SELECT", Reserved: true},
			},
			wantValue:      "SELECT",
			wantQuoteStyle: 0,
			wantKeyword:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.word.Value != tt.wantValue {
				t.Errorf("Word.Value = %v, want %v", tt.word.Value, tt.wantValue)
			}
			if tt.word.QuoteStyle != tt.wantQuoteStyle {
				t.Errorf("Word.QuoteStyle = %v, want %v", tt.word.QuoteStyle, tt.wantQuoteStyle)
			}
			hasKeyword := tt.word.Keyword != nil
			if hasKeyword != tt.wantKeyword {
				t.Errorf("Word.Keyword != nil = %v, want %v", hasKeyword, tt.wantKeyword)
			}
		})
	}
}

func TestKeyword(t *testing.T) {
	tests := []struct {
		name         string
		keyword      Keyword
		wantWord     string
		wantReserved bool
	}{
		{
			name:         "reserved keyword",
			keyword:      Keyword{Word: "SELECT", Reserved: true},
			wantWord:     "SELECT",
			wantReserved: true,
		},
		{
			name:         "non-reserved keyword",
			keyword:      Keyword{Word: "ACTION", Reserved: false},
			wantWord:     "ACTION",
			wantReserved: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.keyword.Word != tt.wantWord {
				t.Errorf("Keyword.Word = %v, want %v", tt.keyword.Word, tt.wantWord)
			}
			if tt.keyword.Reserved != tt.wantReserved {
				t.Errorf("Keyword.Reserved = %v, want %v", tt.keyword.Reserved, tt.wantReserved)
			}
		})
	}
}

func TestWhitespace(t *testing.T) {
	tests := []struct {
		name        string
		whitespace  Whitespace
		wantType    WhitespaceType
		wantContent string
		wantPrefix  string
	}{
		{
			name:        "space",
			whitespace:  Whitespace{Type: WhitespaceTypeSpace, Content: "", Prefix: ""},
			wantType:    WhitespaceTypeSpace,
			wantContent: "",
			wantPrefix:  "",
		},
		{
			name:        "newline",
			whitespace:  Whitespace{Type: WhitespaceTypeNewline, Content: "", Prefix: ""},
			wantType:    WhitespaceTypeNewline,
			wantContent: "",
			wantPrefix:  "",
		},
		{
			name:        "single line comment",
			whitespace:  Whitespace{Type: WhitespaceTypeSingleLineComment, Content: "comment text", Prefix: "--"},
			wantType:    WhitespaceTypeSingleLineComment,
			wantContent: "comment text",
			wantPrefix:  "--",
		},
		{
			name:        "multi-line comment",
			whitespace:  Whitespace{Type: WhitespaceTypeMultiLineComment, Content: "comment\ntext", Prefix: ""},
			wantType:    WhitespaceTypeMultiLineComment,
			wantContent: "comment\ntext",
			wantPrefix:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.whitespace.Type != tt.wantType {
				t.Errorf("Whitespace.Type = %v, want %v", tt.whitespace.Type, tt.wantType)
			}
			if tt.whitespace.Content != tt.wantContent {
				t.Errorf("Whitespace.Content = %v, want %v", tt.whitespace.Content, tt.wantContent)
			}
			if tt.whitespace.Prefix != tt.wantPrefix {
				t.Errorf("Whitespace.Prefix = %v, want %v", tt.whitespace.Prefix, tt.wantPrefix)
			}
		})
	}
}

func TestWhitespaceType(t *testing.T) {
	types := []WhitespaceType{
		WhitespaceTypeSpace,
		WhitespaceTypeNewline,
		WhitespaceTypeTab,
		WhitespaceTypeSingleLineComment,
		WhitespaceTypeMultiLineComment,
	}

	// Ensure all types have unique values
	seen := make(map[WhitespaceType]bool)
	for _, wsType := range types {
		if seen[wsType] {
			t.Errorf("Duplicate WhitespaceType value: %d", wsType)
		}
		seen[wsType] = true
	}

	if len(seen) != 5 {
		t.Errorf("Expected 5 unique WhitespaceType values, got %d", len(seen))
	}
}

func TestTokenWithWord(t *testing.T) {
	word := &Word{Value: "SELECT", Keyword: &Keyword{Word: "SELECT", Reserved: true}}
	token := Token{
		Type:  TokenTypeWord,
		Value: "SELECT",
		Word:  word,
	}

	if token.Word == nil {
		t.Error("Token.Word should not be nil")
	}
	if token.Word.Value != "SELECT" {
		t.Errorf("Token.Word.Value = %v, want SELECT", token.Word.Value)
	}
	if token.Word.Keyword == nil {
		t.Error("Token.Word.Keyword should not be nil")
	}
	if !token.Word.Keyword.Reserved {
		t.Error("Token.Word.Keyword.Reserved should be true")
	}
}

func BenchmarkToken(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Token{Type: TokenTypeIdentifier, Value: "users"}
	}
}

func BenchmarkWord(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Word{Value: "SELECT", Keyword: &Keyword{Word: "SELECT", Reserved: true}}
	}
}
