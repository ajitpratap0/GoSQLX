package tokenizer

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

func TestTokenizer_DollarQuotedStrings(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []struct {
			tokenType models.TokenType
			value     string
		}
		wantErr bool
	}{
		{
			name:  "Simple dollar-quoted string $$...$$",
			input: "SELECT $$hello world$$",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeSelect, "SELECT"},
				{models.TokenTypeDollarQuotedString, "hello world"},
			},
		},
		{
			name:  "Tagged dollar-quoted string $tag$...$tag$",
			input: "SELECT $body$content here$body$",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeSelect, "SELECT"},
				{models.TokenTypeDollarQuotedString, "content here"},
			},
		},
		{
			name:  "Empty content $$$$",
			input: "SELECT $$$$",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeSelect, "SELECT"},
				{models.TokenTypeDollarQuotedString, ""},
			},
		},
		{
			name:  "Function body with $fn$ tag",
			input: "$fn$CREATE FUNCTION foo() RETURNS void$fn$",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeDollarQuotedString, "CREATE FUNCTION foo() RETURNS void"},
			},
		},
		{
			name:  "Multiline content",
			input: "$$line1\nline2\nline3$$",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeDollarQuotedString, "line1\nline2\nline3"},
			},
		},
		{
			name:  "Content with single quotes",
			input: "$$it's a test with 'quotes'$$",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeDollarQuotedString, "it's a test with 'quotes'"},
			},
		},
		{
			name:  "Nested-looking dollar signs in content",
			input: "$outer$contains $$ signs$outer$",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeDollarQuotedString, "contains $$ signs"},
			},
		},
		{
			name:  "Tag with underscore",
			input: "$my_tag$content$my_tag$",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeDollarQuotedString, "content"},
			},
		},
		{
			name:    "Unterminated dollar-quoted string",
			input:   "$$unterminated",
			wantErr: true,
		},
		{
			name:    "Unterminated tagged dollar-quoted string",
			input:   "$tag$unterminated",
			wantErr: true,
		},
		{
			name:  "Dollar-quoted in CREATE FUNCTION context",
			input: "CREATE $$BEGIN RETURN; END;$$ AS plpgsql",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypeCreate, "CREATE"},
				{models.TokenTypeDollarQuotedString, "BEGIN RETURN; END;"},
				{models.TokenTypeAs, "AS"},
				{models.TokenTypeIdentifier, "plpgsql"},
			},
		},
		{
			name:  "Positional param before dollar-quoted string",
			input: "$1 $$text$$",
			expected: []struct {
				tokenType models.TokenType
				value     string
			}{
				{models.TokenTypePlaceholder, "$1"},
				{models.TokenTypeDollarQuotedString, "text"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz := GetTokenizer()
			defer PutTokenizer(tkz)

			tokens, err := tkz.Tokenize([]byte(tt.input))

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Filter out EOF
			var filtered []models.TokenWithSpan
			for _, tok := range tokens {
				if tok.Token.Type != models.TokenTypeEOF {
					filtered = append(filtered, tok)
				}
			}

			if len(filtered) != len(tt.expected) {
				var types []string
				for _, tok := range filtered {
					types = append(types, tok.Token.Type.String()+"("+tok.Token.Value+")")
				}
				t.Fatalf("expected %d tokens, got %d: %s", len(tt.expected), len(filtered), strings.Join(types, ", "))
			}

			for i, exp := range tt.expected {
				if filtered[i].Token.Type != exp.tokenType {
					t.Errorf("token %d: expected type %v, got %v", i, exp.tokenType, filtered[i].Token.Type)
				}
				if filtered[i].Token.Value != exp.value {
					t.Errorf("token %d: expected value %q, got %q", i, exp.value, filtered[i].Token.Value)
				}
			}
		})
	}
}
