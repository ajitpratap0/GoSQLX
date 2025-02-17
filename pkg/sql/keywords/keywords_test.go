package keywords

import (
	"github.com/ajitpratapsingh/GoSQLX/pkg/models"
	"testing"
)

func TestKeywords_IsKeyword(t *testing.T) {
	k := New(DialectGeneric, true) // Use generic dialect with case-insensitive matching
	tests := []struct {
		word     string
		expected bool
	}{
		{"SELECT", true},
		{"FROM", true},
		{"WHERE", true},
		{"NOTAKEYWORD", false},
		{"select", true}, // Case insensitive
		{"FROM", true},   // Case sensitive
		{"noTAkeYWoRd", false},
	}

	for _, tt := range tests {
		if got := k.IsKeyword(tt.word); got != tt.expected {
			t.Errorf("IsKeyword(%q) = %v, want %v", tt.word, got, tt.expected)
		}
	}
}

func TestKeywords_IsReserved(t *testing.T) {
	k := New(DialectGeneric, true) // Use generic dialect with case-insensitive matching
	tests := []struct {
		word     string
		expected bool
	}{
		{"SELECT", true}, // Reserved keyword
		{"COUNT", true},  // Reserved keyword
		{"FROM", true},   // Reserved keyword
		{"select", true}, // Case insensitive
		{"count", true},  // Case insensitive
		{"NOTAKEYWORD", false},
	}

	for _, tt := range tests {
		if got := k.IsReserved(tt.word); got != tt.expected {
			t.Errorf("IsReserved(%q) = %v, want %v", tt.word, got, tt.expected)
		}
	}
}

func TestKeywords_GetKeyword(t *testing.T) {
	k := New(DialectGeneric, true) // Use generic dialect with case-insensitive matching
	tests := []struct {
		word             string
		expectFound      bool
		expectType       models.TokenType
		expectReserved   bool
		expectTableAlias bool
	}{
		{"SELECT", true, models.TokenTypeSelect, true, true},
		{"FROM", true, models.TokenTypeFrom, true, true},
		{"COUNT", true, models.TokenTypeCount, true, true},
		{"NOTAKEYWORD", false, 0, false, false},
		{"select", true, models.TokenTypeSelect, true, true}, // Case insensitive
		{"AS", true, models.TokenTypeKeyword, true, true},    // Table alias keyword
	}

	for _, tt := range tests {
		kw, found := k.GetKeyword(tt.word)
		if found != tt.expectFound {
			t.Errorf("GetKeyword(%q) found = %v, want %v", tt.word, found, tt.expectFound)
			continue
		}
		if found {
			if kw.Type != tt.expectType {
				t.Errorf("GetKeyword(%q) type = %v, want %v", tt.word, kw.Type, tt.expectType)
			}
			if kw.Reserved != tt.expectReserved {
				t.Errorf("GetKeyword(%q) reserved = %v, want %v", tt.word, kw.Reserved, tt.expectReserved)
			}
			if kw.ReservedForTableAlias != tt.expectTableAlias {
				t.Errorf("GetKeyword(%q) reservedForTableAlias = %v, want %v", tt.word, kw.ReservedForTableAlias, tt.expectTableAlias)
			}
		}
	}
}

func TestKeywords_GetTokenType(t *testing.T) {
	k := New(DialectGeneric, true) // Use generic dialect with case-insensitive matching
	tests := []struct {
		word       string
		expectType models.TokenType
	}{
		{"SELECT", models.TokenTypeSelect},
		{"FROM", models.TokenTypeFrom},
		{"COUNT", models.TokenTypeCount},
		{"NOTAKEYWORD", models.TokenTypeUnknown},
		{"select", models.TokenTypeSelect}, // Case insensitive
	}

	for _, tt := range tests {
		if got := k.GetTokenType(tt.word); got != tt.expectType {
			t.Errorf("GetTokenType(%q) = %v, want %v", tt.word, got, tt.expectType)
		}
	}
}

func TestKeywords_CompoundKeywords(t *testing.T) {
	k := New(DialectGeneric, true) // Use generic dialect with case-insensitive matching
	compounds := k.CompoundKeywords()

	// Test specific compound keywords
	tests := []struct {
		compound   string
		expectType models.TokenType
	}{
		{"GROUP BY", models.TokenTypeGroupBy},
		{"ORDER BY", models.TokenTypeOrderBy},
		{"LEFT JOIN", models.TokenTypeLeftJoin},
	}

	for _, tt := range tests {
		if tokenType, ok := compounds[tt.compound]; !ok || tokenType != tt.expectType {
			t.Errorf("CompoundKeywords()[%q] = %v, want %v", tt.compound, tokenType, tt.expectType)
		}
	}
}

func TestKeywords_IsCompoundKeywordStart(t *testing.T) {
	k := New(DialectGeneric, true) // Use generic dialect with case-insensitive matching
	tests := []struct {
		word     string
		expected bool
	}{
		{"GROUP", true},
		{"ORDER", true},
		{"LEFT", true},
		{"BY", false},
		{"JOIN", false},
		{"SELECT", false},
		{"group", true}, // Case insensitive
		{"order", true}, // Case insensitive
	}

	for _, tt := range tests {
		if got := k.IsCompoundKeywordStart(tt.word); got != tt.expected {
			t.Errorf("IsCompoundKeywordStart(%q) = %v, want %v", tt.word, got, tt.expected)
		}
	}
}
