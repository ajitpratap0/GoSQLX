package keywords

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// TestKeywords_ContainsKeyword_CaseSensitive tests the containsKeyword function
// in case-sensitive mode to ensure proper coverage of both branches.
func TestKeywords_ContainsKeyword_CaseSensitive(t *testing.T) {
	// Test case-sensitive matching (ignoreCase = false)
	k := &Keywords{
		keywordMap:       make(map[string]Keyword),
		reservedKeywords: make(map[string]bool),
		ignoreCase:       false, // Case-sensitive mode
	}

	// Add a keyword manually for testing
	k.keywordMap["SELECT"] = Keyword{
		Word:     "SELECT",
		Type:     models.TokenTypeSelect,
		Reserved: true,
	}

	// Test exact match in case-sensitive mode
	if !k.containsKeyword("SELECT") {
		t.Error("containsKeyword('SELECT') should be true in case-sensitive mode")
	}

	// Test case mismatch in case-sensitive mode
	if k.containsKeyword("select") {
		t.Error("containsKeyword('select') should be false in case-sensitive mode")
	}

	// Test non-existent keyword
	if k.containsKeyword("NOTAKEYWORD") {
		t.Error("containsKeyword('NOTAKEYWORD') should be false")
	}
}

// TestKeywords_ContainsKeyword_CaseInsensitive tests the containsKeyword function
// in case-insensitive mode to ensure proper coverage of both branches.
func TestKeywords_ContainsKeyword_CaseInsensitive(t *testing.T) {
	// Test case-insensitive matching (ignoreCase = true)
	k := &Keywords{
		keywordMap:       make(map[string]Keyword),
		reservedKeywords: make(map[string]bool),
		ignoreCase:       true, // Case-insensitive mode
	}

	// Add a keyword manually for testing
	k.keywordMap["SELECT"] = Keyword{
		Word:     "SELECT",
		Type:     models.TokenTypeSelect,
		Reserved: true,
	}

	// Test exact match in case-insensitive mode
	if !k.containsKeyword("SELECT") {
		t.Error("containsKeyword('SELECT') should be true in case-insensitive mode")
	}

	// Test lowercase match in case-insensitive mode
	if !k.containsKeyword("select") {
		t.Error("containsKeyword('select') should be true in case-insensitive mode")
	}

	// Test mixed case match in case-insensitive mode
	if !k.containsKeyword("SeLeCt") {
		t.Error("containsKeyword('SeLeCt') should be true in case-insensitive mode")
	}

	// Test non-existent keyword
	if k.containsKeyword("NOTAKEYWORD") {
		t.Error("containsKeyword('NOTAKEYWORD') should be false")
	}
}

// TestKeywords_AddKeywordsWithCategory_Duplicates tests the addKeywordsWithCategory function
// to ensure it properly handles duplicate keywords and doesn't add them multiple times.
func TestKeywords_AddKeywordsWithCategory_Duplicates(t *testing.T) {
	k := &Keywords{
		keywordMap:       make(map[string]Keyword),
		reservedKeywords: make(map[string]bool),
		ignoreCase:       true,
	}

	// Add keywords with duplicates
	keywords := []Keyword{
		{Word: "SELECT", Type: models.TokenTypeSelect, Reserved: true},
		{Word: "FROM", Type: models.TokenTypeFrom, Reserved: true},
		{Word: "SELECT", Type: models.TokenTypeSelect, Reserved: true}, // Duplicate
	}

	k.addKeywordsWithCategory(keywords)

	// Verify only unique keywords were added
	if len(k.keywordMap) != 2 {
		t.Errorf("keywordMap should contain 2 unique keywords, got %d", len(k.keywordMap))
	}

	// Verify SELECT exists only once
	count := 0
	for word := range k.keywordMap {
		if strings.ToUpper(word) == "SELECT" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("SELECT should appear once in keywordMap, found %d times", count)
	}

	// Verify reserved keywords are properly tracked
	if len(k.reservedKeywords) != 2 {
		t.Errorf("reservedKeywords should contain 2 entries, got %d", len(k.reservedKeywords))
	}
}

// TestKeywords_AddKeywordsWithCategory_CaseSensitive tests addKeywordsWithCategory
// in case-sensitive mode to cover the else branch.
func TestKeywords_AddKeywordsWithCategory_CaseSensitive(t *testing.T) {
	k := &Keywords{
		keywordMap:       make(map[string]Keyword),
		reservedKeywords: make(map[string]bool),
		ignoreCase:       false, // Case-sensitive mode
	}

	keywords := []Keyword{
		{Word: "SELECT", Type: models.TokenTypeSelect, Reserved: true},
		{Word: "FROM", Type: models.TokenTypeFrom, Reserved: true},
		{Word: "WHERE", Type: models.TokenTypeWhere, Reserved: false}, // Non-reserved
	}

	k.addKeywordsWithCategory(keywords)

	// Verify keywords were added with exact case
	if _, exists := k.keywordMap["SELECT"]; !exists {
		t.Error("SELECT should exist in keywordMap with exact case")
	}
	if _, exists := k.keywordMap["FROM"]; !exists {
		t.Error("FROM should exist in keywordMap with exact case")
	}

	// Verify reserved keywords are tracked with exact case
	if _, exists := k.reservedKeywords["SELECT"]; !exists {
		t.Error("SELECT should exist in reservedKeywords with exact case")
	}
	if _, exists := k.reservedKeywords["FROM"]; !exists {
		t.Error("FROM should exist in reservedKeywords with exact case")
	}

	// Verify non-reserved keyword is not in reservedKeywords
	if _, exists := k.reservedKeywords["WHERE"]; exists {
		t.Error("WHERE should not exist in reservedKeywords (it's not reserved)")
	}

	// Verify total counts
	if len(k.keywordMap) != 3 {
		t.Errorf("keywordMap should contain 3 keywords, got %d", len(k.keywordMap))
	}
	if len(k.reservedKeywords) != 2 {
		t.Errorf("reservedKeywords should contain 2 entries, got %d", len(k.reservedKeywords))
	}
}

// TestKeywords_AddKeywordsWithCategory_NonReserved tests addKeywordsWithCategory
// with non-reserved keywords to cover the conditional branches.
func TestKeywords_AddKeywordsWithCategory_NonReserved(t *testing.T) {
	k := &Keywords{
		keywordMap:       make(map[string]Keyword),
		reservedKeywords: make(map[string]bool),
		ignoreCase:       true,
	}

	keywords := []Keyword{
		{Word: "ROW_NUMBER", Type: models.TokenTypeKeyword, Reserved: false},
		{Word: "RANK", Type: models.TokenTypeKeyword, Reserved: false},
		{Word: "COUNT", Type: models.TokenTypeCount, Reserved: true},
	}

	k.addKeywordsWithCategory(keywords)

	// Verify non-reserved keywords are in keywordMap
	if _, exists := k.keywordMap["ROW_NUMBER"]; !exists {
		t.Error("ROW_NUMBER should exist in keywordMap")
	}
	if _, exists := k.keywordMap["RANK"]; !exists {
		t.Error("RANK should exist in keywordMap")
	}

	// Verify non-reserved keywords are NOT in reservedKeywords
	if _, exists := k.reservedKeywords["ROW_NUMBER"]; exists {
		t.Error("ROW_NUMBER should not exist in reservedKeywords")
	}
	if _, exists := k.reservedKeywords["RANK"]; exists {
		t.Error("RANK should not exist in reservedKeywords")
	}

	// Verify reserved keyword IS in reservedKeywords
	if _, exists := k.reservedKeywords["COUNT"]; !exists {
		t.Error("COUNT should exist in reservedKeywords")
	}

	// Verify counts
	if len(k.keywordMap) != 3 {
		t.Errorf("keywordMap should contain 3 keywords, got %d", len(k.keywordMap))
	}
	if len(k.reservedKeywords) != 1 {
		t.Errorf("reservedKeywords should contain 1 entry, got %d", len(k.reservedKeywords))
	}
}

// TestKeywords_GetTokenType_CaseSensitive tests GetTokenType in case-sensitive mode
// to cover the else branch in the function.
func TestKeywords_GetTokenType_CaseSensitive(t *testing.T) {
	k := &Keywords{
		keywordMap:       make(map[string]Keyword),
		reservedKeywords: make(map[string]bool),
		ignoreCase:       false, // Case-sensitive mode
	}

	// Add keywords manually
	k.keywordMap["SELECT"] = Keyword{
		Word:     "SELECT",
		Type:     models.TokenTypeSelect,
		Reserved: true,
	}
	k.keywordMap["FROM"] = Keyword{
		Word:     "FROM",
		Type:     models.TokenTypeFrom,
		Reserved: true,
	}

	// Test exact case match
	if tokenType := k.GetTokenType("SELECT"); tokenType != models.TokenTypeSelect {
		t.Errorf("GetTokenType('SELECT') = %v, want %v", tokenType, models.TokenTypeSelect)
	}

	// Test case mismatch (should return TokenTypeWord)
	if tokenType := k.GetTokenType("select"); tokenType != models.TokenTypeWord {
		t.Errorf("GetTokenType('select') = %v, want %v in case-sensitive mode", tokenType, models.TokenTypeWord)
	}

	// Test non-existent keyword
	if tokenType := k.GetTokenType("NOTAKEYWORD"); tokenType != models.TokenTypeWord {
		t.Errorf("GetTokenType('NOTAKEYWORD') = %v, want %v", tokenType, models.TokenTypeWord)
	}
}

// TestKeywords_GetTokenType_EdgeCases tests GetTokenType with edge cases
// to ensure comprehensive coverage.
func TestKeywords_GetTokenType_EdgeCases(t *testing.T) {
	k := New(DialectGeneric, true)

	tests := []struct {
		name       string
		word       string
		expectType models.TokenType
	}{
		{
			name:       "empty string",
			word:       "",
			expectType: models.TokenTypeWord,
		},
		{
			name:       "whitespace only",
			word:       "   ",
			expectType: models.TokenTypeWord,
		},
		{
			name:       "special characters",
			word:       "@#$%",
			expectType: models.TokenTypeWord,
		},
		{
			name:       "numeric string",
			word:       "12345",
			expectType: models.TokenTypeWord,
		},
		{
			name:       "mixed alphanumeric",
			word:       "SELECT123",
			expectType: models.TokenTypeWord,
		},
		{
			name:       "valid keyword with trailing space",
			word:       "SELECT ",
			expectType: models.TokenTypeWord, // Should not match due to trailing space
		},
		{
			name:       "valid keyword with leading space",
			word:       " SELECT",
			expectType: models.TokenTypeWord, // Should not match due to leading space
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenType := k.GetTokenType(tt.word)
			if tokenType != tt.expectType {
				t.Errorf("GetTokenType(%q) = %v, want %v", tt.word, tokenType, tt.expectType)
			}
		})
	}
}

// TestKeywords_InitializationCoverage tests all initialization paths
// to ensure comprehensive coverage of the New function.
func TestKeywords_InitializationCoverage(t *testing.T) {
	dialects := []struct {
		name    string
		dialect SQLDialect
	}{
		{"generic", DialectGeneric},
		{"mysql", DialectMySQL},
		{"postgresql", DialectPostgreSQL},
		{"sqlite", DialectSQLite},
		{"unknown", DialectUnknown},
	}

	for _, tc := range dialects {
		t.Run(tc.name, func(t *testing.T) {
			dialect := tc.dialect
			k := New(dialect, true)
			if k == nil {
				t.Fatal("New() should never return nil")
			}

			// Verify critical maps are initialized
			if k.keywordMap == nil {
				t.Error("keywordMap should be initialized")
			}
			if k.reservedKeywords == nil {
				t.Error("reservedKeywords should be initialized")
			}
			// Note: DMLKeywords and CompoundKeywords are only initialized by NewKeywords(),
			// not by New() - that's expected behavior

			// Verify common keywords exist
			if !k.IsKeyword("SELECT") {
				t.Error("Common keyword SELECT should exist for all dialects")
			}
		})
	}
}

// TestKeywords_DialectSpecificCoverage tests each dialect's specific initialization
// to ensure all dialect-specific branches are covered.
func TestKeywords_DialectSpecificCoverage(t *testing.T) {
	t.Run("MySQL dialect with specific keywords", func(t *testing.T) {
		k := New(DialectMySQL, true)
		mysqlSpecific := []string{"ZEROFILL", "UNSIGNED", "FORCE", "BINARY"}
		for _, word := range mysqlSpecific {
			if !k.IsKeyword(word) {
				t.Errorf("MySQL-specific keyword %q should exist", word)
			}
		}
	})

	t.Run("PostgreSQL dialect with specific keywords", func(t *testing.T) {
		k := New(DialectPostgreSQL, true)
		postgresSpecific := []string{"ILIKE", "MATERIALIZED", "RETURNING", "FREEZE"}
		for _, word := range postgresSpecific {
			if !k.IsKeyword(word) {
				t.Errorf("PostgreSQL-specific keyword %q should exist", word)
			}
		}
	})

	t.Run("SQLite dialect with specific keywords", func(t *testing.T) {
		k := New(DialectSQLite, true)
		sqliteSpecific := []string{"AUTOINCREMENT", "VACUUM", "VIRTUAL"}
		for _, word := range sqliteSpecific {
			if !k.IsKeyword(word) {
				t.Errorf("SQLite-specific keyword %q should exist", word)
			}
		}
	})

	t.Run("Generic dialect should not have dialect-specific keywords", func(t *testing.T) {
		k := New(DialectGeneric, true)
		dialectSpecific := []string{"ZEROFILL", "ILIKE", "AUTOINCREMENT"}
		for _, word := range dialectSpecific {
			if k.IsKeyword(word) {
				t.Errorf("Generic dialect should not have dialect-specific keyword %q", word)
			}
		}
	})

	t.Run("Unknown dialect should behave like generic", func(t *testing.T) {
		k := New(DialectUnknown, true)
		if k.IsKeyword("ZEROFILL") {
			t.Error("Unknown dialect should not have MySQL-specific keywords")
		}
		if k.IsKeyword("ILIKE") {
			t.Error("Unknown dialect should not have PostgreSQL-specific keywords")
		}
		// But should have common keywords
		if !k.IsKeyword("SELECT") {
			t.Error("Unknown dialect should have common keywords")
		}
	})
}
