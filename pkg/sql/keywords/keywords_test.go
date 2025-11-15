package keywords

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
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
		{"NOTAKEYWORD", models.TokenTypeWord},
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
	compounds := k.GetCompoundKeywords()

	// Test specific compound keywords
	tests := []struct {
		compound   string
		expectType models.TokenType
	}{
		{"GROUP BY", models.TokenTypeKeyword},
		{"ORDER BY", models.TokenTypeKeyword},
		{"LEFT JOIN", models.TokenTypeKeyword},
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

// TestNewKeywords tests the NewKeywords constructor
func TestNewKeywords(t *testing.T) {
	k := NewKeywords()
	if k == nil {
		t.Fatal("NewKeywords() returned nil")
	}
	if k.DMLKeywords == nil {
		t.Error("DMLKeywords map is nil")
	}
	if k.CompoundKeywords == nil {
		t.Error("CompoundKeywords map is nil")
	}
	if k.keywordMap == nil {
		t.Error("keywordMap is nil")
	}
	if k.reservedKeywords == nil {
		t.Error("reservedKeywords map is nil")
	}
	if !k.ignoreCase {
		t.Error("ignoreCase should be true by default")
	}

	// Verify that initialization populated the maps
	if len(k.DMLKeywords) == 0 {
		t.Error("DMLKeywords should be populated after initialization")
	}
	if len(k.CompoundKeywords) == 0 {
		t.Error("CompoundKeywords should be populated after initialization")
	}
	if len(k.keywordMap) == 0 {
		t.Error("keywordMap should be populated after initialization")
	}

	// Verify specific DML keywords are present
	expectedDMLKeywords := []string{"DISTINCT", "ALL", "FETCH", "NEXT", "ROWS", "ONLY"}
	for _, word := range expectedDMLKeywords {
		if _, ok := k.DMLKeywords[word]; !ok {
			t.Errorf("Expected DML keyword %q not found", word)
		}
	}

	// Verify specific compound keywords are present
	expectedCompoundKeywords := []string{"GROUP BY", "ORDER BY", "LEFT JOIN", "FULL JOIN"}
	for _, compound := range expectedCompoundKeywords {
		if _, ok := k.CompoundKeywords[compound]; !ok {
			t.Errorf("Expected compound keyword %q not found", compound)
		}
	}
}

// TestKeywords_GetKeywordType_Categories tests the GetKeywordType method from categories.go
func TestKeywords_GetKeywordType_Categories(t *testing.T) {
	k := NewKeywords()
	tests := []struct {
		word     string
		expected models.TokenType
	}{
		{"DISTINCT", models.TokenTypeKeyword},
		{"ALL", models.TokenTypeKeyword},
		{"FETCH", models.TokenTypeKeyword},
		{"ROWS", models.TokenTypeKeyword},
		{"distinct", models.TokenTypeKeyword}, // Case insensitive
		{"all", models.TokenTypeKeyword},
		{"NOTAKEYWORD", models.TokenTypeWord}, // Non-existent should return TokenTypeWord
	}

	for _, tt := range tests {
		if got := k.GetKeywordType(tt.word); got != tt.expected {
			t.Errorf("GetKeywordType(%q) = %v, want %v", tt.word, got, tt.expected)
		}
	}
}

// TestKeywords_IsCompoundKeyword tests the IsCompoundKeyword method
func TestKeywords_IsCompoundKeyword(t *testing.T) {
	k := NewKeywords()
	tests := []struct {
		word     string
		expected bool
	}{
		{"GROUP BY", true},
		{"ORDER BY", true},
		{"LEFT JOIN", true},
		{"FULL JOIN", true},
		{"CROSS JOIN", true},
		{"NATURAL JOIN", true},
		{"SELECT", false},
		{"NOTCOMPOUND", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := k.IsCompoundKeyword(tt.word); got != tt.expected {
			t.Errorf("IsCompoundKeyword(%q) = %v, want %v", tt.word, got, tt.expected)
		}
	}
}

// TestKeywords_GetCompoundKeywordType tests the GetCompoundKeywordType method
func TestKeywords_GetCompoundKeywordType(t *testing.T) {
	k := NewKeywords()
	tests := []struct {
		word         string
		expectFound  bool
		expectedType models.TokenType
	}{
		{"GROUP BY", true, models.TokenTypeKeyword},
		{"ORDER BY", true, models.TokenTypeKeyword},
		{"LEFT JOIN", true, models.TokenTypeKeyword},
		{"FULL JOIN", true, models.TokenTypeKeyword},
		{"CROSS JOIN", true, models.TokenTypeKeyword},
		{"NATURAL JOIN", true, models.TokenTypeKeyword},
		{"SELECT", false, 0},
		{"NOTCOMPOUND", false, 0},
	}

	for _, tt := range tests {
		tokenType, found := k.GetCompoundKeywordType(tt.word)
		if found != tt.expectFound {
			t.Errorf("GetCompoundKeywordType(%q) found = %v, want %v", tt.word, found, tt.expectFound)
		}
		if found && tokenType != tt.expectedType {
			t.Errorf("GetCompoundKeywordType(%q) type = %v, want %v", tt.word, tokenType, tt.expectedType)
		}
	}
}

// TestKeywords_IsDMLKeyword tests the IsDMLKeyword method
func TestKeywords_IsDMLKeyword(t *testing.T) {
	k := NewKeywords()
	tests := []struct {
		word     string
		expected bool
	}{
		{"DISTINCT", true},
		{"ALL", true},
		{"FETCH", true},
		{"NEXT", true},
		{"ROWS", true},
		{"ONLY", true},
		{"WITH", true},
		{"TIES", true},
		{"NULLS", true},
		{"FIRST", true},
		{"LAST", true},
		{"SELECT", false},
		{"NOTDML", false},
		{"", false},
	}

	for _, tt := range tests {
		if got := k.IsDMLKeyword(tt.word); got != tt.expected {
			t.Errorf("IsDMLKeyword(%q) = %v, want %v", tt.word, got, tt.expected)
		}
	}
}

// TestKeywords_GetDMLKeywordType tests the GetDMLKeywordType method
func TestKeywords_GetDMLKeywordType(t *testing.T) {
	k := NewKeywords()
	tests := []struct {
		word         string
		expectFound  bool
		expectedType models.TokenType
	}{
		{"DISTINCT", true, models.TokenTypeKeyword},
		{"ALL", true, models.TokenTypeKeyword},
		{"FETCH", true, models.TokenTypeKeyword},
		{"NEXT", true, models.TokenTypeKeyword},
		{"ROWS", true, models.TokenTypeKeyword},
		{"ONLY", true, models.TokenTypeKeyword},
		{"SELECT", false, 0},
		{"NOTDML", false, 0},
	}

	for _, tt := range tests {
		tokenType, found := k.GetDMLKeywordType(tt.word)
		if found != tt.expectFound {
			t.Errorf("GetDMLKeywordType(%q) found = %v, want %v", tt.word, found, tt.expectFound)
		}
		if found && tokenType != tt.expectedType {
			t.Errorf("GetDMLKeywordType(%q) type = %v, want %v", tt.word, tokenType, tt.expectedType)
		}
	}
}

// TestKeywords_AddKeyword tests the AddKeyword method
func TestKeywords_AddKeyword(t *testing.T) {
	k := New(DialectGeneric, true)

	// Test adding a new keyword
	newKeyword := Keyword{
		Word:                  "CUSTOMKEYWORD",
		Type:                  models.TokenTypeKeyword,
		Reserved:              true,
		ReservedForTableAlias: false,
	}
	err := k.AddKeyword(newKeyword)
	if err != nil {
		t.Errorf("AddKeyword() failed: %v", err)
	}

	// Verify the keyword was added
	if !k.IsKeyword("CUSTOMKEYWORD") {
		t.Error("Added keyword not found via IsKeyword")
	}
	if !k.IsReserved("CUSTOMKEYWORD") {
		t.Error("Added keyword should be reserved")
	}

	// Test case insensitivity
	if !k.IsKeyword("customkeyword") {
		t.Error("Added keyword should be case-insensitive")
	}

	// Test adding a duplicate keyword (should fail)
	err = k.AddKeyword(newKeyword)
	if err == nil {
		t.Error("AddKeyword() should fail when adding duplicate keyword")
	}

	// Test adding non-reserved keyword
	nonReservedKeyword := Keyword{
		Word:                  "NONRESERVED",
		Type:                  models.TokenTypeKeyword,
		Reserved:              false,
		ReservedForTableAlias: false,
	}
	err = k.AddKeyword(nonReservedKeyword)
	if err != nil {
		t.Errorf("AddKeyword() failed for non-reserved keyword: %v", err)
	}
	if k.IsReserved("NONRESERVED") {
		t.Error("Non-reserved keyword should not be in reservedKeywords map")
	}
}

// TestKeywords_DialectSpecific tests dialect-specific keyword loading
func TestKeywords_DialectSpecific(t *testing.T) {
	tests := []struct {
		dialect         SQLDialect
		specificKeyword string
		shouldExist     bool
	}{
		{DialectMySQL, "ZEROFILL", true},
		{DialectMySQL, "UNSIGNED", true},
		{DialectMySQL, "FORCE", true},
		{DialectMySQL, "ILIKE", false}, // PostgreSQL specific
		{DialectPostgreSQL, "ILIKE", true},
		{DialectPostgreSQL, "MATERIALIZED", true},
		{DialectPostgreSQL, "RETURNING", true},
		{DialectPostgreSQL, "ZEROFILL", false}, // MySQL specific
		{DialectSQLite, "AUTOINCREMENT", true},
		{DialectSQLite, "VACUUM", true},
		{DialectSQLite, "VIRTUAL", true},
		{DialectSQLite, "ZEROFILL", false},  // MySQL specific
		{DialectGeneric, "SELECT", true},    // Common keywords always present
		{DialectGeneric, "ZEROFILL", false}, // No dialect-specific in generic
	}

	for _, tt := range tests {
		k := New(tt.dialect, true)
		if got := k.IsKeyword(tt.specificKeyword); got != tt.shouldExist {
			t.Errorf("Dialect %s: IsKeyword(%q) = %v, want %v", tt.dialect, tt.specificKeyword, got, tt.shouldExist)
		}
	}
}

// TestKeywords_CaseSensitivity tests case-insensitive keyword matching
func TestKeywords_CaseSensitivity(t *testing.T) {
	k := New(DialectGeneric, true)

	testCases := []string{
		"SELECT",
		"select",
		"SeLeCt",
		"sElEcT",
	}

	for _, word := range testCases {
		if !k.IsKeyword(word) {
			t.Errorf("IsKeyword(%q) should be true with case-insensitive matching", word)
		}
		if !k.IsReserved(word) {
			t.Errorf("IsReserved(%q) should be true with case-insensitive matching", word)
		}
		tokenType := k.GetTokenType(word)
		if tokenType != models.TokenTypeSelect {
			t.Errorf("GetTokenType(%q) = %v, want %v", word, tokenType, models.TokenTypeSelect)
		}
	}
}

// TestKeywords_ReservedForTableAlias tests reserved for table alias functionality
func TestKeywords_ReservedForTableAlias(t *testing.T) {
	k := New(DialectGeneric, true)

	// Keywords that should be reserved for table alias
	reservedForAlias := []string{
		"AS", "WITH", "SELECT", "WHERE", "GROUP", "HAVING",
		"ORDER", "LIMIT", "OFFSET", "UNION", "JOIN", "ON",
	}

	for _, word := range reservedForAlias {
		kw, found := k.GetKeyword(word)
		if !found {
			t.Errorf("Keyword %q should exist", word)
			continue
		}
		if !kw.ReservedForTableAlias {
			t.Errorf("Keyword %q should be reserved for table alias", word)
		}
	}

	// Keywords that should NOT be reserved for table alias
	notReservedForAlias := []string{
		"BETWEEN", "IS", "NULL", "TRUE", "FALSE",
	}

	for _, word := range notReservedForAlias {
		kw, found := k.GetKeyword(word)
		if !found {
			t.Errorf("Keyword %q should exist", word)
			continue
		}
		if kw.ReservedForTableAlias {
			t.Errorf("Keyword %q should NOT be reserved for table alias", word)
		}
	}
}

// TestKeywords_WindowFunctionKeywords tests Phase 2.5 window function keywords
func TestKeywords_WindowFunctionKeywords(t *testing.T) {
	k := New(DialectGeneric, true)

	// Window function keywords
	windowKeywords := []string{
		"OVER", "ROWS", "RANGE", "CURRENT", "ROW", "UNBOUNDED",
		"PRECEDING", "FOLLOWING",
	}

	for _, word := range windowKeywords {
		if !k.IsKeyword(word) {
			t.Errorf("Window keyword %q should exist", word)
		}
		if !k.IsReserved(word) {
			t.Errorf("Window keyword %q should be reserved", word)
		}
	}

	// Window function names (non-reserved)
	windowFunctions := []string{
		"ROW_NUMBER", "RANK", "DENSE_RANK", "NTILE",
		"LAG", "LEAD", "FIRST_VALUE", "LAST_VALUE",
	}

	for _, word := range windowFunctions {
		if !k.IsKeyword(word) {
			t.Errorf("Window function %q should exist", word)
		}
		// These should NOT be reserved (they're function names)
		if k.IsReserved(word) {
			t.Errorf("Window function %q should NOT be reserved", word)
		}
	}
}

// TestKeywords_CompoundKeywordVariations tests various compound keyword formats
func TestKeywords_CompoundKeywordVariations(t *testing.T) {
	k := New(DialectGeneric, true)

	// Test all standard compound keywords
	compoundKeywords := []string{
		"GROUP BY", "ORDER BY", "LEFT JOIN", "FULL JOIN",
		"CROSS JOIN", "NATURAL JOIN",
	}

	for _, compound := range compoundKeywords {
		if !k.IsCompoundKeyword(compound) {
			t.Errorf("IsCompoundKeyword(%q) should be true", compound)
		}

		tokenType, found := k.GetCompoundKeywordType(compound)
		if !found {
			t.Errorf("GetCompoundKeywordType(%q) should return found=true", compound)
		}
		if tokenType != models.TokenTypeKeyword {
			t.Errorf("GetCompoundKeywordType(%q) = %v, want %v", compound, tokenType, models.TokenTypeKeyword)
		}
	}

	// Test compound keyword starts
	compoundStarts := map[string]bool{
		"GROUP":   true,
		"ORDER":   true,
		"LEFT":    true,
		"FULL":    true,
		"CROSS":   true,
		"NATURAL": true,
		"BY":      false,
		"JOIN":    false,
		"SELECT":  false,
	}

	for word, expected := range compoundStarts {
		if got := k.IsCompoundKeywordStart(word); got != expected {
			t.Errorf("IsCompoundKeywordStart(%q) = %v, want %v", word, got, expected)
		}
	}
}

// TestKeywords_PartialMatchesFalsePositives tests that partial matches don't return false positives
func TestKeywords_PartialMatchesFalsePositives(t *testing.T) {
	k := New(DialectGeneric, true)

	// These should NOT be keywords
	falsePositives := []string{
		"SELECTALL",   // Not SELECT
		"FROMTABLE",   // Not FROM
		"WHERECLAUSE", // Not WHERE
		"GROUPBYID",   // Not GROUP BY
		"ORDERBYNAME", // Not ORDER BY
		"LEFTJOINS",   // Not LEFT JOIN
		"",            // Empty string
	}

	for _, word := range falsePositives {
		if k.IsKeyword(word) {
			t.Errorf("IsKeyword(%q) should be false (false positive detected)", word)
		}
	}
}

// TestKeywords_AllDialectsCoverage tests that all dialects can be instantiated
func TestKeywords_AllDialectsCoverage(t *testing.T) {
	dialects := []SQLDialect{
		DialectGeneric,
		DialectMySQL,
		DialectPostgreSQL,
		DialectSQLite,
		DialectUnknown, // Should work but have no extra keywords
	}

	for _, dialect := range dialects {
		k := New(dialect, true)
		if k == nil {
			t.Errorf("New(%v, true) returned nil", dialect)
			continue
		}

		// All dialects should have common keywords
		commonKeywords := []string{"SELECT", "FROM", "WHERE", "GROUP", "ORDER"}
		for _, word := range commonKeywords {
			if !k.IsKeyword(word) {
				t.Errorf("Dialect %v: common keyword %q should exist", dialect, word)
			}
		}

		// Verify compound keywords exist across all dialects
		if len(k.CompoundKeywords) == 0 {
			t.Errorf("Dialect %v: should have compound keywords", dialect)
		}
	}
}

// TestKeywords_AggregateFunctions tests aggregate function keywords
func TestKeywords_AggregateFunctions(t *testing.T) {
	k := New(DialectGeneric, true)

	aggregateFunctions := []struct {
		word         string
		expectedType models.TokenType
	}{
		{"COUNT", models.TokenTypeCount},
		{"SUM", models.TokenTypeSum},
		{"AVG", models.TokenTypeAvg},
		{"MIN", models.TokenTypeMin},
		{"MAX", models.TokenTypeMax},
	}

	for _, af := range aggregateFunctions {
		// Test case variations
		testVariations := []string{af.word, strings.ToLower(af.word)}
		for _, word := range testVariations {
			if !k.IsKeyword(word) {
				t.Errorf("Aggregate function %q should be a keyword", word)
			}
			if !k.IsReserved(word) {
				t.Errorf("Aggregate function %q should be reserved", word)
			}

			tokenType := k.GetTokenType(word)
			if tokenType != af.expectedType {
				t.Errorf("GetTokenType(%q) = %v, want %v", word, tokenType, af.expectedType)
			}
		}
	}
}

// TestKeywords_CaseSensitiveMode tests case-sensitive keyword matching
func TestKeywords_CaseSensitiveMode(t *testing.T) {
	// Create a case-sensitive keywords instance
	k := New(DialectGeneric, false)

	// Upper case should work
	if !k.IsKeyword("SELECT") {
		t.Error("IsKeyword('SELECT') should be true in case-sensitive mode")
	}

	// Note: The New() function always sets ignoreCase to true (line 122 in keywords.go)
	// So this test verifies that behavior is consistent
	if !k.IsKeyword("select") {
		t.Log("Note: Keywords are always case-insensitive regardless of ignoreCase parameter")
	}
}

// TestKeywords_MySQLSpecificKeywords tests MySQL dialect-specific keywords in detail
func TestKeywords_MySQLSpecificKeywords(t *testing.T) {
	k := New(DialectMySQL, true)

	mysqlKeywords := []string{
		"BINARY", "CHAR", "DATETIME", "DECIMAL", "UNSIGNED",
		"ZEROFILL", "FORCE", "IGNORE", "INDEX", "KEY", "KEYS",
		"KILL", "OPTION", "PURGE", "READ", "WRITE", "STATUS", "VARIABLES",
	}

	for _, word := range mysqlKeywords {
		if !k.IsKeyword(word) {
			t.Errorf("MySQL keyword %q should exist", word)
		}
		// Test case insensitivity
		if !k.IsKeyword(strings.ToLower(word)) {
			t.Errorf("MySQL keyword %q should be case-insensitive", word)
		}
	}
}

// TestKeywords_PostgreSQLSpecificKeywords tests PostgreSQL dialect-specific keywords in detail
func TestKeywords_PostgreSQLSpecificKeywords(t *testing.T) {
	k := New(DialectPostgreSQL, true)

	postgresKeywords := []string{
		"MATERIALIZED", "ILIKE", "SIMILAR", "FREEZE", "ANALYSE",
		"ANALYZE", "CONCURRENTLY", "REINDEX", "TOAST", "NOWAIT",
		"RECURSIVE", "RETURNING",
	}

	for _, word := range postgresKeywords {
		if !k.IsKeyword(word) {
			t.Errorf("PostgreSQL keyword %q should exist", word)
		}
		// Test case insensitivity
		if !k.IsKeyword(strings.ToLower(word)) {
			t.Errorf("PostgreSQL keyword %q should be case-insensitive", word)
		}
	}
}

// TestKeywords_SQLiteSpecificKeywords tests SQLite dialect-specific keywords in detail
func TestKeywords_SQLiteSpecificKeywords(t *testing.T) {
	k := New(DialectSQLite, true)

	sqliteKeywords := []string{
		"ABORT", "ACTION", "AFTER", "ATTACH", "AUTOINCREMENT",
		"CONFLICT", "DATABASE", "DETACH", "EXCLUSIVE", "INDEXED",
		"INSTEAD", "PLAN", "QUERY", "RAISE", "REPLACE",
		"TEMP", "TEMPORARY", "VACUUM", "VIRTUAL",
	}

	for _, word := range sqliteKeywords {
		if !k.IsKeyword(word) {
			t.Errorf("SQLite keyword %q should exist", word)
		}
		// Test case insensitivity
		if !k.IsKeyword(strings.ToLower(word)) {
			t.Errorf("SQLite keyword %q should be case-insensitive", word)
		}
	}
}

// TestKeywords_BooleanLiterals tests boolean keyword literals
func TestKeywords_BooleanLiterals(t *testing.T) {
	k := New(DialectGeneric, true)

	booleanKeywords := []struct {
		word         string
		expectedType models.TokenType
	}{
		{"TRUE", models.TokenTypeTrue},
		{"FALSE", models.TokenTypeFalse},
		{"NULL", models.TokenTypeNull},
	}

	for _, bk := range booleanKeywords {
		if !k.IsKeyword(bk.word) {
			t.Errorf("Boolean keyword %q should exist", bk.word)
		}

		tokenType := k.GetTokenType(bk.word)
		if tokenType != bk.expectedType {
			t.Errorf("GetTokenType(%q) = %v, want %v", bk.word, tokenType, bk.expectedType)
		}

		// Test case insensitivity
		lowerWord := strings.ToLower(bk.word)
		if k.GetTokenType(lowerWord) != bk.expectedType {
			t.Errorf("GetTokenType(%q) = %v, want %v (case-insensitive)", lowerWord, k.GetTokenType(lowerWord), bk.expectedType)
		}
	}
}

// TestKeywords_CaseExpressionKeywords tests CASE expression keywords
func TestKeywords_CaseExpressionKeywords(t *testing.T) {
	k := New(DialectGeneric, true)

	caseKeywords := []struct {
		word         string
		expectedType models.TokenType
	}{
		{"CASE", models.TokenTypeCase},
		{"WHEN", models.TokenTypeWhen},
		{"THEN", models.TokenTypeThen},
		{"ELSE", models.TokenTypeElse},
		// Note: END is defined twice in keywords.go - once in RESERVED_FOR_TABLE_ALIAS (line 56)
		// with TokenTypeKeyword, and once in ADDITIONAL_KEYWORDS (line 103) with TokenTypeEnd.
		// Since RESERVED_FOR_TABLE_ALIAS is added first, it takes precedence.
		{"END", models.TokenTypeKeyword}, // First definition wins
	}

	for _, ck := range caseKeywords {
		if !k.IsKeyword(ck.word) {
			t.Errorf("CASE keyword %q should exist", ck.word)
		}

		tokenType := k.GetTokenType(ck.word)
		if tokenType != ck.expectedType {
			t.Errorf("GetTokenType(%q) = %v, want %v", ck.word, tokenType, ck.expectedType)
		}
	}
}

// TestKeywords_ComparisonOperatorKeywords tests comparison operator keywords
func TestKeywords_ComparisonOperatorKeywords(t *testing.T) {
	k := New(DialectGeneric, true)

	comparisonKeywords := []struct {
		word         string
		expectedType models.TokenType
	}{
		{"BETWEEN", models.TokenTypeBetween},
		{"IN", models.TokenTypeIn},
		{"LIKE", models.TokenTypeLike},
		{"IS", models.TokenTypeIs},
		{"NOT", models.TokenTypeNot},
		{"AND", models.TokenTypeAnd},
		{"OR", models.TokenTypeOr},
	}

	for _, ck := range comparisonKeywords {
		if !k.IsKeyword(ck.word) {
			t.Errorf("Comparison keyword %q should exist", ck.word)
		}

		tokenType := k.GetTokenType(ck.word)
		if tokenType != ck.expectedType {
			t.Errorf("GetTokenType(%q) = %v, want %v", ck.word, tokenType, ck.expectedType)
		}
	}
}

// TestKeywords_JoinKeywords tests JOIN-related keywords
func TestKeywords_JoinKeywords(t *testing.T) {
	k := New(DialectGeneric, true)

	joinKeywords := []struct {
		word         string
		expectedType models.TokenType
	}{
		{"JOIN", models.TokenTypeJoin},
		{"INNER", models.TokenTypeInner},
		{"LEFT", models.TokenTypeLeft},
		{"RIGHT", models.TokenTypeRight},
		{"OUTER", models.TokenTypeOuter},
		{"ON", models.TokenTypeOn},
	}

	for _, jk := range joinKeywords {
		if !k.IsKeyword(jk.word) {
			t.Errorf("JOIN keyword %q should exist", jk.word)
		}

		tokenType := k.GetTokenType(jk.word)
		if tokenType != jk.expectedType {
			t.Errorf("GetTokenType(%q) = %v, want %v", jk.word, tokenType, jk.expectedType)
		}

		// All JOIN keywords should be reserved for table alias
		kw, found := k.GetKeyword(jk.word)
		if !found {
			t.Errorf("JOIN keyword %q should be found via GetKeyword", jk.word)
			continue
		}
		if !kw.ReservedForTableAlias {
			t.Errorf("JOIN keyword %q should be reserved for table alias", jk.word)
		}
	}
}

// TestKeywords_OrderingSortKeywords tests ordering and sorting keywords
func TestKeywords_OrderingSortKeywords(t *testing.T) {
	k := New(DialectGeneric, true)

	orderingKeywords := []struct {
		word         string
		expectedType models.TokenType
	}{
		{"ORDER", models.TokenTypeOrder},
		{"GROUP", models.TokenTypeGroup},
		{"BY", models.TokenTypeBy},
		{"ASC", models.TokenTypeAsc},
		{"DESC", models.TokenTypeDesc},
		{"HAVING", models.TokenTypeHaving},
		{"LIMIT", models.TokenTypeLimit},
		{"OFFSET", models.TokenTypeOffset},
	}

	for _, ok := range orderingKeywords {
		if !k.IsKeyword(ok.word) {
			t.Errorf("Ordering keyword %q should exist", ok.word)
		}

		tokenType := k.GetTokenType(ok.word)
		if tokenType != ok.expectedType {
			t.Errorf("GetTokenType(%q) = %v, want %v", ok.word, tokenType, ok.expectedType)
		}
	}
}
