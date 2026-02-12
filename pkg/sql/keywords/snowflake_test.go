package keywords

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// TestSnowflakeKeywords tests that Snowflake-specific keywords are properly defined
// and loaded when using DialectSnowflake.
func TestSnowflakeKeywords(t *testing.T) {
	k := New(DialectSnowflake, true)

	// Snowflake-specific keywords that should be present
	snowflakeKeywords := []struct {
		word         string
		expectedType models.TokenType
	}{
		// Semi-structured data types
		{"VARIANT", models.TokenTypeKeyword},
		{"OBJECT", models.TokenTypeKeyword},

		// Semi-structured data functions
		{"FLATTEN", models.TokenTypeKeyword},
		{"PARSE_JSON", models.TokenTypeKeyword},
		{"STRIP_NULL_VALUE", models.TokenTypeKeyword},
		{"TYPEOF", models.TokenTypeKeyword},

		// Snowflake-specific clauses and objects
		{"CHANGES", models.TokenTypeKeyword},
		{"STREAM", models.TokenTypeKeyword},
		{"TASK", models.TokenTypeKeyword},
		{"PIPE", models.TokenTypeKeyword},
		{"STAGE", models.TokenTypeKeyword},
		{"FILE_FORMAT", models.TokenTypeKeyword},

		// Snowflake DDL
		{"WAREHOUSE", models.TokenTypeKeyword},
		{"DATABASE", models.TokenTypeDatabase},
		{"CLONE", models.TokenTypeKeyword},
		{"UNDROP", models.TokenTypeKeyword},
		{"RECLUSTER", models.TokenTypeKeyword},

		// Time Travel
		{"BEFORE", models.TokenTypeKeyword},
		{"AT", models.TokenTypeKeyword},
		{"TIMESTAMP", models.TokenTypeTimestamp},
		{"STATEMENT", models.TokenTypeKeyword},

		// Data Loading
		{"COPY", models.TokenTypeKeyword},
		{"PUT", models.TokenTypeKeyword},
		{"GET", models.TokenTypeKeyword},
		{"REMOVE", models.TokenTypeKeyword},

		// Access Control
		{"ROLE", models.TokenTypeRole},
		{"GRANT", models.TokenTypeGrant},
		{"REVOKE", models.TokenTypeRevoke},
		{"OWNERSHIP", models.TokenTypeKeyword},

		// Snowflake functions
		{"IFF", models.TokenTypeKeyword},
		{"IFNULL", models.TokenTypeKeyword},
		{"NVL", models.TokenTypeKeyword},
		{"NVL2", models.TokenTypeKeyword},
		{"ZEROIFNULL", models.TokenTypeKeyword},
		{"EQUAL_NULL", models.TokenTypeKeyword},
		{"TRY_CAST", models.TokenTypeKeyword},
		{"TRY_TO_NUMBER", models.TokenTypeKeyword},
		{"TRY_TO_DATE", models.TokenTypeKeyword},

		// Utility functions
		{"RESULT_SCAN", models.TokenTypeKeyword},
		{"GENERATOR", models.TokenTypeKeyword},
		{"ROWCOUNT", models.TokenTypeKeyword},
		{"LAST_QUERY_ID", models.TokenTypeKeyword},
		{"SYSTEM", models.TokenTypeKeyword},
	}

	for _, tt := range snowflakeKeywords {
		t.Run(tt.word, func(t *testing.T) {
			if !k.IsKeyword(tt.word) {
				t.Errorf("Snowflake keyword %q should exist", tt.word)
			}

			tokenType := k.GetTokenType(tt.word)
			if tokenType != tt.expectedType {
				t.Errorf("GetTokenType(%q) = %v, want %v", tt.word, tokenType, tt.expectedType)
			}

			// Test case insensitivity
			lowerWord := strings.ToLower(tt.word)
			if !k.IsKeyword(lowerWord) {
				t.Errorf("Snowflake keyword %q should be case-insensitive", tt.word)
			}
		})
	}
}

// TestSnowflakeKeywordsNotInGeneric verifies that Snowflake-specific keywords
// are NOT present when using the generic dialect.
func TestSnowflakeKeywordsNotInGeneric(t *testing.T) {
	k := New(DialectGeneric, true)

	snowflakeOnlyKeywords := []string{
		"VARIANT", "OBJECT", "FLATTEN", "PARSE_JSON", "STRIP_NULL_VALUE",
		"TYPEOF", "CHANGES", "STREAM", "TASK", "PIPE", "STAGE",
		"FILE_FORMAT", "WAREHOUSE", "CLONE", "UNDROP", "RECLUSTER",
		"BEFORE", "AT", "STATEMENT", "COPY", "PUT", "GET", "REMOVE",
		"OWNERSHIP", "IFF", "IFNULL", "NVL", "NVL2", "ZEROIFNULL",
		"EQUAL_NULL", "TRY_CAST", "TRY_TO_NUMBER", "TRY_TO_DATE",
		"RESULT_SCAN", "GENERATOR", "ROWCOUNT", "LAST_QUERY_ID", "SYSTEM",
	}

	for _, word := range snowflakeOnlyKeywords {
		if k.IsKeyword(word) {
			t.Errorf("Snowflake-only keyword %q should NOT exist in generic dialect", word)
		}
	}
}

// TestSnowflakeIncludesBaseKeywords verifies that the Snowflake dialect includes
// all standard base keywords in addition to Snowflake-specific ones.
func TestSnowflakeIncludesBaseKeywords(t *testing.T) {
	k := New(DialectSnowflake, true)

	baseKeywords := []string{
		"SELECT", "FROM", "WHERE", "GROUP", "ORDER", "BY",
		"JOIN", "INNER", "LEFT", "RIGHT", "ON", "AS",
		"AND", "OR", "NOT", "IN", "LIKE", "BETWEEN",
		"HAVING", "LIMIT", "OFFSET", "UNION",
		"COUNT", "SUM", "AVG", "MIN", "MAX",
		"CASE", "WHEN", "THEN", "ELSE", "END",
	}

	for _, word := range baseKeywords {
		if !k.IsKeyword(word) {
			t.Errorf("Base keyword %q should exist in Snowflake dialect", word)
		}
	}
}

// TestSnowflakeKeywordsBaseOverlap verifies that keywords which exist in both
// the base set and the Snowflake set don't cause issues (the base definition
// takes precedence since addKeywordsWithCategory skips duplicates).
func TestSnowflakeKeywordsBaseOverlap(t *testing.T) {
	k := New(DialectSnowflake, true)

	// These keywords exist in the base set and should retain their base token types
	baseOverlapKeywords := []struct {
		word         string
		expectedType models.TokenType
	}{
		{"ARRAY", models.TokenTypeArray},
		{"LATERAL", models.TokenTypeLateral},
		{"QUALIFY", models.TokenTypeKeyword},
		{"SAMPLE", models.TokenTypeKeyword},
		{"CLUSTER", models.TokenTypeKeyword},
		{"OFFSET", models.TokenTypeOffset},
		{"SHARE", models.TokenTypeShare},
		{"LIST", models.TokenTypeKeyword},
	}

	for _, tt := range baseOverlapKeywords {
		t.Run(tt.word, func(t *testing.T) {
			if !k.IsKeyword(tt.word) {
				t.Errorf("Overlapping keyword %q should exist in Snowflake dialect", tt.word)
			}

			tokenType := k.GetTokenType(tt.word)
			if tokenType != tt.expectedType {
				t.Errorf("GetTokenType(%q) = %v, want %v (base definition should take precedence)",
					tt.word, tokenType, tt.expectedType)
			}
		})
	}
}

// TestSnowflakeDialectKeywords verifies DialectKeywords returns the Snowflake keyword list.
func TestSnowflakeDialectKeywords(t *testing.T) {
	kws := DialectKeywords(DialectSnowflake)
	if kws == nil {
		t.Fatal("DialectKeywords(DialectSnowflake) returned nil")
	}

	if len(kws) != len(SNOWFLAKE_SPECIFIC) {
		t.Errorf("DialectKeywords(DialectSnowflake) returned %d keywords, want %d",
			len(kws), len(SNOWFLAKE_SPECIFIC))
	}

	// Verify the returned slice contains expected keywords
	foundVariant := false
	foundWarehouse := false
	for _, kw := range kws {
		if kw.Word == "VARIANT" {
			foundVariant = true
		}
		if kw.Word == "WAREHOUSE" {
			foundWarehouse = true
		}
	}
	if !foundVariant {
		t.Error("DialectKeywords should contain VARIANT")
	}
	if !foundWarehouse {
		t.Error("DialectKeywords should contain WAREHOUSE")
	}
}

// TestSnowflakeKeywordsNoDuplicateBaseKeywords ensures that the SNOWFLAKE_SPECIFIC
// slice does not contain keywords that already exist in the base keyword sets
// (RESERVED_FOR_TABLE_ALIAS and ADDITIONAL_KEYWORDS).
func TestSnowflakeKeywordsNoDuplicateBaseKeywords(t *testing.T) {
	// Build a set of all base keywords
	baseKeywords := make(map[string]bool)
	for _, kw := range RESERVED_FOR_TABLE_ALIAS {
		baseKeywords[strings.ToUpper(kw.Word)] = true
	}
	for _, kw := range ADDITIONAL_KEYWORDS {
		baseKeywords[strings.ToUpper(kw.Word)] = true
	}

	for _, kw := range SNOWFLAKE_SPECIFIC {
		if baseKeywords[strings.ToUpper(kw.Word)] {
			t.Errorf("Snowflake keyword %q already exists in the base keyword set; "+
				"it should not be duplicated in SNOWFLAKE_SPECIFIC", kw.Word)
		}
	}
}

// TestDialectDetection tests the DetectDialect function with various SQL inputs.
func TestDialectDetection(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		expected SQLDialect
	}{
		// Snowflake detection
		{
			name:     "Snowflake QUALIFY clause",
			sql:      "SELECT * FROM users QUALIFY ROW_NUMBER() OVER (ORDER BY id) = 1",
			expected: DialectSnowflake,
		},
		{
			name:     "Snowflake FLATTEN",
			sql:      "SELECT f.value FROM my_table, LATERAL FLATTEN(input => my_table.json_col) f",
			expected: DialectSnowflake,
		},
		{
			name:     "Snowflake VARIANT type",
			sql:      "CREATE TABLE t (data VARIANT)",
			expected: DialectSnowflake,
		},
		{
			name:     "Snowflake WAREHOUSE",
			sql:      "CREATE WAREHOUSE my_wh WITH WAREHOUSE_SIZE = 'X-SMALL'",
			expected: DialectSnowflake,
		},
		{
			name:     "Snowflake CLONE",
			sql:      "CREATE TABLE t2 CLONE t1",
			expected: DialectSnowflake,
		},
		{
			name:     "Snowflake UNDROP",
			sql:      "UNDROP TABLE my_table",
			expected: DialectSnowflake,
		},
		{
			name:     "Snowflake RESULT_SCAN",
			sql:      "SELECT * FROM TABLE(RESULT_SCAN(LAST_QUERY_ID()))",
			expected: DialectSnowflake,
		},
		{
			name:     "Snowflake IFF function",
			sql:      "SELECT IFF(status = 'active', 1, 0) FROM users",
			expected: DialectSnowflake,
		},
		{
			name:     "Snowflake lowercase",
			sql:      "select * from users qualify row_number() over (order by id) = 1",
			expected: DialectSnowflake,
		},

		// PostgreSQL detection
		{
			name:     "PostgreSQL DISTINCT ON",
			sql:      "SELECT DISTINCT ON (dept) * FROM emp",
			expected: DialectPostgreSQL,
		},
		{
			name:     "PostgreSQL ILIKE",
			sql:      "SELECT * FROM users WHERE name ILIKE '%john%'",
			expected: DialectPostgreSQL,
		},
		{
			name:     "PostgreSQL type casting",
			sql:      "SELECT id::text FROM users",
			expected: DialectPostgreSQL,
		},

		// MySQL detection
		{
			name:     "MySQL backtick identifiers",
			sql:      "SELECT * FROM `users` WHERE `name` = 'John'",
			expected: DialectMySQL,
		},
		{
			name:     "MySQL ZEROFILL",
			sql:      "CREATE TABLE t (id INT UNSIGNED ZEROFILL)",
			expected: DialectMySQL,
		},
		{
			name:     "MySQL AUTO_INCREMENT",
			sql:      "CREATE TABLE t (id INT AUTO_INCREMENT PRIMARY KEY)",
			expected: DialectMySQL,
		},

		// SQL Server detection
		{
			name:     "SQL Server NOLOCK",
			sql:      "SELECT * FROM users WITH (NOLOCK)",
			expected: DialectSQLServer,
		},
		{
			name:     "SQL Server bracket identifiers",
			sql:      "SELECT [id], [name] FROM [users]",
			expected: DialectSQLServer,
		},

		// Oracle detection
		{
			name:     "Oracle ROWNUM",
			sql:      "SELECT * FROM users WHERE ROWNUM <= 10",
			expected: DialectOracle,
		},
		{
			name:     "Oracle CONNECT BY",
			sql:      "SELECT * FROM emp CONNECT BY PRIOR id = manager_id",
			expected: DialectOracle,
		},

		// SQLite detection
		{
			name:     "SQLite AUTOINCREMENT",
			sql:      "CREATE TABLE t (id INTEGER PRIMARY KEY AUTOINCREMENT)",
			expected: DialectSQLite,
		},
		{
			name:     "SQLite GLOB",
			sql:      "SELECT * FROM files WHERE name GLOB '*.txt'",
			expected: DialectSQLite,
		},

		// Generic SQL (no specific dialect detected)
		{
			name:     "generic SELECT",
			sql:      "SELECT * FROM users",
			expected: DialectGeneric,
		},
		{
			name:     "generic INSERT",
			sql:      "INSERT INTO users (name) VALUES ('John')",
			expected: DialectGeneric,
		},
		{
			name:     "empty string",
			sql:      "",
			expected: DialectGeneric,
		},
		{
			name:     "generic complex query",
			sql:      "SELECT a.id, b.name FROM a JOIN b ON a.id = b.id WHERE a.status = 1 ORDER BY a.name",
			expected: DialectGeneric,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectDialect(tt.sql)
			if got != tt.expected {
				t.Errorf("DetectDialect(%q) = %q, want %q", tt.sql, got, tt.expected)
			}
		})
	}
}

// TestDialectDetectionMultipleHints tests detection when SQL contains hints from
// multiple dialects, verifying the strongest signal wins.
func TestDialectDetectionMultipleHints(t *testing.T) {
	// Snowflake-heavy SQL with NVL (which also hints Oracle weakly)
	sql := "SELECT FLATTEN(data), NVL(name, 'unknown'), WAREHOUSE FROM tbl"
	got := DetectDialect(sql)
	if got != DialectSnowflake {
		t.Errorf("Expected DialectSnowflake for multi-hint SQL, got %q", got)
	}
}

// TestDialectDetectionWordBoundaries verifies that keyword detection respects word
// boundaries and does not match partial words.
func TestDialectDetectionWordBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		sql      string
		expected SQLDialect
	}{
		{
			name:     "QUALIFYING should not match QUALIFY",
			sql:      "SELECT * FROM qualifying_table",
			expected: DialectGeneric,
		},
		{
			name:     "FLATTENED should not match FLATTEN",
			sql:      "SELECT * FROM flattened_data",
			expected: DialectGeneric,
		},
		{
			name:     "VARIANTS should not match VARIANT",
			sql:      "SELECT * FROM variants",
			expected: DialectGeneric,
		},
		{
			name:     "WAREHOUSES should not match WAREHOUSE",
			sql:      "SELECT * FROM warehouses",
			expected: DialectGeneric,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectDialect(tt.sql)
			if got != tt.expected {
				t.Errorf("DetectDialect(%q) = %q, want %q (word boundary check failed)",
					tt.sql, got, tt.expected)
			}
		})
	}
}

// TestDialectRegistry tests the AllDialects and DialectKeywords registry functions.
func TestDialectRegistry(t *testing.T) {
	t.Run("AllDialects returns expected list", func(t *testing.T) {
		dialects := AllDialects()
		if len(dialects) == 0 {
			t.Fatal("AllDialects() returned empty slice")
		}

		// Check that all expected dialects are present
		expectedDialects := map[SQLDialect]bool{
			DialectGeneric:    false,
			DialectPostgreSQL: false,
			DialectMySQL:      false,
			DialectSQLServer:  false,
			DialectOracle:     false,
			DialectSQLite:     false,
			DialectSnowflake:  false,
			DialectBigQuery:   false,
			DialectRedshift:   false,
		}

		for _, d := range dialects {
			if _, ok := expectedDialects[d]; !ok {
				t.Errorf("Unexpected dialect %q in AllDialects()", d)
			}
			expectedDialects[d] = true
		}

		for d, found := range expectedDialects {
			if !found {
				t.Errorf("Expected dialect %q not found in AllDialects()", d)
			}
		}
	})

	t.Run("DialectKeywords for Snowflake", func(t *testing.T) {
		kws := DialectKeywords(DialectSnowflake)
		if kws == nil {
			t.Fatal("DialectKeywords(DialectSnowflake) returned nil")
		}
		if len(kws) == 0 {
			t.Fatal("DialectKeywords(DialectSnowflake) returned empty slice")
		}
	})

	t.Run("DialectKeywords for MySQL", func(t *testing.T) {
		kws := DialectKeywords(DialectMySQL)
		if kws == nil {
			t.Fatal("DialectKeywords(DialectMySQL) returned nil")
		}
	})

	t.Run("DialectKeywords for PostgreSQL", func(t *testing.T) {
		kws := DialectKeywords(DialectPostgreSQL)
		if kws == nil {
			t.Fatal("DialectKeywords(DialectPostgreSQL) returned nil")
		}
	})

	t.Run("DialectKeywords for SQLite", func(t *testing.T) {
		kws := DialectKeywords(DialectSQLite)
		if kws == nil {
			t.Fatal("DialectKeywords(DialectSQLite) returned nil")
		}
	})

	t.Run("DialectKeywords for generic returns nil", func(t *testing.T) {
		kws := DialectKeywords(DialectGeneric)
		if kws != nil {
			t.Errorf("DialectKeywords(DialectGeneric) should return nil, got %d keywords", len(kws))
		}
	})

	t.Run("DialectKeywords for unknown returns nil", func(t *testing.T) {
		kws := DialectKeywords(DialectUnknown)
		if kws != nil {
			t.Errorf("DialectKeywords(DialectUnknown) should return nil, got %d keywords", len(kws))
		}
	})

	t.Run("DialectKeywords for unrecognized string returns nil", func(t *testing.T) {
		kws := DialectKeywords(SQLDialect("nonexistent"))
		if kws != nil {
			t.Errorf("DialectKeywords for unrecognized dialect should return nil, got %d keywords", len(kws))
		}
	})
}

// TestSnowflakeDialectInstantiation verifies that New() with DialectSnowflake
// creates a valid Keywords instance.
func TestSnowflakeDialectInstantiation(t *testing.T) {
	k := New(DialectSnowflake, true)
	if k == nil {
		t.Fatal("New(DialectSnowflake, true) returned nil")
	}

	// Verify compound keywords are present (from base initialization)
	if len(k.CompoundKeywords) == 0 {
		t.Error("Snowflake dialect should have compound keywords from base")
	}

	// Verify the keyword count is larger than generic (because Snowflake keywords are added)
	generic := New(DialectGeneric, true)
	snowflakeCount := 0
	genericCount := 0
	for range k.keywordMap {
		snowflakeCount++
	}
	for range generic.keywordMap {
		genericCount++
	}

	if snowflakeCount <= genericCount {
		t.Errorf("Snowflake dialect (%d keywords) should have more keywords than generic (%d keywords)",
			snowflakeCount, genericCount)
	}
}

// TestContainsWord tests the containsWord helper function.
func TestContainsWord(t *testing.T) {
	tests := []struct {
		text     string
		pattern  string
		expected bool
	}{
		{"SELECT FLATTEN(data)", "FLATTEN", true},
		{"SELECT FLATTENED(data)", "FLATTEN", false},
		{"FLATTEN(data)", "FLATTEN", true},
		{"data FLATTEN", "FLATTEN", true},
		{"NO MATCH", "FLATTEN", false},
		{"", "FLATTEN", false},
		{"QUALIFYING", "QUALIFY", false},
		{"QUALIFY", "QUALIFY", true},
		{"(QUALIFY)", "QUALIFY", true},
		{" QUALIFY ", "QUALIFY", true},
		{"XQUALIFY", "QUALIFY", false},
		{"DISTINCT ON (DEPT)", "DISTINCT ON", true},
		{"SELECT DISTINCT ON (DEPT)", "DISTINCT ON", true},
		{"CONNECT BY PRIOR", "CONNECT BY", true},
	}

	for _, tt := range tests {
		t.Run(tt.text+"_"+tt.pattern, func(t *testing.T) {
			got := containsWord(tt.text, tt.pattern)
			if got != tt.expected {
				t.Errorf("containsWord(%q, %q) = %v, want %v", tt.text, tt.pattern, got, tt.expected)
			}
		})
	}
}

// TestSnowflakeKeywordReservationStatus verifies the reservation status of Snowflake keywords.
func TestSnowflakeKeywordReservationStatus(t *testing.T) {
	k := New(DialectSnowflake, true)

	// Keywords that should be reserved
	reservedKeywords := []string{
		"UNDROP", "COPY", "GRANT", "REVOKE",
	}
	for _, word := range reservedKeywords {
		if !k.IsReserved(word) {
			t.Errorf("Snowflake keyword %q should be reserved", word)
		}
	}

	// Keywords that should NOT be reserved (function names, object types)
	nonReservedKeywords := []string{
		"VARIANT", "FLATTEN", "PARSE_JSON", "IFF", "IFNULL",
		"NVL", "NVL2", "WAREHOUSE", "STREAM", "TASK",
		"RESULT_SCAN", "GENERATOR", "CLONE", "RECLUSTER",
	}
	for _, word := range nonReservedKeywords {
		if k.IsReserved(word) {
			t.Errorf("Snowflake keyword %q should NOT be reserved", word)
		}
	}
}

// TestDialectAllDialectsCoverage ensures all returned dialects from AllDialects()
// can be used to create Keywords instances.
func TestDialectAllDialectsCoverage(t *testing.T) {
	dialects := AllDialects()
	for _, dialect := range dialects {
		t.Run(string(dialect), func(t *testing.T) {
			k := New(dialect, true)
			if k == nil {
				t.Errorf("New(%q, true) returned nil", dialect)
				return
			}
			// All dialects should have core SQL keywords
			if !k.IsKeyword("SELECT") {
				t.Errorf("Dialect %q should have SELECT keyword", dialect)
			}
			if !k.IsKeyword("FROM") {
				t.Errorf("Dialect %q should have FROM keyword", dialect)
			}
			if !k.IsKeyword("WHERE") {
				t.Errorf("Dialect %q should have WHERE keyword", dialect)
			}
		})
	}
}
