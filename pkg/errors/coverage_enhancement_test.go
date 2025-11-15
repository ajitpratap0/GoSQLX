package errors

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// TestAdvancedErrorBuilders tests all previously uncovered error builder functions
// to achieve comprehensive coverage of the builders.go file.
func TestAdvancedErrorBuilders(t *testing.T) {
	location := models.Location{Line: 1, Column: 10}
	sql := "SELECT * FROM users WHERE id = 1"

	t.Run("InputTooLargeError", func(t *testing.T) {
		err := InputTooLargeError(20000000, 10000000, location)

		if err == nil {
			t.Fatal("InputTooLargeError should return non-nil error")
		}
		if err.Code != ErrCodeInputTooLarge {
			t.Errorf("Error code = %s, want %s", err.Code, ErrCodeInputTooLarge)
		}
		if !strings.Contains(err.Message, "20000000 bytes") {
			t.Errorf("Error message should contain size: %s", err.Message)
		}
		if !strings.Contains(err.Message, "10000000 bytes") {
			t.Errorf("Error message should contain max size: %s", err.Message)
		}
		if err.Hint == "" {
			t.Error("Error should have hint")
		}
		if !strings.Contains(err.Hint, "10000000") {
			t.Errorf("Hint should contain max size: %s", err.Hint)
		}
	})

	t.Run("TokenLimitReachedError", func(t *testing.T) {
		err := TokenLimitReachedError(5000, 1000, location, sql)

		if err == nil {
			t.Fatal("TokenLimitReachedError should return non-nil error")
		}
		if err.Code != ErrCodeTokenLimitReached {
			t.Errorf("Error code = %s, want %s", err.Code, ErrCodeTokenLimitReached)
		}
		if !strings.Contains(err.Message, "5000") {
			t.Errorf("Error message should contain token count: %s", err.Message)
		}
		if !strings.Contains(err.Message, "1000") {
			t.Errorf("Error message should contain max tokens: %s", err.Message)
		}
		if err.Context == nil {
			t.Error("Error should have context")
		}
		if err.Hint == "" {
			t.Error("Error should have hint")
		}
		if !strings.Contains(err.Hint, "1000") {
			t.Errorf("Hint should contain limit: %s", err.Hint)
		}
	})

	t.Run("TokenizerPanicError", func(t *testing.T) {
		panicValue := "unexpected nil pointer"
		err := TokenizerPanicError(panicValue, location)

		if err == nil {
			t.Fatal("TokenizerPanicError should return non-nil error")
		}
		if err.Code != ErrCodeTokenizerPanic {
			t.Errorf("Error code = %s, want %s", err.Code, ErrCodeTokenizerPanic)
		}
		if !strings.Contains(err.Message, panicValue) {
			t.Errorf("Error message should contain panic value: %s", err.Message)
		}
		if err.Hint == "" {
			t.Error("Error should have hint")
		}
		if !strings.Contains(err.Hint, "report") {
			t.Errorf("Hint should mention reporting: %s", err.Hint)
		}
	})

	t.Run("RecursionDepthLimitError", func(t *testing.T) {
		err := RecursionDepthLimitError(150, 100, location, sql)

		if err == nil {
			t.Fatal("RecursionDepthLimitError should return non-nil error")
		}
		if err.Code != ErrCodeRecursionDepthLimit {
			t.Errorf("Error code = %s, want %s", err.Code, ErrCodeRecursionDepthLimit)
		}
		if !strings.Contains(err.Message, "150") {
			t.Errorf("Error message should contain depth: %s", err.Message)
		}
		if !strings.Contains(err.Message, "100") {
			t.Errorf("Error message should contain max depth: %s", err.Message)
		}
		if err.Context == nil {
			t.Error("Error should have context")
		}
		if err.Hint == "" {
			t.Error("Error should have hint")
		}
		if !strings.Contains(err.Hint, "100") {
			t.Errorf("Hint should contain limit: %s", err.Hint)
		}
	})

	t.Run("UnsupportedDataTypeError", func(t *testing.T) {
		err := UnsupportedDataTypeError("GEOMETRY", location, sql)

		if err == nil {
			t.Fatal("UnsupportedDataTypeError should return non-nil error")
		}
		if err.Code != ErrCodeUnsupportedDataType {
			t.Errorf("Error code = %s, want %s", err.Code, ErrCodeUnsupportedDataType)
		}
		if !strings.Contains(err.Message, "GEOMETRY") {
			t.Errorf("Error message should contain data type: %s", err.Message)
		}
		if err.Context == nil {
			t.Error("Error should have context")
		}
		if err.Hint == "" {
			t.Error("Error should have hint")
		}
		if !strings.Contains(err.Hint, "INTEGER") || !strings.Contains(err.Hint, "VARCHAR") {
			t.Errorf("Hint should mention supported types: %s", err.Hint)
		}
	})

	t.Run("UnsupportedConstraintError", func(t *testing.T) {
		err := UnsupportedConstraintError("EXCLUDE", location, sql)

		if err == nil {
			t.Fatal("UnsupportedConstraintError should return non-nil error")
		}
		if err.Code != ErrCodeUnsupportedConstraint {
			t.Errorf("Error code = %s, want %s", err.Code, ErrCodeUnsupportedConstraint)
		}
		if !strings.Contains(err.Message, "EXCLUDE") {
			t.Errorf("Error message should contain constraint: %s", err.Message)
		}
		if err.Context == nil {
			t.Error("Error should have context")
		}
		if err.Hint == "" {
			t.Error("Error should have hint")
		}
		if !strings.Contains(err.Hint, "PRIMARY KEY") || !strings.Contains(err.Hint, "FOREIGN KEY") {
			t.Errorf("Hint should mention supported constraints: %s", err.Hint)
		}
	})

	t.Run("UnsupportedJoinError", func(t *testing.T) {
		err := UnsupportedJoinError("LATERAL", location, sql)

		if err == nil {
			t.Fatal("UnsupportedJoinError should return non-nil error")
		}
		if err.Code != ErrCodeUnsupportedJoin {
			t.Errorf("Error code = %s, want %s", err.Code, ErrCodeUnsupportedJoin)
		}
		if !strings.Contains(err.Message, "LATERAL") {
			t.Errorf("Error message should contain join type: %s", err.Message)
		}
		if err.Context == nil {
			t.Error("Error should have context")
		}
		if err.Hint == "" {
			t.Error("Error should have hint")
		}
		if !strings.Contains(err.Hint, "INNER JOIN") || !strings.Contains(err.Hint, "LEFT JOIN") {
			t.Errorf("Hint should mention supported joins: %s", err.Hint)
		}
	})

	t.Run("InvalidCTEError", func(t *testing.T) {
		err := InvalidCTEError("missing AS clause", location, sql)

		if err == nil {
			t.Fatal("InvalidCTEError should return non-nil error")
		}
		if err.Code != ErrCodeInvalidCTE {
			t.Errorf("Error code = %s, want %s", err.Code, ErrCodeInvalidCTE)
		}
		if !strings.Contains(err.Message, "missing AS clause") {
			t.Errorf("Error message should contain description: %s", err.Message)
		}
		if err.Context == nil {
			t.Error("Error should have context")
		}
		if err.Hint == "" {
			t.Error("Error should have hint")
		}
		if !strings.Contains(err.Hint, "WITH") {
			t.Errorf("Hint should mention WITH clause: %s", err.Hint)
		}
	})

	t.Run("InvalidSetOperationError", func(t *testing.T) {
		err := InvalidSetOperationError("UNION", "column count mismatch", location, sql)

		if err == nil {
			t.Fatal("InvalidSetOperationError should return non-nil error")
		}
		if err.Code != ErrCodeInvalidSetOperation {
			t.Errorf("Error code = %s, want %s", err.Code, ErrCodeInvalidSetOperation)
		}
		if !strings.Contains(err.Message, "UNION") {
			t.Errorf("Error message should contain operation: %s", err.Message)
		}
		if !strings.Contains(err.Message, "column count mismatch") {
			t.Errorf("Error message should contain description: %s", err.Message)
		}
		if err.Context == nil {
			t.Error("Error should have context")
		}
		if err.Hint == "" {
			t.Error("Error should have hint")
		}
		if !strings.Contains(err.Hint, "same number") {
			t.Errorf("Hint should mention column matching: %s", err.Hint)
		}
	})
}

// TestAdvancedSuggestionFunctions tests all previously uncovered suggestion functions
// to achieve comprehensive coverage of the suggestions.go file.
func TestAdvancedSuggestionFunctions(t *testing.T) {
	t.Run("SuggestForWindowFunction - missing OVER", func(t *testing.T) {
		context := "SELECT ROW_NUMBER() FROM users"
		suggestion := SuggestForWindowFunction(context, "ROW_NUMBER")

		if !strings.Contains(suggestion, "OVER") {
			t.Errorf("Suggestion should mention OVER clause: %s", suggestion)
		}
		if !strings.Contains(suggestion, "ROW_NUMBER") {
			t.Errorf("Suggestion should mention function name: %s", suggestion)
		}
		if !strings.Contains(suggestion, "ORDER BY") {
			t.Errorf("Suggestion should mention ORDER BY: %s", suggestion)
		}
	})

	t.Run("SuggestForWindowFunction - PARTITION without OVER", func(t *testing.T) {
		context := "SELECT RANK() PARTITION BY dept FROM users"
		suggestion := SuggestForWindowFunction(context, "RANK")

		// Since context doesn't contain "OVER", it will return the missing OVER suggestion
		if !strings.Contains(suggestion, "OVER") {
			t.Errorf("Suggestion should mention OVER clause: %s", suggestion)
		}
	})

	t.Run("SuggestForWindowFunction - frame without ORDER BY", func(t *testing.T) {
		context := "SELECT SUM(amount) OVER (ROWS BETWEEN 1 PRECEDING AND CURRENT ROW)"
		suggestion := SuggestForWindowFunction(context, "SUM")

		if !strings.Contains(suggestion, "ORDER BY") {
			t.Errorf("Suggestion should mention ORDER BY requirement: %s", suggestion)
		}
		if !strings.Contains(suggestion, "ROWS") || !strings.Contains(suggestion, "RANGE") {
			t.Errorf("Suggestion should mention frame clauses: %s", suggestion)
		}
	})

	t.Run("SuggestForWindowFunction - general syntax check", func(t *testing.T) {
		context := "SELECT LAG(price) OVER (something wrong)"
		suggestion := SuggestForWindowFunction(context, "LAG")

		if !strings.Contains(suggestion, "window function") || !strings.Contains(suggestion, "syntax") {
			t.Errorf("Suggestion should provide syntax help: %s", suggestion)
		}
	})

	t.Run("SuggestForCTE - missing statement after WITH", func(t *testing.T) {
		context := "WITH cte AS (something) "
		suggestion := SuggestForCTE(context)

		// Should provide guidance about needing a statement after WITH
		if !strings.Contains(suggestion, "WITH") || !strings.Contains(suggestion, "SELECT") {
			t.Errorf("Suggestion should provide CTE guidance: %s", suggestion)
		}
	})

	t.Run("SuggestForCTE - recursive without UNION", func(t *testing.T) {
		context := "WITH RECURSIVE cte AS (SELECT * FROM base)"
		suggestion := SuggestForCTE(context)

		if !strings.Contains(suggestion, "UNION") {
			t.Errorf("Suggestion should mention UNION requirement: %s", suggestion)
		}
		if !strings.Contains(suggestion, "RECURSIVE") {
			t.Errorf("Suggestion should mention RECURSIVE: %s", suggestion)
		}
	})

	t.Run("SuggestForCTE - missing comma between CTEs", func(t *testing.T) {
		context := "WITH cte1 AS (SELECT 1) cte2 AS (SELECT 2) SELECT * FROM cte1"
		suggestion := SuggestForCTE(context)

		if !strings.Contains(suggestion, "comma") {
			t.Errorf("Suggestion should mention comma requirement: %s", suggestion)
		}
	})

	t.Run("SuggestForCTE - general syntax", func(t *testing.T) {
		context := "WITH something wrong SELECT x"
		suggestion := SuggestForCTE(context)

		// Should provide general CTE syntax guidance
		if suggestion == "" {
			t.Error("Should return a suggestion for CTE errors")
		}
	})

	t.Run("SuggestForSetOperation - ORDER BY in subquery", func(t *testing.T) {
		context := "(SELECT * FROM t1 ORDER BY id) UNION (SELECT * FROM t2)"
		suggestion := SuggestForSetOperation("UNION", context)

		if !strings.Contains(suggestion, "ORDER BY") {
			t.Errorf("Suggestion should mention ORDER BY placement: %s", suggestion)
		}
		if !strings.Contains(suggestion, "after") {
			t.Errorf("Suggestion should explain ORDER BY should be after: %s", suggestion)
		}
	})

	t.Run("SuggestForSetOperation - column mismatch", func(t *testing.T) {
		context := "column count mismatch between queries"
		suggestion := SuggestForSetOperation("INTERSECT", context)

		if !strings.Contains(suggestion, "same number") {
			t.Errorf("Suggestion should mention column matching: %s", suggestion)
		}
		if !strings.Contains(suggestion, "INTERSECT") {
			t.Errorf("Suggestion should mention operation: %s", suggestion)
		}
	})

	t.Run("SuggestForSetOperation - general syntax", func(t *testing.T) {
		context := "some error with EXCEPT"
		suggestion := SuggestForSetOperation("EXCEPT", context)

		if !strings.Contains(suggestion, "EXCEPT") {
			t.Errorf("Suggestion should mention operation: %s", suggestion)
		}
		if !strings.Contains(suggestion, "syntax") {
			t.Errorf("Suggestion should provide syntax help: %s", suggestion)
		}
	})

	t.Run("SuggestForJoinError - missing ON clause for INNER JOIN", func(t *testing.T) {
		context := "FROM users INNER JOIN orders"
		suggestion := SuggestForJoinError("INNER", context)

		if !strings.Contains(suggestion, "ON") {
			t.Errorf("Suggestion should mention ON clause: %s", suggestion)
		}
		if !strings.Contains(suggestion, "INNER JOIN") {
			t.Errorf("Suggestion should mention join type: %s", suggestion)
		}
	})

	t.Run("SuggestForJoinError - CROSS JOIN doesn't need ON", func(t *testing.T) {
		context := "FROM users CROSS JOIN products"
		suggestion := SuggestForJoinError("CROSS", context)

		if !strings.Contains(suggestion, "CROSS JOIN") {
			t.Errorf("Suggestion should mention CROSS JOIN: %s", suggestion)
		}
		if !strings.Contains(suggestion, "doesn't require") {
			t.Errorf("Suggestion should explain CROSS JOIN behavior: %s", suggestion)
		}
	})

	t.Run("SuggestForJoinError - ambiguous column", func(t *testing.T) {
		context := "ambiguous column reference in JOIN ON t1.id"
		suggestion := SuggestForJoinError("LEFT", context)

		if !strings.Contains(suggestion, "Qualify") || !strings.Contains(suggestion, "table") {
			t.Errorf("Suggestion should mention qualifying columns: %s", suggestion)
		}
	})

	t.Run("SuggestForJoinError - general syntax", func(t *testing.T) {
		context := "some error with RIGHT JOIN ON condition"
		suggestion := SuggestForJoinError("RIGHT", context)

		if !strings.Contains(suggestion, "RIGHT JOIN") {
			t.Errorf("Suggestion should mention join type: %s", suggestion)
		}
	})

	t.Run("GetAdvancedFeatureHint - all features", func(t *testing.T) {
		features := []string{
			"window_functions",
			"cte",
			"recursive_cte",
			"set_operations",
			"window_frames",
			"partition_by",
			"lateral_join",
			"grouping_sets",
		}

		for _, feature := range features {
			hint := GetAdvancedFeatureHint(feature)
			if hint == "" {
				t.Errorf("GetAdvancedFeatureHint(%q) should return non-empty hint", feature)
			}
			// Each hint should contain meaningful content
			if len(hint) < 20 {
				t.Errorf("GetAdvancedFeatureHint(%q) hint too short: %s", feature, hint)
			}
		}
	})

	t.Run("GetAdvancedFeatureHint - unknown feature", func(t *testing.T) {
		hint := GetAdvancedFeatureHint("unknown_feature")
		// Function returns a default message for unknown features
		if hint == "" {
			t.Error("GetAdvancedFeatureHint should return a default message for unknown features")
		}
		if !strings.Contains(hint, "documentation") && !strings.Contains(hint, "supported") {
			t.Errorf("Default hint should mention documentation or supported features: %s", hint)
		}
	})

	t.Run("GetAdvancedFeatureHint - window_functions content", func(t *testing.T) {
		hint := GetAdvancedFeatureHint("window_functions")
		expectedKeywords := []string{"ROW_NUMBER", "RANK", "DENSE_RANK", "LAG", "LEAD", "SUM", "OVER"}
		for _, keyword := range expectedKeywords {
			if !strings.Contains(hint, keyword) {
				t.Errorf("Window functions hint should contain %q: %s", keyword, hint)
			}
		}
	})

	t.Run("GetAdvancedFeatureHint - cte content", func(t *testing.T) {
		hint := GetAdvancedFeatureHint("cte")
		if !strings.Contains(hint, "WITH") || !strings.Contains(hint, "Common Table") {
			t.Errorf("CTE hint should mention WITH and Common Table Expressions: %s", hint)
		}
	})

	t.Run("GetAdvancedFeatureHint - recursive_cte content", func(t *testing.T) {
		hint := GetAdvancedFeatureHint("recursive_cte")
		if !strings.Contains(hint, "RECURSIVE") || !strings.Contains(hint, "UNION") {
			t.Errorf("Recursive CTE hint should mention RECURSIVE and UNION: %s", hint)
		}
	})

	t.Run("GetAdvancedFeatureHint - set_operations content", func(t *testing.T) {
		hint := GetAdvancedFeatureHint("set_operations")
		expectedOps := []string{"UNION", "INTERSECT", "EXCEPT"}
		for _, op := range expectedOps {
			if !strings.Contains(hint, op) {
				t.Errorf("Set operations hint should contain %q: %s", op, hint)
			}
		}
	})
}

// TestErrorBuilderIntegration tests error builders work correctly with other error package functions
func TestErrorBuilderIntegration(t *testing.T) {
	location := models.Location{Line: 5, Column: 20}
	sql := "WITH RECURSIVE cte AS (SELECT 1)"

	t.Run("Error builders chain with WithHint", func(t *testing.T) {
		err := InputTooLargeError(1000, 500, location)
		// Error already has a hint, verify it's set
		if err.Hint == "" {
			t.Error("Error should have hint from builder")
		}
	})

	t.Run("Error builders chain with WithContext", func(t *testing.T) {
		err := TokenLimitReachedError(100, 50, location, sql)
		// Error already has context, verify it's set
		if err.Context == nil {
			t.Error("Error should have context from builder")
		}
	})

	t.Run("Multiple errors can be created independently", func(t *testing.T) {
		err1 := RecursionDepthLimitError(50, 25, location, sql)
		err2 := UnsupportedDataTypeError("CUSTOM_TYPE", location, sql)

		if err1.Code == err2.Code {
			t.Error("Different error types should have different codes")
		}
		if err1.Message == err2.Message {
			t.Error("Different errors should have different messages")
		}
	})

	t.Run("Error builders preserve location information", func(t *testing.T) {
		testLocation := models.Location{Line: 42, Column: 13}
		err := UnsupportedConstraintError("EXCLUSION", testLocation, sql)

		if err.Location.Line != 42 {
			t.Errorf("Location line = %d, want 42", err.Location.Line)
		}
		if err.Location.Column != 13 {
			t.Errorf("Location column = %d, want 13", err.Location.Column)
		}
	})
}

// TestSuggestionEdgeCases tests edge cases in suggestion functions
func TestSuggestionEdgeCases(t *testing.T) {
	t.Run("SuggestForWindowFunction with empty context", func(t *testing.T) {
		suggestion := SuggestForWindowFunction("", "COUNT")
		if suggestion == "" {
			t.Error("Should return suggestion even for empty context")
		}
	})

	t.Run("SuggestForCTE with empty context", func(t *testing.T) {
		suggestion := SuggestForCTE("")
		if suggestion == "" {
			t.Error("Should return suggestion even for empty context")
		}
	})

	t.Run("SuggestForSetOperation with empty context", func(t *testing.T) {
		suggestion := SuggestForSetOperation("UNION", "")
		if suggestion == "" {
			t.Error("Should return suggestion even for empty context")
		}
	})

	t.Run("SuggestForJoinError with empty context", func(t *testing.T) {
		suggestion := SuggestForJoinError("INNER", "")
		if suggestion == "" {
			t.Error("Should return suggestion even for empty context")
		}
	})

	t.Run("SuggestForWindowFunction with case variations", func(t *testing.T) {
		contexts := []string{
			"select row_number() from users",
			"SELECT ROW_NUMBER() FROM USERS",
			"SeLeCt RoW_NuMbEr() FrOm UsErS",
		}
		for _, ctx := range contexts {
			suggestion := SuggestForWindowFunction(ctx, "ROW_NUMBER")
			// All should produce suggestions (case-insensitive matching)
			if !strings.Contains(suggestion, "OVER") {
				t.Errorf("Should handle case variations, got: %s", suggestion)
			}
		}
	})
}
