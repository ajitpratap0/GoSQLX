package compatibility

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// TestBackwardCompatibility_v1_x ensures all queries that worked in v1.x continue to work
// This is the main regression test suite
func TestBackwardCompatibility_v1_x(t *testing.T) {
	versions := []string{
		"v1.0.0",
		"v1.2.0",
		"v1.4.0",
		"v1.5.0",
		"v1.5.1",
	}

	for _, version := range versions {
		t.Run(version, func(t *testing.T) {
			testVersionCompatibility(t, version)
		})
	}
}

// testVersionCompatibility tests all golden queries for a specific version
func testVersionCompatibility(t *testing.T, version string) {
	goldenDir := filepath.Join("testdata", version)

	// Check if golden files exist for this version
	if _, err := os.Stat(goldenDir); os.IsNotExist(err) {
		t.Skipf("No golden files for %s (expected directory: %s)", version, goldenDir)
		return
	}

	// Load queries for this version
	queriesFile := filepath.Join(goldenDir, "queries.json")
	queries, err := loadQueriesFromJSON(queriesFile)
	if err != nil {
		t.Fatalf("Failed to load queries for %s: %v", version, err)
	}

	t.Logf("Testing %d queries from %s", len(queries), version)

	passCount := 0
	failCount := 0

	for _, query := range queries {
		t.Run(query.Name, func(t *testing.T) {
			// Parse query
			success, errMsg := parseQuery(query.SQL)

			if query.ShouldPass {
				if !success {
					// Enhanced error reporting for regressions
					t.Errorf("REGRESSION DETECTED in %s\n"+
						"Query Name: %s\n"+
						"Description: %s\n"+
						"Dialect: %s\n"+
						"Added In: %s\n"+
						"SQL: %s\n"+
						"Error: %s",
						version, query.Name, query.Description, query.Dialect,
						query.AddedVersion, query.SQL, errMsg)
					failCount++
				} else {
					passCount++
				}
			} else {
				// Document known failures - these are expected to fail but we track them
				if !success {
					t.Logf("Known failure (expected): %s - %s\nReason: %s",
						query.Name, errMsg, query.Description)
				} else {
					t.Logf("Previously failing query now passes: %s\nDescription: %s",
						query.Name, query.Description)
				}
			}
		})
	}

	// Summary
	total := len(queries)
	if total > 0 {
		passRate := float64(passCount) / float64(total) * 100
		t.Logf("Summary for %s: %d/%d passed (%.1f%%)", version, passCount, total, passRate)

		// Fail if we have any regressions
		if failCount > 0 {
			t.Errorf("REGRESSION DETECTED: %d queries that worked in %s now fail", failCount, version)
		}
	}
}

// QueryRecord represents a single query in the golden file
type QueryRecord struct {
	Name         string `json:"name"`
	SQL          string `json:"sql"`
	Dialect      string `json:"dialect"`
	ShouldPass   bool   `json:"shouldPass"`
	Description  string `json:"description"`
	AddedVersion string `json:"addedVersion"`
}

// loadQueriesFromJSON loads query records from a JSON file
func loadQueriesFromJSON(filePath string) ([]QueryRecord, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var queries []QueryRecord
	if err := json.Unmarshal(data, &queries); err != nil {
		return nil, err
	}

	return queries, nil
}

// parseQuery attempts to parse a SQL query and returns success status and error message
func parseQuery(sql string) (bool, string) {
	// Tokenize
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		return false, "Tokenization error: " + err.Error()
	}

	// Parse directly from model tokens
	p := parser.NewParser()
	defer p.Release()
	_, err = p.ParseFromModelTokens(tokens)
	if err != nil {
		return false, "Parse error: " + err.Error()
	}

	return true, ""
}

// TestBackwardCompatibility_ExistingTestData validates existing test data still parses
func TestBackwardCompatibility_ExistingTestData(t *testing.T) {
	// Test against existing testdata directories
	testdataDirs := []string{
		"../../testdata/postgresql",
		"../../testdata/mysql",
		"../../testdata/mssql",
		"../../testdata/oracle",
		"../../testdata/sql",
	}

	totalQueries := 0
	successQueries := 0

	for _, dir := range testdataDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue // Skip if directory doesn't exist
		}

		dialect := filepath.Base(dir)
		t.Run(dialect, func(t *testing.T) {
			err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				// Only process .sql files
				if info.IsDir() || !strings.HasSuffix(path, ".sql") {
					return nil
				}

				// Read SQL file
				content, err := os.ReadFile(path)
				if err != nil {
					t.Errorf("Failed to read %s: %v", path, err)
					return nil
				}

				// Parse queries from file
				queries := extractQueries(string(content))

				for _, query := range queries {
					totalQueries++
					queryName := filepath.Base(path) + "_q" + strings.TrimSpace(strings.Split(query, "\n")[0])

					success, errMsg := parseQuery(query)
					if success {
						successQueries++
					} else {
						t.Logf("Query from %s failed: %s\nError: %s", path, queryName, errMsg)
					}
				}

				return nil
			})

			if err != nil {
				t.Errorf("Error walking directory %s: %v", dir, err)
			}
		})
	}

	if totalQueries > 0 {
		successRate := float64(successQueries) / float64(totalQueries) * 100
		t.Logf("Overall success rate on existing test data: %.1f%% (%d/%d)",
			successRate, successQueries, totalQueries)
	}
}

// extractQueries splits a SQL file into individual queries
// Handles multi-line queries separated by semicolons and comment blocks
func extractQueries(content string) []string {
	var queries []string
	var currentQuery strings.Builder
	inBlockComment := false

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Skip empty lines
		if trimmed == "" {
			continue
		}

		// Handle block comments
		if strings.HasPrefix(trimmed, "/*") {
			inBlockComment = true
		}
		if strings.HasSuffix(trimmed, "*/") {
			inBlockComment = false
			continue
		}
		if inBlockComment {
			continue
		}

		// Skip line comments
		if strings.HasPrefix(trimmed, "--") || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Add line to current query
		currentQuery.WriteString(line)
		currentQuery.WriteString("\n")

		// Check for query terminator
		if strings.HasSuffix(trimmed, ";") {
			query := strings.TrimSpace(currentQuery.String())
			if query != "" && query != ";" {
				queries = append(queries, query)
			}
			currentQuery.Reset()
		}
	}

	// Add any remaining query
	if currentQuery.Len() > 0 {
		query := strings.TrimSpace(currentQuery.String())
		if query != "" && query != ";" {
			queries = append(queries, query)
		}
	}

	return queries
}
