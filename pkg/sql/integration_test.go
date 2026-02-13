package sql

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// SQLTestFile represents a test file with metadata
type SQLTestFile struct {
	Path       string
	Dialect    string
	Name       string
	Complexity string // Simple, Medium, Complex
	Content    string
}

// TestResult stores the result of parsing a SQL file
type TestResult struct {
	File      string
	Dialect   string
	Success   bool
	Error     error
	ParseTime time.Duration
}

// loadSQLTestFiles loads all SQL files from testdata directory
func loadSQLTestFiles(t *testing.T, rootPath string) []SQLTestFile {
	var files []SQLTestFile

	dialects := []string{"postgresql", "mysql", "mssql", "oracle", "real_world"}

	for _, dialect := range dialects {
		dialectPath := filepath.Join(rootPath, "testdata", dialect)

		err := filepath.WalkDir(dialectPath, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() || !strings.HasSuffix(path, ".sql") {
				return nil
			}

			content, err := os.ReadFile(path)
			if err != nil {
				t.Logf("Warning: Could not read file %s: %v", path, err)
				return nil
			}

			// Extract complexity from comment
			complexity := "Medium"
			contentStr := string(content)
			if strings.Contains(contentStr, "Complexity: Simple") {
				complexity = "Simple"
			} else if strings.Contains(contentStr, "Complexity: Complex") {
				complexity = "Complex"
			}

			files = append(files, SQLTestFile{
				Path:       path,
				Dialect:    dialect,
				Name:       filepath.Base(path),
				Complexity: complexity,
				Content:    contentStr,
			})

			return nil
		})

		if err != nil {
			t.Logf("Warning: Could not walk directory %s: %v", dialectPath, err)
		}
	}

	return files
}

// extractSQLStatement extracts the main SQL statement from a file (ignoring comments)
func extractSQLStatement(content string) string {
	lines := strings.Split(content, "\n")
	var sqlLines []string

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip empty lines and comment-only lines
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		sqlLines = append(sqlLines, line)
	}

	return strings.Join(sqlLines, "\n")
}

// TestIntegration_AllDialects tests all SQL files across all dialects
func TestIntegration_AllDialects(t *testing.T) {
	// Get the project root (go up from pkg/sql to project root)
	projectRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("Failed to determine project root: %v", err)
	}

	files := loadSQLTestFiles(t, projectRoot)

	if len(files) == 0 {
		t.Skip("No SQL test files found - testdata directory may not exist")
	}

	t.Logf("Found %d SQL test files to process", len(files))

	var results []TestResult
	successCount := 0
	failCount := 0

	// Group tests by dialect for better organization
	dialectGroups := make(map[string][]SQLTestFile)
	for _, file := range files {
		dialectGroups[file.Dialect] = append(dialectGroups[file.Dialect], file)
	}

	// Run tests for each dialect
	for dialect, dialectFiles := range dialectGroups {
		t.Run(dialect, func(t *testing.T) {
			dialectSuccess := 0
			dialectFail := 0

			for _, file := range dialectFiles {
				t.Run(file.Name, func(t *testing.T) {
					result := testSQLFile(t, file)
					results = append(results, result)

					if result.Success {
						dialectSuccess++
						successCount++
					} else {
						dialectFail++
						failCount++
						t.Logf("Failed to parse %s: %v", file.Name, result.Error)
					}
				})
			}

			t.Logf("Dialect %s: %d passed, %d failed (%.1f%% success rate)",
				dialect, dialectSuccess, dialectFail,
				100.0*float64(dialectSuccess)/float64(dialectSuccess+dialectFail))
		})
	}

	// Summary statistics
	t.Logf("\n=== Integration Test Summary ===")
	t.Logf("Total files tested: %d", len(files))
	t.Logf("Successful parses: %d", successCount)
	t.Logf("Failed parses: %d", failCount)
	t.Logf("Success rate: %.2f%%", 100.0*float64(successCount)/float64(len(files)))

	// Breakdown by dialect
	t.Logf("\n=== Results by Dialect ===")
	for dialect, dialectFiles := range dialectGroups {
		dialectSuccess := 0
		for _, file := range dialectFiles {
			for _, result := range results {
				if result.File == file.Name && result.Success {
					dialectSuccess++
					break
				}
			}
		}
		t.Logf("%s: %d/%d files (%.1f%%)",
			dialect, dialectSuccess, len(dialectFiles),
			100.0*float64(dialectSuccess)/float64(len(dialectFiles)))
	}

	// Breakdown by complexity
	t.Logf("\n=== Results by Complexity ===")
	complexityGroups := make(map[string]int)
	complexitySuccess := make(map[string]int)
	for _, file := range files {
		complexityGroups[file.Complexity]++
		for _, result := range results {
			if result.File == file.Name && result.Success {
				complexitySuccess[file.Complexity]++
				break
			}
		}
	}
	for complexity, total := range complexityGroups {
		success := complexitySuccess[complexity]
		t.Logf("%s: %d/%d files (%.1f%%)",
			complexity, success, total,
			100.0*float64(success)/float64(total))
	}
}

// testSQLFile tests parsing a single SQL file
func testSQLFile(t *testing.T, file SQLTestFile) TestResult {
	result := TestResult{
		File:    file.Name,
		Dialect: file.Dialect,
		Success: false,
	}

	// Extract SQL statement (remove comments)
	sqlStatement := extractSQLStatement(file.Content)
	if strings.TrimSpace(sqlStatement) == "" {
		result.Error = fmt.Errorf("empty SQL statement after removing comments")
		return result
	}

	// Get tokenizer from pool
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	// Tokenize
	startTime := time.Now()
	tokens, err := tkz.Tokenize([]byte(sqlStatement))
	if err != nil {
		result.Error = fmt.Errorf("tokenization failed: %w", err)
		return result
	}

	// Convert tokens
	//lint:ignore SA1019 intentional use during #215 migration
	convertedTokens, err := parser.ConvertTokensForParser(tokens)
	if err != nil {
		result.Error = fmt.Errorf("token conversion failed: %w", err)
		return result
	}

	// Parse
	p := parser.NewParser()
	defer p.Release()

	ast, err := p.Parse(convertedTokens)
	result.ParseTime = time.Since(startTime)

	if err != nil {
		result.Error = fmt.Errorf("parsing failed: %w", err)
		return result
	}

	if ast == nil {
		result.Error = fmt.Errorf("parser returned nil AST without error")
		return result
	}

	if len(ast.Statements) == 0 {
		result.Error = fmt.Errorf("parser returned empty statement list")
		return result
	}

	result.Success = true
	return result
}

// TestIntegration_PostgreSQL_Simple tests simple PostgreSQL queries
func TestIntegration_PostgreSQL_Simple(t *testing.T) {
	projectRoot, _ := filepath.Abs(filepath.Join("..", ".."))
	files := loadSQLTestFiles(t, projectRoot)

	simplePostgres := filterFiles(files, "postgresql", "Simple")
	if len(simplePostgres) == 0 {
		t.Skip("No simple PostgreSQL test files found")
	}

	runTestBatch(t, simplePostgres, "PostgreSQL Simple Queries")
}

// TestIntegration_MySQL_Medium tests medium complexity MySQL queries
func TestIntegration_MySQL_Medium(t *testing.T) {
	projectRoot, _ := filepath.Abs(filepath.Join("..", ".."))
	files := loadSQLTestFiles(t, projectRoot)

	mediumMySQL := filterFiles(files, "mysql", "Medium")
	if len(mediumMySQL) == 0 {
		t.Skip("No medium MySQL test files found")
	}

	runTestBatch(t, mediumMySQL, "MySQL Medium Queries")
}

// TestIntegration_RealWorld_Complex tests complex real-world queries
func TestIntegration_RealWorld_Complex(t *testing.T) {
	projectRoot, _ := filepath.Abs(filepath.Join("..", ".."))
	files := loadSQLTestFiles(t, projectRoot)

	complexRealWorld := filterFiles(files, "real_world", "Complex")
	if len(complexRealWorld) == 0 {
		t.Skip("No complex real-world test files found")
	}

	runTestBatch(t, complexRealWorld, "Real-World Complex Queries")
}

// TestIntegration_WindowFunctions tests window function support across dialects
func TestIntegration_WindowFunctions(t *testing.T) {
	projectRoot, _ := filepath.Abs(filepath.Join("..", ".."))
	files := loadSQLTestFiles(t, projectRoot)

	windowFiles := []SQLTestFile{}
	for _, file := range files {
		if strings.Contains(strings.ToLower(file.Content), "over") &&
			(strings.Contains(strings.ToLower(file.Content), "partition") ||
				strings.Contains(strings.ToLower(file.Content), "row_number") ||
				strings.Contains(strings.ToLower(file.Content), "rank")) {
			windowFiles = append(windowFiles, file)
		}
	}

	if len(windowFiles) == 0 {
		t.Skip("No window function test files found")
	}

	t.Logf("Found %d files with window functions", len(windowFiles))
	runTestBatch(t, windowFiles, "Window Functions")
}

// TestIntegration_CTEs tests Common Table Expression support
func TestIntegration_CTEs(t *testing.T) {
	projectRoot, _ := filepath.Abs(filepath.Join("..", ".."))
	files := loadSQLTestFiles(t, projectRoot)

	cteFiles := []SQLTestFile{}
	for _, file := range files {
		if strings.Contains(strings.ToUpper(file.Content), "WITH") &&
			(strings.Contains(strings.ToUpper(file.Content), "AS (") ||
				strings.Contains(strings.ToUpper(file.Content), "RECURSIVE")) {
			cteFiles = append(cteFiles, file)
		}
	}

	if len(cteFiles) == 0 {
		t.Skip("No CTE test files found")
	}

	t.Logf("Found %d files with CTEs", len(cteFiles))
	runTestBatch(t, cteFiles, "Common Table Expressions")
}

// TestIntegration_JOINs tests JOIN support across dialects
func TestIntegration_JOINs(t *testing.T) {
	projectRoot, _ := filepath.Abs(filepath.Join("..", ".."))
	files := loadSQLTestFiles(t, projectRoot)

	joinFiles := []SQLTestFile{}
	for _, file := range files {
		content := strings.ToUpper(file.Content)
		if strings.Contains(content, "JOIN") &&
			(strings.Contains(content, "INNER JOIN") ||
				strings.Contains(content, "LEFT JOIN") ||
				strings.Contains(content, "RIGHT JOIN") ||
				strings.Contains(content, "FULL JOIN") ||
				strings.Contains(content, "CROSS JOIN")) {
			joinFiles = append(joinFiles, file)
		}
	}

	if len(joinFiles) == 0 {
		t.Skip("No JOIN test files found")
	}

	t.Logf("Found %d files with JOINs", len(joinFiles))
	runTestBatch(t, joinFiles, "JOIN Operations")
}

// filterFiles filters files by dialect and complexity
func filterFiles(files []SQLTestFile, dialect string, complexity string) []SQLTestFile {
	var filtered []SQLTestFile
	for _, file := range files {
		if file.Dialect == dialect && file.Complexity == complexity {
			filtered = append(filtered, file)
		}
	}
	return filtered
}

// runTestBatch runs a batch of tests and reports statistics
func runTestBatch(t *testing.T, files []SQLTestFile, batchName string) {
	if len(files) == 0 {
		t.Skip("No files to test")
	}

	successCount := 0
	var totalTime time.Duration

	for _, file := range files {
		result := testSQLFile(t, file)
		if result.Success {
			successCount++
		} else {
			t.Logf("Failed: %s - %v", file.Name, result.Error)
		}
		totalTime += result.ParseTime
	}

	avgTime := totalTime / time.Duration(len(files))
	successRate := 100.0 * float64(successCount) / float64(len(files))

	t.Logf("\n=== %s Summary ===", batchName)
	t.Logf("Total files: %d", len(files))
	t.Logf("Successful: %d", successCount)
	t.Logf("Failed: %d", len(files)-successCount)
	t.Logf("Success rate: %.2f%%", successRate)
	t.Logf("Average parse time: %v", avgTime)
	t.Logf("Total parse time: %v", totalTime)
}

// BenchmarkIntegration_SimpleQueries benchmarks simple queries across all dialects
func BenchmarkIntegration_SimpleQueries(b *testing.B) {
	projectRoot, _ := filepath.Abs(filepath.Join("..", ".."))
	files := loadSQLTestFiles(&testing.T{}, projectRoot)

	simpleFiles := []SQLTestFile{}
	for _, file := range files {
		if file.Complexity == "Simple" {
			simpleFiles = append(simpleFiles, file)
		}
	}

	if len(simpleFiles) == 0 {
		b.Skip("No simple test files found")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, file := range simpleFiles {
			sqlStatement := extractSQLStatement(file.Content)
			tkz := tokenizer.GetTokenizer()
			tokens, _ := tkz.Tokenize([]byte(sqlStatement))
			//lint:ignore SA1019 intentional use during #215 migration
			convertedTokens, _ := parser.ConvertTokensForParser(tokens)
			tokenizer.PutTokenizer(tkz)

			p := parser.NewParser()
			_, _ = p.Parse(convertedTokens)
			p.Release()
		}
	}
}

// BenchmarkIntegration_ComplexQueries benchmarks complex queries
func BenchmarkIntegration_ComplexQueries(b *testing.B) {
	projectRoot, _ := filepath.Abs(filepath.Join("..", ".."))
	files := loadSQLTestFiles(&testing.T{}, projectRoot)

	complexFiles := []SQLTestFile{}
	for _, file := range files {
		if file.Complexity == "Complex" {
			complexFiles = append(complexFiles, file)
		}
	}

	if len(complexFiles) == 0 {
		b.Skip("No complex test files found")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, file := range complexFiles {
			sqlStatement := extractSQLStatement(file.Content)
			tkz := tokenizer.GetTokenizer()
			tokens, _ := tkz.Tokenize([]byte(sqlStatement))
			//lint:ignore SA1019 intentional use during #215 migration
			convertedTokens, _ := parser.ConvertTokensForParser(tokens)
			tokenizer.PutTokenizer(tkz)

			p := parser.NewParser()
			_, _ = p.Parse(convertedTokens)
			p.Release()
		}
	}
}

// BenchmarkIntegration_RealWorldScenarios benchmarks real-world query scenarios
func BenchmarkIntegration_RealWorldScenarios(b *testing.B) {
	projectRoot, _ := filepath.Abs(filepath.Join("..", ".."))
	files := loadSQLTestFiles(&testing.T{}, projectRoot)

	realWorldFiles := []SQLTestFile{}
	for _, file := range files {
		if file.Dialect == "real_world" {
			realWorldFiles = append(realWorldFiles, file)
		}
	}

	if len(realWorldFiles) == 0 {
		b.Skip("No real-world test files found")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, file := range realWorldFiles {
			sqlStatement := extractSQLStatement(file.Content)
			tkz := tokenizer.GetTokenizer()
			tokens, _ := tkz.Tokenize([]byte(sqlStatement))
			//lint:ignore SA1019 intentional use during #215 migration
			convertedTokens, _ := parser.ConvertTokensForParser(tokens)
			tokenizer.PutTokenizer(tkz)

			p := parser.NewParser()
			_, _ = p.Parse(convertedTokens)
			p.Release()
		}
	}
}
