package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// BenchmarkDetectAndReadInput benchmarks the input detection functionality
func BenchmarkDetectAndReadInput(b *testing.B) {
	testCases := []struct {
		name  string
		input string
	}{
		{"DirectSQL_Simple", "SELECT id FROM users"},
		{"DirectSQL_Complex", "SELECT u.name, COUNT(p.id) FROM users u LEFT JOIN posts p ON u.id = p.user_id GROUP BY u.name"},
		{"DirectSQL_WithCTE", "WITH cte AS (SELECT id FROM users) SELECT * FROM cte"},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := DetectAndReadInput(tc.input)
				if err != nil {
					b.Fatalf("DetectAndReadInput failed: %v", err)
				}
			}
		})
	}

	// File input benchmark
	b.Run("FileInput", func(b *testing.B) {
		tmpDir := b.TempDir()
		testFile := filepath.Join(tmpDir, "benchmark.sql")
		testSQL := "SELECT u.id, u.name, COUNT(p.id) as post_count FROM users u LEFT JOIN posts p ON u.id = p.user_id WHERE u.active = true GROUP BY u.id, u.name ORDER BY post_count DESC"

		err := os.WriteFile(testFile, []byte(testSQL), 0644)
		if err != nil {
			b.Fatalf("Failed to create test file: %v", err)
		}

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := DetectAndReadInput(testFile)
			if err != nil {
				b.Fatalf("DetectAndReadInput failed: %v", err)
			}
		}
	})
}

// BenchmarkValidateFile benchmarks the SQL validation functionality
func BenchmarkValidateFile(b *testing.B) {
	tmpDir := b.TempDir()

	testCases := []struct {
		name string
		sql  string
	}{
		{"Simple_SELECT", "SELECT id, name FROM users"},
		{"SELECT_with_columns", "SELECT id, name FROM users"},
		{"SELECT_star", "SELECT * FROM users"},
		{"Basic_query", "SELECT name FROM table1"},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			testFile := filepath.Join(tmpDir, fmt.Sprintf("benchmark_%s.sql", tc.name))
			err := os.WriteFile(testFile, []byte(tc.sql), 0644)
			if err != nil {
				b.Fatalf("Failed to create test file: %v", err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _, err := validateFile(testFile)
				if err != nil {
					b.Fatalf("validateFile failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkFormatFile benchmarks the SQL formatting functionality
func BenchmarkFormatFile(b *testing.B) {
	tmpDir := b.TempDir()

	testCases := []struct {
		name string
		sql  string
	}{
		{"Unformatted_Simple", "select id,name from users"},
		{"SELECT_format", "select * from table1"},
		{"Already_Formatted", "SELECT id, name FROM users"},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			testFile := filepath.Join(tmpDir, fmt.Sprintf("benchmark_%s.sql", tc.name))
			err := os.WriteFile(testFile, []byte(tc.sql), 0644)
			if err != nil {
				b.Fatalf("Failed to create test file: %v", err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _, err := formatFile(testFile)
				if err != nil {
					b.Fatalf("formatFile failed: %v", err)
				}
			}
		})
	}
}

// BenchmarkLooksLikeSQL benchmarks the SQL detection heuristics
func BenchmarkLooksLikeSQL(b *testing.B) {
	testCases := []struct {
		name  string
		input string
	}{
		{"SQL_SELECT", "SELECT id FROM users"},
		{"SQL_INSERT", "INSERT INTO users (name) VALUES ('test')"},
		{"SQL_Complex", "WITH cte AS (SELECT id FROM users) SELECT * FROM cte WHERE active = true"},
		{"Not_SQL_Text", "this is just plain text"},
		{"Not_SQL_Filename", "myfile.sql"},
		{"Not_SQL_Path", "/path/to/file"},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = looksLikeSQL(tc.input)
			}
		})
	}
}

// BenchmarkValidateFileAccess benchmarks the file access validation
func BenchmarkValidateFileAccess(b *testing.B) {
	tmpDir := b.TempDir()
	testFile := filepath.Join(tmpDir, "test.sql")
	err := os.WriteFile(testFile, []byte("SELECT 1"), 0644)
	if err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := ValidateFileAccess(testFile)
		if err != nil {
			b.Fatalf("ValidateFileAccess failed: %v", err)
		}
	}
}

// BenchmarkExpandFileArgs benchmarks the file expansion functionality
func BenchmarkExpandFileArgs(b *testing.B) {
	tmpDir := b.TempDir()

	// Create multiple test files
	for i := 0; i < 10; i++ {
		testFile := filepath.Join(tmpDir, fmt.Sprintf("test%d.sql", i))
		err := os.WriteFile(testFile, []byte("SELECT 1"), 0644)
		if err != nil {
			b.Fatalf("Failed to create test file: %v", err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ExpandFileArgs([]string{tmpDir})
		if err != nil {
			b.Fatalf("ExpandFileArgs failed: %v", err)
		}
	}
}

// BenchmarkCLIThroughput measures overall CLI processing throughput
func BenchmarkCLIThroughput(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping throughput benchmark in short mode")
	}

	tmpDir := b.TempDir()

	// Create various SQL files for throughput testing
	sqlQueries := []string{
		"SELECT id FROM users",
		"SELECT * FROM table1",
		"SELECT name FROM users",
		"SELECT id, name FROM table2",
	}

	files := make([]string, len(sqlQueries))
	for i, sql := range sqlQueries {
		filename := filepath.Join(tmpDir, fmt.Sprintf("query%d.sql", i))
		err := os.WriteFile(filename, []byte(sql), 0644)
		if err != nil {
			b.Fatalf("Failed to create test file: %v", err)
		}
		files[i] = filename
	}

	b.Run("Validation_Throughput", func(b *testing.B) {
		b.ResetTimer()
		start := time.Now()

		totalFiles := 0
		for i := 0; i < b.N; i++ {
			for _, file := range files {
				_, _, err := validateFile(file)
				if err != nil {
					b.Fatalf("validateFile failed: %v", err)
				}
				totalFiles++
			}
		}

		duration := time.Since(start)
		filesPerSecond := float64(totalFiles) / duration.Seconds()

		b.ReportMetric(filesPerSecond, "files/sec")
		b.Logf("Validation throughput: %.2f files/second", filesPerSecond)
	})

	b.Run("Format_Throughput", func(b *testing.B) {
		b.ResetTimer()
		start := time.Now()

		totalFiles := 0
		for i := 0; i < b.N; i++ {
			for _, file := range files {
				_, _, err := formatFile(file)
				if err != nil {
					b.Fatalf("formatFile failed: %v", err)
				}
				totalFiles++
			}
		}

		duration := time.Since(start)
		filesPerSecond := float64(totalFiles) / duration.Seconds()

		b.ReportMetric(filesPerSecond, "files/sec")
		b.Logf("Format throughput: %.2f files/second", filesPerSecond)
	})
}

// BenchmarkMemoryEfficiency tests memory efficiency of CLI operations
func BenchmarkMemoryEfficiency(b *testing.B) {
	tmpDir := b.TempDir()

	// Create a reasonably sized SQL file
	var sqlBuilder strings.Builder
	sqlBuilder.WriteString("SELECT ")
	for i := 0; i < 50; i++ {
		if i > 0 {
			sqlBuilder.WriteString(", ")
		}
		sqlBuilder.WriteString(fmt.Sprintf("col%d", i))
	}
	sqlBuilder.WriteString(" FROM large_table WHERE ")
	for i := 0; i < 20; i++ {
		if i > 0 {
			sqlBuilder.WriteString(" AND ")
		}
		sqlBuilder.WriteString(fmt.Sprintf("col%d > %d", i, i*10))
	}

	testSQL := "SELECT id, name, email, status FROM users"
	testFile := filepath.Join(tmpDir, "large.sql")
	err := os.WriteFile(testFile, []byte(testSQL), 0644)
	if err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	b.Run("Memory_Efficiency_Validation", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, err := validateFile(testFile)
			if err != nil {
				b.Fatalf("validateFile failed: %v", err)
			}
		}
	})

	b.Run("Memory_Efficiency_Format", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, err := formatFile(testFile)
			if err != nil {
				b.Fatalf("formatFile failed: %v", err)
			}
		}
	})
}
