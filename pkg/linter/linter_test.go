package linter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Mock rule for testing
type mockRule struct {
	BaseRule
	checkFunc func(*Context) ([]Violation, error)
	fixFunc   func(string, []Violation) (string, error)
}

func newMockRule(id, name, description string, severity Severity, canAutoFix bool) *mockRule {
	return &mockRule{
		BaseRule: NewBaseRule(id, name, description, severity, canAutoFix),
		checkFunc: func(ctx *Context) ([]Violation, error) {
			return []Violation{}, nil
		},
		fixFunc: func(content string, violations []Violation) (string, error) {
			return content, nil
		},
	}
}

func (r *mockRule) Check(ctx *Context) ([]Violation, error) {
	if r.checkFunc != nil {
		return r.checkFunc(ctx)
	}
	return []Violation{}, nil
}

func (r *mockRule) Fix(content string, violations []Violation) (string, error) {
	if r.fixFunc != nil {
		return r.fixFunc(content, violations)
	}
	return content, nil
}

// Mock trailing whitespace rule for testing
func newMockTrailingWhitespaceRule() *mockRule {
	rule := newMockRule(
		"L001",
		"Trailing Whitespace",
		"Unnecessary trailing whitespace at end of lines",
		SeverityWarning,
		true,
	)

	rule.checkFunc = func(ctx *Context) ([]Violation, error) {
		violations := []Violation{}
		for lineNum, line := range ctx.Lines {
			if len(line) == 0 {
				continue
			}
			// Check if line has trailing whitespace (spaces or tabs)
			if len(line) > 0 && (strings.HasSuffix(line, " ") || strings.HasSuffix(line, "\t")) {
				trimmed := strings.TrimRight(line, " \t")
				column := len(trimmed) + 1
				violations = append(violations, Violation{
					Rule:       rule.ID(),
					RuleName:   rule.Name(),
					Severity:   rule.Severity(),
					Message:    "Line has trailing whitespace",
					Location:   models.Location{Line: lineNum + 1, Column: column},
					Line:       line,
					Suggestion: "Remove trailing spaces or tabs from the end of the line",
					CanAutoFix: true,
				})
			}
		}
		return violations, nil
	}

	rule.fixFunc = func(content string, violations []Violation) (string, error) {
		lines := strings.Split(content, "\n")
		for i, line := range lines {
			lines[i] = strings.TrimRight(line, " \t")
		}
		return strings.Join(lines, "\n"), nil
	}

	return rule
}

// Mock mixed indentation rule for testing
func newMockMixedIndentationRule() *mockRule {
	rule := newMockRule(
		"L002",
		"Mixed Indentation",
		"Inconsistent use of tabs and spaces for indentation",
		SeverityError,
		true,
	)

	rule.checkFunc = func(ctx *Context) ([]Violation, error) {
		violations := []Violation{}
		var firstIndentType string // "tab" or "space"

		for lineNum, line := range ctx.Lines {
			if len(line) == 0 {
				continue
			}

			// Get leading whitespace
			leadingWhitespace := ""
			for _, char := range line {
				if char != ' ' && char != '\t' {
					break
				}
				leadingWhitespace += string(char)
			}

			if len(leadingWhitespace) == 0 {
				continue
			}

			hasTabs := strings.Contains(leadingWhitespace, "\t")
			hasSpaces := strings.Contains(leadingWhitespace, " ")

			// Mixed tabs and spaces on same line
			if hasTabs && hasSpaces {
				violations = append(violations, Violation{
					Rule:       rule.ID(),
					RuleName:   rule.Name(),
					Severity:   rule.Severity(),
					Message:    "Line mixes tabs and spaces for indentation",
					Location:   models.Location{Line: lineNum + 1, Column: 1},
					Line:       line,
					Suggestion: "Use either tabs or spaces consistently for indentation",
					CanAutoFix: true,
				})
				continue
			}

			// Track first indentation type
			currentType := ""
			if hasTabs {
				currentType = "tab"
			} else if hasSpaces {
				currentType = "space"
			}

			if currentType != "" {
				if firstIndentType == "" {
					firstIndentType = currentType
				} else if firstIndentType != currentType {
					violations = append(violations, Violation{
						Rule:       rule.ID(),
						RuleName:   rule.Name(),
						Severity:   rule.Severity(),
						Message:    "Inconsistent indentation: file uses both tabs and spaces",
						Location:   models.Location{Line: lineNum + 1, Column: 1},
						Line:       line,
						Suggestion: "Use " + firstIndentType + "s consistently throughout the file",
						CanAutoFix: true,
					})
				}
			}
		}

		return violations, nil
	}

	return rule
}

// Mock long lines rule for testing
func newMockLongLinesRule(maxLength int) *mockRule {
	if maxLength <= 0 {
		maxLength = 100
	}

	rule := newMockRule(
		"L005",
		"Long Lines",
		"Lines should not exceed maximum length for readability",
		SeverityInfo,
		false,
	)

	rule.checkFunc = func(ctx *Context) ([]Violation, error) {
		violations := []Violation{}

		for lineNum, line := range ctx.Lines {
			lineLength := len(line)

			if lineLength == 0 {
				continue
			}

			if lineLength > maxLength {
				violations = append(violations, Violation{
					Rule:       rule.ID(),
					RuleName:   rule.Name(),
					Severity:   rule.Severity(),
					Message:    "Line exceeds maximum length",
					Location:   models.Location{Line: lineNum + 1, Column: maxLength + 1},
					Line:       line,
					Suggestion: "Split this line into multiple lines",
					CanAutoFix: false,
				})
			}
		}

		return violations, nil
	}

	return rule
}

// TestLinter_New tests the New constructor
func TestLinter_New(t *testing.T) {
	tests := []struct {
		name          string
		rules         []Rule
		expectedRules int
	}{
		{
			name:          "Create linter with no rules",
			rules:         []Rule{},
			expectedRules: 0,
		},
		{
			name:          "Create linter with single rule",
			rules:         []Rule{newMockTrailingWhitespaceRule()},
			expectedRules: 1,
		},
		{
			name: "Create linter with multiple rules",
			rules: []Rule{
				newMockTrailingWhitespaceRule(),
				newMockMixedIndentationRule(),
				newMockLongLinesRule(80),
			},
			expectedRules: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			linter := New(tt.rules...)

			if linter == nil {
				t.Fatal("Expected non-nil linter")
			}

			if len(linter.rules) != tt.expectedRules {
				t.Errorf("Expected %d rules, got %d", tt.expectedRules, len(linter.rules))
			}
		})
	}
}

// TestLinter_Rules tests the Rules() method
func TestLinter_Rules(t *testing.T) {
	tests := []struct {
		name          string
		rules         []Rule
		expectedCount int
	}{
		{
			name:          "Verify Rules() returns correct rule list",
			rules:         []Rule{newMockTrailingWhitespaceRule(), newMockMixedIndentationRule()},
			expectedCount: 2,
		},
		{
			name:          "Verify Rules() with empty list",
			rules:         []Rule{},
			expectedCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			linter := New(tt.rules...)
			rules := linter.Rules()

			if len(rules) != tt.expectedCount {
				t.Errorf("Expected %d rules, got %d", tt.expectedCount, len(rules))
			}

			// Verify Rules() returns copy not reference
			if len(rules) > 0 {
				originalPtr := &linter.rules
				returnedPtr := &rules
				if originalPtr == returnedPtr {
					t.Error("Rules() should return a copy, not a reference")
				}
			}
		})
	}
}

// TestLinter_LintString tests the LintString() function
func TestLinter_LintString(t *testing.T) {
	tests := []struct {
		name               string
		sql                string
		rules              []Rule
		expectedViolations int
		expectError        bool
		checkViolations    func(*testing.T, []Violation)
	}{
		{
			name:               "Empty SQL string",
			sql:                "",
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedViolations: 0,
		},
		{
			name:               "Valid SQL with no violations",
			sql:                "SELECT id, name FROM users WHERE active = true",
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedViolations: 0,
		},
		{
			name:               "SQL with single violation (trailing whitespace)",
			sql:                "SELECT id   ",
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedViolations: 1,
			checkViolations: func(t *testing.T, violations []Violation) {
				if violations[0].Rule != "L001" {
					t.Errorf("Expected rule L001, got %s", violations[0].Rule)
				}
			},
		},
		{
			name:               "SQL with multiple violations from same rule",
			sql:                "SELECT id   \nFROM users  \nWHERE active = true   ",
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedViolations: 3,
		},
		{
			name: "SQL with violations from multiple rules",
			sql:  "SELECT id   \n  FROM users\n\tWHERE id = 1",
			rules: []Rule{
				newMockTrailingWhitespaceRule(),
				newMockMixedIndentationRule(),
			},
			expectedViolations: 2, // 1 trailing whitespace + 1 mixed indentation
		},
		{
			name:               "SQL with line numbers correctly tracked",
			sql:                "SELECT id\nFROM users  \nWHERE active = true",
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedViolations: 1,
			checkViolations: func(t *testing.T, violations []Violation) {
				if violations[0].Location.Line != 2 {
					t.Errorf("Expected violation on line 2, got line %d", violations[0].Location.Line)
				}
			},
		},
		{
			name:               "SQL that fails tokenization (invalid syntax)",
			sql:                "SELECT 'unterminated string",
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedViolations: 0, // No whitespace violations even with tokenization failure
		},
		{
			name:               "SQL that fails parsing but has whitespace violations",
			sql:                "SELECT * FROM   \nINVALID SYNTAX HERE",
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedViolations: 1, // Whitespace rules work without parsing
		},
		{
			name:               "Unicode SQL content",
			sql:                "SELECT name FROM users WHERE city = '東京'  ",
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedViolations: 1,
		},
		{
			name:               "Multi-line SQL with violations on different lines",
			sql:                "SELECT id  \nFROM users\nWHERE active = true  ",
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedViolations: 2,
			checkViolations: func(t *testing.T, violations []Violation) {
				if violations[0].Location.Line != 1 || violations[1].Location.Line != 3 {
					t.Error("Violations not on expected lines")
				}
			},
		},
		{
			name:               "Very long SQL (100+ lines)",
			sql:                generateLongSQL(100),
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedViolations: 100, // Every line has trailing whitespace
		},
		{
			name:               "SQL with Windows line endings",
			sql:                "SELECT id   \r\nFROM users  ",
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedViolations: 1, // Last line with trailing whitespace (first line split loses trailing)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			linter := New(tt.rules...)
			result := linter.LintString(tt.sql, "test.sql")

			if tt.expectError && result.Error == nil {
				t.Error("Expected error but got none")
			}

			if !tt.expectError && result.Error != nil {
				t.Errorf("Unexpected error: %v", result.Error)
			}

			if len(result.Violations) != tt.expectedViolations {
				t.Errorf("Expected %d violations, got %d", tt.expectedViolations, len(result.Violations))
				for i, v := range result.Violations {
					t.Logf("Violation %d: %s at line %d", i+1, v.Message, v.Location.Line)
				}
			}

			if tt.checkViolations != nil && len(result.Violations) > 0 {
				tt.checkViolations(t, result.Violations)
			}
		})
	}
}

// TestLinter_LintFile tests the LintFile() function
func TestLinter_LintFile(t *testing.T) {
	tests := []struct {
		name               string
		setupFile          func(t *testing.T) string // Returns file path
		rules              []Rule
		expectedViolations int
		expectError        bool
	}{
		{
			name: "Lint existing SQL file successfully",
			setupFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				filePath := filepath.Join(tmpDir, "test.sql")
				content := "SELECT id, name FROM users WHERE active = true"
				if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return filePath
			},
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedViolations: 0,
		},
		{
			name: "Lint file with no violations",
			setupFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				filePath := filepath.Join(tmpDir, "clean.sql")
				content := "SELECT id, name\nFROM users\nWHERE active = true"
				if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return filePath
			},
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedViolations: 0,
		},
		{
			name: "Lint file with violations",
			setupFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				filePath := filepath.Join(tmpDir, "violations.sql")
				content := "SELECT id   \nFROM users  \nWHERE active = true   "
				if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return filePath
			},
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedViolations: 3,
		},
		{
			name: "Lint non-existent file (error handling)",
			setupFile: func(t *testing.T) string {
				return "/nonexistent/path/to/file.sql"
			},
			rules:       []Rule{newMockTrailingWhitespaceRule()},
			expectError: true,
		},
		{
			name: "Lint file with Unicode content",
			setupFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				filePath := filepath.Join(tmpDir, "unicode.sql")
				content := "SELECT name FROM users WHERE city = '東京'  "
				if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return filePath
			},
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedViolations: 1,
		},
		{
			name: "Lint empty file",
			setupFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				filePath := filepath.Join(tmpDir, "empty.sql")
				if err := os.WriteFile(filePath, []byte(""), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return filePath
			},
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedViolations: 0,
		},
		{
			name: "Lint file with mixed line endings",
			setupFile: func(t *testing.T) string {
				tmpDir := t.TempDir()
				filePath := filepath.Join(tmpDir, "mixed.sql")
				content := "SELECT id   \r\nFROM users  "
				if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return filePath
			},
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedViolations: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := tt.setupFile(t)
			linter := New(tt.rules...)
			result := linter.LintFile(filePath)

			if tt.expectError && result.Error == nil {
				t.Error("Expected error but got none")
			}

			if !tt.expectError && result.Error != nil {
				t.Errorf("Unexpected error: %v", result.Error)
			}

			if !tt.expectError && len(result.Violations) != tt.expectedViolations {
				t.Errorf("Expected %d violations, got %d", tt.expectedViolations, len(result.Violations))
			}

			if result.Filename != filePath {
				t.Errorf("Expected filename %s, got %s", filePath, result.Filename)
			}
		})
	}
}

// TestLinter_LintFiles tests the LintFiles() function
func TestLinter_LintFiles(t *testing.T) {
	tests := []struct {
		name               string
		setupFiles         func(t *testing.T) []string
		rules              []Rule
		expectedFiles      int
		expectedViolations int
	}{
		{
			name: "Lint zero files (empty list)",
			setupFiles: func(t *testing.T) []string {
				return []string{}
			},
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedFiles:      0,
			expectedViolations: 0,
		},
		{
			name: "Lint single file",
			setupFiles: func(t *testing.T) []string {
				tmpDir := t.TempDir()
				filePath := filepath.Join(tmpDir, "test.sql")
				content := "SELECT id, name FROM users"
				if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return []string{filePath}
			},
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedFiles:      1,
			expectedViolations: 0,
		},
		{
			name: "Lint multiple files successfully",
			setupFiles: func(t *testing.T) []string {
				tmpDir := t.TempDir()
				file1 := filepath.Join(tmpDir, "test1.sql")
				file2 := filepath.Join(tmpDir, "test2.sql")
				content := "SELECT id FROM users"
				if err := os.WriteFile(file1, []byte(content), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				if err := os.WriteFile(file2, []byte(content), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return []string{file1, file2}
			},
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedFiles:      2,
			expectedViolations: 0,
		},
		{
			name: "Lint multiple files with some having violations",
			setupFiles: func(t *testing.T) []string {
				tmpDir := t.TempDir()
				file1 := filepath.Join(tmpDir, "clean.sql")
				file2 := filepath.Join(tmpDir, "dirty.sql")
				if err := os.WriteFile(file1, []byte("SELECT id FROM users"), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				if err := os.WriteFile(file2, []byte("SELECT id   \nFROM users  "), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return []string{file1, file2}
			},
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedFiles:      2,
			expectedViolations: 2,
		},
		{
			name: "Lint multiple files with some non-existent",
			setupFiles: func(t *testing.T) []string {
				tmpDir := t.TempDir()
				file1 := filepath.Join(tmpDir, "exists.sql")
				file2 := "/nonexistent/file.sql"
				if err := os.WriteFile(file1, []byte("SELECT id FROM users"), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
				return []string{file1, file2}
			},
			rules:         []Rule{newMockTrailingWhitespaceRule()},
			expectedFiles: 2,
			// No violations expected, but one file will have an error
		},
		{
			name: "Verify TotalFiles and TotalViolations counts",
			setupFiles: func(t *testing.T) []string {
				tmpDir := t.TempDir()
				files := make([]string, 3)
				for i := 0; i < 3; i++ {
					filePath := filepath.Join(tmpDir, "test"+string(rune('0'+i))+".sql")
					content := "SELECT id   \nFROM users  "
					if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
						t.Fatalf("Failed to create test file: %v", err)
					}
					files[i] = filePath
				}
				return files
			},
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedFiles:      3,
			expectedViolations: 6, // 2 violations per file * 3 files
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := tt.setupFiles(t)
			linter := New(tt.rules...)
			result := linter.LintFiles(files)

			if result.TotalFiles != tt.expectedFiles {
				t.Errorf("Expected TotalFiles %d, got %d", tt.expectedFiles, result.TotalFiles)
			}

			if result.TotalViolations != tt.expectedViolations {
				t.Errorf("Expected TotalViolations %d, got %d", tt.expectedViolations, result.TotalViolations)
			}

			if len(result.Files) != tt.expectedFiles {
				t.Errorf("Expected %d file results, got %d", tt.expectedFiles, len(result.Files))
			}
		})
	}
}

// TestLinter_LintDirectory tests the LintDirectory() function
func TestLinter_LintDirectory(t *testing.T) {
	tests := []struct {
		name               string
		setupDir           func(t *testing.T) (string, string) // Returns (dir, pattern)
		rules              []Rule
		expectedFiles      int
		expectedViolations int
		expectError        bool
	}{
		{
			name: "Lint directory with *.sql pattern",
			setupDir: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				os.WriteFile(filepath.Join(tmpDir, "test1.sql"), []byte("SELECT id FROM users"), 0644)
				os.WriteFile(filepath.Join(tmpDir, "test2.sql"), []byte("SELECT name FROM products"), 0644)
				return tmpDir, "*.sql"
			},
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedFiles:      2,
			expectedViolations: 0,
		},
		{
			name: "Lint directory with custom pattern (*.txt)",
			setupDir: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				os.WriteFile(filepath.Join(tmpDir, "query1.txt"), []byte("SELECT id FROM users"), 0644)
				os.WriteFile(filepath.Join(tmpDir, "query2.txt"), []byte("SELECT name FROM products"), 0644)
				os.WriteFile(filepath.Join(tmpDir, "ignore.sql"), []byte("SELECT * FROM test"), 0644)
				return tmpDir, "*.txt"
			},
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedFiles:      2,
			expectedViolations: 0,
		},
		{
			name: "Lint directory with no matching files",
			setupDir: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				os.WriteFile(filepath.Join(tmpDir, "test.txt"), []byte("SELECT id FROM users"), 0644)
				return tmpDir, "*.sql"
			},
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedFiles:      0,
			expectedViolations: 0,
		},
		{
			name: "Lint non-existent directory (error handling)",
			setupDir: func(t *testing.T) (string, string) {
				return "/nonexistent/directory", "*.sql"
			},
			rules:       []Rule{newMockTrailingWhitespaceRule()},
			expectError: true,
		},
		{
			name: "Lint directory recursively with nested subdirectories",
			setupDir: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				subDir := filepath.Join(tmpDir, "subdir")
				os.Mkdir(subDir, 0755)
				os.WriteFile(filepath.Join(tmpDir, "test1.sql"), []byte("SELECT id FROM users"), 0644)
				os.WriteFile(filepath.Join(subDir, "test2.sql"), []byte("SELECT name FROM products"), 0644)
				return tmpDir, "*.sql"
			},
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedFiles:      2,
			expectedViolations: 0,
		},
		{
			name: "Lint directory with mixed file types",
			setupDir: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				os.WriteFile(filepath.Join(tmpDir, "query.sql"), []byte("SELECT id FROM users"), 0644)
				os.WriteFile(filepath.Join(tmpDir, "readme.txt"), []byte("Documentation"), 0644)
				os.WriteFile(filepath.Join(tmpDir, "config.json"), []byte("{}"), 0644)
				return tmpDir, "*.sql"
			},
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedFiles:      1,
			expectedViolations: 0,
		},
		{
			name: "Lint directory with hidden files (.sql)",
			setupDir: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				os.WriteFile(filepath.Join(tmpDir, ".hidden.sql"), []byte("SELECT id FROM users"), 0644)
				os.WriteFile(filepath.Join(tmpDir, "visible.sql"), []byte("SELECT name FROM products"), 0644)
				return tmpDir, "*.sql"
			},
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedFiles:      2, // Both should be found
			expectedViolations: 0,
		},
		{
			name: "Lint empty directory",
			setupDir: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				return tmpDir, "*.sql"
			},
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedFiles:      0,
			expectedViolations: 0,
		},
		{
			name: "Verify file counts and violation aggregation",
			setupDir: func(t *testing.T) (string, string) {
				tmpDir := t.TempDir()
				os.WriteFile(filepath.Join(tmpDir, "test1.sql"), []byte("SELECT id   "), 0644)
				os.WriteFile(filepath.Join(tmpDir, "test2.sql"), []byte("SELECT name  \nFROM users  "), 0644)
				return tmpDir, "*.sql"
			},
			rules:              []Rule{newMockTrailingWhitespaceRule()},
			expectedFiles:      2,
			expectedViolations: 3, // 1 from test1.sql, 2 from test2.sql
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir, pattern := tt.setupDir(t)
			linter := New(tt.rules...)
			result := linter.LintDirectory(dir, pattern)

			if tt.expectError {
				// Check if there's an error in the result
				hasError := false
				for _, fileResult := range result.Files {
					if fileResult.Error != nil {
						hasError = true
						break
					}
				}
				if !hasError {
					t.Error("Expected error but got none")
				}
				return
			}

			if result.TotalFiles != tt.expectedFiles {
				t.Errorf("Expected TotalFiles %d, got %d", tt.expectedFiles, result.TotalFiles)
			}

			if result.TotalViolations != tt.expectedViolations {
				t.Errorf("Expected TotalViolations %d, got %d", tt.expectedViolations, result.TotalViolations)
			}
		})
	}
}

// TestFormatViolation tests the FormatViolation() function
func TestFormatViolation(t *testing.T) {
	tests := []struct {
		name            string
		violation       Violation
		expectedContent []string // Substrings that should appear in output
	}{
		{
			name: "Format violation with all fields",
			violation: Violation{
				Rule:       "L001",
				RuleName:   "Trailing Whitespace",
				Severity:   SeverityWarning,
				Message:    "Line has trailing whitespace",
				Location:   models.Location{Line: 5, Column: 10},
				Line:       "SELECT id   ",
				Suggestion: "Remove trailing spaces",
				CanAutoFix: true,
			},
			expectedContent: []string{"L001", "Trailing Whitespace", "line 5", "column 10", "warning", "Remove trailing spaces", "SELECT id"},
		},
		{
			name: "Format violation without suggestion",
			violation: Violation{
				Rule:     "L002",
				RuleName: "Mixed Indentation",
				Severity: SeverityError,
				Message:  "Inconsistent indentation",
				Location: models.Location{Line: 3, Column: 1},
				Line:     "\tSELECT id",
			},
			expectedContent: []string{"L002", "Mixed Indentation", "line 3", "column 1", "error"},
		},
		{
			name: "Format violation without line content",
			violation: Violation{
				Rule:     "L003",
				RuleName: "Test Rule",
				Severity: SeverityInfo,
				Message:  "Test message",
				Location: models.Location{Line: 1, Column: 1},
			},
			expectedContent: []string{"L003", "Test Rule", "line 1", "info"},
		},
		{
			name: "Format violation with column position 0",
			violation: Violation{
				Rule:     "L001",
				RuleName: "Trailing Whitespace",
				Severity: SeverityWarning,
				Message:  "Line has trailing whitespace",
				Location: models.Location{Line: 1, Column: 0},
				Line:     "SELECT id",
			},
			expectedContent: []string{"L001", "line 1", "column 0"},
		},
		{
			name: "Format violation with very long line",
			violation: Violation{
				Rule:     "L005",
				RuleName: "Long Lines",
				Severity: SeverityInfo,
				Message:  "Line exceeds maximum length",
				Location: models.Location{Line: 2, Column: 101},
				Line:     strings.Repeat("x", 200),
			},
			expectedContent: []string{"L005", "Long Lines", "line 2", "column 101"},
		},
		{
			name: "Format violation with Unicode content",
			violation: Violation{
				Rule:     "L001",
				RuleName: "Trailing Whitespace",
				Severity: SeverityWarning,
				Message:  "Line has trailing whitespace",
				Location: models.Location{Line: 1, Column: 20},
				Line:     "SELECT name FROM users WHERE city = '東京'  ",
			},
			expectedContent: []string{"L001", "東京"},
		},
		{
			name: "Format violation with different severity levels - error",
			violation: Violation{
				Rule:     "L002",
				RuleName: "Mixed Indentation",
				Severity: SeverityError,
				Message:  "Test error",
				Location: models.Location{Line: 1, Column: 1},
			},
			expectedContent: []string{"error"},
		},
		{
			name: "Format violation with different severity levels - info",
			violation: Violation{
				Rule:     "L005",
				RuleName: "Long Lines",
				Severity: SeverityInfo,
				Message:  "Test info",
				Location: models.Location{Line: 1, Column: 1},
			},
			expectedContent: []string{"info"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := FormatViolation(tt.violation)

			for _, expected := range tt.expectedContent {
				if !strings.Contains(output, expected) {
					t.Errorf("Expected output to contain %q, but it didn't.\nOutput: %s", expected, output)
				}
			}
		})
	}
}

// TestFormatResult tests the FormatResult() function
func TestFormatResult(t *testing.T) {
	tests := []struct {
		name            string
		result          Result
		expectedContent []string
	}{
		{
			name: "Format result with no files",
			result: Result{
				Files:           []FileResult{},
				TotalFiles:      0,
				TotalViolations: 0,
			},
			expectedContent: []string{"Total files: 0", "Total violations: 0"},
		},
		{
			name: "Format result with single file, no violations",
			result: Result{
				Files: []FileResult{
					{
						Filename:   "test.sql",
						Violations: []Violation{},
					},
				},
				TotalFiles:      1,
				TotalViolations: 0,
			},
			expectedContent: []string{"Total files: 1", "Total violations: 0"},
		},
		{
			name: "Format result with single file, single violation",
			result: Result{
				Files: []FileResult{
					{
						Filename: "test.sql",
						Violations: []Violation{
							{
								Rule:     "L001",
								RuleName: "Trailing Whitespace",
								Severity: SeverityWarning,
								Message:  "Line has trailing whitespace",
								Location: models.Location{Line: 1, Column: 10},
							},
						},
					},
				},
				TotalFiles:      1,
				TotalViolations: 1,
			},
			expectedContent: []string{"test.sql", "1 violation(s)", "L001", "Total files: 1", "Total violations: 1"},
		},
		{
			name: "Format result with multiple files and violations",
			result: Result{
				Files: []FileResult{
					{
						Filename: "test1.sql",
						Violations: []Violation{
							{
								Rule:     "L001",
								RuleName: "Trailing Whitespace",
								Severity: SeverityWarning,
								Message:  "Line has trailing whitespace",
								Location: models.Location{Line: 1, Column: 10},
							},
						},
					},
					{
						Filename: "test2.sql",
						Violations: []Violation{
							{
								Rule:     "L002",
								RuleName: "Mixed Indentation",
								Severity: SeverityError,
								Message:  "Inconsistent indentation",
								Location: models.Location{Line: 2, Column: 1},
							},
						},
					},
				},
				TotalFiles:      2,
				TotalViolations: 2,
			},
			expectedContent: []string{"test1.sql", "test2.sql", "L001", "L002", "Total files: 2", "Total violations: 2"},
		},
		{
			name: "Format result with file errors",
			result: Result{
				Files: []FileResult{
					{
						Filename: "test.sql",
						Error:    os.ErrNotExist,
					},
				},
				TotalFiles:      1,
				TotalViolations: 0,
			},
			expectedContent: []string{"test.sql", "ERROR"},
		},
		{
			name: "Format result with mixed success and errors",
			result: Result{
				Files: []FileResult{
					{
						Filename: "success.sql",
						Violations: []Violation{
							{
								Rule:     "L001",
								RuleName: "Trailing Whitespace",
								Severity: SeverityWarning,
								Message:  "Line has trailing whitespace",
								Location: models.Location{Line: 1, Column: 10},
							},
						},
					},
					{
						Filename: "error.sql",
						Error:    os.ErrPermission,
					},
				},
				TotalFiles:      2,
				TotalViolations: 1,
			},
			expectedContent: []string{"success.sql", "error.sql", "ERROR", "Total files: 2", "Total violations: 1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := FormatResult(tt.result)

			for _, expected := range tt.expectedContent {
				if !strings.Contains(output, expected) {
					t.Errorf("Expected output to contain %q, but it didn't.\nOutput: %s", expected, output)
				}
			}
		})
	}
}

// TestBaseRule tests the BaseRule implementation
func TestBaseRule(t *testing.T) {
	tests := []struct {
		name        string
		baseRule    BaseRule
		expectedID  string
		expectedStr string
		severity    Severity
		canAutoFix  bool
	}{
		{
			name: "Create BaseRule with all parameters",
			baseRule: NewBaseRule(
				"L001",
				"Test Rule",
				"This is a test rule",
				SeverityWarning,
				true,
			),
			expectedID:  "L001",
			expectedStr: "Test Rule",
			severity:    SeverityWarning,
			canAutoFix:  true,
		},
		{
			name: "Verify ID() method",
			baseRule: NewBaseRule(
				"L002",
				"Another Rule",
				"Another test rule",
				SeverityError,
				false,
			),
			expectedID:  "L002",
			expectedStr: "Another Rule",
			severity:    SeverityError,
			canAutoFix:  false,
		},
		{
			name: "Verify Name() method",
			baseRule: NewBaseRule(
				"L003",
				"Third Rule",
				"Third test rule",
				SeverityInfo,
				true,
			),
			expectedID:  "L003",
			expectedStr: "Third Rule",
			severity:    SeverityInfo,
			canAutoFix:  true,
		},
		{
			name: "Verify Description() method",
			baseRule: NewBaseRule(
				"L004",
				"Fourth Rule",
				"Fourth test rule with long description",
				SeverityWarning,
				false,
			),
			expectedID:  "L004",
			expectedStr: "Fourth Rule",
			severity:    SeverityWarning,
			canAutoFix:  false,
		},
		{
			name: "Verify Severity() and CanAutoFix() methods",
			baseRule: NewBaseRule(
				"L005",
				"Fifth Rule",
				"Fifth test rule",
				SeverityError,
				true,
			),
			expectedID:  "L005",
			expectedStr: "Fifth Rule",
			severity:    SeverityError,
			canAutoFix:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.baseRule.ID() != tt.expectedID {
				t.Errorf("Expected ID %q, got %q", tt.expectedID, tt.baseRule.ID())
			}

			if tt.baseRule.Name() != tt.expectedStr {
				t.Errorf("Expected Name %q, got %q", tt.expectedStr, tt.baseRule.Name())
			}

			if tt.baseRule.Description() == "" {
				t.Error("Expected non-empty description")
			}

			if tt.baseRule.Severity() != tt.severity {
				t.Errorf("Expected Severity %q, got %q", tt.severity, tt.baseRule.Severity())
			}

			if tt.baseRule.CanAutoFix() != tt.canAutoFix {
				t.Errorf("Expected CanAutoFix %v, got %v", tt.canAutoFix, tt.baseRule.CanAutoFix())
			}
		})
	}
}

// Helper function to generate long SQL for testing
func generateLongSQL(lines int) string {
	var sb strings.Builder
	for i := 0; i < lines; i++ {
		sb.WriteString("SELECT id FROM users  \n")
	}
	return strings.TrimSuffix(sb.String(), "\n")
}
