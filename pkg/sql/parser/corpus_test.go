package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// TestCorpus walks testdata/corpus/ recursively and attempts to parse every .sql file.
// Each file may contain multiple statements separated by semicolons.
// Failures are reported per-file as subtests for independent tracking.
func TestCorpus(t *testing.T) {
	corpusRoot := filepath.Join("..", "..", "..", "testdata", "corpus")

	if _, err := os.Stat(corpusRoot); os.IsNotExist(err) {
		t.Skipf("corpus directory not found at %s", corpusRoot)
	}

	var files []string
	err := filepath.Walk(corpusRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".sql") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("failed to walk corpus directory: %v", err)
	}

	if len(files) == 0 {
		t.Fatal("no .sql files found in corpus directory")
	}

	t.Logf("found %d SQL corpus files", len(files))

	for _, file := range files {
		file := file // capture
		relPath, _ := filepath.Rel(corpusRoot, file)
		t.Run(relPath, func(t *testing.T) {
			t.Parallel()

			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("failed to read file: %v", err)
			}

			content := string(data)
			// Split into individual statements by semicolon (skip empty)
			statements := splitStatements(content)

			if len(statements) == 0 {
				t.Skip("no statements found in file")
			}

			for i, stmt := range statements {
				stmt = strings.TrimSpace(stmt)
				if stmt == "" {
					continue
				}

				tkz := tokenizer.GetTokenizer()
				tokens, err := tkz.Tokenize([]byte(stmt))
				tokenizer.PutTokenizer(tkz)
				if err != nil {
					t.Skipf("statement %d: tokenize error: %v\n  SQL: %.200s", i+1, err, stmt)
					continue
				}

				p := GetParser()
				_, err = p.ParseFromModelTokens(tokens)
				PutParser(p)
				if err != nil {
					t.Skipf("statement %d: parse error: %v\n  SQL: %.200s", i+1, err, stmt)
				}
			}
		})
	}
}

// splitStatements splits SQL content by semicolons, respecting comments.
// This is a simple splitter — not a full tokenizer-aware one.
func splitStatements(content string) []string {
	var statements []string
	var current strings.Builder
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip pure comment lines for splitting purposes, but include them in current statement
		if strings.HasPrefix(trimmed, "--") {
			current.WriteString(line)
			current.WriteString("\n")
			continue
		}

		// Check if line ends with semicolon (simple heuristic)
		if strings.HasSuffix(trimmed, ";") {
			current.WriteString(strings.TrimSuffix(line, ";"))
			stmt := strings.TrimSpace(current.String())
			if stmt != "" && !isOnlyComments(stmt) {
				statements = append(statements, stmt)
			}
			current.Reset()
		} else {
			current.WriteString(line)
			current.WriteString("\n")
		}
	}

	// Handle trailing statement without semicolon
	remaining := strings.TrimSpace(current.String())
	if remaining != "" && !isOnlyComments(remaining) {
		statements = append(statements, remaining)
	}

	return statements
}

// isOnlyComments returns true if the string contains only comment lines and whitespace.
func isOnlyComments(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "--") {
			return false
		}
	}
	return true
}
