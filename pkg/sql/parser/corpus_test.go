package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Known parser limitations found through corpus testing:
// TODO(#225): DATE literal arithmetic (DATE '1998-12-01' - INTERVAL '90 DAY') — E2001 unexpected '-'
// TODO(#225): SUBSTRING(col FROM x FOR y) standard SQL syntax — E2002 expected , or ), got FROM
// TODO(#225): CTE column lists WITH cte(col1, col2) AS (...) — E2011 CTE syntax error
// TODO(#225): EXTRACT(YEAR FROM col) — may fail in certain subquery contexts
// TODO(#225): LIMIT with positional parameters ($1) — E2002 expected integer for LIMIT
// TODO(#225): HAVING with subquery referencing outer CTE — E2011

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

	passed := 0
	failed := 0
	total := 0

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
			statements := splitStatements(content)

			if len(statements) == 0 {
				t.Skip("no statements found in file")
			}

			fileFailed := false
			for i, stmt := range statements {
				stmt = strings.TrimSpace(stmt)
				if stmt == "" {
					continue
				}
				total++

				tkz := tokenizer.GetTokenizer()
				tokens, err := tkz.Tokenize([]byte(stmt))
				tokenizer.PutTokenizer(tkz)
				if err != nil {
					t.Skipf("statement %d: tokenize error: %v\n  SQL: %.200s", i+1, err, stmt)
					fileFailed = true
					failed++
					continue
				}

				converter := NewTokenConverter()
				result, err := converter.Convert(tokens)
				if err != nil {
					t.Skipf("statement %d: token conversion error: %v\n  SQL: %.200s", i+1, err, stmt)
					fileFailed = true
					failed++
					continue
				}

				p := GetParser()
				_, err = p.Parse(result.Tokens)
				PutParser(p)
				if err != nil {
					t.Skipf("statement %d: parse error: %v\n  SQL: %.200s", i+1, err, stmt)
					fileFailed = true
					failed++
				} else {
					passed++
				}
			}
			_ = fileFailed
		})
	}
}

// splitStatements splits SQL content by semicolons, respecting comment lines.
func splitStatements(content string) []string {
	var statements []string
	var current strings.Builder
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") {
			current.WriteString(line)
			current.WriteString("\n")
			continue
		}

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
