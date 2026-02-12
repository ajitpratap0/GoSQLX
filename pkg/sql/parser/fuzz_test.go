package parser

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// FuzzParse fuzzes the full parse pipeline (tokenizer + token conversion + parser)
// with arbitrary SQL input. The parser must never panic — only return errors gracefully.
func FuzzParse(f *testing.F) {
	// Seed from existing test fixture files
	seedDirs := []string{
		"testdata/real_world",
		"testdata/postgresql",
		"testdata/mysql",
	}
	for _, dir := range seedDirs {
		files, err := filepath.Glob(filepath.Join(dir, "*.sql"))
		if err != nil {
			continue
		}
		for _, file := range files {
			data, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			for _, stmt := range strings.Split(string(data), ";") {
				stmt = strings.TrimSpace(stmt)
				if stmt != "" && !strings.HasPrefix(stmt, "--") {
					f.Add(stmt)
				}
			}
		}
	}

	// Hand-crafted seeds covering edge cases
	seeds := []string{
		"SELECT 1",
		"SELECT * FROM t",
		"INSERT INTO t (a) VALUES (1)",
		"UPDATE t SET a = 1 WHERE b = 2",
		"DELETE FROM t WHERE a = 1",
		"CREATE TABLE t (id INT PRIMARY KEY)",
		"DROP TABLE t",
		"SELECT a FROM t1 JOIN t2 ON t1.id = t2.id",
		"SELECT * FROM t WHERE a IN (1, 2, 3)",
		"SELECT * FROM t WHERE a BETWEEN 1 AND 10",
		"SELECT COUNT(*) FROM t GROUP BY a HAVING COUNT(*) > 1",
		"WITH cte AS (SELECT 1) SELECT * FROM cte",
		"SELECT * FROM t ORDER BY a NULLS FIRST",
		"SELECT ROW_NUMBER() OVER (PARTITION BY a ORDER BY b) FROM t",
		"MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET t.a = s.a",
		"SELECT data->>'name' FROM t",
		"TRUNCATE TABLE t CASCADE",
		"",
		";;;",
		"SELECT",
		"FROM",
		"WHERE AND OR",
		"SELECT 'unclosed string",
		"SELECT (((",
		"SELECT * FROM",
		"INSERT INTO",
		"SELECT 1 UNION ALL SELECT 2 INTERSECT SELECT 3",
		"SELECT CASE WHEN 1=1 THEN 'a' ELSE 'b' END FROM t",
		"SELECT CAST(1 AS VARCHAR) FROM t",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, sql string) {
		// Step 1: Tokenize — must not panic
		tkz := tokenizer.GetTokenizer()
		defer tokenizer.PutTokenizer(tkz)

		tokens, err := tkz.Tokenize([]byte(sql))
		if err != nil {
			return // tokenizer errors are expected
		}

		// Step 2: Convert tokens — must not panic
		converter := NewTokenConverter()
		result, err := converter.Convert(tokens)
		if err != nil {
			return // conversion errors are expected
		}

		// Step 3: Parse — must not panic
		p := NewParser()
		defer p.Release()
		_, _ = p.ParseWithPositions(result)
	})
}
