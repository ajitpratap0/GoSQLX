package keywords_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestDialectMariaDB_Constant(t *testing.T) {
	if string(keywords.DialectMariaDB) != "mariadb" {
		t.Fatalf("expected DialectMariaDB = \"mariadb\", got %q", keywords.DialectMariaDB)
	}
}

func TestDialectMariaDB_InAllDialects(t *testing.T) {
	found := false
	for _, d := range keywords.AllDialects() {
		if d == keywords.DialectMariaDB {
			found = true
			break
		}
	}
	if !found {
		t.Error("DialectMariaDB not found in AllDialects()")
	}
}

func TestDialectMariaDB_IsValidDialect(t *testing.T) {
	if !keywords.IsValidDialect("mariadb") {
		t.Error("IsValidDialect(\"mariadb\") returned false")
	}
}

func TestDialectMariaDB_InheritsMySQL(t *testing.T) {
	kw := keywords.New(keywords.DialectMariaDB, true)
	for _, word := range []string{"UNSIGNED", "ZEROFILL", "DATETIME"} {
		if !kw.IsKeyword(word) {
			t.Errorf("expected MariaDB to inherit MySQL keyword %q", word)
		}
	}
}

func TestMariaDBKeywords_Recognized(t *testing.T) {
	kw := keywords.New(keywords.DialectMariaDB, true)

	mariadbOnly := []string{
		// Sequence DDL
		"SEQUENCE", "NEXTVAL", "LASTVAL", "SETVAL",
		// Temporal tables
		"VERSIONING", "PERIOD", "OVERLAPS",
		// Hierarchical queries
		"PRIOR", "NOCYCLE",
		// Index visibility
		"INVISIBLE", "VISIBLE",
	}
	for _, word := range mariadbOnly {
		if !kw.IsKeyword(word) {
			t.Errorf("expected %q to be a keyword in DialectMariaDB", word)
		}
	}
}

func TestMariaDBKeywords_InheritsMySQLKeywords(t *testing.T) {
	kw := keywords.New(keywords.DialectMariaDB, true)

	// These are MySQL-specific keywords that MariaDB must also recognize
	mysqlKeywords := []string{"UNSIGNED", "ZEROFILL", "KILL", "PURGE", "STATUS", "VARIABLES"}
	for _, word := range mysqlKeywords {
		if !kw.IsKeyword(word) {
			t.Errorf("MariaDB dialect must inherit MySQL keyword %q", word)
		}
	}
}

func TestMariaDBKeywords_NotRecognizedInMySQLDialect(t *testing.T) {
	kw := keywords.New(keywords.DialectMySQL, true)

	mariadbOnlyKeywords := []string{"VERSIONING", "PRIOR", "NOCYCLE", "INVISIBLE"}
	for _, word := range mariadbOnlyKeywords {
		if kw.IsKeyword(word) {
			t.Errorf("keyword %q should NOT be recognized in pure MySQL dialect", word)
		}
	}
}

func TestDetectDialect_MariaDB(t *testing.T) {
	tests := []struct {
		name string
		sql  string
	}{
		{
			name: "CREATE SEQUENCE",
			sql:  "CREATE SEQUENCE seq_orders START WITH 1 INCREMENT BY 1",
		},
		{
			name: "WITH SYSTEM VERSIONING",
			sql:  "CREATE TABLE orders (id INT) WITH SYSTEM VERSIONING",
		},
		{
			name: "FOR SYSTEM_TIME",
			sql:  "SELECT * FROM orders FOR SYSTEM_TIME AS OF TIMESTAMP '2024-01-01'",
		},
		{
			name: "DROP SEQUENCE",
			sql:  "DROP SEQUENCE seq_orders",
		},
		{
			name: "NEXTVAL",
			sql:  "SELECT NEXTVAL(seq_orders)",
		},
		{
			name: "CONNECT BY with NEXTVAL (MariaDB wins on accumulation)",
			sql:  "SELECT NEXTVAL(s) FROM t CONNECT BY PRIOR id = parent_id",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := keywords.DetectDialect(tt.sql)
			if got != keywords.DialectMariaDB {
				t.Errorf("DetectDialect(%q) = %q, want %q", tt.sql, got, keywords.DialectMariaDB)
			}
		})
	}
}
