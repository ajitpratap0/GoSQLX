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
