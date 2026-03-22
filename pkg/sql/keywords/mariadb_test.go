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
