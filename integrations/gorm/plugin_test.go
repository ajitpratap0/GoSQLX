package gosqlxgorm_test

import (
	"testing"

	gosqlxgorm "github.com/ajitpratap0/GoSQLX/integrations/gorm"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type User struct {
	gorm.Model
	Name  string
	Email string
}

type Order struct {
	gorm.Model
	UserID uint
	Total  float64
}

func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open gorm db: %v", err)
	}
	_ = db.AutoMigrate(&User{}, &Order{})
	return db
}

func TestPlugin_Name(t *testing.T) {
	plugin := gosqlxgorm.NewPlugin()
	if plugin.Name() != "gosqlx" {
		t.Errorf("plugin name: got %q want gosqlx", plugin.Name())
	}
}

func TestPlugin_Initialize_NoError(t *testing.T) {
	db := openTestDB(t)
	plugin := gosqlxgorm.NewPlugin()
	if err := db.Use(plugin); err != nil {
		t.Fatalf("Use plugin: %v", err)
	}
}

func TestPlugin_RecordsQueriesOnQuery(t *testing.T) {
	db := openTestDB(t)
	plugin := gosqlxgorm.NewPlugin()
	if err := db.Use(plugin); err != nil {
		t.Fatal(err)
	}

	var users []User
	db.Find(&users)

	stats := plugin.Stats()
	if stats.TotalQueries == 0 {
		t.Error("expected at least one recorded query")
	}
}

func TestPlugin_RecordsTableName(t *testing.T) {
	db := openTestDB(t)
	plugin := gosqlxgorm.NewPlugin()
	_ = db.Use(plugin)

	var users []User
	db.Where("name = ?", "alice").Find(&users)

	stats := plugin.Stats()
	found := false
	for _, q := range stats.Queries {
		for _, tbl := range q.Tables {
			if tbl == "users" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("expected 'users' in recorded table names; got %+v", stats.Queries)
	}
}

func TestPlugin_ParseErrorDoesNotPanic(t *testing.T) {
	db := openTestDB(t)
	plugin := gosqlxgorm.NewPlugin()
	_ = db.Use(plugin)

	// Raw SQL that might not parse perfectly — plugin must not panic
	var result int
	db.Raw("SELECT 1 + 1").Scan(&result)

	// No panic = success
}
