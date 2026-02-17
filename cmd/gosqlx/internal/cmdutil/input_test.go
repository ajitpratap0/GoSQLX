package cmdutil

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsValidSQLFileExtension(t *testing.T) {
	tests := []struct {
		ext  string
		want bool
	}{
		{".sql", true},
		{".txt", true},
		{"", false},
		{".go", false},
		{".csv", false},
		{".SQL", false}, // case-sensitive
	}
	for _, tt := range tests {
		if got := IsValidSQLFileExtension(tt.ext); got != tt.want {
			t.Errorf("IsValidSQLFileExtension(%q) = %v, want %v", tt.ext, got, tt.want)
		}
	}
}

func TestExpandDirectory(t *testing.T) {
	dir := t.TempDir()

	// Create test files
	os.WriteFile(filepath.Join(dir, "a.sql"), []byte("SELECT 1"), 0644)
	os.WriteFile(filepath.Join(dir, "b.txt"), []byte("SELECT 2"), 0644)
	os.WriteFile(filepath.Join(dir, "c.go"), []byte("package x"), 0644)
	os.Mkdir(filepath.Join(dir, "subdir"), 0755)

	files, err := ExpandDirectory(dir)
	if err != nil {
		t.Fatalf("ExpandDirectory() error: %v", err)
	}

	// Should find .sql and .txt but not .go or subdir
	if len(files) != 2 {
		t.Errorf("ExpandDirectory() returned %d files, want 2: %v", len(files), files)
	}
}

func TestExpandDirectory_NotExist(t *testing.T) {
	_, err := ExpandDirectory("/nonexistent/path")
	if err == nil {
		t.Error("ExpandDirectory() expected error for nonexistent path")
	}
}

func TestLooksLikeSQL(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"SELECT * FROM t", true},
		{"INSERT INTO t VALUES (1)", true},
		{"hello world", false},
		{"", false},
		{"CREATE TABLE t (id INT)", true},
	}
	for _, tt := range tests {
		if got := LooksLikeSQL(tt.input); got != tt.want {
			t.Errorf("LooksLikeSQL(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
