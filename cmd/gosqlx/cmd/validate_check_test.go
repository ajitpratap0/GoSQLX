package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateCheckMode(t *testing.T) {
	// Create temp dir with test SQL files
	dir := t.TempDir()

	validSQL := filepath.Join(dir, "valid.sql")
	if err := os.WriteFile(validSQL, []byte("SELECT 1"), 0600); err != nil {
		t.Fatal(err)
	}

	invalidSQL := filepath.Join(dir, "invalid.sql")
	if err := os.WriteFile(invalidSQL, []byte("SELEC BOGUS FROM"), 0600); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		wantEmpty bool // stdout+stderr should be empty in quiet mode
	}{
		{
			name:      "check valid file produces no output",
			args:      []string{"validate", "--check", validSQL},
			wantErr:   false,
			wantEmpty: true,
		},
		{
			name:      "quiet valid file produces no output",
			args:      []string{"validate", "--quiet", validSQL},
			wantErr:   false,
			wantEmpty: true,
		},
		{
			name:    "check invalid file returns error",
			args:    []string{"validate", "--check", invalidSQL},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and reset all global validate flags
			savedQuiet := validateQuiet
			savedRecursive := validateRecursive
			savedPattern := validatePattern
			savedStats := validateStats
			savedDialect := validateDialect
			savedStrict := validateStrict
			savedOutputFormat := validateOutputFormat
			savedOutputFile := validateOutputFile
			t.Cleanup(func() {
				validateQuiet = savedQuiet
				validateRecursive = savedRecursive
				validatePattern = savedPattern
				validateStats = savedStats
				validateDialect = savedDialect
				validateStrict = savedStrict
				validateOutputFormat = savedOutputFormat
				validateOutputFile = savedOutputFile
			})

			validateQuiet = false

			stdout := &bytes.Buffer{}
			stderr := &bytes.Buffer{}

			// Use rootCmd to properly route subcommands (cobra's Execute traverses to root anyway)
			rootCmd.SetOut(stdout)
			rootCmd.SetErr(stderr)
			rootCmd.SetArgs(tt.args)

			err := rootCmd.Execute()

			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantEmpty && stdout.Len() > 0 {
				t.Errorf("Expected empty stdout in check mode, got: %s", stdout.String())
			}
		})
	}
}
