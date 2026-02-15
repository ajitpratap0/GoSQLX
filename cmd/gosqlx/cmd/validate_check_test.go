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
		name       string
		args       []string
		wantErr    bool
		wantEmpty  bool // stdout+stderr should be empty in quiet mode
	}{
		{
			name:      "check valid file produces no output",
			args:      []string{"--check", validSQL},
			wantErr:   false,
			wantEmpty: true,
		},
		{
			name:      "quiet valid file produces no output",
			args:      []string{"--quiet", validSQL},
			wantErr:   false,
			wantEmpty: true,
		},
		{
			name:    "check invalid file returns error",
			args:    []string{"--check", invalidSQL},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset the global flag
			validateQuiet = false

			stdout := &bytes.Buffer{}
			stderr := &bytes.Buffer{}

			cmd := validateCmd
			cmd.SetOut(stdout)
			cmd.SetErr(stderr)
			cmd.SetArgs(tt.args)

			err := cmd.Execute()

			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantEmpty && stdout.Len() > 0 {
				t.Errorf("Expected empty stdout in check mode, got: %s", stdout.String())
			}

			// Reset
			validateQuiet = false
		})
	}
}
