// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
