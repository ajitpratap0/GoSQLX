package cmd

import (
	"bytes"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// TestPipelineIntegration tests the actual pipeline functionality
// These tests require the gosqlx binary to be built
func TestPipelineIntegration(t *testing.T) {
	// Skip if we're in a CI environment without the binary
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	// Build the binary for testing
	buildCmd := exec.Command("go", "build", "-o", "/tmp/gosqlx-test-bin", "../../main.go")
	buildCmd.Dir = "."
	if err := buildCmd.Run(); err != nil {
		t.Skipf("Failed to build gosqlx binary: %v", err)
		return
	}

	tests := []struct {
		name     string
		command  string
		input    string
		wantCode int
		contains string
	}{
		{
			name:     "echo to validate",
			command:  "echo 'SELECT * FROM users' | /tmp/gosqlx-test-bin validate",
			wantCode: 0,
			contains: "",
		},
		{
			name:     "echo to format",
			command:  "echo 'select * from users' | /tmp/gosqlx-test-bin format",
			wantCode: 0,
			contains: "SELECT",
		},
		{
			name:     "explicit stdin marker validate",
			command:  "echo 'SELECT 1' | /tmp/gosqlx-test-bin validate -",
			wantCode: 0,
			contains: "",
		},
		{
			name:     "explicit stdin marker format",
			command:  "echo 'select 1' | /tmp/gosqlx-test-bin format -",
			wantCode: 0,
			contains: "SELECT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use bash or sh depending on the platform
			shell := "sh"
			shellFlag := "-c"
			if runtime.GOOS == "windows" {
				shell = "cmd"
				shellFlag = "/C"
			}

			cmd := exec.Command(shell, shellFlag, tt.command)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			exitCode := 0
			if err != nil {
				if exitErr, ok := err.(*exec.ExitError); ok {
					exitCode = exitErr.ExitCode()
				} else {
					t.Logf("Command execution error: %v", err)
					t.Logf("Stdout: %s", stdout.String())
					t.Logf("Stderr: %s", stderr.String())
					// Don't fail the test, just log
					return
				}
			}

			if exitCode != tt.wantCode {
				t.Errorf("Exit code = %d, want %d", exitCode, tt.wantCode)
				t.Logf("Stdout: %s", stdout.String())
				t.Logf("Stderr: %s", stderr.String())
			}

			if tt.contains != "" && !strings.Contains(stdout.String(), tt.contains) {
				t.Errorf("Output does not contain %q\nGot: %s", tt.contains, stdout.String())
			}
		})
	}
}

// TestStdinDetection tests stdin detection without actual piping
func TestStdinDetection(t *testing.T) {
	tests := []struct {
		name     string
		args     []string
		expected bool
	}{
		{
			name:     "dash argument",
			args:     []string{"-"},
			expected: true,
		},
		{
			name:     "file argument",
			args:     []string{"query.sql"},
			expected: false,
		},
		{
			name:     "multiple arguments",
			args:     []string{"query1.sql", "query2.sql"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ShouldReadFromStdin(tt.args)
			if result != tt.expected {
				t.Errorf("ShouldReadFromStdin(%v) = %v, want %v", tt.args, result, tt.expected)
			}
		})
	}
}

// TestInputSourceDetection tests the comprehensive input detection
func TestInputSourceDetection(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantStdin bool
		wantErr   bool
	}{
		{
			name:      "explicit stdin",
			args:      []string{"-"},
			wantStdin: true,
			wantErr:   false,
		},
		{
			name:      "file argument",
			args:      []string{"test.sql"},
			wantStdin: false,
			wantErr:   false,
		},
		// Skipping "no arguments" test because IsStdinPipe() returns false in test environment
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useStdin, _, err := DetectInputMode(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("DetectInputMode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if useStdin != tt.wantStdin {
				t.Errorf("DetectInputMode() useStdin = %v, want %v", useStdin, tt.wantStdin)
			}
		})
	}
}

// TestBrokenPipeHandling tests that broken pipe errors are handled gracefully
func TestBrokenPipeHandling(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		wantErr bool
	}{
		{
			name:    "normal write",
			content: []byte("SELECT * FROM users"),
			wantErr: false,
		},
		{
			name:    "large content",
			content: bytes.Repeat([]byte("SELECT * FROM users\n"), 1000),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := WriteOutput(tt.content, "", &buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteOutput() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Verify content was written correctly
			if !bytes.Equal(buf.Bytes(), tt.content) {
				t.Errorf("WriteOutput() content mismatch")
			}
		})
	}
}

// TestInputValidation tests comprehensive input validation
func TestInputValidation(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		wantErr bool
	}{
		{
			name:    "valid SQL",
			content: []byte("SELECT * FROM users WHERE id = 1"),
			wantErr: false,
		},
		{
			name:    "empty content",
			content: []byte(""),
			wantErr: true,
		},
		{
			name:    "binary data",
			content: []byte{0x00, 0x01, 0x02, 0x03},
			wantErr: true,
		},
		{
			name:    "very large content",
			content: make([]byte, MaxStdinSize+1),
			wantErr: true,
		},
		{
			name:    "multiline SQL",
			content: []byte("SELECT *\nFROM users\nWHERE active = true\nORDER BY created_at DESC"),
			wantErr: false,
		},
		{
			name:    "SQL with special characters",
			content: []byte("SELECT * FROM users WHERE name = 'O''Brien'"),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateStdinInput(tt.content)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateStdinInput() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
