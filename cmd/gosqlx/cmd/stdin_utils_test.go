package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestValidateStdinInput(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		wantErr bool
	}{
		{
			name:    "valid SQL content",
			content: []byte("SELECT * FROM users"),
			wantErr: false,
		},
		{
			name:    "empty content",
			content: []byte(""),
			wantErr: true,
		},
		{
			name:    "content exceeds max size",
			content: make([]byte, MaxStdinSize+1),
			wantErr: true,
		},
		{
			name:    "binary data (null bytes)",
			content: []byte("SELECT\x00* FROM users"),
			wantErr: true,
		},
		{
			name:    "valid multiline SQL",
			content: []byte("SELECT *\nFROM users\nWHERE id = 1"),
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

func TestDetectInputMode(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantStdin   bool
		wantArg     string
		wantErr     bool
		description string
	}{
		{
			name:        "explicit stdin marker",
			args:        []string{"-"},
			wantStdin:   true,
			wantArg:     "-",
			wantErr:     false,
			description: "Single dash should trigger stdin",
		},
		{
			name:        "file argument",
			args:        []string{"query.sql"},
			wantStdin:   false,
			wantArg:     "query.sql",
			wantErr:     false,
			description: "File path should not trigger stdin",
		},
		// Skipping "no arguments" test because IsStdinPipe() returns false in test environment
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotStdin, gotArg, err := DetectInputMode(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("DetectInputMode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotStdin != tt.wantStdin {
				t.Errorf("DetectInputMode() gotStdin = %v, want %v", gotStdin, tt.wantStdin)
			}
			if gotArg != tt.wantArg {
				t.Errorf("DetectInputMode() gotArg = %v, want %v", gotArg, tt.wantArg)
			}
		})
	}
}

func TestShouldReadFromStdin(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{
			name: "explicit stdin marker",
			args: []string{"-"},
			want: true,
		},
		{
			name: "file argument",
			args: []string{"query.sql"},
			want: false,
		},
		{
			name: "multiple arguments",
			args: []string{"query1.sql", "query2.sql"},
			want: false,
		},
		{
			name: "no arguments",
			args: []string{},
			want: false, // Note: This depends on IsStdinPipe() which we can't easily test
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For this test, we can only test the explicit "-" case reliably
			// The IsStdinPipe() check requires actual pipe state
			if len(tt.args) > 0 {
				got := ShouldReadFromStdin(tt.args)
				if got != tt.want {
					t.Errorf("ShouldReadFromStdin() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestIsBrokenPipe(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "EPIPE error",
			err:  syscall.EPIPE,
			want: true,
		},
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "generic error",
			err:  io.ErrUnexpectedEOF,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsBrokenPipe(tt.err)
			if got != tt.want {
				t.Errorf("IsBrokenPipe() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWriteOutput(t *testing.T) {
	// Use platform-appropriate temp directory
	tmpFile := filepath.Join(os.TempDir(), "test_output.sql")

	tests := []struct {
		name       string
		content    []byte
		outputFile string
		wantErr    bool
		cleanup    func()
	}{
		{
			name:       "write to stdout",
			content:    []byte("SELECT * FROM users"),
			outputFile: "",
			wantErr:    false,
		},
		{
			name:       "write to file",
			content:    []byte("SELECT * FROM users"),
			outputFile: tmpFile,
			wantErr:    false,
			cleanup: func() {
				os.Remove(tmpFile)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.cleanup != nil {
				defer tt.cleanup()
			}

			var buf bytes.Buffer
			err := WriteOutput(tt.content, tt.outputFile, &buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteOutput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// If writing to stdout, verify content
			if tt.outputFile == "" {
				if !bytes.Equal(buf.Bytes(), tt.content) {
					t.Errorf("WriteOutput() stdout content mismatch")
				}
			} else {
				// If writing to file, verify file exists and content
				content, err := os.ReadFile(tt.outputFile)
				if err != nil {
					t.Errorf("Failed to read output file: %v", err)
					return
				}
				if !bytes.Equal(content, tt.content) {
					t.Errorf("WriteOutput() file content mismatch")
				}
			}
		})
	}
}

func TestGetInputSource(t *testing.T) {
	// Create a temporary SQL file for testing
	tmpFile, err := os.CreateTemp("", "test_*.sql")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	testSQL := "SELECT * FROM users WHERE id = 1"
	if _, err := tmpFile.Write([]byte(testSQL)); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	tests := []struct {
		name    string
		arg     string
		wantErr bool
		wantSrc string
	}{
		{
			name:    "file path",
			arg:     tmpFile.Name(),
			wantErr: false,
			wantSrc: tmpFile.Name(),
		},
		{
			name:    "direct SQL",
			arg:     "SELECT * FROM users",
			wantErr: false,
			wantSrc: "direct input",
		},
		{
			name:    "empty input",
			arg:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := GetInputSource(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetInputSource() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result.Source != tt.wantSrc {
				t.Errorf("GetInputSource() source = %v, want %v", result.Source, tt.wantSrc)
			}
		})
	}
}

// Benchmark tests
func BenchmarkValidateStdinInput(b *testing.B) {
	content := []byte("SELECT * FROM users WHERE id = 1")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ValidateStdinInput(content)
	}
}

func BenchmarkWriteOutput(b *testing.B) {
	content := []byte("SELECT * FROM users WHERE id = 1")
	var buf bytes.Buffer
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		_ = WriteOutput(content, "", &buf)
	}
}
