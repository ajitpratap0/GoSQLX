package cmd

import (
	"testing"
)

func TestCLIOracleExecuteSlashFidelity(t *testing.T) {
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	for _, input := range []string{"BEGIN\n  NULL;\nEND;\n/\nSELECT 1 FROM dual;\n/", "SELECT 1 FROM dual\n/\nSELECT 2 FROM dual\n/\n"} {
		path := writeTemp(t, "oracle-execute.sql", input)
		result := runCLI(t, nil, "format", "--dialect", "oracle", path)
		if result.err != nil {
			t.Fatalf("format: %v\n%s", result.err, result.stderr)
		}
		want := "SELECT 1\nFROM dual\n/\nSELECT 2\nFROM dual\n/\n"
		if input[0] == 'B' {
			want = "BEGIN NULL; END;\n/\nSELECT 1\nFROM dual\n/\n"
		}
		if result.stdout != want {
			t.Errorf("got %q; want %q", result.stdout, want)
		}
	}
}
