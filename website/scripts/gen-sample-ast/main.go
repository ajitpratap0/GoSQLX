// Command gen-sample-ast writes the real GoSQLX AST JSON for the homepage
// demo's sample query (the same encoding/json output wasm/main.go returns).
//
// Usage: go run ./website/scripts/gen-sample-ast <sql-file> <out-json>
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

func run() error {
	if len(os.Args) != 3 {
		return fmt.Errorf("usage: gen-sample-ast <sql-file> <out-json>")
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		return fmt.Errorf("read sql: %w", err)
	}
	sql := strings.TrimRight(string(raw), "\n")
	tree, err := gosqlx.Parse(sql)
	if err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	astJSON, err := json.Marshal(tree)
	if err != nil {
		return fmt.Errorf("marshal ast: %w", err)
	}
	// Emit the query alongside its AST so the UI has one source for both.
	b, err := json.MarshalIndent(struct {
		SQL string          `json:"sql"`
		AST json.RawMessage `json:"ast"`
	}{SQL: sql, AST: astJSON}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return os.WriteFile(os.Args[2], append(b, '\n'), 0o644)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen-sample-ast:", err)
		os.Exit(1)
	}
}
