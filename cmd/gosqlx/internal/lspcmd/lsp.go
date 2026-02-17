// Package lspcmd implements the gosqlx lsp subcommand.
package lspcmd

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/ajitpratap0/GoSQLX/pkg/lsp"
	"github.com/spf13/cobra"
)

var (
	lspLogFile string
)

// NewCmd returns the lsp cobra.Command.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lsp",
		Short: "Start Language Server Protocol (LSP) server",
		Long: `Start the GoSQLX LSP server for IDE integration.

The LSP server provides real-time SQL validation, formatting,
hover documentation, and code completion for IDEs and text editors.

Features:
  - Real-time syntax error detection
  - SQL formatting
  - Keyword documentation on hover
  - SQL keyword and function completion

Examples:
  gosqlx lsp                      # Start LSP server on stdio
  gosqlx lsp --log /tmp/lsp.log   # Start with logging enabled

VSCode Integration:
  Add to your settings.json:
  {
    "gosqlx.lsp.enable": true,
    "gosqlx.lsp.path": "gosqlx"
  }

Neovim Integration (nvim-lspconfig):
  require('lspconfig.configs').gosqlx = {
    default_config = {
      cmd = { 'gosqlx', 'lsp' },
      filetypes = { 'sql' },
      root_dir = function() return vim.fn.getcwd() end,
    },
  }
  require('lspconfig').gosqlx.setup{}

Emacs Integration (lsp-mode):
  (lsp-register-client
    (make-lsp-client
      :new-connection (lsp-stdio-connection '("gosqlx" "lsp"))
      :major-modes '(sql-mode)
      :server-id 'gosqlx))`,
		RunE: runLSP,
	}

	cmd.Flags().StringVar(&lspLogFile, "log", "", "Log file path (optional, for debugging)")

	return cmd
}

func runLSP(_ *cobra.Command, _ []string) error {
	var logger *log.Logger
	if lspLogFile != "" {
		f, err := os.OpenFile(filepath.Clean(lspLogFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600) // #nosec G304
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		defer func() { _ = f.Close() }()
		logger = log.New(f, "[gosqlx-lsp] ", log.LstdFlags|log.Lshortfile)
	} else {
		logger = log.New(io.Discard, "", 0)
	}

	logger.Println("Starting GoSQLX LSP server...")

	server := lsp.NewStdioServer(logger)
	return server.Run()
}
