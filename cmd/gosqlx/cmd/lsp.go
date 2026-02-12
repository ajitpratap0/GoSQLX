package cmd

import (
	"fmt"
	"io"
	"log"
	"os"

	"github.com/ajitpratap0/GoSQLX/pkg/lsp"
	"github.com/spf13/cobra"
)

var (
	lspLogFile string
)

// lspCmd represents the lsp command
var lspCmd = &cobra.Command{
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
	RunE: lspRun,
}

func init() {
	rootCmd.AddCommand(lspCmd)

	lspCmd.Flags().StringVar(&lspLogFile, "log", "", "Log file path (optional, for debugging)")
}

func lspRun(cmd *cobra.Command, args []string) error {
	// Set up logging
	var logger *log.Logger
	if lspLogFile != "" {
		f, err := os.OpenFile(lspLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600) // #nosec G304
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		defer f.Close() //nolint:errcheck // best-effort close of log file
		logger = log.New(f, "[gosqlx-lsp] ", log.LstdFlags|log.Lshortfile)
	} else {
		// Discard logs by default (LSP should only communicate via protocol)
		logger = log.New(io.Discard, "", 0)
	}

	logger.Println("Starting GoSQLX LSP server...")

	// Create and run the LSP server
	server := lsp.NewStdioServer(logger)
	return server.Run()
}
