package lsp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Server configuration constants
const (
	// MaxContentLength limits the size of a single LSP message (10MB)
	MaxContentLength = 10 * 1024 * 1024
	// MaxDocumentSize limits the size of SQL documents (5MB)
	MaxDocumentSize = 5 * 1024 * 1024
	// RateLimitRequests is the max requests per rate limit window
	RateLimitRequests = 100
	// RateLimitWindow is the time window for rate limiting
	RateLimitWindow = time.Second
	// RequestTimeout limits how long a request can take
	RequestTimeout = 30 * time.Second
)

// Server represents the LSP server instance.
//
// Server implements the Language Server Protocol for SQL code intelligence.
// It manages client-server communication over stdin/stdout using JSON-RPC 2.0,
// handles document lifecycle events, and coordinates all LSP protocol handlers.
//
// # Features
//
// The server provides the following capabilities:
//   - Real-time syntax validation with diagnostics (textDocument/publishDiagnostics)
//   - SQL code formatting with intelligent indentation (textDocument/formatting)
//   - Keyword hover documentation for 60+ SQL keywords (textDocument/hover)
//   - Auto-completion with 100+ keywords and 22 snippets (textDocument/completion)
//   - Document outline and symbol navigation (textDocument/documentSymbol)
//   - Function signature help for 20+ SQL functions (textDocument/signatureHelp)
//   - Quick fixes and code actions (textDocument/codeAction)
//
// # Architecture
//
// The server uses a multi-component architecture:
//   - Server: Main server loop and JSON-RPC message handling
//   - DocumentManager: Thread-safe document state management
//   - Handler: LSP protocol request and notification processing
//
// # Concurrency
//
// Server is designed for concurrent operation:
//   - Thread-safe document management with read/write locks
//   - Atomic rate limiting for request throttling
//   - Synchronized write operations to prevent message corruption
//
// # Rate Limiting
//
// Built-in rate limiting protects against request floods:
//   - Maximum 100 requests per second (configurable via RateLimitRequests)
//   - Automatic rate limit window reset
//   - Client receives RequestCancelled error when limit exceeded
//
// # Message Size Limits
//
// The server enforces size limits for stability:
//   - MaxContentLength: 10MB per LSP message
//   - MaxDocumentSize: 5MB per SQL document
//
// # Error Handling
//
// Robust error handling throughout the server:
//   - Malformed JSON-RPC messages handled gracefully
//   - Position information extracted from GoSQLX errors
//   - Structured errors with error codes for diagnostics
//
// # Example Usage
//
//	logger := log.New(os.Stderr, "[LSP] ", log.LstdFlags)
//	server := lsp.NewStdioServer(logger)
//	if err := server.Run(); err != nil {
//	    log.Fatal(err)
//	}
//
// Or via the CLI:
//
//	./gosqlx lsp
//	./gosqlx lsp --log /tmp/lsp.log
//
// # IDE Integration
//
// The server can be integrated with various editors:
//
// VSCode - Add to settings.json:
//
//	{
//	  "gosqlx-lsp": {
//	    "command": "gosqlx",
//	    "args": ["lsp"],
//	    "filetypes": ["sql"]
//	  }
//	}
//
// Neovim - Add to init.lua:
//
//	vim.api.nvim_create_autocmd("FileType", {
//	  pattern = "sql",
//	  callback = function()
//	    vim.lsp.start({
//	      name = "gosqlx-lsp",
//	      cmd = {"gosqlx", "lsp"}
//	    })
//	  end
//	})
//
// Emacs (lsp-mode) - Add to init.el:
//
//	(require 'lsp-mode)
//	(add-to-list 'lsp-language-id-configuration '(sql-mode . "sql"))
//	(lsp-register-client
//	  (make-lsp-client :new-connection (lsp-stdio-connection '("gosqlx" "lsp"))
//	                   :major-modes '(sql-mode)
//	                   :server-id 'gosqlx-lsp))
//
// See docs/LSP_GUIDE.md for comprehensive integration documentation.
type Server struct {
	reader    *bufio.Reader
	writer    io.Writer
	writeMu   sync.Mutex
	documents *DocumentManager
	handler   *Handler
	logger    *log.Logger
	shutdown  bool

	// Rate limiting
	requestCount int64
	lastReset    time.Time
	rateMu       sync.Mutex
}

// NewServer creates a new LSP server with custom input/output streams.
//
// This constructor allows you to specify custom reader and writer for the
// JSON-RPC 2.0 communication. The server will read LSP messages from reader
// and write responses to writer.
//
// Parameters:
//   - reader: Input stream for receiving LSP messages (typically os.Stdin)
//   - writer: Output stream for sending LSP responses (typically os.Stdout)
//   - logger: Logger for server diagnostics (use io.Discard for silent operation)
//
// The logger parameter can be nil, in which case logging will be disabled.
// For production deployments, it's recommended to provide a logger that
// writes to a file rather than stderr to avoid interfering with LSP communication.
//
// Example:
//
//	logFile, _ := os.Create("/tmp/gosqlx-lsp.log")
//	logger := log.New(logFile, "[GoSQLX LSP] ", log.LstdFlags)
//	server := lsp.NewServer(os.Stdin, os.Stdout, logger)
//	defer logFile.Close()
//
// Returns a fully initialized Server ready to call Run().
func NewServer(reader io.Reader, writer io.Writer, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	s := &Server{
		reader:    bufio.NewReader(reader),
		writer:    writer,
		documents: NewDocumentManager(),
		logger:    logger,
		lastReset: time.Now(),
	}
	s.handler = NewHandler(s)
	return s
}

// NewStdioServer creates a new LSP server using stdin/stdout.
//
// This is the standard constructor for LSP servers that communicate over
// standard input/output streams, which is the typical mode for editor integration.
//
// The server reads LSP protocol messages from os.Stdin and writes responses to
// os.Stdout. This is the recommended way to create an LSP server for use with
// editors like VSCode, Neovim, and Emacs.
//
// Parameters:
//   - logger: Logger for server diagnostics. Should write to a file or os.Stderr,
//     never to os.Stdout (which is reserved for LSP communication)
//
// Example:
//
//	logFile, _ := os.Create("/tmp/gosqlx-lsp.log")
//	logger := log.New(logFile, "", log.LstdFlags)
//	server := lsp.NewStdioServer(logger)
//	if err := server.Run(); err != nil {
//	    logger.Fatal(err)
//	}
//
// This is equivalent to:
//
//	NewServer(os.Stdin, os.Stdout, logger)
func NewStdioServer(logger *log.Logger) *Server {
	return NewServer(os.Stdin, os.Stdout, logger)
}

// Run starts the server's main loop and processes LSP messages.
//
// This method blocks until the server receives an exit notification or
// encounters an unrecoverable error. It continuously reads LSP messages
// from the input stream, processes them, and sends responses.
//
// The main loop:
//  1. Reads a complete LSP message (headers + content)
//  2. Validates message size against MaxContentLength
//  3. Applies rate limiting (RateLimitRequests per RateLimitWindow)
//  4. Parses JSON-RPC 2.0 structure
//  5. Dispatches to appropriate handler
//  6. Sends response or error back to client
//
// Shutdown Sequence:
//
// The server follows the LSP shutdown protocol:
//  1. Client sends "shutdown" request → Server responds with empty result
//  2. Client sends "exit" notification → Server stops message loop
//  3. Run() returns nil for clean shutdown
//
// Error Handling:
//
// The server handles various error conditions gracefully:
//   - EOF on stdin: Assumes client disconnected, returns nil
//   - Parse errors: Sends ParseError response, continues
//   - Rate limit exceeded: Sends RequestCancelled error
//   - Malformed JSON: Attempts to extract ID for error response
//   - Unknown methods: Sends MethodNotFound error
//
// Returns:
//   - nil on clean shutdown (exit notification received)
//   - nil on EOF (client disconnected)
//   - error only for unexpected fatal conditions
//
// Example:
//
//	server := lsp.NewStdioServer(logger)
//	if err := server.Run(); err != nil {
//	    log.Fatalf("LSP server error: %v", err)
//	}
func (s *Server) Run() error {
	s.logger.Println("GoSQLX LSP server starting...")

	for {
		msg, err := s.readMessage()
		if err != nil {
			if err == io.EOF {
				s.logger.Println("EOF received, shutting down")
				return nil
			}
			s.logger.Printf("Error reading message: %v", err)
			continue
		}

		s.handleMessage(msg)

		// Exit after shutdown
		if s.shutdown {
			s.logger.Println("Shutdown complete")
			return nil
		}
	}
}

// readMessage reads a single LSP message from the input
func (s *Server) readMessage() (json.RawMessage, error) {
	// Read headers
	var contentLength int
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimSpace(line)

		if line == "" {
			// End of headers
			break
		}

		// Parse Content-Length header
		if strings.HasPrefix(line, "Content-Length:") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "Content-Length:"))
			contentLength, err = strconv.Atoi(value)
			if err != nil {
				return nil, fmt.Errorf("invalid Content-Length: %v", err)
			}
		}
	}

	if contentLength == 0 {
		return nil, fmt.Errorf("missing Content-Length header")
	}

	// Validate content length against maximum
	if contentLength > MaxContentLength {
		return nil, fmt.Errorf("content length %d exceeds maximum allowed %d", contentLength, MaxContentLength)
	}

	// Read content
	content := make([]byte, contentLength)
	_, err := io.ReadFull(s.reader, content)
	if err != nil {
		return nil, fmt.Errorf("failed to read content: %v", err)
	}

	return json.RawMessage(content), nil
}

// handleMessage processes a single message
func (s *Server) handleMessage(msg json.RawMessage) {
	// Enforce rate limiting
	if !s.checkRateLimit() {
		// For requests with IDs, send rate limit error response
		var req Request
		if err := json.Unmarshal(msg, &req); err == nil && req.ID != nil {
			s.sendError(req.ID, RequestCancelled, "rate limit exceeded")
		}
		return
	}

	// Validate message is not empty or too small to be valid JSON-RPC
	if len(msg) < 2 {
		s.logger.Printf("Invalid message: too short (%d bytes)", len(msg))
		return
	}

	// Try to parse as request
	var req Request
	if err := json.Unmarshal(msg, &req); err != nil {
		s.logger.Printf("Failed to parse message: %v", err)
		// Try to extract ID for error response even with malformed JSON
		s.handleMalformedRequest(msg, err)
		return
	}

	// Validate required JSON-RPC fields
	if req.Method == "" {
		s.logger.Printf("Invalid request: missing method")
		if req.ID != nil {
			s.sendError(req.ID, InvalidRequest, "missing method field")
		}
		return
	}

	s.logger.Printf("Received: %s", req.Method)

	// Handle the request
	if req.ID != nil {
		// It's a request expecting a response
		result, err := s.handler.HandleRequest(req.Method, req.Params)
		if err != nil {
			s.sendError(req.ID, InternalError, err.Error())
		} else {
			s.sendResult(req.ID, result)
		}
	} else {
		// It's a notification
		s.handler.HandleNotification(req.Method, req.Params)
	}
}

// handleMalformedRequest attempts to extract an ID from malformed JSON and send error
func (s *Server) handleMalformedRequest(msg json.RawMessage, parseErr error) {
	// Try to extract just the ID from the malformed request
	var partial struct {
		ID interface{} `json:"id"`
	}
	if err := json.Unmarshal(msg, &partial); err == nil && partial.ID != nil {
		s.sendError(partial.ID, ParseError, fmt.Sprintf("parse error: %v", parseErr))
	}
}

// sendResult sends a successful response
func (s *Server) sendResult(id interface{}, result interface{}) {
	resp := Response{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	s.sendMessage(resp)
}

// sendError sends an error response
func (s *Server) sendError(id interface{}, code int, message string) {
	resp := Response{
		JSONRPC: "2.0",
		ID:      id,
		Error: &ResponseError{
			Code:    code,
			Message: message,
		},
	}
	s.sendMessage(resp)
}

// SendNotification sends a notification to the client.
//
// This method sends a JSON-RPC 2.0 notification (a request without an ID) to the
// client. Notifications are one-way messages that do not expect a response.
//
// The server uses this method to push information to the client asynchronously,
// such as diagnostic results (textDocument/publishDiagnostics) or progress updates.
//
// Parameters:
//   - method: The LSP method name (e.g., "textDocument/publishDiagnostics")
//   - params: The parameters object to send (will be JSON-marshaled)
//
// Thread Safety: This method is thread-safe and can be called concurrently from
// multiple goroutines. Write operations are protected by a mutex.
//
// Common notification methods:
//   - "textDocument/publishDiagnostics": Send syntax errors to client
//   - "window/showMessage": Display message to user
//   - "window/logMessage": Log message in client
//
// Example:
//
//	s.SendNotification("textDocument/publishDiagnostics", PublishDiagnosticsParams{
//	    URI:         "file:///query.sql",
//	    Diagnostics: diagnostics,
//	})
//
// If params is nil, an empty notification without params will be sent.
// If marshaling params fails, the error is logged but no notification is sent.
func (s *Server) SendNotification(method string, params interface{}) {
	notif := Notification{
		JSONRPC: "2.0",
		Method:  method,
	}
	if params != nil {
		data, err := json.Marshal(params)
		if err != nil {
			s.logger.Printf("Failed to marshal notification params for %s: %v", method, err)
			return
		}
		notif.Params = json.RawMessage(data)
	}
	s.sendMessage(notif)
}

// sendMessage sends a message to the client
func (s *Server) sendMessage(msg interface{}) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	content, err := json.Marshal(msg)
	if err != nil {
		s.logger.Printf("Failed to marshal response: %v", err)
		return
	}

	// Write headers
	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(content))
	if _, err := s.writer.Write([]byte(header)); err != nil {
		s.logger.Printf("Failed to write header: %v", err)
		return
	}

	// Write content
	if _, err := s.writer.Write(content); err != nil {
		s.logger.Printf("Failed to write content: %v", err)
		return
	}

	s.logger.Printf("Sent response: %d bytes", len(content))
}

// Documents returns the server's document manager.
//
// The DocumentManager provides access to all currently open SQL documents and
// their state. This method is primarily used internally by request handlers to
// access document content when processing LSP requests.
//
// Returns:
//   - *DocumentManager: The server's document manager instance
//
// Thread Safety: The returned DocumentManager is thread-safe and can be used
// concurrently from multiple request handlers.
//
// Usage:
//
//	doc, ok := server.Documents().Get("file:///query.sql")
//	if ok {
//	    content := doc.Content
//	    // Process document content
//	}
func (s *Server) Documents() *DocumentManager {
	return s.documents
}

// Logger returns the server's logger instance.
//
// The logger is used for debugging and diagnostic output. It should write to
// a file or os.Stderr, never to os.Stdout (which is reserved for LSP protocol
// communication).
//
// Returns:
//   - *log.Logger: The server's logger, or a logger that discards output if
//     the server was created with a nil logger
//
// Thread Safety: The standard log.Logger is thread-safe and can be used
// concurrently from multiple goroutines.
//
// Example:
//
//	server.Logger().Printf("Processing request: %s", method)
func (s *Server) Logger() *log.Logger {
	return s.logger
}

// SetShutdown marks the server for shutdown.
//
// This method is called when the server receives an "exit" notification from
// the client. It sets an internal flag that causes the main message loop in
// Run() to terminate cleanly.
//
// Thread Safety: This method is safe to call concurrently, though it's typically
// only called from the exit notification handler.
//
// The shutdown sequence:
//  1. Client sends "shutdown" request → Server responds with empty result
//  2. Client sends "exit" notification → Server calls SetShutdown()
//  3. Run() method checks shutdown flag and returns nil
//
// This method does not immediately stop the server; it only marks it for shutdown.
// The actual termination occurs when the Run() loop checks the flag.
func (s *Server) SetShutdown() {
	s.shutdown = true
}

// checkRateLimit enforces rate limiting on incoming requests
// Returns true if the request should be allowed, false if rate limited
func (s *Server) checkRateLimit() bool {
	s.rateMu.Lock()
	defer s.rateMu.Unlock()

	now := time.Now()
	elapsed := now.Sub(s.lastReset)

	// Reset counter if window has passed
	if elapsed >= RateLimitWindow {
		s.lastReset = now
		atomic.StoreInt64(&s.requestCount, 1)
		return true
	}

	// Increment and check count
	count := atomic.AddInt64(&s.requestCount, 1)
	if count > RateLimitRequests {
		s.logger.Printf("Rate limit exceeded: %d requests in %v", count, elapsed)
		return false
	}

	return true
}

// MaxDocumentSizeBytes returns the maximum allowed document size
func (s *Server) MaxDocumentSizeBytes() int {
	return MaxDocumentSize
}
