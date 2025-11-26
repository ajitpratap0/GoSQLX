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

// Server represents the LSP server
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

// NewServer creates a new LSP server
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

// NewStdioServer creates a new LSP server using stdin/stdout
func NewStdioServer(logger *log.Logger) *Server {
	return NewServer(os.Stdin, os.Stdout, logger)
}

// Run starts the server's main loop
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

// SendNotification sends a notification to the client
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

// Documents returns the document manager
func (s *Server) Documents() *DocumentManager {
	return s.documents
}

// Logger returns the server's logger
func (s *Server) Logger() *log.Logger {
	return s.logger
}

// SetShutdown marks the server for shutdown
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
