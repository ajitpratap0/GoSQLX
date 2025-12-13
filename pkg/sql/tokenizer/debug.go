package tokenizer

// DebugLogger is an interface for debug logging during tokenization.
//
// Implementing this interface allows you to capture detailed trace information
// about the tokenization process, including each token produced, position tracking,
// and internal state transitions.
//
// This is useful for:
//   - Diagnosing tokenization issues with specific SQL queries
//   - Understanding how SQL is broken into tokens
//   - Debugging position tracking and error reporting
//   - Performance analysis and profiling
//   - Educational purposes (learning how SQL is tokenized)
//
// The Debug method will be called frequently during tokenization (potentially
// once per token), so implementations should be efficient if performance matters.
//
// Example Implementation:
//
//	type FileLogger struct {
//	    file *os.File
//	}
//
//	func (l *FileLogger) Debug(format string, args ...interface{}) {
//	    fmt.Fprintf(l.file, "[%s] ", time.Now().Format("15:04:05.000"))
//	    fmt.Fprintf(l.file, format, args...)
//	    fmt.Fprintln(l.file)
//	}
//
//	// Usage:
//	logger := &FileLogger{file: os.Stdout}
//	tkz := tokenizer.GetTokenizer()
//	tkz.SetDebugLogger(logger)
//	tokens, _ := tkz.Tokenize([]byte(sql))
//
// Simple Console Logger:
//
//	type ConsoleLogger struct{}
//
//	func (l *ConsoleLogger) Debug(format string, args ...interface{}) {
//	    log.Printf("[TOKENIZER] "+format, args...)
//	}
//
// No-Op Logger (for disabling):
//
//	tkz.SetDebugLogger(nil)  // Disable debug logging
//
// Thread Safety:
// Debug method may be called from multiple goroutines if multiple tokenizers
// are in use concurrently. Implementations should be thread-safe if they will
// be shared across tokenizer instances.
type DebugLogger interface {
	// Debug logs a debug message with printf-style formatting.
	//
	// Parameters:
	//   - format: Printf-style format string
	//   - args: Arguments to be formatted according to the format string
	//
	// The method should not return errors. If logging fails, the error
	// should be handled internally (e.g., logged to stderr) rather than
	// affecting tokenization.
	Debug(format string, args ...interface{})
}
