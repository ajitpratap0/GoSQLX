package tokenizer

// DebugLogger is an interface for debug logging
type DebugLogger interface {
	Debug(format string, args ...interface{})
}
