package tokenizer

import "log/slog"

// SetLogger configures a structured logger for verbose tracing during tokenization.
// The logger receives slog.Debug messages for each token produced, which is useful
// for diagnosing tokenization issues or understanding token stream structure.
//
// Pass nil to disable debug logging (the default).
//
// Logging is guarded by slog.LevelDebug checks so there is no performance cost
// when the handler's minimum level is above Debug.
//
// Example:
//
//	tkz := tokenizer.GetTokenizer()
//	tkz.SetLogger(slog.Default())
//	tokens, _ := tkz.Tokenize([]byte(sql))
//
// To disable:
//
//	tkz.SetLogger(nil)
//
// Thread Safety:
// The logger may be called from multiple goroutines if tokenizers are used
// concurrently. *slog.Logger is safe for concurrent use.
func (t *Tokenizer) SetLogger(logger *slog.Logger) {
	t.logger = logger
}
