// Copyright 2026 GoSQLX Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
