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

import (
	"bytes"
	"sync"

	"github.com/ajitpratap0/GoSQLX/pkg/metrics"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

// maxRetainedLitBuf is the largest litBuf capacity Reset keeps. A pooled
// tokenizer that scanned a huge escaped literal drops the buffer instead of
// holding it for later callers.
const maxRetainedLitBuf = 64 << 10

// maxRetainedComments is the largest Comments capacity (in entries, 64 bytes
// each, so 64 KiB) Reset keeps. A pooled tokenizer that collected more
// comments drops the slice instead of holding it for later callers.
const maxRetainedComments = 1024

// maxRetainedLineStarts is the largest lineStarts capacity (in entries, 8
// bytes each on 64-bit platforms, so 64 KiB) Reset keeps. A pooled tokenizer
// that scanned an input with many lines drops the slice instead of holding it
// for later callers; load re-grows it for the next large input.
const maxRetainedLineStarts = 8 << 10

// tokenizerPool provides object pooling for Tokenizer instances.
// This dramatically reduces allocations in high-throughput scenarios.
//
// Performance Impact:
//   - 60-80% reduction in allocations
//   - 95%+ pool hit rate in production workloads
//   - Zero-allocation instance reuse when pool is warm
var tokenizerPool = sync.Pool{
	New: func() interface{} {
		t, err := New()
		if err != nil {
			panic("gosqlx: failed to initialize tokenizer pool: " + err.Error())
		}
		return t
	},
}

// GetTokenizer retrieves a Tokenizer instance from the pool.
//
// This is the recommended way to obtain a Tokenizer for production use.
// The returned tokenizer is reset and ready for use.
//
// Thread Safety: Safe for concurrent calls from multiple goroutines.
// Each call returns a separate instance.
//
// Memory Management: Always pair with PutTokenizer() using defer to ensure
// the instance is returned to the pool, even if errors occur.
//
// Metrics: Records pool get operations for monitoring pool efficiency.
//
// Example:
//
//	tkz := tokenizer.GetTokenizer()
//	defer tokenizer.PutTokenizer(tkz)  // MANDATORY - ensures pool return
//
//	tokens, err := tkz.Tokenize([]byte(sql))
//	if err != nil {
//	    return err  // defer ensures PutTokenizer is called
//	}
//	// Process tokens...
//
// Performance: 95%+ hit rate means most calls reuse existing instances
// rather than allocating new ones, providing significant performance benefits.
func GetTokenizer() *Tokenizer {
	t := tokenizerPool.Get().(*Tokenizer)

	// Record pool metrics
	metrics.RecordPoolGet(true) // Assume from pool (New() creates if empty)
	metrics.RecordNamedPoolGet("tokenizer")

	return t
}

// PutTokenizer returns a Tokenizer instance to the pool for reuse.
//
// This must be called after you're done with a Tokenizer obtained from
// GetTokenizer() to enable instance reuse and prevent memory leaks.
//
// The tokenizer is automatically reset before being returned to the pool,
// clearing all state including input references, positions, and debug loggers.
//
// Thread Safety: Safe for concurrent calls from multiple goroutines.
//
// Best Practice: Always use with defer immediately after GetTokenizer():
//
//	tkz := tokenizer.GetTokenizer()
//	defer tokenizer.PutTokenizer(tkz)  // MANDATORY
//
// Nil Safety: Safely ignores nil tokenizers (no-op).
//
// Metrics: Records pool put operations for monitoring pool efficiency.
//
// State Reset:
//   - Input reference cleared (enables GC of SQL bytes)
//   - Position tracking reset to initial state
//   - Line tracking cleared; capacity preserved up to 8192 entries (64 KiB), a larger slice is dropped
//   - Debug logger cleared
//   - Dialect restored to the default (PostgreSQL) so a configured dialect
//     does not leak to the next caller
func PutTokenizer(t *Tokenizer) {
	if t != nil {
		t.Reset()

		// Restore the default dialect so a pooled tokenizer never leaks a
		// configured dialect to a later caller. This is done here (at the pool
		// boundary) rather than in Reset, which also runs at the start of every
		// Tokenize call where the configured dialect must persist. The dialect
		// is a plain field, so restoring it is a single assignment.
		t.dialect = keywords.DialectPostgreSQL

		tokenizerPool.Put(t)

		// Record pool return
		metrics.RecordPoolPut()
		metrics.RecordNamedPoolPut("tokenizer")
	}
}

// Reset clears a Tokenizer's state for reuse while preserving allocated memory.
//
// This method is called automatically by PutTokenizer() and generally should
// not be called directly by users. It's exposed for advanced use cases where
// you want to reuse a tokenizer instance without going through the pool.
//
// Memory Optimization:
//   - Clears input references (input, src and the current Word chunk), so a
//     pooled tokenizer does not keep the previous SQL alive
//   - Zeroes the used Comments entries and truncates the slice (capacity is
//     preserved up to 1024 entries; a larger slice is dropped). Comments is
//     therefore valid only until the next Tokenize, Reset or PutTokenizer;
//     copy it first if it must outlive those
//   - Resets position tracking to initial values
//   - Preserves lineStarts capacity up to 8192 entries (avoids reallocation); a larger slice is dropped
//   - Clears debug logger reference
//
// State After Reset:
//   - pos: Line 1, Column 0, Index 0
//   - lineStarts: [0], capacity preserved up to 8192 entries, or a fresh 16-entry slice when it was larger
//   - input: nil, src: "" (ready for new input)
//   - Word chunk: nil (Words already returned stay valid; the chunk is never reused)
//   - litBuf (slow-path literal scratch): zeroed and truncated, or dropped
//     above 64 KiB
//   - Comments: length 0, previously used entries zeroed, or nil when its
//     capacity exceeded 1024 entries
//   - dialect: preserved (Reset also runs at the start of every
//     Tokenize call, so the configured dialect must persist; the pool restores
//     the default dialect in PutTokenizer instead)
//   - logger: nil (must be set again if needed)
//   - position column cursor: invalidated
//
// Performance: By preserving slice capacity, subsequent Tokenize() calls
// avoid reallocation of lineStarts for similarly-sized inputs, up to the
// retention caps above.
func (t *Tokenizer) Reset() {
	// Clear input references to allow garbage collection. The Word chunk is
	// dropped, never truncated: its elements belong to tokens already
	// returned to callers.
	t.input = nil
	t.src = ""
	t.wordChunk = nil
	t.wordHint = 0

	// litBuf contents never escape (slow paths copy them out with String),
	// but truncating alone would leave the previous request's decoded
	// literal text in pooled memory. Zero the whole backing array (every
	// slow reader restarts at offset 0, so earlier literals of the same call
	// may lie beyond the current length); drop an oversized buffer. The
	// clear is free for tokenizers that never took a slow path (cap 0).
	if t.litBuf.Cap() > maxRetainedLitBuf {
		t.litBuf = bytes.Buffer{}
	} else {
		t.litBuf.Reset()
		b := t.litBuf.Bytes()
		clear(b[:cap(b)])
	}

	// Reset position tracking
	t.pos = NewPosition(1, 0)
	t.lineStart = Position{}

	// Keep the lineStarts backing array for reuse up to maxRetainedLineStarts
	// entries; a larger one (an input with many lines) is dropped so the pool
	// does not hold it for later callers.
	if c := cap(t.lineStarts); c > 0 && c <= maxRetainedLineStarts {
		t.lineStarts = append(t.lineStarts[:0], 0)
	} else {
		t.lineStarts = make([]int, 1, 16) // Start with reasonable capacity
	}

	t.line = 0

	// Invalidate the toSQLPosition line hint: it is only valid for the
	// input and lineStarts it was built on.
	t.posCacheLine = 0
	t.tokStart = models.Location{}
	t.inlLine, t.inlScan, t.inlCode = 0, 0, false

	// Don't reset the dialect here: Reset also runs at the start of every
	// Tokenize call, where the configured dialect must persist across calls.
	// Dialect is restored to the default in PutTokenizer, at the pool boundary.
	t.logger = nil

	// Zero the used Comments (their Text is a substring of the previous
	// input, which would otherwise stay pinned by the pooled tokenizer) and
	// reset the length, preserving capacity. Elements beyond len are already
	// zero from earlier Resets. A slice grown past maxRetainedComments is
	// dropped instead, so a pooled tokenizer does not hold a large backing
	// array for later callers.
	if cap(t.Comments) > maxRetainedComments {
		t.Comments = nil
	} else {
		clear(t.Comments)
		t.Comments = t.Comments[:0]
	}
	t.emitted = 0
}
