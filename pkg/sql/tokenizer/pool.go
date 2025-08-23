package tokenizer

import (
	"bytes"
	"sync"

	"github.com/ajitpratap0/GoSQLX/pkg/metrics"
)

// bufferPool is used to reuse buffers during tokenization
var bufferPool = sync.Pool{
	New: func() interface{} {
		// Increase initial capacity for better performance with typical SQL queries
		return bytes.NewBuffer(make([]byte, 0, 256))
	},
}

// getBuffer gets a buffer from the pool
func getBuffer() *bytes.Buffer {
	return bufferPool.Get().(*bytes.Buffer)
}

// putBuffer returns a buffer to the pool
func putBuffer(buf *bytes.Buffer) {
	if buf != nil {
		buf.Reset()
		bufferPool.Put(buf)
	}
}

// tokenizerPool allows reuse of Tokenizer instances
var tokenizerPool = sync.Pool{
	New: func() interface{} {
		t, _ := New() // Error ignored as New() only errors on keyword initialization
		return t
	},
}

// GetTokenizer gets a Tokenizer from the pool
func GetTokenizer() *Tokenizer {
	t := tokenizerPool.Get().(*Tokenizer)

	// Record pool metrics
	metrics.RecordPoolGet(true) // Assume from pool (New() creates if empty)

	return t
}

// PutTokenizer returns a Tokenizer to the pool
func PutTokenizer(t *Tokenizer) {
	if t != nil {
		t.Reset()
		tokenizerPool.Put(t)

		// Record pool return
		metrics.RecordPoolPut()
	}
}

// Reset resets a Tokenizer's state for reuse
func (t *Tokenizer) Reset() {
	// Clear input reference to allow garbage collection
	t.input = nil

	// Reset position tracking
	t.pos = NewPosition(1, 0)
	t.lineStart = Position{}

	// Preserve lineStarts slice capacity but reset length
	if cap(t.lineStarts) > 0 {
		t.lineStarts = t.lineStarts[:0]
		t.lineStarts = append(t.lineStarts, 0)
	} else {
		// Initialize if not yet allocated
		t.lineStarts = make([]int, 1, 16) // Start with reasonable capacity
		t.lineStarts[0] = 0
	}

	t.line = 0

	// Don't reset keywords as they're constant
	t.debugLog = nil
}
