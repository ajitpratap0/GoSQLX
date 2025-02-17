package tokenizer

import (
	"bytes"
	"sync"
)

// bufferPool is used to reuse buffers during tokenization
var bufferPool = sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, 128))
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
	return tokenizerPool.Get().(*Tokenizer)
}

// PutTokenizer returns a Tokenizer to the pool
func PutTokenizer(t *Tokenizer) {
	if t != nil {
		t.Reset()
		tokenizerPool.Put(t)
	}
}

// Reset resets a Tokenizer's state for reuse
func (t *Tokenizer) Reset() {
	t.input = nil
	t.pos = NewPosition(1, 0)
	t.lineStart = Position{}
	t.lineStarts = t.lineStarts[:0]
	t.lineStarts = append(t.lineStarts, 0)
	t.line = 0
	// Don't reset keywords as they're constant
	t.debugLog = nil
}
