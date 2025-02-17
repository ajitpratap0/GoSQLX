package tokenizer

import (
	"sync"
)

// BufferPool manages a pool of reusable byte buffers for token content
type BufferPool struct {
	pool sync.Pool
}

// NewBufferPool creates a new buffer pool with optimized initial capacity
func NewBufferPool() *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() interface{} {
				// Pre-allocate buffer for common token sizes
				b := make([]byte, 0, 128)
				return &b
			},
		},
	}
}

// Get retrieves a buffer from the pool
func (p *BufferPool) Get() []byte {
	buf := p.pool.Get().(*[]byte)
	*buf = (*buf)[:0] // Reset length but keep capacity
	return *buf
}

// Put returns a buffer to the pool
func (p *BufferPool) Put(buf []byte) {
	if cap(buf) > 0 {
		p.pool.Put(&buf)
	}
}

// Grow ensures the buffer has enough capacity
func (p *BufferPool) Grow(buf []byte, n int) []byte {
	if cap(buf)-len(buf) < n {
		// Create new buffer with doubled capacity
		newBuf := make([]byte, len(buf), 2*cap(buf)+n)
		copy(newBuf, buf)
		p.Put(buf) // Return old buffer to pool
		return newBuf
	}
	return buf
}
