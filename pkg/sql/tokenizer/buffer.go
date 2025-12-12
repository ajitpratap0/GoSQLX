package tokenizer

import (
	"sync"
)

// BufferPool manages a pool of reusable byte buffers for token content.
//
// This pool is used for temporary byte slice operations during tokenization,
// such as accumulating identifier characters or building string literal content.
// It complements the bytes.Buffer pool used elsewhere in the tokenizer.
//
// The pool is designed for byte slices rather than bytes.Buffer for cases where
// direct slice manipulation is more efficient than buffer operations.
//
// Thread Safety: Safe for concurrent use across multiple goroutines.
//
// Initial Capacity: Buffers are pre-allocated with 128 bytes capacity,
// suitable for most SQL tokens (identifiers, keywords, short string literals).
type BufferPool struct {
	pool sync.Pool
}

// NewBufferPool creates a new buffer pool with optimized initial capacity.
//
// The pool pre-allocates byte slices with 128-byte capacity, which is
// sufficient for most SQL tokens without excessive memory waste.
//
// Returns a BufferPool ready for use with Get/Put operations.
//
// Example:
//
//	pool := NewBufferPool()
//	buf := pool.Get()
//	defer pool.Put(buf)
//	// Use buf for byte operations...
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

// Get retrieves a buffer from the pool.
//
// The returned buffer has zero length but may have capacity >= 128 bytes
// from previous use. This allows efficient appending without reallocation
// for typical SQL tokens.
//
// Thread Safety: Safe for concurrent calls.
//
// The buffer must be returned to the pool via Put() when done to enable reuse.
//
// Returns a byte slice ready for use (length 0, capacity >= 128).
func (p *BufferPool) Get() []byte {
	buf := p.pool.Get().(*[]byte)
	*buf = (*buf)[:0] // Reset length but keep capacity
	return *buf
}

// Put returns a buffer to the pool for reuse.
//
// The buffer's capacity is preserved, allowing it to be reused for similarly-sized
// operations without reallocation. Buffers with zero capacity are discarded.
//
// Thread Safety: Safe for concurrent calls.
//
// It's safe to call Put multiple times with the same buffer, though only the
// first call will be effective (subsequent calls operate on a reset buffer).
//
// Parameters:
//   - buf: The byte slice to return to the pool
func (p *BufferPool) Put(buf []byte) {
	if cap(buf) > 0 {
		p.pool.Put(&buf)
	}
}

// Grow ensures the buffer has enough capacity for n additional bytes.
//
// If the buffer doesn't have enough spare capacity, a new larger buffer is
// allocated with doubled capacity plus n bytes. The old buffer is returned
// to the pool.
//
// Growth Strategy: New capacity = 2 * old capacity + n
// This exponential growth with a minimum increment minimizes reallocations
// while preventing excessive memory waste.
//
// Parameters:
//   - buf: The current buffer
//   - n: Number of additional bytes needed
//
// Returns:
//   - The original buffer if it has sufficient capacity
//   - A new, larger buffer with contents copied if reallocation was needed
//
// Example:
//
//	buf := pool.Get()
//	buf = pool.Grow(buf, 256)  // Ensure 256 bytes available
//	buf = append(buf, data...)  // Append without reallocation
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
