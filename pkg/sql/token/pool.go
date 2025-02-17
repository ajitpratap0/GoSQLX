package token

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// PoolStats tracks token pool statistics
type PoolStats struct {
	Gets   uint64
	Puts   uint64
	Misses uint64
}

var (
	tokenPool = sync.Pool{
		New: func() interface{} {
			stats.Misses++
			return &Token{}
		},
	}
	stats PoolStats
)

// Get retrieves a Token from the pool with safety checks
func Get() *Token {
	atomic.AddUint64(&stats.Gets, 1)
	token, ok := tokenPool.Get().(*Token)
	if !ok {
		panic("token pool corrupted: retrieved invalid type")
	}
	if token == nil {
		panic("token pool returned nil token")
	}
	return token
}

// Put returns a Token to the pool with validation
func Put(t *Token) error {
	if t == nil {
		return fmt.Errorf("cannot put nil token into pool")
	}

	// Validate token state
	if t.Type == ILLEGAL {
		return fmt.Errorf("cannot pool token with ILLEGAL type")
	}

	atomic.AddUint64(&stats.Puts, 1)
	t.Reset()
	tokenPool.Put(t)
	return nil
}

// Reset resets a token's fields
func (t *Token) Reset() {
	if t != nil {
		t.Type = ""
		t.Literal = ""
	}
}

// GetPoolStats returns current pool statistics
func GetPoolStats() PoolStats {
	return PoolStats{
		Gets:   atomic.LoadUint64(&stats.Gets),
		Puts:   atomic.LoadUint64(&stats.Puts),
		Misses: atomic.LoadUint64(&stats.Misses),
	}
}

// ResetPoolStats resets pool statistics
func ResetPoolStats() {
	atomic.StoreUint64(&stats.Gets, 0)
	atomic.StoreUint64(&stats.Puts, 0)
	atomic.StoreUint64(&stats.Misses, 0)
}
