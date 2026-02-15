package token

import (
	"sync"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// tokenPool is the global token pool for memory-efficient token reuse.
var tokenPool = sync.Pool{
	New: func() interface{} {
		return &Token{}
	},
}

// Get retrieves a Token from the pool.
// The token is pre-initialized with zero values.
// Always use defer to return the token to the pool when done.
func Get() *Token {
	token := tokenPool.Get().(*Token)
	token.Type = models.TokenTypeUnknown
	token.Literal = ""
	return token
}

// Put returns a Token to the pool for reuse.
// Safe to call with nil token (no-op).
func Put(t *Token) error {
	if t == nil {
		return nil
	}
	t.Type = models.TokenTypeUnknown
	t.Literal = ""
	tokenPool.Put(t)
	return nil
}

// Reset resets a token's fields to zero values.
func (t *Token) Reset() {
	t.Type = models.TokenTypeUnknown
	t.Literal = ""
}
