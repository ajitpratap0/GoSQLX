package token

import (
	"sync"
)

var tokenPool = sync.Pool{
	New: func() interface{} {
		return &Token{}
	},
}

// Get retrieves a Token from the pool
func Get() *Token {
	token := tokenPool.Get().(*Token)
	token.Type = ""
	token.Literal = ""
	return token
}

// Put returns a Token to the pool
func Put(t *Token) error {
	if t == nil {
		return nil
	}
	t.Type = ""
	t.Literal = ""
	tokenPool.Put(t)
	return nil
}

// Reset resets a token's fields
func (t *Token) Reset() {
	t.Type = ""
	t.Literal = ""
}
