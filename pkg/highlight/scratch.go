package highlight

import "sync"

// scratch retains reusable buffers but never pins a document while pooled.
// Lexemes beyond their high-water mark are zero while in the pool.
type scratch struct {
	lineStarts []int
	comments   []Span
	lexemes    []lexeme
	lexHigh    int
	parens     []string
}

const (
	maxRetainedLexemes    = 1 << 15
	maxRetainedLineStarts = 1 << 15
	maxRetainedComments   = 1024
	maxRetainedParens     = 256
)

var scratchPool = sync.Pool{New: func() any { return new(scratch) }}

func getScratch() *scratch { return scratchPool.Get().(*scratch) }

// putScratch clears document references before pooling and drops oversized
// buffers independently. No tokenizer or *Word is retained by the scratch.
func putScratch(sc *scratch) {
	clear(sc.lexemes[:sc.lexHigh])
	clear(sc.parens[:cap(sc.parens)])
	if cap(sc.lexemes) > maxRetainedLexemes {
		sc.lexemes = nil
	}
	if cap(sc.lineStarts) > maxRetainedLineStarts {
		sc.lineStarts = nil
	}
	if cap(sc.comments) > maxRetainedComments {
		sc.comments = nil
	}
	if cap(sc.parens) > maxRetainedParens {
		sc.parens = nil
	}
	sc.lexemes, sc.comments, sc.parens, sc.lineStarts = sc.lexemes[:0], sc.comments[:0], sc.parens[:0], sc.lineStarts[:0]
	sc.lexHigh = 0
	scratchPool.Put(sc)
}
