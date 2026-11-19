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

package highlight

import "sync"

// scratch retains reusable buffers but never pins a document while pooled.
// Lexemes are cleared on return so pooled buffers hold no strings.
type scratch struct {
	lineStarts []int
	comments   []Span
	lexemes    []lexeme
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
// resetScratch drops every retained reference and truncates the buffers. It is
// separate from putScratch so tests never touch an object the pool owns.
func resetScratch(sc *scratch) {
	clear(sc.lexemes[:cap(sc.lexemes)])
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
}

func putScratch(sc *scratch) {
	resetScratch(sc)
	scratchPool.Put(sc)
}
