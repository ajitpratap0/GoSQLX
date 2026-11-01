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
	"strings"
	"unicode/utf8"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// IsKeyword reports whether word, written bare, is read by the tokenizer as a
// keyword token (SELECT, TABLE, ORDER, KEY, ...) rather than as a plain
// identifier. Case is ignored. The parser uses it to decide whether a name
// that was written as a delimited identifier ("table", `order`) must keep its
// delimiters when it is rendered back. Pure-ASCII words are looked up without
// allocating.
func IsKeyword(word string) bool {
	if word == "" {
		return false
	}
	var kbuf [keywordKeyBufLen]byte
	if len(word) <= keywordKeyBufLen {
		if h, ok := asciiUpperHash(kbuf[:len(word)], word); ok {
			e := kwLookup(h, kbuf[:len(word)])
			return e != nil && e.isKeyword
		}
	}
	if isASCII(word) {
		return false // longer than any keyword
	}
	_, ok := keywordTokenTypes[strings.ToUpper(word)]
	return ok
}

// kwTableSize is the number of slots in the fused keyword table. It must be a
// power of two and comfortably larger than the number of distinct keys in
// keywordTokenTypes and compoundKeywordStarts (load factor stays below 0.5).
const kwTableSize = 512

// kwEntry is one slot of the keyword table. A key may be a plain keyword, a
// compound-keyword start, or both. W3-03 adds the parser-remap type field here
// (it is omitted until then because the linter rejects unused fields).
type kwEntry struct {
	key           string
	typ           models.TokenType // valid only when isKeyword
	isKeyword     bool
	compoundStart bool
	used          bool
}

// kwTable is an open-addressed (linear probing) hash table generated at init
// from keywordTokenTypes and compoundKeywordStarts. It is read-only after
// init and therefore safe for concurrent use. Looking a word up costs one
// FNV-1a hash fused into the ASCII upper-casing loop plus, typically, one
// probe, replacing two Go map lookups.
var kwTable [kwTableSize]kwEntry

const (
	fnvOffset32 = 2166136261
	fnvPrime32  = 16777619
)

func kwHash(s string) uint32 {
	h := uint32(fnvOffset32)
	for i := 0; i < len(s); i++ {
		h = (h ^ uint32(s[i])) * fnvPrime32
	}
	return h
}

func init() {
	insert := func(k string) *kwEntry {
		i := kwHash(k) & (kwTableSize - 1)
		for kwTable[i].used && kwTable[i].key != k {
			i = (i + 1) & (kwTableSize - 1)
		}
		e := &kwTable[i]
		e.used, e.key = true, k
		return e
	}
	for k, v := range keywordTokenTypes {
		e := insert(k)
		e.typ, e.isKeyword = v, true
	}
	for k, v := range compoundKeywordStarts {
		if v {
			insert(k).compoundStart = true
		}
	}
}

// asciiUpperHash upper-cases s into dst (len(dst) >= len(s)) and returns the
// FNV-1a hash of the upper-cased bytes. ok is false when s contains a
// non-ASCII byte, in which case dst and the hash are unspecified.
func asciiUpperHash(dst []byte, s string) (h uint32, ok bool) {
	h = fnvOffset32
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= utf8.RuneSelf {
			return 0, false
		}
		if 'a' <= c && c <= 'z' {
			c -= 'a' - 'A'
		}
		dst[i] = c
		h = (h ^ uint32(c)) * fnvPrime32
	}
	return h, true
}

// kwLookup returns the table entry for the already upper-cased key whose hash
// is h, or nil when the key is in neither map. The table is never full, so
// the probe loop terminates at an unused slot.
func kwLookup(h uint32, key []byte) *kwEntry {
	i := h & (kwTableSize - 1)
	for {
		e := &kwTable[i]
		if !e.used {
			return nil
		}
		if e.key == string(key) {
			return e
		}
		i = (i + 1) & (kwTableSize - 1)
	}
}
