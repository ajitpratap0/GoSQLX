---
title: "Inside a zero-copy SQL tokenizer in Go"
description: "How the GoSQLX tokenizer turns SQL into tokens without copying it: substring token values, a sizing prescan, chunked keyword records and pool hygiene."
date: 2026-10-18
tags: [go, performance, tokenizer, sql]
---

A SQL tokenizer reads a string of characters and cuts it into tokens: keywords, identifiers, numbers, string literals and operators. The obvious Go implementation builds each token value with a `strings.Builder` or by converting a byte slice to a string. Both allocate. Across a long query, that means hundreds of small allocations before the parser has even started.

GoSQLX takes a different route. In the common case, every token value it returns is a substring of the SQL you passed in, so the tokenizer allocates the token slice and very little else. This post walks through how that works, where the rule has to bend, and what it costs you as a caller.

## Strings are already views

A Go `string` is a pointer and a length. Slicing a string, `s[i:j]`, creates a new header that points into the same bytes. No copy is made. That is the whole trick: if the tokenizer keeps the input as a string and returns `src[start:end]` for every token, the token values cost nothing beyond their 16-byte headers.

The tokenizer therefore keeps two views of the same input for the duration of a call:

- `t.input`, a `[]byte`, which the scanner indexes byte by byte, and
- `t.src`, a `string` holding the same bytes, which is what token values are sliced from.

When an identifier ends, the scanner does not build anything. It slices:

```go
start := t.pos.Index
// ... advance over identifier characters ...
ident := t.src[start:t.pos.Index]
```

## Two entry points, one copy at most

Where the two views come from depends on how you call the tokenizer.

`Tokenize([]byte)` copies the input once, into a string, right after the size check. That single copy is deliberate. A caller's `[]byte` is mutable: if tokens aliased it and the caller reused the buffer for the next request, every token from the previous call would silently change. One copy per call buys tokens that are always safe to keep.

`TokenizeString(string)` makes no copy at all. A string is immutable, so the tokenizer can slice it directly. To scan it as bytes, it builds a read-only `[]byte` view of the same memory:

```go
func stringBytes(s string) []byte {
	if s == "" {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(s), len(s)) // read-only view
}
```

This is the only use of `unsafe` in the tokenizer, and it is sound because of one invariant: the scanner never writes to, appends to or returns `t.input`. Everything it hands out is a substring of `t.src` or a fresh copy. The high-level `gosqlx.Parse` uses `TokenizeString`, which is why parsing a string never copies it.

The repository has a benchmark that compares the two entry points on the same inputs, so you can see the cost of that one copy on your own machine:

```bash
go test -run='^$' -bench=BenchmarkTokenizeString -benchmem ./pkg/sql/tokenizer/
```

## Keyword lookup without allocating

SQL keywords are case-insensitive, so `select`, `Select` and `SELECT` must all map to the same token type. The textbook approach is `strings.ToUpper(ident)` followed by a map lookup, and `ToUpper` allocates a new string whenever the input has a lowercase letter.

GoSQLX upper-cases ASCII words into a 32-byte array on the stack instead, then indexes the keyword map with `m[string(buf[:n])]`. The Go compiler recognises that pattern and performs the lookup without converting the bytes to a heap string. The longest keyword key is shorter than the buffer, so any ASCII word that does not fit can be rejected without a lookup at all. Only non-ASCII words fall back to `strings.ToUpper`, which keeps Unicode case folding exactly right.

Compound keywords such as `GROUP BY` or `ORDER BY` get the same treatment. When the two words are separated by exactly one space, the token value is again a substring of the input. Only unusual spacing (`GROUP    BY`, or a newline in between) forces the scanner to build a normalised `"GROUP BY"` string.

## Where zero-copy has to stop

Some tokens cannot be substrings, because their value is not literally present in the input:

- a string literal with an escape sequence, such as `'it\'s'` in MySQL,
- a doubled quote, such as `'it''s'`,
- a Unicode quote character that is normalised to an ASCII one, and
- invalid UTF-8 inside a literal or quoted identifier.

Each quoted-token reader has two paths. The fast path scans to the closing quote and, if it saw none of the cases above, returns a substring. The slow path decodes the content into a reusable scratch buffer and returns a fresh string. Most real SQL never leaves the fast path.

## Sizing before scanning

A tokenizer that appends to an empty slice will grow it several times on a long query, copying every token each time. GoSQLX runs a cheap prescan first: a single loop over the bytes that counts token boundaries and records where each line starts. The count is an upper bound in practice, so the token slice is allocated once at roughly the right size. The line-start table also makes converting a byte offset into a line and column a binary search instead of a rescan.

The same prescan counts words that look like identifiers. Keywords and identifiers carry a small `Word` record, and instead of allocating each one separately the tokenizer carves them out of chunks sized from that count. A chunk is never reallocated once records have been handed out, so pointers already returned stay valid; when it fills up, a new one is started.

## The cost: retention

Zero-copy has one consequence you should know about. Because token values, and the identifiers and literals in the AST built from them, are substrings of your SQL, keeping any one of them keeps the entire SQL string alive. If you parse a 2 MB migration file and store one table name in a long-lived map, the whole 2 MB stays in memory.

The fix is one call:

```go
name := strings.Clone(ident.Name) // independent copy, frees the source SQL
```

The metadata helpers in the high-level API, such as `gosqlx.ExtractTables`, already return independent copies, so you only need `strings.Clone` when you hold on to raw AST fields.

## Pooling without leaking the last query

Tokenizers come from a `sync.Pool` (`tokenizer.GetTokenizer` and `tokenizer.PutTokenizer`). A pooled object that still pointed at the previous input would keep that SQL alive for as long as the tokenizer sat in the pool, so `Reset` clears every reference to the input and zeroes the literal scratch buffer before the tokenizer goes back. It also caps how much capacity it keeps: a tokenizer that once scanned a huge file drops its oversized buffers instead of pinning them for every later caller. The [next article](/blog/sync-pool-ast-nodes-without-races/) covers the pooling rules in more detail.

## Try it

```go
package main

import (
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func main() {
	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.TokenizeString("SELECT id, name FROM users WHERE id = 42")
	if err != nil {
		panic(err)
	}
	for _, t := range tokens {
		if t.Token.Type == models.TokenTypeEOF {
			break
		}
		fmt.Printf("%-12q line %d col %d\n", t.Token.Value, t.Start.Line, t.Start.Column)
	}
}
```

None of the printed values was copied: keywords, identifiers and numbers such as `"SELECT"`, `"id"` and `"42"` point into the string passed to `TokenizeString`, and operators such as `","` and `"="` are constant strings compiled into the binary.

Further reading:

- [Architecture](/docs/concepts/architecture/): how the tokenizer, parser and AST fit together
- [tokenizer package reference](/docs/reference/api/tokenizer/)
- [Performance tuning](/docs/guides/performance-tuning/)
