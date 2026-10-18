---
title: "sync.Pool for AST nodes without races"
description: "The rules GoSQLX follows to pool tokenizers, parsers and AST nodes with sync.Pool safely: one owner, reset before Put, capped capacity and tests."
date: 2026-10-18
tags: [go, concurrency, sync-pool, performance]
---

`sync.Pool` looks like a free performance win. Put an object back when you are done, get it again next time, and the garbage collector has less to do. In a SQL parser, where every query produces a tokenizer, a parser, a token slice and a tree of nodes, the temptation is to pool everything.

The pool itself is safe for concurrent use. The bugs come from what you put in it. A pooled object that is still referenced somewhere, or that still holds state from its last user, turns into a data race or a silent wrong answer the moment two goroutines share it. GoSQLX pools its tokenizer, its parser, the AST container and a set of statement and expression nodes, and it runs its test suite under the race detector on every change. These are the rules that keep that combination working.

## Rule 1: one owner, and the owner calls Put

A pooled object has exactly one owner at a time. The owner gets it, uses it and puts it back, and nothing else may hold a reference afterwards. In Go the reliable way to express that is `defer` on the line after the `Get`:

```go
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)

p := parser.GetParser()
defer parser.PutParser(p)
```

`defer` guarantees the object goes back on every path, including early error returns and panics. It also makes ownership visible in review: if a pooled value is passed to a goroutine or stored in a struct, the `defer` in the same function is a red flag.

The high-level API does this for you. `gosqlx.Parse` gets a tokenizer and a parser from their pools, defers both Puts and returns only the AST, so callers never see the pooled machinery.

## Rule 2: reset before Put, not after Get

An object in the pool should be clean. If `Get` callers were responsible for clearing state, a single forgotten field would leak one request's data into the next. GoSQLX resets in the `Put` path, at the pool boundary, so every object in the pool is already in a known state.

Reset is about more than zeroing counters. Two kinds of state matter most:

- **References to the last input.** Token values in GoSQLX are substrings of the caller's SQL (see [Inside a zero-copy SQL tokenizer](/blog/zero-copy-sql-tokenizer-in-go/)). A pooled parser that kept its token slice would keep the previous query's SQL alive for as long as it sat in the pool. `Parser.Reset` drops the reference and clears the used part of its token buffer; `Tokenizer.Reset` clears its input, its word chunk and its literal scratch buffer.
- **Configuration.** A tokenizer can be switched to a dialect such as MySQL. If that setting survived the pool, the next caller, who asked for nothing in particular, would tokenize with MySQL rules. `PutTokenizer` restores the default dialect before the object goes back. This is not a data race, and the race detector will never report it, but it is the same class of bug: state crossing from one owner to the next.

## Rule 3: cap what the pool keeps

Reusing capacity is the point of pooling, but capacity is also memory. One request that tokenizes a 50 MB migration grows the tokenizer's buffers to match, and if those buffers return to the pool they stay pinned for every later caller, most of whom parse a short query.

Every reset in GoSQLX keeps capacity only up to a limit and drops anything larger:

```go
if cap(p.tokenBuf) > maxPooledTokenBuf {
	p.tokenBuf = nil // let the GC have it
} else {
	clear(p.tokenBuf)
	p.tokenBuf = p.tokenBuf[:0]
}
```

The same pattern applies to line-start tables, comment slices, literal buffers and the work queue used to release expressions. The result is that the steady-state memory of the pools tracks typical queries, not the largest one ever seen.

## Rule 4: never Put the same object twice

A double Put is the most dangerous pooling bug, because it does not fail where it happens. The object goes into the pool twice, two later `Get` calls receive the same pointer, and two goroutines now mutate one struct. The race detector may catch it eventually, far away from the cause.

Double Puts creep in when trees share nodes. A derived table in a `JOIN` can be reachable from two places, and a naive recursive release visits it twice. GoSQLX has regression tests that parse such queries, release the tree, then take several objects from the pool and fail if any pointer appears twice. A test is the only reliable defence here, because the bug produces no error at the point where it is introduced.

## Rule 5: only pool what you actually reuse

This is the least obvious rule. The GoSQLX parser does not draw every node type from a pool. Most nodes, such as identifiers, literals and binary expressions, are created as ordinary heap values. Putting those into a pool on release would only grow pools that no `Get` ever reads from, which is pure overhead.

So `ast.ReleaseAST` follows a "release what was drawn" policy: it walks the tree and returns only the node types the parser actually obtains from pools, and leaves everything else to the garbage collector. A test keeps the policy honest by comparing the list of node types `ReleaseAST` releases with the pool constructors the parser calls; if someone makes the parser pool a new node type and forgets the release side, or the reverse, the test fails.

Trees you build by hand from `Get*` constructors are a different case, and the matching `Put*` functions release every pooled node they reach.

## Rule 6: release iteratively, and pool the work queue

Releasing a tree recursively is natural, but a query with thousands of nested expressions can overflow the stack. GoSQLX releases expressions with an explicit work queue instead, with a depth-limited recursive fallback for pathological trees so no node is skipped.

That work queue is itself pooled, which brings in a classic Go detail: storing a slice in an `interface{}` allocates, because the slice header has to be boxed. The pool stores a `*[]Expression` instead, and queues that grew unusually large are dropped rather than returned (Rule 3 again).

```go
putExpressionWorkQueuePool = sync.Pool{
	New: func() interface{} {
		s := make([]Expression, 0, 32)
		return &s
	},
}
```

## Rule 7: prove it with the race detector

None of these rules can be checked by reading code alone. GoSQLX runs its whole test suite with `-race` in CI, including tests that parse concurrently from many goroutines, and the project's standard gate is:

```bash
task test:race
# or directly:
go test -race -timeout 60s ./...
```

Two practical notes. First, the race detector slows code down several times, so performance regression tests skip themselves when it is enabled (GoSQLX uses a `race` build tag to detect that). Second, the race detector only finds races that actually happen during the run, which is why the concurrency tests deliberately hammer the pools from many goroutines.

## What this means for callers

If you use the high-level API, you do not need to think about any of this:

```go
tree, err := gosqlx.Parse("SELECT id FROM users WHERE active = true")
if err != nil {
	return err
}
defer ast.ReleaseAST(tree) // optional: returns pooled nodes for reuse
```

If you use the low-level API, follow Rule 1 exactly: `Get`, then `defer Put` on the next line, and never let a pooled object escape the function that owns it.

Further reading:

- [Usage guide](/docs/usage-guide/): high-level and low-level APIs
- [Run in production](/docs/guides/production/): pool sizing and concurrency advice
- [ast package reference](/docs/reference/api/ast/)
