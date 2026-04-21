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

package gosqlx

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// ParseReader reads SQL from r and parses it, returning an opaque Tree.
//
// This is a convenience wrapper for callers who already have an io.Reader
// (HTTP request body, file handle, strings.Reader, etc.) and don't want to
// manage the buffering themselves. Input is consumed in full via io.ReadAll
// before parsing begins.
//
// If ctx is nil, context.Background is used. Options are forwarded to
// ParseTree unchanged; see ParseTree for the context/dialect/timeout
// semantics.
//
// Read errors are surfaced verbatim (not wrapped in one of the gosqlx
// sentinels) because they originate outside the SQL layer. Parse errors
// follow the normal ParseTree wrapping (ErrSyntax / ErrTokenize / ErrTimeout
// / ErrUnsupportedDialect).
//
// Example:
//
//	f, _ := os.Open("query.sql")
//	defer f.Close()
//	tree, err := gosqlx.ParseReader(ctx, f, gosqlx.WithDialect("postgresql"))
//	if err != nil {
//	    return err
//	}
//
// Cancellation: if ctx is cancelled before the reader finishes draining,
// the underlying io.ReadAll call does not abort mid-read — callers who need
// truly cancellable reads must wrap r in a context-aware reader (see
// golang.org/x/net/http2/h2c or similar). ParseReader does re-check ctx
// after the read and before dispatching to the parser.
func ParseReader(ctx context.Context, r io.Reader, opts ...Option) (*Tree, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if r == nil {
		return nil, fmt.Errorf("%w: nil reader", ErrTokenize)
	}

	// Fail fast if already cancelled.
	if err := ctx.Err(); err != nil {
		return nil, wrapContextErr(err)
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("gosqlx: read: %w", err)
	}

	// Re-check context after I/O — long reads may have exhausted the deadline.
	if err := ctx.Err(); err != nil {
		return nil, wrapContextErr(err)
	}

	return ParseTree(ctx, string(data), opts...)
}

// ParseReaderMultiple reads SQL from r, splits it on unquoted semicolons into
// separate statements, and parses each, returning one Tree per statement.
//
// The splitter is intentionally simple and designed for well-formed scripts:
//   - It respects single-quoted string literals ('...').
//   - It respects double-quoted identifiers ("...").
//   - It ignores semicolons inside line comments (-- ...) and block comments
//     (/* ... */) that do not cross statement boundaries.
//   - It does NOT attempt to handle dialect-specific delimiter directives
//     (MySQL's DELIMITER $$, Oracle's / etc.) — for those, split upstream.
//
// Empty segments (trailing whitespace after the last ;, or blank lines) are
// skipped. Each surviving segment is dispatched to ParseTree with the same
// options. The first segment that fails to parse short-circuits and returns
// its error wrapped in the usual ParseTree sentinels.
//
// Example:
//
//	tree, err := gosqlx.ParseReaderMultiple(ctx,
//	    strings.NewReader("SELECT 1; INSERT INTO t VALUES (1);"),
//	)
func ParseReaderMultiple(ctx context.Context, r io.Reader, opts ...Option) ([]*Tree, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if r == nil {
		return nil, fmt.Errorf("%w: nil reader", ErrTokenize)
	}

	if err := ctx.Err(); err != nil {
		return nil, wrapContextErr(err)
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("gosqlx: read: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return nil, wrapContextErr(err)
	}

	segments := splitSQLStatements(string(data))
	trees := make([]*Tree, 0, len(segments))
	for i, seg := range segments {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		tree, err := ParseTree(ctx, seg, opts...)
		if err != nil {
			return nil, fmt.Errorf("statement %d: %w", i, err)
		}
		trees = append(trees, tree)
	}
	return trees, nil
}

// splitSQLStatements splits src on top-level semicolons, respecting the
// common string/identifier/comment contexts. It is intentionally small and
// conservative; see ParseReaderMultiple doc comment for caveats.
func splitSQLStatements(src string) []string {
	var out []string
	var cur strings.Builder

	// State machine flags. Only one of these can be true at a time.
	inSingle := false // inside '...'
	inDouble := false // inside "..."
	inLine := false   // inside -- ... \n
	inBlock := false  // inside /* ... */

	for i := 0; i < len(src); i++ {
		c := src[i]

		switch {
		case inLine:
			cur.WriteByte(c)
			if c == '\n' {
				inLine = false
			}
			continue
		case inBlock:
			cur.WriteByte(c)
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				cur.WriteByte(src[i+1])
				i++
				inBlock = false
			}
			continue
		case inSingle:
			cur.WriteByte(c)
			if c == '\'' {
				// Handle escaped quote ''.
				if i+1 < len(src) && src[i+1] == '\'' {
					cur.WriteByte(src[i+1])
					i++
					continue
				}
				inSingle = false
			}
			continue
		case inDouble:
			cur.WriteByte(c)
			if c == '"' {
				inDouble = false
			}
			continue
		}

		// Top-level state: look for comment starts, string opens, or ';'.
		switch {
		case c == '-' && i+1 < len(src) && src[i+1] == '-':
			inLine = true
			cur.WriteByte(c)
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			inBlock = true
			cur.WriteByte(c)
		case c == '\'':
			inSingle = true
			cur.WriteByte(c)
		case c == '"':
			inDouble = true
			cur.WriteByte(c)
		case c == ';':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	// Tail.
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
