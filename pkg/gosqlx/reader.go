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
// manage the buffering themselves. Input is consumed in full before parsing
// begins; by default the read is unbounded, but callers that handle hostile
// or user-supplied input should pass WithMaxBytes to cap allocation.
//
// If ctx is nil, context.Background is used. Options are forwarded to
// ParseTree unchanged; see ParseTree for the context/dialect/timeout
// semantics.
//
// Read errors are surfaced verbatim (not wrapped in one of the gosqlx
// sentinels) because they originate outside the SQL layer. Parse errors
// follow the normal ParseTree wrapping (ErrSyntax / ErrTokenize / ErrTimeout
// / ErrUnsupportedDialect). Inputs that exceed WithMaxBytes return an error
// that satisfies errors.Is(err, ErrTooLarge).
//
// Example:
//
//	f, _ := os.Open("query.sql")
//	defer f.Close()
//	tree, err := gosqlx.ParseReader(ctx, f,
//	    gosqlx.WithDialect("postgresql"),
//	    gosqlx.WithMaxBytes(1<<20), // reject >1 MiB
//	)
//	if err != nil {
//	    return err
//	}
//
// Cancellation: the reader is wrapped so that each Read call short-circuits
// with the context error if ctx is cancelled. This does not interrupt a Read
// that has already entered a syscall — callers dealing with pathological
// network readers should still enforce deadlines at the transport layer.
func ParseReader(ctx context.Context, r io.Reader, opts ...Option) (*Tree, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if r == nil {
		return nil, fmt.Errorf("%w: nil reader", ErrTokenize)
	}

	cfg := applyOptions(opts)

	// Fail fast if already cancelled.
	if err := ctx.Err(); err != nil {
		return nil, wrapContextErr(err)
	}

	data, err := readAllBounded(ctx, r, cfg.maxBytes)
	if err != nil {
		return nil, err
	}

	// Re-check context after I/O — long reads may have exhausted the deadline.
	if err := ctx.Err(); err != nil {
		return nil, wrapContextErr(err)
	}

	return ParseTree(ctx, string(data), opts...)
}

// ParseReaderMultiple reads SQL from r, splits it into individual statements
// on unquoted top-level semicolons, and parses each, returning one Tree per
// statement.
//
// The splitter is dialect-aware: pass WithDialect("postgresql") to opt into
// dollar-quoting and E-string handling, WithDialect("mysql") for backtick
// identifiers, WithDialect("sqlserver") for [bracketed identifiers], and so
// on. When no dialect is set the conservative ANSI rules apply (single and
// double quotes, line comments, and non-nested block comments).
//
// ParseReaderMultiple honours WithMaxBytes the same way ParseReader does:
// inputs larger than the cap are rejected with ErrTooLarge before any
// splitting or parsing work begins.
//
// Empty segments (whitespace between consecutive semicolons, trailing
// whitespace after the last ';', etc.) are skipped. The first segment that
// fails to parse short-circuits the call and returns its error wrapped in
// the usual ParseTree sentinels, prefixed with the 1-based statement index.
//
// Example:
//
//	tree, err := gosqlx.ParseReaderMultiple(ctx,
//	    strings.NewReader(script),
//	    gosqlx.WithDialect("postgresql"),
//	    gosqlx.WithMaxBytes(4<<20),
//	)
func ParseReaderMultiple(ctx context.Context, r io.Reader, opts ...Option) ([]*Tree, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if r == nil {
		return nil, fmt.Errorf("%w: nil reader", ErrTokenize)
	}

	cfg := applyOptions(opts)

	if err := ctx.Err(); err != nil {
		return nil, wrapContextErr(err)
	}

	data, err := readAllBounded(ctx, r, cfg.maxBytes)
	if err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, wrapContextErr(err)
	}

	segments := SplitStatements(string(data), cfg.dialect)
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

// readAllBounded reads from r with optional cap enforcement and context
// cancellation. When maxBytes <= 0 the read is unbounded and behaves exactly
// like the pre-existing io.ReadAll path. When maxBytes > 0 the caller sees
// either all bytes (up to maxBytes) or ErrTooLarge — never a silently
// truncated prefix.
//
// Implementation notes:
//   - We request up to maxBytes+1 bytes from the underlying reader; if the
//     result is longer than maxBytes we know the input exceeded the cap and
//     reject it. This costs one extra byte of allocation but avoids racing
//     EOF against the limit.
//   - The reader is always wrapped in a ctxReader so that a cancelled context
//     short-circuits subsequent Read calls. This does NOT interrupt a Read
//     already blocked in a syscall — that is a known limitation of the
//     io.Reader contract.
func readAllBounded(ctx context.Context, r io.Reader, maxBytes int64) ([]byte, error) {
	reader := &ctxReader{ctx: ctx, r: r}

	if maxBytes <= 0 {
		data, err := io.ReadAll(reader)
		if err != nil {
			return nil, classifyReadErr(ctx, err)
		}
		return data, nil
	}

	// Read at most maxBytes+1 so we can distinguish "exactly at cap" from
	// "over cap". The one-byte overshoot is discarded if we trip the cap.
	limited := io.LimitReader(reader, maxBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, classifyReadErr(ctx, err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("%w: read %d bytes, cap is %d", ErrTooLarge, len(data), maxBytes)
	}
	return data, nil
}

// classifyReadErr routes a read error through the gosqlx sentinel taxonomy.
// Context errors become ErrTimeout; everything else is returned verbatim
// under a generic "gosqlx: read" prefix so callers can still unwrap the
// underlying io error with errors.Is.
func classifyReadErr(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return wrapContextErr(ctxErr)
	}
	return fmt.Errorf("gosqlx: read: %w", err)
}

// ctxReader is an io.Reader that checks ctx.Done() before each Read. It
// allows ParseReader / ParseReaderMultiple to abort between Read calls when
// the context is cancelled — Go's io package offers no such hook.
//
// It does NOT interrupt a Read that is already blocked in a syscall (for
// example a TCP socket read). That limitation is inherent to the io.Reader
// interface; callers that need hard cancellation should wrap their reader
// with a transport-aware deadline (e.g. net.Conn.SetReadDeadline) before
// handing it to ParseReader.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

// Read forwards to the wrapped reader after checking for context
// cancellation. It returns ctx.Err() directly — the caller (readAllBounded)
// converts that into the ErrTimeout sentinel.
func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// splitSQLStatements is retained as a thin shim over SplitStatements so
// existing tests and internal callers that use the ANSI default keep working
// unchanged. New code should call SplitStatements directly with an explicit
// dialect.
func splitSQLStatements(src string) []string {
	return SplitStatements(src, "")
}
