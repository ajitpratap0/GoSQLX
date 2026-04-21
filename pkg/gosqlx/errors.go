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

import "errors"

// Sentinel error values returned (wrapped) by the new ParseTree / ParseReader
// entry points. Callers can test specific failure classes with errors.Is:
//
//	tree, err := gosqlx.ParseTree(ctx, sql)
//	switch {
//	case errors.Is(err, gosqlx.ErrSyntax):
//	    // surface SQL syntax problem to the user
//	case errors.Is(err, gosqlx.ErrTokenize):
//	    // lexical/tokenization problem
//	case errors.Is(err, gosqlx.ErrTimeout):
//	    // context deadline exceeded
//	case errors.Is(err, gosqlx.ErrUnsupportedDialect):
//	    // caller passed an unknown WithDialect value
//	}
//
// The underlying *errors.Error is still available via errors.As or via the
// ErrorCode / ErrorLocation / ErrorHint helpers in this package.
var (
	// ErrSyntax indicates a parser-level syntax problem.
	ErrSyntax = errors.New("gosqlx: syntax error")
	// ErrTokenize indicates a tokenizer/lexer problem before parsing began.
	ErrTokenize = errors.New("gosqlx: tokenize error")
	// ErrTimeout indicates parsing was aborted because the context deadline
	// expired. Equivalent to errors.Is(err, context.DeadlineExceeded) for
	// context-originated timeouts; gosqlx wraps both under ErrTimeout so
	// callers can match a single sentinel.
	ErrTimeout = errors.New("gosqlx: parse timeout")
	// ErrUnsupportedDialect indicates the dialect supplied via WithDialect is
	// not recognized by the underlying keywords package.
	ErrUnsupportedDialect = errors.New("gosqlx: unsupported dialect")
)
