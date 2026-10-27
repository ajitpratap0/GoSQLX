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

// Package tokscratch lets GoSQLX's own tokenize-then-parse entry points
// tokenize into a buffer owned by the pooled tokenizer instead of a fresh
// slice, without adding that borrowed-result contract to the public
// tokenizer API.
//
// Package tokenizer registers the implementation in its init. Every function
// here takes the *tokenizer.Tokenizer as t (typed any only to avoid an import
// cycle) and returns the same tokens and errors as the matching public method
// (Tokenize, TokenizeString, TokenizeStringContext), with one difference: the
// returned slice, and the Word values its tokens point to, are owned by t.
// They are valid only until the next tokenize call on t, t.Reset or
// tokenizer.PutTokenizer(t). Callers must copy what they keep (the parser's
// preprocess step does) and must never return the slice to a user. Token
// strings are substrings of the input as with the public methods, so they
// stay valid.
package tokscratch

import (
	"context"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Func is the registered implementation. When isString is true, src is the
// SQL and input is ignored; otherwise input is the SQL and is copied once
// into a string as Tokenize does.
type Func func(ctx context.Context, t any, input []byte, src string, isString bool) ([]models.TokenWithSpan, error)

var impl Func

// Register installs the implementation. It is called once by package
// tokenizer's init and must not be called by anyone else.
func Register(f Func) { impl = f }

func requireImplementation() {
	if impl == nil {
		panic("tokscratch: tokenizer not linked")
	}
}

// Bytes is t.Tokenize(input) into t's scratch buffer.
func Bytes(t any, input []byte) ([]models.TokenWithSpan, error) {
	requireImplementation()
	return impl(context.Background(), t, input, "", false)
}

// String is t.TokenizeString(s) into t's scratch buffer.
func String(t any, s string) ([]models.TokenWithSpan, error) {
	requireImplementation()
	return impl(context.Background(), t, nil, s, true)
}

// StringContext is t.TokenizeStringContext(ctx, s) into t's scratch buffer.
func StringContext(ctx context.Context, t any, s string) ([]models.TokenWithSpan, error) {
	requireImplementation()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return impl(ctx, t, nil, s, true)
}
