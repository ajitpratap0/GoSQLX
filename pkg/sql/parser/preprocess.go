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

// preprocessTokens implements token preprocessing (normalization) for the parser.
// It replaces the old token_conversion.go conversion layer.
// Instead of converting models.TokenWithSpan → token.Token (which stripped span
// information), it normalises a []models.TokenWithSpan in-place so the parser
// can consume it directly.
//
// The two responsibilities of the old layer are preserved here:
//
//  1. Compound-token expansion   – e.g. a single INNER_JOIN token becomes
//     [INNER, JOIN] (each carrying the original span).
//  2. Token-type normalisation – identifier/keyword strings whose type was
//     not resolved by the tokenizer are remapped to the appropriate
//     models.TokenType constant.
//
// The rules themselves (compound tables, type remaps, the backtick-width
// rule) live in internal/tokclass, the single source of truth shared with
// the tokenizer; this file is only the loop over a token stream.

package parser

import (
	"github.com/ajitpratap0/GoSQLX/internal/tokclass"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// preprocessTokens normalises a token stream for the parser.
// It expands compound tokens and remaps identifier/keyword types, returning a
// new slice of models.TokenWithSpan that the parser consumes directly.
//
// The returned slice is freshly allocated and owned by the caller; use it when
// the preprocessed stream outlives the parse (e.g. ParseBytesWithTokens).
func preprocessTokens(tokens []models.TokenWithSpan) []models.TokenWithSpan {
	return preprocessTokensInto(nil, tokens)
}

// preprocessTokensInto is preprocessTokens appending into dst[:0], so a caller
// that owns a scratch buffer (Parser.tokenBuf) can reuse it across parses.
// It allocates only when cap(dst) < len(tokens)+4 (the headroom covers the
// common compound-token expansions).
//
// dst must not alias tokens. The returned slice may share dst's backing array,
// so it must not be handed to anyone who could outlive the next call with the
// same dst.
//
// The loop body is tokclass.AppendReady, written out so the type gate and the
// common unchanged-token append stay inline in this loop;
// TestPreprocessFastPath_EveryTokenType and TestPreprocessFastPath_Corpus
// check the two agree.
func preprocessTokensInto(dst, tokens []models.TokenWithSpan) []models.TokenWithSpan {
	dst = dst[:0]
	if need := len(tokens) + 4; cap(dst) < need {
		dst = make([]models.TokenWithSpan, 0, need)
	}
	for i := range tokens {
		t := &tokens[i]
		if tokclass.Gate(t.Token.Type) {
			var ok bool
			if dst, ok = tokclass.AppendCompound(dst, t); ok {
				continue
			}
			dst = append(dst, *t)
			tokclass.NormalizeInPlace(&dst[len(dst)-1])
			continue
		}
		dst = append(dst, *t)
	}
	return dst
}
