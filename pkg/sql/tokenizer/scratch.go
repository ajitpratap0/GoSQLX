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
	"context"
	"fmt"

	"github.com/ajitpratap0/GoSQLX/internal/tokscratch"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

func init() { tokscratch.Register(tokenizeScratch) }

// tokenizeScratch implements tokscratch.Func: the public tokenize paths, but
// building the result in the tokenizer-owned t.tokBuf.
func tokenizeScratch(ctx context.Context, tv any, input []byte, src string, isString bool) ([]models.TokenWithSpan, error) {
	t, ok := tv.(*Tokenizer)
	if !ok || t == nil {
		return nil, fmt.Errorf("tokscratch: want a non-nil *tokenizer.Tokenizer, got %T", tv)
	}
	if isString {
		return t.tokenize(ctx, stringBytes(src), src, true, true)
	}
	return t.tokenize(ctx, input, "", false, true)
}
