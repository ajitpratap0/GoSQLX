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

import "github.com/ajitpratap0/GoSQLX/pkg/models"

// Token readers on the scan path (nextToken and the read* functions it
// dispatches to) write the token they read into out, which points at the
// token's slot in the output slice, instead of returning it by value.
//
// Returning the 40-byte models.Token by value, then copying it into a 72-byte
// models.TokenWithSpan and appending that, cost several struct copies per
// token. On amd64 each copy reloads, with 16-byte loads, a struct that was
// just spilled with 8-byte stores; those loads cannot be store-forwarded and
// stall. Writing the fields through a pointer into the final slot removes
// every intermediate copy.
//
// Readers write *out only on success. On error *out is left as it was or
// partly written; the caller discards the slot.

// setToken stores v in *out and returns nil. It inlines, and the compiler
// then builds a composite literal argument directly in *out.
func setToken(out *models.Token, v models.Token) error {
	*out = v
	return nil
}

// storeToken bridges a by-value reader (the slow reference readers and the
// rarely used prefixed and Unicode-escape readers) into an out parameter.
// It copies field by field: a whole-struct copy would reload the spilled
// result with the 16-byte loads that stall on amd64.
func storeToken(out *models.Token, v models.Token, err error) error {
	if err != nil {
		return err
	}
	out.Type = v.Type
	out.Value = v.Value
	out.Word = v.Word
	out.Long = v.Long
	out.Quote = v.Quote
	return nil
}
