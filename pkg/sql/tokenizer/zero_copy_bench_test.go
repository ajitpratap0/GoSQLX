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

import "testing"

// BenchmarkTokenizeString compares the []byte entry point, which copies the
// input once into a string, with TokenizeString, which slices the caller's
// string directly (#546).
func BenchmarkTokenizeString(b *testing.B) {
	inputs := []struct {
		name string
		sql  []byte
	}{
		{"SimpleSQL", simpleSQL},
		{"ComplexSQL", complexSQL},
		{"MediumSQL_10KB", mediumSQL10KB},
	}
	for _, in := range inputs {
		s := string(in.sql)
		b.Run(in.name+"/Bytes", func(b *testing.B) {
			tkz := GetTokenizer()
			defer PutTokenizer(tkz)
			b.ReportAllocs()
			b.SetBytes(int64(len(in.sql)))
			for b.Loop() {
				if _, err := tkz.Tokenize(in.sql); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(in.name+"/String", func(b *testing.B) {
			tkz := GetTokenizer()
			defer PutTokenizer(tkz)
			b.ReportAllocs()
			b.SetBytes(int64(len(s)))
			for b.Loop() {
				if _, err := tkz.TokenizeString(s); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
