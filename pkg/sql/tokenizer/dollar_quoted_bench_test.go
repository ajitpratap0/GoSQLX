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
	"fmt"
	"strings"
	"testing"
)

// BenchmarkDollarQuotedString measures tokenization performance for dollar-quoted
// strings of various sizes, from small literals to large function bodies.
func BenchmarkDollarQuotedString(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{"Empty", 0},
		{"Tiny_16B", 16},
		{"Small_256B", 256},
		{"Medium_4KB", 4 * 1024},
		{"Large_64KB", 64 * 1024},
		{"Huge_1MB", 1024 * 1024},
	}

	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			content := strings.Repeat("x", sz.size)
			input := []byte(fmt.Sprintf("SELECT $$%s$$", content))
			b.SetBytes(int64(len(input)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				tkz := GetTokenizer()
				_, err := tkz.Tokenize(input)
				if err != nil {
					b.Fatal(err)
				}
				PutTokenizer(tkz)
			}
		})
	}
}

// BenchmarkDollarQuotedStringTagged measures performance with a named tag ($tag$...$tag$).
func BenchmarkDollarQuotedStringTagged(b *testing.B) {
	sizes := []int{256, 4096, 65536}

	for _, sz := range sizes {
		b.Run(fmt.Sprintf("%dB", sz), func(b *testing.B) {
			content := strings.Repeat("a", sz)
			input := []byte(fmt.Sprintf("$body$%s$body$", content))
			b.SetBytes(int64(len(input)))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				tkz := GetTokenizer()
				_, err := tkz.Tokenize(input)
				if err != nil {
					b.Fatal(err)
				}
				PutTokenizer(tkz)
			}
		})
	}
}

// BenchmarkDollarQuotedStringRealistic benchmarks a realistic CREATE FUNCTION
// statement with a dollar-quoted body.
func BenchmarkDollarQuotedStringRealistic(b *testing.B) {
	body := `
BEGIN
    IF NEW.updated_at IS NULL THEN
        NEW.updated_at := NOW();
    END IF;
    INSERT INTO audit_log (table_name, action, row_id, changed_at)
    VALUES (TG_TABLE_NAME, TG_OP, NEW.id, NOW());
    RETURN NEW;
END;
`
	input := []byte(fmt.Sprintf(
		"CREATE OR REPLACE FUNCTION update_timestamp() RETURNS trigger LANGUAGE plpgsql AS $fn$%s$fn$",
		body,
	))
	b.SetBytes(int64(len(input)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tkz := GetTokenizer()
		_, err := tkz.Tokenize(input)
		if err != nil {
			b.Fatal(err)
		}
		PutTokenizer(tkz)
	}
}
