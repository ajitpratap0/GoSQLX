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

package keywords_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestClickHouseDialectKeywords(t *testing.T) {
	kws := keywords.DialectKeywords(keywords.DialectClickHouse)
	if len(kws) == 0 {
		t.Fatal("expected ClickHouse keywords, got none")
	}
	found := map[string]bool{}
	for _, kw := range kws {
		found[kw.Word] = true
	}
	required := []string{"PREWHERE", "FINAL", "ENGINE", "GLOBAL", "ASOF", "TTL", "FORMAT"}
	for _, w := range required {
		if !found[w] {
			t.Errorf("missing expected ClickHouse keyword: %s", w)
		}
	}
}

func TestClickHouseInAllDialects(t *testing.T) {
	found := false
	for _, d := range keywords.AllDialects() {
		if d == keywords.DialectClickHouse {
			found = true
			break
		}
	}
	if !found {
		t.Error("DialectClickHouse not in AllDialects()")
	}
}

func TestIsValidDialectClickHouse(t *testing.T) {
	if !keywords.IsValidDialect("clickhouse") {
		t.Error("IsValidDialect should return true for 'clickhouse'")
	}
}
