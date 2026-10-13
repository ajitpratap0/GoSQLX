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

package fingerprint_test

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/fingerprint"
)

const benchJoinSQL = "SELECT c.id, c.name, SUM(o.total) AS spend FROM customers c " +
	"JOIN orders o ON o.customer_id = c.id LEFT JOIN regions g ON g.code = c.region " +
	"WHERE c.active = 1 AND o.created_at > '2024-01-01' GROUP BY c.id, c.name " +
	"ORDER BY spend DESC, c.name LIMIT 50"

func BenchmarkFingerprint(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := fingerprint.Fingerprint(benchJoinSQL); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNormalize(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := fingerprint.Normalize(benchJoinSQL); err != nil {
			b.Fatal(err)
		}
	}
}
