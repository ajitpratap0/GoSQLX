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

package keywords

import "github.com/ajitpratap0/GoSQLX/pkg/models"

// CLICKHOUSE_SPECIFIC contains ClickHouse-specific SQL keywords not in the base set.
// These keywords are recognized when using DialectClickHouse.
//
// Keywords that already exist in the base keyword set (RESERVED_FOR_TABLE_ALIAS or
// ADDITIONAL_KEYWORDS) are NOT duplicated here. The following base keywords overlap
// with ClickHouse features but are already defined in the base set:
//   - PREWHERE (Reserved, ReservedForTableAlias)
//   - FINAL  — not in base set, included here
//   - SAMPLE (Reserved, ReservedForTableAlias)
//   - SETTINGS (Reserved, ReservedForTableAlias)
//   - FORMAT (Reserved, ReservedForTableAlias)
//   - GLOBAL (Reserved, ReservedForTableAlias)
//   - MATERIALIZED — added by DialectPostgreSQL; safe to include as addKeywordsWithCategory
//     skips duplicates, but omitted here to keep CLICKHOUSE_SPECIFIC self-contained.
//
// Examples: ENGINE, CODEC, TTL, REPLICATED, DISTRIBUTED, FIXEDSTRING, LOWCARDINALITY
var CLICKHOUSE_SPECIFIC = []Keyword{
	// ClickHouse-specific clauses (not in base set)
	{Word: "FINAL", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},

	// DDL extensions
	{Word: "ENGINE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "CODEC", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "TTL", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "REPLICATED", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "DISTRIBUTED", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "MATERIALIZED", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "ALIAS", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},

	// ClickHouse data types (as keywords)
	{Word: "FIXEDSTRING", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "LOWCARDINALITY", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "NULLABLE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "DATETIME64", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "IPV4", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "IPV6", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},

	// Replication/cluster (ON CLUSTER and PASTE are multi-token; register single-token variants)
	{Word: "PASTE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
}
