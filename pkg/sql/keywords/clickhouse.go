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

// CLICKHOUSE_SPECIFIC contains ClickHouse-specific SQL keywords and extensions.
// These keywords are recognized when using DialectClickHouse.
//
// Note: PREWHERE and FINAL also appear in the tokenizer's hardcoded keywordTokenTypes
// map (tokenizer.go) to ensure they are emitted as TokenTypeKeyword rather than
// TokenTypeIdentifier. This is required for correct clause boundary detection during
// FROM clause parsing. All other keywords here are dialect-scoped only.
//
// Examples: PREWHERE, FINAL, ENGINE, MERGETREE, CODEC, TTL, DISTRIBUTED, GLOBAL, ASOF
var CLICKHOUSE_SPECIFIC = []Keyword{
	// ClickHouse-specific query clauses
	{Word: "PREWHERE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "FINAL", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "SAMPLE", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "GLOBAL", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},
	{Word: "ASOF", Type: models.TokenTypeKeyword, Reserved: true, ReservedForTableAlias: true},

	// ClickHouse DDL — table engine and column options
	{Word: "ENGINE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "CODEC", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "TTL", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "GRANULARITY", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "SETTINGS", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "FORMAT", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "ALIAS", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "MATERIALIZED", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "TUPLE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},

	// MergeTree engine family
	{Word: "MERGETREE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "REPLACINGMERGETREE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "AGGREGATINGMERGETREE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "COLLAPSINGMERGETREE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "SUMMINGMERGETREE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "REPLICATEDMERGETREE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "REPLICATED", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},

	// Other table engines
	{Word: "DISTRIBUTED", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "MEMORY", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "LOG", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "TINYLOG", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "STRIPELOG", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},

	// ClickHouse data types (as keywords)
	{Word: "FIXEDSTRING", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "LOWCARDINALITY", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "NULLABLE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "DATETIME64", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "IPV4", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
	{Word: "IPV6", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},

	// JOIN modifiers
	{Word: "PASTE", Type: models.TokenTypeKeyword, Reserved: false, ReservedForTableAlias: false},
}
