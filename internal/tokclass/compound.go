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

package tokclass

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// Compound token expansion tables. These slices are shared, read-only package
// data and must never be mutated: AppendCompound copies each element into a
// fresh TokenWithSpan, so callers never alias them.
var (
	compoundInnerJoin      = []models.Token{{Type: models.TokenTypeInner, Value: "INNER"}, {Type: models.TokenTypeJoin, Value: "JOIN"}}
	compoundLeftJoin       = []models.Token{{Type: models.TokenTypeLeft, Value: "LEFT"}, {Type: models.TokenTypeJoin, Value: "JOIN"}}
	compoundRightJoin      = []models.Token{{Type: models.TokenTypeRight, Value: "RIGHT"}, {Type: models.TokenTypeJoin, Value: "JOIN"}}
	compoundOuterJoin      = []models.Token{{Type: models.TokenTypeOuter, Value: "OUTER"}, {Type: models.TokenTypeJoin, Value: "JOIN"}}
	compoundFullJoin       = []models.Token{{Type: models.TokenTypeFull, Value: "FULL"}, {Type: models.TokenTypeJoin, Value: "JOIN"}}
	compoundCrossJoin      = []models.Token{{Type: models.TokenTypeCross, Value: "CROSS"}, {Type: models.TokenTypeJoin, Value: "JOIN"}}
	compoundOrderBy        = []models.Token{{Type: models.TokenTypeOrder, Value: "ORDER"}, {Type: models.TokenTypeBy, Value: "BY"}}
	compoundGroupBy        = []models.Token{{Type: models.TokenTypeGroup, Value: "GROUP"}, {Type: models.TokenTypeBy, Value: "BY"}}
	compoundGroupingSets   = []models.Token{{Type: models.TokenTypeGrouping, Value: "GROUPING"}, {Type: models.TokenTypeSets, Value: "SETS"}}
	compoundLeftOuterJoin  = []models.Token{{Type: models.TokenTypeLeft, Value: "LEFT"}, {Type: models.TokenTypeOuter, Value: "OUTER"}, {Type: models.TokenTypeJoin, Value: "JOIN"}}
	compoundRightOuterJoin = []models.Token{{Type: models.TokenTypeRight, Value: "RIGHT"}, {Type: models.TokenTypeOuter, Value: "OUTER"}, {Type: models.TokenTypeJoin, Value: "JOIN"}}
	compoundFullOuterJoin  = []models.Token{{Type: models.TokenTypeFull, Value: "FULL"}, {Type: models.TokenTypeOuter, Value: "OUTER"}, {Type: models.TokenTypeJoin, Value: "JOIN"}}
)

// compoundByValue maps the multi-word Value of a generic keyword token to its
// sub-token table. Matching is ASCII case-insensitive; see CompoundParts.
var compoundByValue = [...]struct {
	value string
	parts []models.Token
}{
	{"INNER JOIN", compoundInnerJoin},
	{"LEFT JOIN", compoundLeftJoin},
	{"RIGHT JOIN", compoundRightJoin},
	{"FULL JOIN", compoundFullJoin},
	{"CROSS JOIN", compoundCrossJoin},
	{"LEFT OUTER JOIN", compoundLeftOuterJoin},
	{"RIGHT OUTER JOIN", compoundRightOuterJoin},
	{"FULL OUTER JOIN", compoundFullOuterJoin},
	{"ORDER BY", compoundOrderBy},
	{"GROUP BY", compoundGroupBy},
	{"GROUPING SETS", compoundGroupingSets},
}

// CompoundParts returns the read-only sub-token table for a compound token such
// as INNER_JOIN → [INNER, JOIN], or nil if the token is not compound.
// The returned slice is shared package data and must not be modified.
func CompoundParts(t *models.TokenWithSpan) []models.Token {
	switch t.Token.Type {
	case models.TokenTypeInnerJoin:
		return compoundInnerJoin
	case models.TokenTypeLeftJoin:
		return compoundLeftJoin
	case models.TokenTypeRightJoin:
		return compoundRightJoin
	case models.TokenTypeOuterJoin:
		return compoundOuterJoin
	case models.TokenTypeFullJoin:
		return compoundFullJoin
	case models.TokenTypeCrossJoin:
		return compoundCrossJoin
	case models.TokenTypeOrderBy:
		return compoundOrderBy
	case models.TokenTypeGroupBy:
		return compoundGroupBy
	case models.TokenTypeGroupingSets:
		return compoundGroupingSets
	}

	// Value-based compound token matching. The tokenizer emits these as
	// TokenTypeKeyword whose Value keeps the source spelling ("cross join",
	// "Grouping Sets"), so the match is case-insensitive (#842). Only keyword
	// tokens qualify: a string literal such as 'CROSS JOIN' is not a join.
	if t.Token.Type != models.TokenTypeKeyword {
		return nil
	}
	v := t.Token.Value
	for i := range compoundByValue {
		if len(v) == len(compoundByValue[i].value) && strings.EqualFold(v, compoundByValue[i].value) {
			return compoundByValue[i].parts
		}
	}
	return nil
}

// CompoundPartsByKey returns the read-only sub-token table for an upper-case
// compound key with single-space separators ("GROUP BY", "LEFT OUTER JOIN"),
// or nil if key is not one. It is the lookup a tokenizer that has already
// built the upper-case key uses. The returned slice must not be modified.
func CompoundPartsByKey(key string) []models.Token {
	for i := range compoundByKey {
		if compoundByKey[i].key == key {
			return compoundByKey[i].parts
		}
	}
	return nil
}

// compoundByKey contains every key the tokenizer joins, sorted by key. It is
// separate from compoundByValue because a generic keyword "OUTER JOIN" must
// remain unsplit, while a typed OUTER_JOIN token splits.
var compoundByKey = [...]struct {
	key   string
	parts []models.Token
}{
	{"CROSS JOIN", compoundCrossJoin},
	{"FULL JOIN", compoundFullJoin},
	{"FULL OUTER JOIN", compoundFullOuterJoin},
	{"GROUP BY", compoundGroupBy},
	{"GROUPING SETS", compoundGroupingSets},
	{"INNER JOIN", compoundInnerJoin},
	{"LEFT JOIN", compoundLeftJoin},
	{"LEFT OUTER JOIN", compoundLeftOuterJoin},
	{"ORDER BY", compoundOrderBy},
	{"OUTER JOIN", compoundOuterJoin},
	{"RIGHT JOIN", compoundRightJoin},
	{"RIGHT OUTER JOIN", compoundRightOuterJoin},
}

// CompoundKeys returns a fresh, sorted copy of the tokenizer's compound keys.
func CompoundKeys() []string {
	keys := make([]string, len(compoundByKey))
	for i := range compoundByKey {
		keys[i] = compoundByKey[i].key
	}
	return keys
}
