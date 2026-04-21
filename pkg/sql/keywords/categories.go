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

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// KeywordCategory represents a category of SQL keywords mapped to their token types.
// Each category groups related keywords together (e.g., DML keywords, compound keywords).
type KeywordCategory map[string]models.TokenType

// Keywords holds all SQL keyword categories and configuration for a specific SQL dialect.
//
// This is the main structure for keyword management, containing:
//   - Keyword categorization (DML, compound keywords)
//   - Complete keyword mapping to token types
//   - Reserved keyword tracking
//   - Dialect-specific configuration
//   - Case sensitivity settings
//
// Use New() to create a properly initialized Keywords instance:
//
//	kw := keywords.New(keywords.DialectPostgreSQL, true)
type Keywords struct {
	// Keyword categories
	DMLKeywords      KeywordCategory
	CompoundKeywords KeywordCategory

	// Core keyword mapping and configuration
	keywordMap            map[string]Keyword
	reservedKeywords      map[string]bool
	compoundKeywordStarts map[string]bool // O(1) lookup for first words of compound keywords
	dialect               SQLDialect
	ignoreCase            bool

	// Conflict tracking. When trackConflicts is true, addKeywordsWithCategory
	// records any keyword collision into conflicts. New() sets this to true
	// and, once construction is complete, publishes the conflict slice to the
	// package-level lastConflicts so callers can inspect it via Conflicts().
	trackConflicts bool
	conflicts      []KeywordConflict
}

// NewKeywords creates a new Keywords instance
func NewKeywords() *Keywords {
	k := &Keywords{
		DMLKeywords:      make(KeywordCategory),
		CompoundKeywords: make(KeywordCategory),
		keywordMap:       make(map[string]Keyword),
		reservedKeywords: make(map[string]bool),
		ignoreCase:       true,
	}
	k.initialize()
	return k
}

// initialize sets up the initial keyword mappings
func (k *Keywords) initialize() {
	// Initialize DML keywords
	k.DMLKeywords = map[string]models.TokenType{
		"DISTINCT": models.TokenTypeDistinct,
		"ALL":      models.TokenTypeAll,
		"FETCH":    models.TokenTypeFetch,
		"NEXT":     models.TokenTypeNext,
		"ROWS":     models.TokenTypeRows,
		"ONLY":     models.TokenTypeOnly,
		"WITH":     models.TokenTypeWith,
		"TIES":     models.TokenTypeTies,
		"NULLS":    models.TokenTypeNulls,
		"FIRST":    models.TokenTypeFirst,
		"LAST":     models.TokenTypeLast,
		"PERCENT":  models.TokenTypePercent,  // SQL-99 FETCH ... PERCENT ROWS
		"ROLLUP":   models.TokenTypeRollup,   // SQL-99 grouping operation
		"CUBE":     models.TokenTypeCube,     // SQL-99 grouping operation
		"GROUPING": models.TokenTypeGrouping, // SQL-99 GROUPING SETS
		"SETS":     models.TokenTypeSets,     // SQL-99 GROUPING SETS
		"CAST":     models.TokenTypeCast,     // CAST expression
		"INTERVAL": models.TokenTypeInterval, // INTERVAL expression
		// Row locking keywords (SQL:2003, PostgreSQL, MySQL)
		"FOR":    models.TokenTypeFor,
		"SHARE":  models.TokenTypeShare,
		"NOWAIT": models.TokenTypeNoWait,
		"SKIP":   models.TokenTypeSkip,
		"LOCKED": models.TokenTypeLocked,
		"OF":     models.TokenTypeOf,
	}

	// Initialize compound keywords
	k.CompoundKeywords = map[string]models.TokenType{
		"FULL JOIN":     models.TokenTypeKeyword,
		"CROSS JOIN":    models.TokenTypeKeyword,
		"NATURAL JOIN":  models.TokenTypeKeyword,
		"GROUP BY":      models.TokenTypeKeyword,
		"ORDER BY":      models.TokenTypeKeyword,
		"LEFT JOIN":     models.TokenTypeKeyword,
		"GROUPING SETS": models.TokenTypeKeyword, // SQL-99 grouping operation
	}

	// Add all keywords to the main keyword map
	for word, tokenType := range k.DMLKeywords {
		k.keywordMap[word] = Keyword{
			Word:     word,
			Type:     tokenType,
			Reserved: true,
		}
		k.reservedKeywords[word] = true
	}

	for word, tokenType := range k.CompoundKeywords {
		k.keywordMap[word] = Keyword{
			Word:     word,
			Type:     tokenType,
			Reserved: true,
		}
		k.reservedKeywords[word] = true
	}
}

// IsKeyword checks if a string is a recognized SQL keyword.
// Returns true if the word is found in the keyword map, false otherwise.
//
// The check is case-insensitive when the Keywords instance was created
// with case-insensitive matching (default).
//
// Example:
//
//	kw := keywords.New(keywords.DialectGeneric, true)
//	kw.IsKeyword("SELECT")   // true
//	kw.IsKeyword("select")   // true (case-insensitive)
//	kw.IsKeyword("unknown")  // false
func (k *Keywords) IsKeyword(s string) bool {
	if k.ignoreCase {
		s = strings.ToUpper(s)
	}
	_, ok := k.keywordMap[s]
	return ok
}

// GetKeywordType returns the token type for a keyword
func (k *Keywords) GetKeywordType(s string) models.TokenType {
	if k.ignoreCase {
		s = strings.ToUpper(s)
	}
	if kw, ok := k.keywordMap[s]; ok {
		return kw.Type
	}
	return models.TokenTypeWord
}

// IsReserved checks if a keyword is reserved and cannot be used as an identifier.
// Reserved keywords include SQL statements (SELECT, INSERT), clauses (WHERE, FROM),
// and other keywords that have special meaning in SQL syntax.
//
// Example:
//
//	kw := keywords.New(keywords.DialectGeneric, true)
//	kw.IsReserved("SELECT")      // true - reserved keyword
//	kw.IsReserved("ROW_NUMBER")  // false - window function (non-reserved)
func (k *Keywords) IsReserved(s string) bool {
	if k.ignoreCase {
		s = strings.ToUpper(s)
	}
	return k.reservedKeywords[s]
}
