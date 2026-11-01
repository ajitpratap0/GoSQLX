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
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/metrics"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
	sqldialect "github.com/ajitpratap0/GoSQLX/pkg/sql/dialect"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

const (
	// MaxInputSize is the maximum allowed input size in bytes (10MB default).
	//
	// This limit prevents denial-of-service (DoS) attacks via extremely large
	// SQL queries that could exhaust server memory. Queries exceeding this size
	// will return an InputTooLargeError.
	//
	// Rationale:
	//   - 10MB is sufficient for complex SQL queries with large IN clauses
	//   - Protects against malicious or accidental memory exhaustion
	//   - Can be increased if needed for legitimate large queries
	//
	// If your application requires larger queries, consider:
	//   - Breaking queries into smaller batches
	//   - Using prepared statements with parameter binding
	//   - Increasing the limit (but ensure adequate memory protection)
	MaxInputSize = 10 * 1024 * 1024 // 10MB

	// MaxTokens is the maximum number of tokens allowed in a single SQL query
	// (1M tokens default).
	//
	// This limit prevents denial-of-service (DoS) attacks via "token explosion"
	// where maliciously crafted or accidentally generated SQL creates an excessive
	// number of tokens, exhausting CPU and memory.
	//
	// Rationale:
	//   - 1M tokens is far beyond any reasonable SQL query size
	//   - Typical queries have 10-1000 tokens
	//   - Complex queries rarely exceed 10,000 tokens
	//   - Protects against pathological cases and attacks
	//
	// Example token counts:
	//   - Simple SELECT: ~10-50 tokens
	//   - Complex query with joins: ~100-500 tokens
	//   - Large IN clause with 1000 values: ~3000-4000 tokens
	//
	// Collected comments count toward this limit as well: the number of
	// tokens plus the number of comments may not exceed MaxTokens, so an
	// input made only of comments is bounded like one made of tokens.
	//
	// If this limit is hit on a legitimate query, the query should likely
	// be redesigned for better performance and maintainability.
	MaxTokens = 1000000 // 1M tokens
)

// keywordTokenTypes maps SQL keywords to their token types for fast lookup
var keywordTokenTypes = map[string]models.TokenType{
	"SELECT":   models.TokenTypeSelect,
	"FROM":     models.TokenTypeFrom,
	"WHERE":    models.TokenTypeWhere,
	"GROUP":    models.TokenTypeGroup,
	"ORDER":    models.TokenTypeOrder,
	"HAVING":   models.TokenTypeHaving,
	"JOIN":     models.TokenTypeJoin,
	"INNER":    models.TokenTypeInner,
	"LEFT":     models.TokenTypeLeft,
	"RIGHT":    models.TokenTypeRight,
	"OUTER":    models.TokenTypeOuter,
	"ON":       models.TokenTypeOn,
	"AND":      models.TokenTypeAnd,
	"OR":       models.TokenTypeOr,
	"NOT":      models.TokenTypeNot,
	"AS":       models.TokenTypeAs,
	"BY":       models.TokenTypeBy,
	"IN":       models.TokenTypeIn,
	"LIKE":     models.TokenTypeLike,
	"ILIKE":    models.TokenTypeILike,
	"BETWEEN":  models.TokenTypeBetween,
	"IS":       models.TokenTypeIs,
	"NULL":     models.TokenTypeNull,
	"TRUE":     models.TokenTypeTrue,
	"FALSE":    models.TokenTypeFalse,
	"CASE":     models.TokenTypeCase,
	"WHEN":     models.TokenTypeWhen,
	"THEN":     models.TokenTypeThen,
	"ELSE":     models.TokenTypeElse,
	"END":      models.TokenTypeEnd,
	"CAST":     models.TokenTypeCast,
	"INTERVAL": models.TokenTypeInterval,
	"ASC":      models.TokenTypeAsc,
	"DESC":     models.TokenTypeDesc,
	"LIMIT":    models.TokenTypeLimit,
	"OFFSET":   models.TokenTypeOffset,
	"COUNT":    models.TokenTypeCount,
	// Additional Join Keywords
	"FULL":    models.TokenTypeFull,
	"CROSS":   models.TokenTypeCross,
	"USING":   models.TokenTypeUsing,
	"NATURAL": models.TokenTypeNatural,
	// CTE and Set Operations
	"WITH":      models.TokenTypeWith,
	"RECURSIVE": models.TokenTypeRecursive,
	"UNION":     models.TokenTypeUnion,
	"EXCEPT":    models.TokenTypeExcept,
	"INTERSECT": models.TokenTypeIntersect,
	"ALL":       models.TokenTypeAll,
	// Aggregate functions
	"SUM": models.TokenTypeSum,
	"AVG": models.TokenTypeAvg,
	"MIN": models.TokenTypeMin,
	"MAX": models.TokenTypeMax,
	// SQL-99 grouping operations
	"ROLLUP":   models.TokenTypeRollup,
	"CUBE":     models.TokenTypeCube,
	"GROUPING": models.TokenTypeGrouping,
	"SETS":     models.TokenTypeSets,
	// DML keywords
	"INSERT":  models.TokenTypeInsert,
	"UPDATE":  models.TokenTypeUpdate,
	"DELETE":  models.TokenTypeDelete,
	"INTO":    models.TokenTypeInto,
	"VALUES":  models.TokenTypeValues,
	"SET":     models.TokenTypeSet,
	"DEFAULT": models.TokenTypeDefault,
	// MERGE statement keywords (SQL:2003 F312)
	"MERGE":   models.TokenTypeMerge,
	"MATCHED": models.TokenTypeMatched,
	"SOURCE":  models.TokenTypeSource,
	"TARGET":  models.TokenTypeTarget,
	// DDL keywords (Phase 4 - Materialized Views & Partitioning)
	"CREATE":       models.TokenTypeCreate,
	"DROP":         models.TokenTypeDrop,
	"ALTER":        models.TokenTypeAlter,
	"TRUNCATE":     models.TokenTypeTruncate,
	"TABLE":        models.TokenTypeTable,
	"INDEX":        models.TokenTypeIndex,
	"ADD":          models.TokenTypeKeyword, // ALTER TABLE ADD
	"COLUMN":       models.TokenTypeColumn,  // ALTER TABLE ADD COLUMN
	"RENAME":       models.TokenTypeKeyword, // ALTER TABLE RENAME
	"VIEW":         models.TokenTypeView,
	"MATERIALIZED": models.TokenTypeMaterialized,
	"REFRESH":      models.TokenTypeRefresh,
	"CONCURRENTLY": models.TokenTypeKeyword, // No specific type for this
	"CASCADE":      models.TokenTypeCascade,
	"RESTRICT":     models.TokenTypeRestrict,
	"REPLACE":      models.TokenTypeReplace,
	"TEMPORARY":    models.TokenTypeKeyword, // No specific type for this
	// Note: TEMP is commonly used as identifier (e.g., CTE name "temp"), not added as keyword
	"IF":         models.TokenTypeIf,
	"EXISTS":     models.TokenTypeExists,
	"UNIQUE":     models.TokenTypeUnique,
	"PRIMARY":    models.TokenTypePrimary,
	"KEY":        models.TokenTypeKey,
	"REFERENCES": models.TokenTypeReferences,
	"FOREIGN":    models.TokenTypeForeign,
	"CHECK":      models.TokenTypeCheck,
	"CONSTRAINT": models.TokenTypeConstraint,
	"TABLESPACE": models.TokenTypeKeyword, // No specific type for this
	// Window function keywords
	"OVER":      models.TokenTypeOver,
	"PARTITION": models.TokenTypePartition,
	"ROWS":      models.TokenTypeRows,
	"RANGE":     models.TokenTypeRange,
	"UNBOUNDED": models.TokenTypeUnbounded,
	"PRECEDING": models.TokenTypePreceding,
	"FOLLOWING": models.TokenTypeFollowing,
	"CURRENT":   models.TokenTypeCurrent,
	"ROW":       models.TokenTypeRow,
	"GROUPS":    models.TokenTypeGroups,
	"FILTER":    models.TokenTypeFilter,
	"EXCLUDE":   models.TokenTypeExclude,
	// NULLS FIRST/LAST
	"NULLS": models.TokenTypeNulls,
	"FIRST": models.TokenTypeFirst,
	"LAST":  models.TokenTypeLast,
	// FETCH clause keywords (SQL:2008 standard pagination)
	"FETCH":   models.TokenTypeFetch,
	"NEXT":    models.TokenTypeNext,
	"ONLY":    models.TokenTypeOnly,
	"TIES":    models.TokenTypeTies,
	"PERCENT": models.TokenTypePercent,
	// Additional SQL Keywords
	"DISTINCT": models.TokenTypeDistinct,
	"COLLATE":  models.TokenTypeCollate,
	"TO":       models.TokenTypeKeyword, // Uses TO for RENAME TO
	// Partitioning keywords (some use generic TokenTypeKeyword)
	"LIST":     models.TokenTypeKeyword,
	"HASH":     models.TokenTypeKeyword,
	"LESS":     models.TokenTypeKeyword,
	"THAN":     models.TokenTypeKeyword,
	"MAXVALUE": models.TokenTypeKeyword,
	// PostgreSQL ARRAY constructor (SQL-99)
	"ARRAY": models.TokenTypeArray,
	// WITHIN GROUP ordered set aggregates (SQL:2003)
	"WITHIN": models.TokenTypeWithin,
	// Row locking keywords (SQL:2003, PostgreSQL, MySQL)
	"FOR":    models.TokenTypeFor,
	"SHARE":  models.TokenTypeShare,
	"NOWAIT": models.TokenTypeNoWait,
	"SKIP":   models.TokenTypeSkip,
	"LOCKED": models.TokenTypeLocked,
	"OF":     models.TokenTypeOf,
	// MySQL admin/utility keywords
	"SHOW":      models.TokenTypeShow,
	"DESCRIBE":  models.TokenTypeDescribe,
	"EXPLAIN":   models.TokenTypeExplain,
	"DATABASES": models.TokenTypeKeyword,
	"TABLES":    models.TokenTypeKeyword,
	// ClickHouse-specific clause keywords — must be in this map so the tokenizer
	// emits TokenTypeKeyword (not TokenTypeIdentifier), enabling correct clause
	// boundary detection. SETTINGS/FORMAT are common words and must NOT be here.
	"PREWHERE": models.TokenTypeKeyword,
	"FINAL":    models.TokenTypeKeyword,
	// NOTE: PIVOT/UNPIVOT are intentionally NOT in this global map.
	// They are non-reserved contextual keywords (legal identifiers in
	// PostgreSQL/MySQL/SQLite/ClickHouse), so the parser matches them
	// by value+dialect via isPivotKeyword/isUnpivotKeyword instead.
}

// Tokenizer provides high-performance SQL tokenization with zero-copy token values.
// It converts raw SQL into a stream of tokens with precise position tracking.
//
// Features:
//   - Token values and comment text are substrings of one string per call:
//     a single copy of the []byte passed to Tokenize/TokenizeContext, or the
//     caller's own string with TokenizeString/TokenizeStringContext (no copy)
//   - Word values for bare identifiers and keywords are allocated in per-call
//     chunks rather than one allocation per token
//   - Precise line/column tracking for error reporting (1-based indexing)
//   - Unicode support for international SQL queries
//   - PostgreSQL operator support (JSON, array, text search operators)
//   - DoS protection with input size and token count limits
//
// Thread Safety:
//   - Individual instances are NOT safe for concurrent use
//   - Use GetTokenizer/PutTokenizer for safe pooling across goroutines
//   - Each goroutine should use its own Tokenizer instance
//
// Memory Management:
//   - Reuses internal buffers to minimize allocations
//   - Preserves slice capacity across Reset() calls
//   - Integrates with sync.Pool for instance reuse
//   - Retaining any token Value, Word, comment Text or AST identifier keeps
//     that call's whole input string (up to MaxInputSize) and its Word chunk
//     alive. Callers that cache such values long-term should strings.Clone
//     them.
//
// Usage:
//
//	// With pooling (recommended for production)
//	tkz := GetTokenizer()
//	defer PutTokenizer(tkz)
//	tokens, err := tkz.Tokenize([]byte(sql))
//
//	// When the SQL is already a string, avoid the []byte round trip
//	tokens, err = tkz.TokenizeString(sql)
//
//	// Without pooling (simple usage)
//	tkz, _ := New()
//	tokens, err := tkz.Tokenize([]byte(sql))
type Tokenizer struct {
	// input is the SQL being scanned. For TokenizeString it is a read-only
	// view of the caller's string (see stringBytes), so the tokenizer must
	// never write to, append to or hand out input or any sub-slice of it;
	// every value it returns is a substring of src or a fresh copy.
	input []byte
	// src holds the same bytes as input, as a string, set once per call.
	// Every token Value and Comment Text is a substring of it. It is either a
	// private copy of the []byte passed to Tokenize/TokenizeContext or the
	// caller's own string for TokenizeString. Cleared by Reset.
	src string
	// wordChunk is the current slab chunk that bare-word Words are handed out
	// from (see newWord). Elements handed out are owned by the returned
	// tokens, so a chunk is never reused once Reset runs: Reset sets it to nil
	// and it is never truncated to [:0].
	wordChunk []models.Word
	// wordHint is prescan's identifier-start count, less the Word slots
	// already allocated this call. It sizes the next word chunk.
	wordHint int
	// litBuf is scratch space for the slow paths of the quoted readers, used
	// only for literals that need rewriting (escapes, doubled quotes,
	// normalized quotes, invalid UTF-8). Its contents are valid only inside
	// one reader call: every slow path ends with litBuf.String(), which
	// copies. Reset zeroes and truncates it, and drops it when it has grown
	// large.
	litBuf bytes.Buffer

	pos        Position            // Current scanning position
	lineStart  Position            // Start of current line
	lineStarts []int               // Byte offsets of line starts (for position tracking)
	line       int                 // Current line number (1-based)
	dialect    keywords.SQLDialect // SQL dialect for dialect-specific keyword recognition
	// strEscape holds the backslash rules for string literals. It stays
	// StringEscapeStrict (the zero value) until a dialect is chosen
	// explicitly: the default PostgreSQL keyword set still decodes the
	// escapes every backslash-escaping dialect agrees on, and rejects the
	// rest instead of guessing their meaning.
	strEscape sqldialect.StringEscape
	logger    *slog.Logger     // Optional structured logger for verbose tracing
	Comments  []models.Comment // Comments captured during tokenization

	// emitted is the number of tokens produced so far by the current call.
	// Together with len(Comments) it is checked against MaxTokens.
	emitted int

	// tokStart is the location of the first byte of the token being scanned,
	// after any whitespace and comments before it. Tokenize sets it before
	// calling nextToken, and nextToken moves it past comments it skips.
	tokStart models.Location

	// posCacheLine is the index into lineStarts of the line the last
	// toSQLPosition request fell on. Position requests made during
	// tokenization are mostly monotone, so lineIndexAt checks it (and the line
	// after it) before falling back to a binary search. It is only meaningful
	// for the current input/lineStarts and is reset by Reset().
	posCacheLine int

	// Forward cursor used by hasCodeBeforeOnLine so that a run of comments
	// on one line costs time linear in the line length instead of
	// rescanning the line prefix for every comment. Invalidated by Reset().
	inlLine int  // index into lineStarts of the cursor's line, plus one; 0 means unset
	inlScan int  // byte offset the line has been scanned up to
	inlCode bool // whether a non-whitespace byte was seen in [lineStart, inlScan)

	// tokBuf is the token slice of the internal scratch path (package
	// internal/tokscratch), which GoSQLX's own parse entry points use
	// because they only read the tokens until the parser has copied them.
	// It is reused across scratch calls, so its tokens are valid only until
	// the next tokenize call, Reset or PutTokenizer. The public Tokenize
	// methods never use it. INVARIANT: tokBuf[len:cap] is zero; Reset zeroes
	// [0:len) and truncates it, or drops it when it has grown past
	// maxRetainedTokBuf.
	tokBuf []models.TokenWithSpan
	// wordSlab is the Word chunk of the scratch path: scratch calls hand out
	// Words from it first instead of allocating a fresh chunk, so it carries
	// the same validity rule as tokBuf. wordSlabUsed is how many of its
	// leading elements the last scratch call handed out; Reset zeroes them.
	// INVARIANT: wordSlab[wordSlabUsed:cap] is zero.
	wordSlab     []models.Word
	wordSlabUsed int
}

// New creates a new Tokenizer with default configuration and keyword support.
// The returned tokenizer is ready to use for tokenizing SQL statements.
//
// For production use, prefer GetTokenizer() which uses object pooling for
// better performance and reduced allocations.
//
// The returned error is always nil; it is retained for API compatibility.
//
// Example:
//
//	tkz, err := tokenizer.New()
//	if err != nil {
//	    return err
//	}
//	tokens, err := tkz.Tokenize([]byte("SELECT * FROM users"))
func New() (*Tokenizer, error) {
	return &Tokenizer{
		dialect:    keywords.DialectPostgreSQL,
		pos:        NewPosition(1, 0),
		lineStarts: []int{0},
	}, nil
}

// NewWithDialect creates a new Tokenizer configured for the given SQL dialect.
// Dialect-specific keywords are recognized based on the dialect parameter.
// If dialect is empty or unknown, defaults to DialectPostgreSQL.
//
// Construction is O(1) and allocates no keyword tables: keyword
// classification uses package-level tables plus the configured dialect at
// tokenize time. The returned error is always nil; it is retained for API
// compatibility.
func NewWithDialect(dialect keywords.SQLDialect) (*Tokenizer, error) {
	t := &Tokenizer{
		pos:        NewPosition(1, 0),
		lineStarts: []int{0},
	}
	t.SetDialect(dialect)
	return t, nil
}

// Dialect returns the SQL dialect configured for this tokenizer.
func (t *Tokenizer) Dialect() keywords.SQLDialect {
	return t.dialect
}

// SetDialect reconfigures the tokenizer for a different SQL dialect.
// If dialect is empty or unknown, DialectPostgreSQL is used.
//
// SetDialect is O(1) and allocation-free; dialect-specific recognition is
// driven by the configured dialect at tokenize time.
func (t *Tokenizer) SetDialect(dialect keywords.SQLDialect) {
	if dialect == "" || dialect == keywords.DialectUnknown {
		t.dialect = keywords.DialectPostgreSQL
		t.strEscape = sqldialect.StringEscapeStrict
		return
	}
	t.dialect = dialect
	t.strEscape = sqldialect.Parse(string(dialect)).StringEscape()
}

// NewWithKeywords initializes a Tokenizer from a keyword classifier.
//
// The keywords parameter must not be nil; an error is returned if it is.
//
// Note: kw is validated but not retained or consulted. Token classification
// always uses the package-level keyword tables and the tokenizer's dialect,
// so keywords added to kw (for example via AddKeyword) do not change how
// input is tokenized. Use NewWithDialect or SetDialect to select a dialect.
//
// Example:
//
//	kw := keywords.NewKeywords()
//	tkz, err := tokenizer.NewWithKeywords(kw)
//	if err != nil {
//	    return err
//	}
func NewWithKeywords(kw *keywords.Keywords) (*Tokenizer, error) {
	if kw == nil {
		return nil, errors.InvalidSyntaxError("keywords cannot be nil", models.Location{Line: 1, Column: 1}, "")
	}

	return &Tokenizer{
		pos:        NewPosition(1, 0),
		lineStarts: []int{0},
	}, nil
}

// Tokenize converts raw SQL bytes into a slice of tokens with position information.
//
// This is the main entry point for tokenization. It copies input once into an
// internal string and returns tokens, with precise start/end positions, whose
// values are substrings of that copy. Callers that already hold the SQL as a
// string should use TokenizeString, which skips the copy.
//
// Performance: 8M+ tokens/sec sustained throughput; token values do not allocate.
//
// DoS Protection:
//   - Input size limited to MaxInputSize (10MB default)
//   - Token count limited to MaxTokens (1M default)
//   - Returns errors if limits exceeded
//
// Position Tracking:
//   - All positions are 1-based (first line is 1, first column is 1)
//   - Start position is inclusive, end position is exclusive
//   - Position information preserved for all tokens including EOF
//
// Error Handling:
//   - Returns structured errors with precise position information
//   - Common errors: UnterminatedStringError, UnexpectedCharError, InvalidNumberError
//   - Errors include line/column location and context
//
// Parameters:
//   - input: Raw SQL bytes to tokenize. Not modified; copied once into an
//     internal string. Returned tokens never alias input, so the caller may
//     reuse the buffer.
//
// Returns:
//   - []models.TokenWithSpan: Slice of tokens with position spans (includes EOF token)
//   - error: Tokenization error with position information, or nil on success
//
// Example:
//
//	tkz := GetTokenizer()
//	defer PutTokenizer(tkz)
//
//	sql := "SELECT id, name FROM users WHERE active = true"
//	tokens, err := tkz.Tokenize([]byte(sql))
//	if err != nil {
//	    log.Printf("Tokenization error at line %d: %v",
//	        err.(errors.TokenizerError).Location.Line, err)
//	    return err
//	}
//
//	for _, tok := range tokens {
//	    fmt.Printf("Token: %s (type: %v) at %d:%d\n",
//	        tok.Token.Value, tok.Token.Type,
//	        tok.Start.Line, tok.Start.Column)
//	}
//
// PostgreSQL Operators (v1.6.0):
//
//	sql := "SELECT data->'field' FROM table WHERE config @> '{\"key\":\"value\"}'"
//	tokens, _ := tkz.Tokenize([]byte(sql))
//	// Produces tokens for: -> (JSON field access), @> (JSONB contains)
//
// Unicode Support:
//
//	sql := "SELECT 名前 FROM ユーザー WHERE 'こんにちは'"
//	tokens, _ := tkz.Tokenize([]byte(sql))
//	// Correctly tokenizes Unicode identifiers and string literals
func (t *Tokenizer) Tokenize(input []byte) ([]models.TokenWithSpan, error) {
	return t.tokenize(context.Background(), input, "", false, false)
}

// TokenizeContext processes the input and returns tokens with context support for cancellation.
// It checks the context at regular intervals (every 100 tokens) to enable fast cancellation.
// Returns context.Canceled or context.DeadlineExceeded when the context is cancelled.
//
// This method is useful for:
//   - Long-running tokenization operations that need to be cancellable
//   - Implementing timeouts for tokenization
//   - Graceful shutdown scenarios
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//	tokens, err := tokenizer.TokenizeContext(ctx, []byte(sql))
//	if err == context.DeadlineExceeded {
//	    // Handle timeout
//	}
func (t *Tokenizer) TokenizeContext(ctx context.Context, input []byte) ([]models.TokenWithSpan, error) {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return t.tokenize(ctx, input, "", false, false)
}

// TokenizeString is Tokenize for SQL that is already held as a string.
//
// It has the same contract, limits, errors and output as Tokenize([]byte(s)),
// but s is not copied: the scanner reads s in place and every returned token
// Value, Word.Value and Comment.Text is a substring of s. Retaining any of them
// keeps s alive; strings.Clone values that must outlive s's other uses.
//
// String literal and quoted identifier values are substrings of s too, unless
// their content held an escape sequence, a doubled quote, a Unicode quote that
// is normalized, or invalid UTF-8; those values are fresh strings.
//
// Example:
//
//	tkz := GetTokenizer()
//	defer PutTokenizer(tkz)
//	tokens, err := tkz.TokenizeString("SELECT id FROM users")
func (t *Tokenizer) TokenizeString(s string) ([]models.TokenWithSpan, error) {
	return t.tokenize(context.Background(), stringBytes(s), s, true, false)
}

// TokenizeStringContext is TokenizeContext for SQL that is already held as a
// string. It checks ctx before starting and every 100 tokens, returning
// ctx.Err() when the context is done. As with TokenizeString, s is not copied
// and every returned Value, Word.Value and Comment.Text aliases s, except
// literal and quoted-identifier values that had to be rewritten (escapes,
// doubled quotes, normalized Unicode quotes, invalid UTF-8).
func (t *Tokenizer) TokenizeStringContext(ctx context.Context, s string) ([]models.TokenWithSpan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return t.tokenize(ctx, stringBytes(s), s, true, false)
}

// load resets t and installs the input for one call. Invariant: t.src and
// t.input hold the same bytes for the whole call.
func (t *Tokenizer) load(input []byte, src string) {
	t.Reset()
	t.input = input
	t.src = src

	// Pre-allocate line starts slice - reuse if possible
	estimatedLines := len(input)/50 + 1 // Estimate 50 chars per line + 1 for initial 0
	if cap(t.lineStarts) < estimatedLines {
		t.lineStarts = make([]int, 0, estimatedLines)
	} else {
		t.lineStarts = t.lineStarts[:0]
	}
	t.lineStarts = append(t.lineStarts, 0)
}

// tokenize is the shared core of Tokenize, TokenizeContext, TokenizeString
// and TokenizeStringContext. When haveSrc is false, src is ignored and input
// is copied once into a string after the size check, so returned tokens never
// alias the caller's buffer. When haveSrc is true, input must be a read-only
// view of src.
//
// ctx is checked every 100 tokens unless ctx.Done() is nil (as for
// context.Background()), in which case no per-token check is made.
//
// When scratch is false the returned slice is freshly allocated and owned by
// the caller. When scratch is true (the internal tokscratch path) it is built
// in t.tokBuf and stays owned by t; see tokBuf.
func (t *Tokenizer) tokenize(ctx context.Context, input []byte, src string, haveSrc, scratch bool) ([]models.TokenWithSpan, error) {
	// Record start time for metrics
	startTime := time.Now()

	// Validate input size to prevent DoS attacks. This must stay ahead of the
	// string copy below so an oversized input is rejected before it is copied.
	if len(input) > MaxInputSize {
		err := errors.InputTooLargeError(int64(len(input)), MaxInputSize, models.Location{Line: 1, Column: 1})
		metrics.RecordTokenization(time.Since(startTime), len(input), err)
		return nil, err
	}

	if !haveSrc {
		src = string(input)
	}
	t.load(input, src)

	// Pre-scan input to build line start indices and estimate token count
	estimatedTokens := t.prescan()

	// A leading UTF-8 byte order mark (U+FEFF) is not part of the SQL: files
	// saved by Windows editors start with one. Start after it and make the
	// first line begin there so columns count from the first real character.
	if len(input) >= 3 && input[0] == 0xEF && input[1] == 0xBB && input[2] == 0xBF {
		t.pos.Index = 3
		t.lineStarts[0] = 3
	}

	var tokens []models.TokenWithSpan
	if scratch {
		// load ran Reset, so tokBuf and wordSlab are empty and all zero.
		if cap(t.tokBuf) >= estimatedTokens {
			tokens = t.tokBuf[:0]
		} else {
			tokens = make([]models.TokenWithSpan, 0, estimatedTokens)
		}
		t.useWordSlab()
	} else {
		tokens = make([]models.TokenWithSpan, 0, estimatedTokens)
	}

	done := ctx.Done()

	var tokenErr error
	func() {
		// Ensure proper cleanup even if we panic
		defer func() {
			if r := recover(); r != nil {
				tokenErr = errors.TokenizerPanicError(r, t.getCurrentPosition())
			}
		}()

		for t.pos.Index < len(t.input) {
			// Check context every 100 tokens for cancellation
			if done != nil && len(tokens)%100 == 0 {
				if err := ctx.Err(); err != nil {
					tokenErr = err
					return
				}
			}

			t.skipWhitespace()

			if t.pos.Index >= len(t.input) {
				break
			}

			// Check token count limit to prevent DoS attacks. Collected
			// comments count toward the same limit.
			if n := len(tokens) + len(t.Comments); n >= MaxTokens {
				tokenErr = errors.TokenLimitReachedError(n+1, MaxTokens, t.getCurrentPosition(), t.src)
				return
			}
			t.emitted = len(tokens)

			// Compute the start location before scanning so position requests
			// stay monotone. nextToken replaces it when it skips comments, so
			// that Start always addresses the token and not the trivia before it.
			t.tokStart = t.toSQLPosition(t.pos)

			token, err := t.nextToken()
			if err != nil {
				// nextToken returns structured errors, pass through directly
				tokenErr = err
				return
			}

			tw := models.TokenWithSpan{
				Token: token,
				Start: t.tokStart,
				End:   t.getCurrentPosition(),
			}
			if t.logger != nil && t.logger.Enabled(context.Background(), slog.LevelDebug) {
				t.logger.LogAttrs(context.Background(), slog.LevelDebug, "token",
					slog.String("type", fmt.Sprintf("%T", token)),
					slog.Int("start_line", int(tw.Start.Line)),
					slog.Int("start_col", int(tw.Start.Column)),
				)
			}
			tokens = append(tokens, tw)
		}
	}()

	if scratch {
		// Keep the slice, partial or not, so the next Reset zeroes it and
		// the next scratch call can reuse it.
		t.tokBuf = tokens
		t.noteWordSlabUse()
	}

	if tokenErr != nil {
		// Record metrics for failed tokenization
		duration := time.Since(startTime)
		metrics.RecordTokenization(duration, len(input), tokenErr)
		return nil, tokenErr
	}

	// Add EOF token
	tokens = append(tokens, models.TokenWithSpan{
		Token: models.Token{Type: models.TokenTypeEOF},
		Start: t.getCurrentPosition(),
		End:   t.getCurrentPosition(),
	})
	if scratch {
		t.tokBuf = tokens
		t.noteWordSlabUse()
	}

	// Record metrics for successful tokenization
	duration := time.Since(startTime)
	metrics.RecordTokenization(duration, len(input), nil)

	return tokens, nil
}

// tokenBoundary marks ASCII bytes that always end the lexeme before them and
// (except whitespace) form a token of their own or start a punctuation/operator
// token. It is used only by prescan to estimate the token count.
var tokenBoundary = func() (tbl [256]bool) {
	for _, c := range []byte(" \t\n\r,()[];.=<>+-*/%|&!^~:?") {
		tbl[c] = true
	}
	return tbl
}()

// minTokenCapacity is the floor for the token slice capacity estimate.
const minTokenCapacity = 16

// prescan walks t.input once, recording the byte offset after every newline in
// t.lineStarts (which must already hold the initial 0) and returning a capacity
// estimate for the token slice.
//
// The estimate counts word ends (a run of non-boundary bytes followed by a
// boundary byte or end of input) plus every non-whitespace boundary byte, plus
// one for the EOF token. Every token the scanner can emit contains at least one
// word end or one boundary byte, so the estimate is an upper bound on the token
// count in practice: multi-character operators, numeric literals with a '.',
// quoted strings containing spaces and comments all count high, never low.
// Measured on the testdata corpus and the dense benchmark inputs the estimate
// is within 1-11% of the real count on dense SQL and ~1.5x on typical SQL,
// against 1.25-2x regrowth (dense) or ~1.9x over-allocation (typical) for the
// previous len/4 guess. The estimate is capped at MaxTokens+1 so a pathological
// input cannot pre-allocate more than the scanner would have grown to anyway.
//
// prescan also counts words that start like an identifier (an ASCII letter,
// '_' or a non-ASCII byte) into t.wordHint, which sizes the Word chunks (see
// nextWordChunk). Words inside comments and string literals are counted too,
// so the hint can run high; nextWordChunk caps how much of it is trusted.
func (t *Tokenizer) prescan() int {
	est := 1 // EOF token
	words := 0
	inWord := false
	for i := 0; i < len(t.input); i++ {
		b := t.input[i]
		if !tokenBoundary[b] {
			if !inWord && (b >= utf8.RuneSelf || b == '_' || (b|0x20 >= 'a' && b|0x20 <= 'z')) {
				words++
			}
			inWord = true
			continue
		}
		if inWord {
			est++
			inWord = false
		}
		switch b {
		case '\n':
			t.lineStarts = append(t.lineStarts, i+1)
		case ' ', '\t', '\r':
		default:
			est++
		}
	}
	if inWord {
		est++
	}
	t.wordHint = words
	if est < minTokenCapacity {
		est = minTokenCapacity
	}
	if est > MaxTokens+1 {
		est = MaxTokens + 1
	}
	return est
}

// Word chunk sizing for newWord.
const (
	// minWordChunk is the smallest chunk allocated.
	minWordChunk = 4
	// firstWordChunkMax caps the first chunk of a call. The prescan hint also
	// counts words inside comments and string literals, so this bounds the
	// waste (64 Words, about 2 KB) when the hint over-counts.
	firstWordChunkMax = 64
	// maxWordChunk caps later chunks.
	maxWordChunk = 4096
)

// newWord returns a Word for a bare identifier or keyword, carved from the
// current per-call chunk. The append below never reallocates (len < cap), so
// pointers already handed out stay valid; a full chunk is replaced, never
// reused, and Reset drops the reference without truncating it.
func (t *Tokenizer) newWord(v string) *models.Word {
	if len(t.wordChunk) == cap(t.wordChunk) {
		t.nextWordChunk()
	}
	t.wordChunk = append(t.wordChunk, models.Word{Value: v})
	return &t.wordChunk[len(t.wordChunk)-1]
}

// nextWordChunk replaces the full current chunk with a new one sized from
// t.wordHint, the number of words prescan expects that have not yet been
// given chunk space. A chunk is at most twice the previous one, so an
// over-counted hint wastes at most about as many Words as were handed out;
// when the hint runs out (an under-count), chunks keep doubling.
func (t *Tokenizer) nextWordChunk() {
	prev := cap(t.wordChunk)
	n := t.wordHint
	if prev == 0 {
		n = min(n, firstWordChunkMax)
	} else if n <= 0 || n > 2*prev {
		n = 2 * prev
	}
	n = max(minWordChunk, min(n, maxWordChunk))
	t.wordHint = max(0, t.wordHint-n)
	t.wordChunk = make([]models.Word, 0, n)
}

// maxRetainedWordSlab is the largest wordSlab capacity (in Words, 32 B each
// on 64-bit platforms, so 128 KiB) the scratch path keeps.
const maxRetainedWordSlab = 4096

// useWordSlab makes the retained wordSlab the first Word chunk of a scratch
// call, first growing it to prescan's word hint when that fits under
// maxRetainedWordSlab. Words beyond the slab come from nextWordChunk as usual.
// It must run after prescan and before the first newWord.
func (t *Tokenizer) useWordSlab() {
	if need := t.wordHint; cap(t.wordSlab) < need && need <= maxRetainedWordSlab {
		t.wordSlab = make([]models.Word, 0, need)
	}
	if c := cap(t.wordSlab); c > 0 {
		t.wordChunk = t.wordSlab[:0]
		t.wordHint = max(0, t.wordHint-c)
	}
}

// noteWordSlabUse records in wordSlabUsed how much of wordSlab the current
// scratch call handed out, so Reset zeroes exactly that prefix. The slab is
// either still the current chunk or was filled before a later chunk replaced
// it.
func (t *Tokenizer) noteWordSlabUse() {
	c := cap(t.wordSlab)
	if c == 0 {
		return
	}
	if cap(t.wordChunk) == c && unsafe.SliceData(t.wordChunk) == unsafe.SliceData(t.wordSlab) {
		t.wordSlabUsed = len(t.wordChunk)
	} else {
		t.wordSlabUsed = c
	}
}

// skipWhitespace advances past any whitespace
// Optimized with ASCII fast-path since >99% of SQL whitespace is ASCII
func (t *Tokenizer) skipWhitespace() {
	for t.pos.Index < len(t.input) {
		b := t.input[t.pos.Index]
		// Fast path: ASCII whitespace (covers >99% of cases)
		if b < 128 {
			switch b {
			case ' ', '\t', '\r':
				t.pos.Index++
				t.pos.Column++
				continue
			case '\n':
				t.pos.Index++
				t.pos.Line++
				t.pos.Column = 0
				continue
			}
			// Not whitespace, exit
			break
		}
		// Slow path: UTF-8 encoded character (rare in SQL)
		r, size := utf8.DecodeRune(t.input[t.pos.Index:])
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			t.pos.AdvanceRune(r, size)
			continue
		}
		break
	}
}

// nextToken picks out the next token from the input.
//
// Comments are recorded in t.Comments and skipped, together with the
// whitespace after them, in a loop until a token or the end of input is
// reached. Skipping iteratively keeps stack usage constant however many
// comments appear in a row.
func (t *Tokenizer) nextToken() (models.Token, error) {
	for {
		if t.pos.Index >= len(t.input) {
			return models.Token{Type: models.TokenTypeEOF}, nil
		}

		// Fast path for common cases
		r, _ := utf8.DecodeRune(t.input[t.pos.Index:])
		switch {
		case isIdentifierStart(r):
			return t.readIdentifier()
		case r >= '0' && r <= '9':
			return t.readNumber(nil)
		case r == '"' || isUnicodeQuote(r):
			return t.readQuotedIdentifier()
		case r == '`':
			// MySQL-style backtick identifier
			return t.readBacktickIdentifier()
		case r == '\'' || r == '\u2018' || r == '\u2019' || r == '\u00AB' || r == '\u00BB':
			return t.readQuotedString(r)
		}

		// Comments: "--" (and MySQL/MariaDB "#") to end of line, "/*" to "*/".
		if r == '#' && (t.dialect == keywords.DialectMySQL || t.dialect == keywords.DialectMariaDB) {
			if err := t.skipLineComment(1); err != nil {
				return models.Token{}, err
			}
			t.skipWhitespace()
			t.tokStart = t.toSQLPosition(t.pos)
			continue
		}
		if (r == '-' || r == '/') && t.pos.Index+1 < len(t.input) {
			next := t.input[t.pos.Index+1]
			if r == '-' && next == '-' {
				if err := t.skipLineComment(2); err != nil {
					return models.Token{}, err
				}
				t.skipWhitespace()
				t.tokStart = t.toSQLPosition(t.pos)
				continue
			}
			if r == '/' && next == '*' {
				if err := t.skipBlockComment(); err != nil {
					return models.Token{}, err
				}
				t.skipWhitespace()
				t.tokStart = t.toSQLPosition(t.pos)
				continue
			}
		}

		// Slower path for punctuation and operators
		return t.readPunctuation()
	}
}

// skipLineComment consumes a line comment starting at t.pos whose opener is
// openerLen bytes long ("--" is 2, the MySQL/MariaDB "#" is 1), up to and
// including the next newline (or to the end of input), and records it in
// t.Comments. The recorded text excludes the trailing newline. It returns a
// token-limit error when the comment would exceed MaxTokens.
func (t *Tokenizer) skipLineComment(openerLen int) error {
	if err := t.commentLimitError(); err != nil {
		return err
	}
	commentStartIdx := t.pos.Index
	commentStartPos := t.toSQLPosition(t.pos)
	t.pos.Index += openerLen
	t.pos.Column += openerLen
	// Skip until end of line or EOF
	for t.pos.Index < len(t.input) {
		cr, csize := utf8.DecodeRune(t.input[t.pos.Index:])
		t.pos.AdvanceRune(cr, csize)
		if cr == '\n' {
			break // the newline is consumed too
		}
	}
	textEnd := t.pos.Index
	if textEnd > 0 && t.input[textEnd-1] == '\n' {
		textEnd--
	}
	t.Comments = append(t.Comments, models.Comment{
		Text:   t.src[commentStartIdx:textEnd],
		Style:  models.LineComment,
		Start:  commentStartPos,
		End:    t.toSQLPosition(t.pos),
		Inline: t.hasCodeBeforeOnLine(commentStartIdx),
	})
	return nil
}

// commentLimitError returns a token-limit error, located at the current
// position, when recording one more comment would bring the number of tokens
// plus comments of the current call past MaxTokens; otherwise nil.
func (t *Tokenizer) commentLimitError() error {
	if n := t.emitted + len(t.Comments); n >= MaxTokens {
		return errors.TokenLimitReachedError(n+1, MaxTokens, t.getCurrentPosition(), t.src)
	}
	return nil
}

// skipBlockComment consumes a "/* ... */" comment starting at t.pos and
// records it in t.Comments. Block comments do not nest. It returns an
// unterminated-comment error when no closing "*/" follows, and a token-limit
// error when the comment would exceed MaxTokens.
func (t *Tokenizer) skipBlockComment() error {
	if err := t.commentLimitError(); err != nil {
		return err
	}
	commentStartIdx := t.pos.Index
	commentStartPos := t.toSQLPosition(t.pos)
	t.pos.Index += 2 // "/*"
	t.pos.Column += 2
	// Skip until */ or EOF
	closed := false
	for t.pos.Index < len(t.input) {
		cr, csize := utf8.DecodeRune(t.input[t.pos.Index:])
		t.pos.AdvanceRune(cr, csize)
		if cr == '*' && t.pos.Index < len(t.input) && t.input[t.pos.Index] == '/' {
			t.pos.AdvanceRune('/', 1) // End of block comment
			closed = true
			break
		}
	}
	if !closed {
		return errors.UnterminatedBlockCommentError(commentStartPos, t.src)
	}
	t.Comments = append(t.Comments, models.Comment{
		Text:   t.src[commentStartIdx:t.pos.Index],
		Style:  models.BlockComment,
		Start:  commentStartPos,
		End:    t.toSQLPosition(t.pos),
		Inline: t.hasCodeBeforeOnLine(commentStartIdx),
	})
	return nil
}

// isIdentifierStart checks if a rune can start an identifier
func isIdentifierStart(r rune) bool {
	return isUnicodeIdentifierStart(r)
}

// readIdentifier reads an identifier (e.g. foo or foo.bar)
func (t *Tokenizer) readIdentifier() (models.Token, error) {
	if (t.input[t.pos.Index] == 'U' || t.input[t.pos.Index] == 'u') && t.pos.Index+2 < len(t.input) &&
		t.input[t.pos.Index+1] == '&' && (t.input[t.pos.Index+2] == '\'' || t.input[t.pos.Index+2] == '"') {
		switch t.dialect {
		case keywords.DialectPostgreSQL:
			return t.readUnicodeEscape()
		case keywords.DialectOracle, keywords.DialectSnowflake, keywords.DialectClickHouse:
			// These dialects have neither U& literals nor an & operator, so
			// U&'...' cannot be read as U & '...' (formatting would turn it
			// into BITAND(U, '...') or bitAnd(U, '...')).
			return models.Token{}, errors.NewError(errors.ErrCodeUnsupportedFeature,
				"unsupported feature: U& Unicode escape literals in "+string(t.dialect), t.toSQLPosition(t.pos)).
				WithContext(t.src, 2).
				WithHint("U&'...' is PostgreSQL syntax; write the characters directly")
		}
	}
	start := t.pos.Index
	r, size := utf8.DecodeRune(t.input[t.pos.Index:])
	t.pos.AdvanceRune(r, size)

	// Read until we hit a non-identifier character
	t.scanIdentifierTail()

	ident := t.src[start:t.pos.Index]

	// Prefixed string literal: N'..', X'..', B'..', E'..', q'[..]' (see
	// prefixed_string.go). Only a single letter directly followed by a quote
	// qualifies.
	if len(ident) == 1 && t.pos.Index < len(t.input) && t.input[t.pos.Index] == '\'' {
		if tok, ok, err := t.readPrefixedString(ident[0]); ok || err != nil {
			return tok, err
		}
	}

	word := t.newWord(ident)

	// Determine token type based on whether it's a keyword. Pure-ASCII words
	// are upper-cased into a stack buffer and the maps are indexed with
	// m[string(b)], which the compiler performs without allocating. The
	// string(kbuf[:n]) conversions below must stay inline in the index
	// expressions; assigning them to a variable would force an allocation.
	var kbuf [keywordKeyBufLen]byte
	var tokenType models.TokenType
	isKeyword, compoundStart := false, false
	kh, kok := uint32(0), false
	if len(ident) <= keywordKeyBufLen {
		kh, kok = asciiUpperHash(kbuf[:len(ident)], ident)
	}
	switch {
	case kok:
		if e := kwLookup(kh, kbuf[:len(ident)]); e != nil {
			tokenType, isKeyword, compoundStart = e.typ, e.isKeyword, e.compoundStart
		}
	case isASCII(ident):
		// Pure-ASCII word longer than any keyword: cannot match.
	default:
		// Non-ASCII word: keep Unicode case mapping so that, for example,
		// U+017F (long s) folds to 'S' and U+0131 (dotless i) folds to 'I'
		// exactly as strings.ToUpper does.
		upper := strings.ToUpper(ident)
		tokenType, isKeyword = keywordTokenTypes[upper]
		compoundStart = compoundKeywordStarts[upper]
	}
	if !isKeyword {
		tokenType = models.TokenTypeIdentifier
	}

	// Check if this could be the start of a compound keyword
	if compoundStart {
		// Save current position
		savePos := t.pos.Clone()

		// Skip whitespace
		t.skipWhitespace()

		if t.pos.Index < len(t.input) {
			// Try to read the next word
			nextStart := t.pos.Index
			r, size := utf8.DecodeRune(t.input[t.pos.Index:])
			if isIdentifierStart(r) {
				t.pos.AdvanceRune(r, size)

				// Read until we hit a non-identifier character
				t.scanIdentifierTail()

				nextIdent := t.src[nextStart:t.pos.Index]

				// Check if it's a valid compound keyword. The key is built in
				// the stack buffer; the joined Value string is only allocated
				// on a hit.
				var compoundType models.TokenType
				matched := false
				n := len(ident) + 1 + len(nextIdent)
				if n <= keywordKeyBufLen &&
					asciiUpper(kbuf[:len(ident)], ident) &&
					asciiUpper(kbuf[len(ident)+1:n], nextIdent) {
					kbuf[len(ident)] = ' '
					compoundType, matched = compoundKeywordTypes[string(kbuf[:n])]
				} else if !isASCII(ident) || !isASCII(nextIdent) {
					compoundType, matched = compoundKeywordTypes[strings.ToUpper(ident+" "+nextIdent)]
				}
				// Otherwise: pure-ASCII pair longer than any compound key, no match.

				if matched {
					// Exactly one ASCII space between the words: the joined
					// Value is already a substring of the input. Otherwise
					// normalize the separator to a single space.
					var value string
					if sep := start + len(ident); nextStart == sep+1 && t.input[sep] == ' ' {
						value = t.src[start:t.pos.Index]
					} else {
						value = ident + " " + nextIdent
					}
					return models.Token{
						Type:  compoundType,
						Word:  word,
						Value: value,
					}, nil
				}
			}
		}

		// Not a compound keyword, restore position
		t.pos = savePos
	}

	return models.Token{
		Type:  tokenType,
		Word:  word,
		Value: ident,
	}, nil
}

// compoundKeywordStarts is a set of keywords that can start compound keywords
var compoundKeywordStarts = map[string]bool{
	"GROUP":    true,
	"ORDER":    true,
	"LEFT":     true,
	"RIGHT":    true,
	"INNER":    true,
	"OUTER":    true,
	"CROSS":    true,
	"NATURAL":  true,
	"FULL":     true,
	"GROUPING": true, // For GROUPING SETS
}

// compoundKeywordTypes maps compound SQL keywords to their token types
var compoundKeywordTypes = map[string]models.TokenType{
	"GROUP BY":         models.TokenTypeGroupBy,
	"ORDER BY":         models.TokenTypeOrderBy,
	"LEFT JOIN":        models.TokenTypeLeftJoin,
	"RIGHT JOIN":       models.TokenTypeRightJoin,
	"INNER JOIN":       models.TokenTypeInnerJoin,
	"OUTER JOIN":       models.TokenTypeOuterJoin,
	"FULL JOIN":        models.TokenTypeKeyword,
	"CROSS JOIN":       models.TokenTypeKeyword,
	"LEFT OUTER JOIN":  models.TokenTypeKeyword,
	"RIGHT OUTER JOIN": models.TokenTypeKeyword,
	"FULL OUTER JOIN":  models.TokenTypeKeyword,
	"GROUPING SETS":    models.TokenTypeKeyword, // SQL-99 grouping operation
}

// keywordKeyBufLen is the size of the stack buffer used to build upper-cased
// keyword lookup keys. It relies on these invariants: the longest key in
// keywordTokenTypes is 12 bytes, the longest in compoundKeywordStarts is 8,
// the longest in compoundKeywordTypes is 16, and all keys are ASCII. ASCII
// upper-casing preserves length, so a pure-ASCII word (or compound pair)
// longer than the buffer can never match a key.
const keywordKeyBufLen = 32

// asciiUpper writes the ASCII upper-case form of s into dst and reports
// whether s was pure ASCII. The caller guarantees len(dst) >= len(s). dst is
// not retained, so the caller's array can stay on the stack. If it returns
// false, dst contents are unspecified.
func asciiUpper(dst []byte, s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= utf8.RuneSelf {
			return false
		}
		if 'a' <= c && c <= 'z' {
			c -= 'a' - 'A'
		}
		dst[i] = c
	}
	return true
}

// isASCII reports whether s contains only ASCII bytes.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// backslashEscapes reports whether '\' starts an escape sequence inside a
// quoted string in the configured dialect. PostgreSQL (standard strings),
// Oracle, SQLite and SQL Server treat '\' as an ordinary character; every
// other dialect, and an unconfigured tokenizer, decodes C-style escapes (see
// sqldialect.StringEscape). Both the fast and slow string scanners use this
// predicate so they cannot drift apart.
func (t *Tokenizer) backslashEscapes() bool {
	return t.strEscape != sqldialect.StringEscapeNone
}

// needsRewrite reports whether the slow quoted readers would write a rune
// other than the one decoded from the source: invalid UTF-8 (written as
// U+FFFD) or a Unicode quote that normalizeQuote rewrites. Only non-ASCII
// runes can need a rewrite.
func needsRewrite(r rune, size int) bool {
	return (r == utf8.RuneError && size == 1) || normalizeQuote(r) != r
}

// nextRuneIsQuote reports whether b starts with a rune that normalizes to
// quote, i.e. whether a quote just scanned is the first half of a doubled
// (escaped) quote. In strict mode (a token opened with an ASCII quote) only
// that ASCII quote counts.
func nextRuneIsQuote(b []byte, quote rune, strict bool) bool {
	if strict {
		return len(b) > 0 && rune(b[0]) == quote
	}
	r, _ := utf8.DecodeRune(b)
	return normalizeQuote(r) == quote
}

// quotedRune returns the rune a quoted reader acts on for the decoded rune r.
// A token opened with a Unicode quote (strict false) normalizes every Unicode
// quote to its ASCII form, so a smart quote may close or escape it. A token
// opened with an ASCII quote (strict true) is closed and escaped only by that
// ASCII quote: Unicode quotes inside it are ordinary content and kept as is,
// so a value such as x”; DROP TABLE t; --“ written inside "..." re-reads as
// one identifier (#632).
func quotedRune(r rune, strict bool) rune {
	if strict {
		return r
	}
	return normalizeQuote(r)
}

// readQuotedIdentifier reads something like "MyColumn" with support for Unicode quotes.
//
// An identifier whose content holds no doubled quote, rewritten Unicode
// quote or invalid UTF-8 is returned as a substring of the input (#548).
// Anything else, including every error, is handled by
// readQuotedIdentifierSlow from the same position.
func (t *Tokenizer) readQuotedIdentifier() (models.Token, error) {
	// Get and normalize opening quote
	r, size := utf8.DecodeRune(t.input[t.pos.Index:])
	quote := normalizeQuote(r)
	startPos := t.pos.Clone()

	// Skip opening quote
	t.pos.AdvanceRune(r, size)

	if v, p, ok := t.scanQuotedIdentFast(quote, r == quote); ok {
		t.pos = p
		word := t.newWord(v)
		word.QuoteStyle = quote
		// Double-quoted strings are identifiers in SQL
		return models.Token{
			Type:  models.TokenTypeDoubleQuotedString,
			Word:  word,
			Value: v,
			Quote: quote,
		}, nil
	}
	return t.readQuotedIdentifierSlow(startPos, r)
}

// scanQuotedIdentFast scans a quoted identifier's content from t.pos on a
// copy of the position. On a clean identifier it returns the content as a
// substring of t.src and the position just past the closing quote, matching
// readQuotedIdentifierSlow exactly. It returns ok=false, without touching
// t.pos, at the first doubled quote, rewritten rune, newline or at EOF.
// strict reports that the identifier was opened with an ASCII quote (see
// quotedRune).
func (t *Tokenizer) scanQuotedIdentFast(quote rune, strict bool) (string, Position, bool) {
	p := t.pos
	in := t.input
	start := p.Index
	for p.Index < len(in) {
		r, size := rune(in[p.Index]), 1
		if r >= utf8.RuneSelf {
			r, size = utf8.DecodeRune(in[p.Index:])
			if strict {
				if r == utf8.RuneError && size == 1 {
					return "", p, false
				}
			} else if needsRewrite(r, size) {
				if normalizeQuote(r) != quote {
					return "", p, false
				}
				r = quote
			}
		}
		if r == quote {
			if p.Index+size < len(in) && nextRuneIsQuote(in[p.Index+size:], quote, strict) {
				return "", p, false
			}
			end := p.Index
			p.Index += size
			p.Column++
			return t.src[start:end], p, true
		}
		if r == '\n' {
			return "", p, false
		}
		p.Index += size
		p.Column++
	}
	return "", p, false
}

// readQuotedIdentifierSlow is the reference quoted-identifier reader. It
// continues from t.pos (just past the opening quote) and builds the value in
// t.litBuf, applying doubled-quote escapes and rune normalization.
//
// opener is the rune that opened the identifier; when it is the ASCII quote
// itself the identifier is read in strict mode (see quotedRune).
func (t *Tokenizer) readQuotedIdentifierSlow(startPos Position, opener rune) (models.Token, error) {
	quote := normalizeQuote(opener)
	strict := opener == quote
	buf := &t.litBuf
	buf.Reset()
	for t.pos.Index < len(t.input) {
		r, size := utf8.DecodeRune(t.input[t.pos.Index:])
		r = quotedRune(r, strict)

		if r == quote {
			// Check for escaped quote
			if t.pos.Index+size < len(t.input) {
				nextR, nextSize := utf8.DecodeRune(t.input[t.pos.Index+size:])
				nextR = quotedRune(nextR, strict)
				if nextR == quote {
					// Include one quote and skip the other
					buf.WriteRune(r)
					t.pos.Index += size + nextSize
					t.pos.Column += 2
					continue
				}
			}

			// End of quoted identifier
			t.pos.Index += size
			t.pos.Column++

			value := buf.String()
			word := t.newWord(value)
			word.QuoteStyle = quote

			// Double-quoted strings are identifiers in SQL
			return models.Token{
				Type:  models.TokenTypeDoubleQuotedString,
				Word:  word,
				Value: value,
				Quote: quote,
			}, nil
		}

		if r == '\n' {
			return models.Token{}, errors.UnterminatedStringError(
				t.toSQLPosition(startPos),
				t.src,
			)
		}

		// Handle regular characters
		buf.WriteRune(r)
		t.pos.Index += size
		t.pos.Column++
	}

	return models.Token{}, errors.UnterminatedStringError(
		t.toSQLPosition(startPos),
		t.src,
	)
}

// readBacktickIdentifier reads MySQL-style backtick identifiers.
//
// An identifier with no doubled backtick is returned as a substring of the
// input (#548); otherwise, and on every error, readBacktickIdentifierSlow
// runs from the same position.
func (t *Tokenizer) readBacktickIdentifier() (models.Token, error) {
	startPos := t.pos.Clone()

	// Skip opening backtick
	t.pos.Index++
	t.pos.Column++

	if v, p, ok := t.scanBacktickFast(); ok {
		t.pos = p
		return models.Token{
			Type:  models.TokenTypeIdentifier, // Backtick identifiers are identifiers
			Value: v,
		}, nil
	}
	return t.readBacktickIdentifierSlow(startPos)
}

// scanBacktickFast scans a backtick identifier's content byte by byte on a
// copy of t.pos, with the same per-byte position accounting as
// readBacktickIdentifierSlow (which copies bytes raw, so invalid UTF-8 needs
// no fallback). It returns ok=false at a doubled backtick or at EOF.
func (t *Tokenizer) scanBacktickFast() (string, Position, bool) {
	p := t.pos
	in := t.input
	start := p.Index
	for p.Index < len(in) {
		ch := in[p.Index]
		if ch == '`' {
			if p.Index+1 < len(in) && in[p.Index+1] == '`' {
				return "", p, false
			}
			end := p.Index
			p.Index++
			p.Column++
			return t.src[start:end], p, true
		}
		if ch == '\n' {
			p.Line++
			p.Column = 1
		} else {
			p.Column++
		}
		p.Index++
	}
	return "", p, false
}

// readBacktickIdentifierSlow is the reference backtick reader. It continues
// from t.pos (just past the opening backtick) and builds the value in
// t.litBuf.
func (t *Tokenizer) readBacktickIdentifierSlow(startPos Position) (models.Token, error) {
	buf := &t.litBuf
	buf.Reset()
	for t.pos.Index < len(t.input) {
		ch := t.input[t.pos.Index]

		if ch == '`' {
			// Check for escaped backtick
			if t.pos.Index+1 < len(t.input) && t.input[t.pos.Index+1] == '`' {
				// Include one backtick and skip the other
				buf.WriteByte('`')
				t.pos.Index += 2
				t.pos.Column += 2
				continue
			}

			// End of backtick identifier
			t.pos.Index++
			t.pos.Column++

			return models.Token{
				Type:  models.TokenTypeIdentifier, // Backtick identifiers are identifiers
				Value: buf.String(),
			}, nil
		}

		if ch == '\n' {
			t.pos.Line++
			t.pos.Column = 1
		} else {
			t.pos.Column++
		}

		buf.WriteByte(ch)
		t.pos.Index++
	}

	return models.Token{}, errors.UnterminatedStringError(
		t.toSQLPosition(startPos),
		t.src,
	)
}

// readQuotedString handles the actual scanning of a single/double-quoted string.
//
// A literal whose content holds no doubled quote, escaping backslash,
// rewritten Unicode quote or invalid UTF-8 is returned as a substring of the
// input (#548). Anything else, including every error, is handled by
// readQuotedStringSlow from the same position.
func (t *Tokenizer) readQuotedString(quote rune) (models.Token, error) {
	// Store start position for error reporting
	startPos := t.pos

	// Check for triple quotes. Only BigQuery has triple-quoted strings;
	// everywhere else ''' opens a string whose text starts with a quote
	// ('''a' is 'a and '''a''' is 'a').
	if t.dialect == keywords.DialectBigQuery && t.pos.Index+2 < len(t.input) {
		next1, _ := utf8.DecodeRune(t.input[t.pos.Index+1:])
		next2, _ := utf8.DecodeRune(t.input[t.pos.Index+2:])
		if next1 == quote && next2 == quote {
			return t.readTripleQuotedString(quote)
		}
	}

	// Get opening quote and remember the original quote character
	r, size := utf8.DecodeRune(t.input[t.pos.Index:])
	originalQuote := r
	quote = normalizeQuote(r)

	// Skip opening quote
	t.pos.AdvanceRune(r, size)

	if v, p, ok := t.scanQuotedStringFast(quote, originalQuote == quote); ok {
		t.pos = p
		return models.Token{
			Type:  quotedStringType(originalQuote),
			Value: v,
			Quote: originalQuote,
		}, nil
	}
	return t.readQuotedStringSlow(startPos, originalQuote, quote)
}

// quotedStringType picks the token type of a quoted string literal from its
// original (un-normalized) opening quote.
func quotedStringType(originalQuote rune) models.TokenType {
	// For test compatibility, use appropriate token types based on quote style
	switch originalQuote {
	case '\'', '‘', '’', '«', '»':
		return models.TokenTypeSingleQuotedString // 124
	case '"', '“', '”':
		return models.TokenTypeDoubleQuotedString // 124
	default:
		return models.TokenTypeString // 20
	}
}

// scanQuotedStringFast scans a quoted string's content from t.pos on a copy
// of the position. On a clean literal it returns the content as a substring
// of t.src and the position just past the closing quote, matching
// readQuotedStringSlow exactly (a newline sets Column to 1 and leaves LastNL
// alone). It returns ok=false, without touching t.pos, at the first doubled
// quote, escaping backslash, rewritten rune or at EOF. strict reports that
// the literal was opened with an ASCII quote (see quotedRune).
func (t *Tokenizer) scanQuotedStringFast(quote rune, strict bool) (string, Position, bool) {
	p := t.pos
	in := t.input
	start := p.Index
	escapes := t.backslashEscapes()
	for p.Index < len(in) {
		r, size := rune(in[p.Index]), 1
		if r >= utf8.RuneSelf {
			r, size = utf8.DecodeRune(in[p.Index:])
			if strict {
				if r == utf8.RuneError && size == 1 {
					return "", p, false
				}
			} else if needsRewrite(r, size) {
				if normalizeQuote(r) != quote {
					return "", p, false
				}
				r = quote
			}
		}
		switch {
		case r == quote:
			if p.Index+size < len(in) && nextRuneIsQuote(in[p.Index+size:], quote, strict) {
				return "", p, false
			}
			end := p.Index
			p.Index += size
			p.Column++
			return t.src[start:end], p, true
		case r == '\\' && escapes, r == 0, r == 0x1a:
			// A NUL or Ctrl-Z byte goes to the slow reader, which decides
			// whether the dialect can write it back (controlUnrepresentable).
			return "", p, false
		case r == '\n':
			p.Index += size
			p.Line++
			p.Column = 1
		default:
			p.Index += size
			p.Column++
		}
	}
	return "", p, false
}

// readQuotedStringSlow is the reference quoted-string reader. It continues
// from t.pos (just past the opening quote) and builds the value in t.litBuf,
// applying doubled-quote and backslash escapes and rune normalization.
//
// A literal opened with the ASCII quote itself (originalQuote == quote) is
// read in strict mode (see quotedRune).
func (t *Tokenizer) readQuotedStringSlow(startPos Position, originalQuote, quote rune) (models.Token, error) {
	strict := originalQuote == quote
	buf := &t.litBuf
	buf.Reset()
	for t.pos.Index < len(t.input) {
		r, size := utf8.DecodeRune(t.input[t.pos.Index:])
		r = quotedRune(r, strict)

		if r == quote {
			// Check for escaped quote
			if t.pos.Index+size < len(t.input) {
				nextR, nextSize := utf8.DecodeRune(t.input[t.pos.Index+size:])
				nextR = quotedRune(nextR, strict)
				if nextR == quote {
					// Include one quote and skip the other
					buf.WriteRune(r)
					t.pos.Index += size + nextSize
					t.pos.Column += 2
					continue
				}
			}

			// End of string
			t.pos.Index += size
			t.pos.Column++

			return models.Token{
				Type:  quotedStringType(originalQuote),
				Value: buf.String(),
				Quote: originalQuote,
			}, nil
		}

		if r == '\\' {
			// Only backslash-escaping dialects treat '\' as an escape; the
			// others keep it as a literal character (see backslashEscapes).
			if t.backslashEscapes() {
				if err := t.handleEscapeSequence(buf); err != nil {
					// On failure handleEscapeSequence has consumed only the
					// backslash, so t.pos is the offending escape character
					// (or end of input), as in the wrapped error.
					return models.Token{}, errors.InvalidSyntaxError(
						fmt.Sprintf("invalid escape sequence: %v", err),
						t.getCurrentPosition(),
						t.src,
					)
				}
				continue
			}
			// For other dialects, treat backslash as a literal character.
			buf.WriteRune(r)
			t.pos.Index += size
			t.pos.Column++
			continue
		}

		if r == '\n' {
			buf.WriteRune(r)
			t.pos.Index += size
			t.pos.Line++
			t.pos.Column = 1
			continue
		}

		if (r == 0 || r == 0x1a) && quote == '\'' && t.controlUnrepresentable(r) {
			return models.Token{}, errors.InvalidSyntaxError(
				fmt.Sprintf("control character %U in a string literal is not supported in this dialect", r),
				t.getCurrentPosition(),
				t.src,
			)
		}

		// Handle regular characters
		buf.WriteRune(r)
		t.pos.Index += size
		t.pos.Column++
	}

	return models.Token{}, errors.UnterminatedStringError(
		t.toSQLPosition(startPos),
		t.src,
	)
}

// readTripleQuotedString reads a triple-quoted string (e.g. """abc""", or abc wrapped in
// three single quotes on each side; gofmt rewrites a literal run of
// apostrophes in a doc comment, so that form is spelled out here).
// Content without invalid UTF-8 is returned as a substring of the input
// (#548); otherwise, and on every error, readTripleQuotedStringSlow runs from
// the same position.
func (t *Tokenizer) readTripleQuotedString(quote rune) (models.Token, error) {
	// Store start position for error reporting
	startPos := t.pos

	// Skip opening triple quotes
	for i := 0; i < 3; i++ {
		r, size := utf8.DecodeRune(t.input[t.pos.Index:])
		t.pos.AdvanceRune(r, size)
	}

	if v, p, ok := t.scanTripleQuotedFast(quote); ok {
		t.pos = p
		return tripleQuotedToken(quote, v), nil
	}
	return t.readTripleQuotedStringSlow(startPos, quote)
}

// tripleQuotedToken builds the token for a triple-quoted string.
func tripleQuotedToken(quote rune, value string) models.Token {
	if quote == '\'' {
		return models.Token{
			Type:  models.TokenTypeTripleSingleQuotedString,
			Value: value,
			Quote: quote,
		}
	}
	return models.Token{
		Type:  models.TokenTypeTripleDoubleQuotedString,
		Value: value,
		Quote: quote,
	}
}

// scanTripleQuotedFast scans a triple-quoted string's content from t.pos on
// a copy of the position, mirroring readTripleQuotedStringSlow (which writes
// raw runes, so only invalid UTF-8 differs from the source bytes). It returns
// the content as a substring of t.src, or ok=false at invalid UTF-8 or EOF.
func (t *Tokenizer) scanTripleQuotedFast(quote rune) (string, Position, bool) {
	p := t.pos
	in := t.input
	start := p.Index
	for p.Index < len(in) {
		// Check for closing triple quotes
		if p.Index+2 < len(in) {
			r1, s1 := utf8.DecodeRune(in[p.Index:])
			r2, s2 := utf8.DecodeRune(in[p.Index+s1:])
			r3, s3 := utf8.DecodeRune(in[p.Index+s1+s2:])
			if r1 == quote && r2 == quote && r3 == quote {
				end := p.Index
				p.Index += s1 + s2 + s3
				p.Column += 3
				return t.src[start:end], p, true
			}
		}

		r, size := utf8.DecodeRune(in[p.Index:])
		if r == utf8.RuneError && size == 1 {
			return "", p, false
		}
		p.Index += size
		if r == '\n' {
			p.Line++
			p.Column = 1
		} else {
			p.Column++
		}
	}
	return "", p, false
}

// readTripleQuotedStringSlow is the reference triple-quoted reader. It
// continues from t.pos (just past the opening quotes) and builds the value
// in t.litBuf.
func (t *Tokenizer) readTripleQuotedStringSlow(startPos Position, quote rune) (models.Token, error) {
	buf := &t.litBuf
	buf.Reset()
	for t.pos.Index < len(t.input) {
		// Check for closing triple quotes
		if t.pos.Index+2 < len(t.input) {
			r1, s1 := utf8.DecodeRune(t.input[t.pos.Index:])
			r2, s2 := utf8.DecodeRune(t.input[t.pos.Index+s1:])
			r3, s3 := utf8.DecodeRune(t.input[t.pos.Index+s1+s2:])
			if r1 == quote && r2 == quote && r3 == quote {
				// Skip closing quotes
				t.pos.Index += s1 + s2 + s3
				t.pos.Column += 3

				return tripleQuotedToken(quote, buf.String()), nil
			}
		}

		// Handle regular characters
		r, size := utf8.DecodeRune(t.input[t.pos.Index:])
		if r == '\n' {
			buf.WriteRune(r)
			t.pos.Index += size
			t.pos.Line++
			t.pos.Column = 1
			continue
		}

		buf.WriteRune(r)
		t.pos.Index += size
		t.pos.Column++
	}

	return models.Token{}, errors.UnterminatedStringError(
		t.toSQLPosition(startPos),
		t.src,
	)
}

// readNumber reads a dialect-specific numeric literal without decoding its spelling.
func (t *Tokenizer) readNumber(buf []byte) (models.Token, error) {
	start := t.pos.Index - len(buf)
	separators := t.dialect == keywords.DialectPostgreSQL || t.dialect == keywords.DialectSQLite || t.dialect == keywords.DialectClickHouse
	mysql := t.dialect == keywords.DialectMySQL || t.dialect == keywords.DialectMariaDB
	if t.input[t.pos.Index] == '0' && t.pos.Index+1 < len(t.input) {
		base := byte(0)
		switch t.input[t.pos.Index+1] {
		case 'x', 'X':
			// 0x hex literals are accepted in every dialect, as before
			// per-dialect lexing (SQL Server binary, MySQL/SQLite/
			// ClickHouse/PostgreSQL 16 hex, BigQuery hex integers).
			base = 16
		case 'b', 'B':
			if t.dialect == keywords.DialectPostgreSQL || t.dialect == keywords.DialectClickHouse || mysql {
				base = 2
			}
		case 'o', 'O':
			if t.dialect == keywords.DialectPostgreSQL {
				base = 8
			}
		}
		if base != 0 {
			t.pos.Index += 2
			t.pos.Column += 2
			digits := t.pos.Index
			// PostgreSQL also permits one separator immediately after a base prefix.
			if t.dialect == keywords.DialectPostgreSQL && t.pos.Index+1 < len(t.input) &&
				t.input[t.pos.Index] == '_' && numericDigit(t.input[t.pos.Index+1], base) {
				t.pos.Index++
				t.pos.Column++
			}
			t.readNumericDigits(base, separators)
			if digits == t.pos.Index {
				if mysql {
					t.scanIdentifierTail()
					return models.Token{Type: models.TokenTypeIdentifier, Value: t.src[start:t.pos.Index]}, nil
				}
				return t.invalidNumeric(start)
			}
			return t.finishNumber(start, mysql)
		}
	}
	t.readNumericDigits(10, separators)
	if t.pos.Index < len(t.input) && t.input[t.pos.Index] == '.' {
		next := t.pos.Index + 1
		if next < len(t.input) && (t.input[next] == '.' || (nextIsWordStart(t.input[next:]) && !t.exponentAt(next))) {
			return t.finishNumber(start, mysql)
		}
		t.pos.Index++
		t.pos.Column++
		t.readNumericDigits(10, separators)
	}
	if (t.dialect == keywords.DialectOracle || t.dialect == keywords.DialectGeneric) && t.storageUnitFollows(start) {
		return models.Token{Type: models.TokenTypeNumber, Value: t.src[start:t.pos.Index]}, nil
	}
	if t.pos.Index < len(t.input) && (t.input[t.pos.Index] == 'e' || t.input[t.pos.Index] == 'E') {
		if mysql && !t.exponentAt(t.pos.Index) && !strings.Contains(t.src[start:t.pos.Index], ".") {
			return t.finishNumber(start, true)
		}
		t.pos.Index++
		t.pos.Column++
		if t.pos.Index < len(t.input) && (t.input[t.pos.Index] == '+' || t.input[t.pos.Index] == '-') {
			t.pos.Index++
			t.pos.Column++
		}
		digits := t.pos.Index
		t.readNumericDigits(10, separators)
		if digits == t.pos.Index {
			return t.invalidNumeric(start)
		}
	}
	// Oracle BINARY_DOUBLE / BINARY_FLOAT literals: 1d, 1.5f, 1e5D.
	if t.dialect == keywords.DialectOracle && t.pos.Index < len(t.input) &&
		strings.IndexByte("dDfF", t.input[t.pos.Index]) >= 0 && !t.identCharAt(t.pos.Index+1) {
		t.pos.Index++
		t.pos.Column++
	}
	return t.finishNumber(start, mysql)
}

// storageUnitFollows reports whether the integer just read is an Oracle
// storage size such as 100M, 8K or 2G: one K/M/G/T/P/E unit letter that is
// not itself followed by a name character (nor, for E, an exponent sign).
// Oracle accepts these wherever a size is expected (SIZE, MAXSIZE, RESIZE,
// BLOCKSIZE, QUOTA, PRIVATE_SGA, ALTER SYSTEM SET ...); the generic dialect
// keeps accepting them too. The number and unit stay separate tokens so
// statement rendering retains its existing spelling and spacing.
func (t *Tokenizer) storageUnitFollows(start int) bool {
	i := t.pos.Index
	if i >= len(t.input) || strings.IndexByte("kKmMgGtTpPeE", t.input[i]) < 0 || t.identCharAt(i+1) {
		return false
	}
	if (t.input[i] == 'e' || t.input[i] == 'E') && i+1 < len(t.input) && (t.input[i+1] == '+' || t.input[i+1] == '-') {
		return false
	}
	for j := start; j < i; j++ {
		if t.input[j] < '0' || t.input[j] > '9' {
			return false
		}
	}
	return true
}

// identCharAt reports whether the input at idx starts a name character.
func (t *Tokenizer) identCharAt(idx int) bool {
	if idx >= len(t.input) {
		return false
	}
	r, _ := utf8.DecodeRune(t.input[idx:])
	return isIdentifierChar(r)
}

// readNumericDigits permits a single separator only between valid digits.
func (t *Tokenizer) readNumericDigits(base byte, separators bool) {
	digit := false
	for t.pos.Index < len(t.input) {
		c := t.input[t.pos.Index]
		if numericDigit(c, base) {
			digit = true
		} else if separators && digit && c == '_' && t.pos.Index+1 < len(t.input) && numericDigit(t.input[t.pos.Index+1], base) {
			digit = false
		} else {
			break
		}
		t.pos.Index++
		t.pos.Column++
	}
}

func numericDigit(c, base byte) bool {
	if c >= '0' && c <= '9' {
		return c-'0' < base
	}
	return base == 16 && (c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F')
}

func (t *Tokenizer) finishNumber(start int, mysql bool) (models.Token, error) {
	if t.pos.Index < len(t.input) {
		r, _ := utf8.DecodeRune(t.input[t.pos.Index:])
		if isIdentifierChar(r) {
			if mysql {
				// MySQL names may begin with digits (1x, 1e5x), but a
				// number with a fraction or signed exponent ends there and
				// the name that follows is an alias: 1.5a is 1.5 AS a.
				if strings.ContainsAny(t.src[start:t.pos.Index], ".+-") {
					return models.Token{Type: models.TokenTypeNumber, Value: t.src[start:t.pos.Index]}, nil
				}
				t.scanIdentifierTail()
				return models.Token{Type: models.TokenTypeIdentifier, Value: t.src[start:t.pos.Index]}, nil
			}
			// Oracle and SQL Server end a number at a keyword written
			// against it (SELECT 1FROM dual, FETCH FIRST 5ROWS ONLY); the
			// generic dialect keeps accepting that too.
			if (t.dialect == keywords.DialectOracle || t.dialect == keywords.DialectSQLServer ||
				t.dialect == keywords.DialectGeneric) && t.keywordAt() {
				return models.Token{Type: models.TokenTypeNumber, Value: t.src[start:t.pos.Index]}, nil
			}
			return t.invalidNumeric(start)
		}
	}
	return models.Token{Type: models.TokenTypeNumber, Value: t.src[start:t.pos.Index]}, nil
}

// keywordAt reports whether the name starting at the cursor is a keyword.
func (t *Tokenizer) keywordAt() bool {
	save := t.pos
	t.scanIdentifierTail()
	word := t.src[save.Index:t.pos.Index]
	t.pos = save
	return IsKeyword(word) && isASCII(word)
}

func (t *Tokenizer) invalidNumeric(start int) (models.Token, error) {
	return models.Token{}, errors.InvalidNumberError(t.src[start:t.pos.Index]+" (trailing junk after numeric literal)", t.getCurrentPosition(), t.src)
}

// isHexDigit reports whether c is an ASCII hexadecimal digit.
func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// nextIsWordStart reports whether b begins with a character that can start an
// identifier.
func nextIsWordStart(b []byte) bool {
	r, _ := utf8.DecodeRune(b)
	return isIdentifierStart(r)
}

// exponentAt reports whether the bytes at idx form an exponent: e or E, an
// optional sign, then a digit.
func (t *Tokenizer) exponentAt(idx int) bool {
	if idx >= len(t.input) || (t.input[idx] != 'e' && t.input[idx] != 'E') {
		return false
	}
	idx++
	if idx < len(t.input) && (t.input[idx] == '+' || t.input[idx] == '-') {
		idx++
	}
	return idx < len(t.input) && t.input[idx] >= '0' && t.input[idx] <= '9'
}

// leadingDotNumber reports whether the '.' at t.pos starts a number such as
// ".5": a digit follows and the dot is not a qualifier separator, i.e. the
// previous byte is not part of a name, a closing bracket or a quote ("t.5",
// "(x).5").
func (t *Tokenizer) leadingDotNumber() bool {
	i := t.pos.Index
	if i+1 >= len(t.input) || t.input[i+1] < '0' || t.input[i+1] > '9' {
		return false
	}
	if i == 0 {
		return true
	}
	switch c := t.input[i-1]; {
	case c >= utf8.RuneSelf, c == '_', c == '$', c == '#', c == ')', c == ']', c == '"', c == '`', c == '\'':
		return false
	case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		return false
	}
	return true
}

// readPunctuation picks out punctuation or operator tokens
func (t *Tokenizer) readPunctuation() (models.Token, error) {
	if t.pos.Index >= len(t.input) {
		return models.Token{}, errors.IncompleteStatementError(t.getCurrentPosition(), t.src)
	}
	r, size := utf8.DecodeRune(t.input[t.pos.Index:])
	switch r {
	case '(':
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeLeftParen, Value: "("}, nil
	case ')':
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeRightParen, Value: ")"}, nil
	case '[':
		// SQL Server and SQLite: [identifier] is a quoted identifier
		if t.dialect == keywords.DialectSQLServer || t.dialect == keywords.DialectSQLite {
			t.pos.AdvanceRune(r, size) // Consume [
			contentStart := t.pos.Index
			escaped := false
			for t.pos.Index < len(t.input) {
				ch, chSize := utf8.DecodeRune(t.input[t.pos.Index:])
				if ch == ']' {
					if t.dialect == keywords.DialectSQLServer && t.pos.Index+1 < len(t.input) && t.input[t.pos.Index+1] == ']' {
						escaped = true
						t.pos.Index += 2
						t.pos.Column += 2
						continue
					}
					v := t.src[contentStart:t.pos.Index]
					if escaped {
						v = strings.ReplaceAll(v, "]]", "]")
					}
					t.pos.AdvanceRune(ch, chSize) // Consume ]
					return models.Token{Type: models.TokenTypeIdentifier, Value: v, Quote: '['}, nil
				}
				t.pos.AdvanceRune(ch, chSize)
			}
			// Report the opening '[', the byte just before contentStart.
			return models.Token{}, errors.InvalidSyntaxError(
				"unterminated bracket identifier",
				t.toSQLPosition(Position{Index: contentStart - 1}),
				t.src,
			)
		}
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeLBracket, Value: "["}, nil
	case ']':
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeRBracket, Value: "]"}, nil
	case ',':
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeComma, Value: ","}, nil
	case ';':
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeSemicolon, Value: ";"}, nil
	case '.':
		if t.leadingDotNumber() {
			return t.readNumber(nil)
		}
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeDot, Value: "."}, nil
	case '+':
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypePlus, Value: "+"}, nil
	case '-':
		t.pos.AdvanceRune(r, size)
		if t.pos.Index < len(t.input) {
			nxtR, nxtSize := utf8.DecodeRune(t.input[t.pos.Index:])
			if nxtR == '>' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				// Check for ->> (JSON text extraction)
				if t.pos.Index < len(t.input) {
					thirdR, thirdSize := utf8.DecodeRune(t.input[t.pos.Index:])
					if thirdR == '>' {
						t.pos.AdvanceRune(thirdR, thirdSize)
						return models.Token{Type: models.TokenTypeLongArrow, Value: "->>"}, nil
					}
				}
				return models.Token{Type: models.TokenTypeArrow, Value: "->"}, nil
			}
			// "--" line comments are handled by nextToken.
		}
		return models.Token{Type: models.TokenTypeMinus, Value: "-"}, nil
	case '*':
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeMul, Value: "*"}, nil
	case '/':
		// "/*" block comments are handled by nextToken.
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeDiv, Value: "/"}, nil
	case '=':
		t.pos.AdvanceRune(r, size)
		if t.pos.Index < len(t.input) {
			nxtR, nxtSize := utf8.DecodeRune(t.input[t.pos.Index:])
			if nxtR == '>' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeRArrow, Value: "=>"}, nil
			}
			if nxtR == '=' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeDoubleEq, Value: "=="}, nil
			}
		}
		return models.Token{Type: models.TokenTypeEq, Value: "="}, nil
	case '<':
		t.pos.AdvanceRune(r, size)
		if t.pos.Index < len(t.input) {
			nxtR, nxtSize := utf8.DecodeRune(t.input[t.pos.Index:])
			if nxtR == '=' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				// <=> is the NULL-safe equality operator (MySQL) and the
				// pgvector cosine-distance operator (PostgreSQL).
				if t.pos.Index < len(t.input) && t.input[t.pos.Index] == '>' {
					t.pos.Index++
					t.pos.Column++
					return models.Token{Type: models.TokenTypeSpaceship, Value: "<=>"}, nil
				}
				return models.Token{Type: models.TokenTypeLtEq, Value: "<="}, nil
			} else if nxtR == '<' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeShiftLeft, Value: "<<"}, nil
			} else if nxtR == '-' && t.pos.Index+1 < len(t.input) && t.input[t.pos.Index+1] == '>' {
				// <-> is the distance operator (PostgreSQL pg_trgm, PostGIS,
				// pgvector).
				t.pos.Index += 2
				t.pos.Column += 2
				return models.Token{Type: models.TokenTypeCustomBinaryOperator, Value: "<->"}, nil
			} else if nxtR == '>' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeNeq, Value: "<>"}, nil
			} else if nxtR == '@' {
				// <@ is the "is contained by" JSON operator
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeArrowAt, Value: "<@"}, nil
			}
		}
		return models.Token{Type: models.TokenTypeLt, Value: "<"}, nil
	case '>':
		t.pos.AdvanceRune(r, size)
		if t.pos.Index < len(t.input) {
			nxtR, nxtSize := utf8.DecodeRune(t.input[t.pos.Index:])
			if nxtR == '=' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeGtEq, Value: ">="}, nil
			}
			if nxtR == '>' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeShiftRight, Value: ">>"}, nil
			}
		}
		return models.Token{Type: models.TokenTypeGt, Value: ">"}, nil
	case '!':
		t.pos.AdvanceRune(r, size)
		if t.pos.Index < len(t.input) {
			nxtR, nxtSize := utf8.DecodeRune(t.input[t.pos.Index:])
			if nxtR == '=' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeNeq, Value: "!="}, nil
			}
			// Check for PostgreSQL regex operators !~ and !~*
			if nxtR == '~' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				// Check for !~* (case-insensitive regex non-match)
				if t.pos.Index < len(t.input) {
					thirdR, thirdSize := utf8.DecodeRune(t.input[t.pos.Index:])
					if thirdR == '*' {
						t.pos.AdvanceRune(thirdR, thirdSize)
						return models.Token{Type: models.TokenTypeExclamationMarkTildeAsterisk, Value: "!~*"}, nil
					}
				}
				// Just !~ (case-sensitive regex non-match)
				return models.Token{Type: models.TokenTypeExclamationMarkTilde, Value: "!~"}, nil
			}
		}
		return models.Token{Type: models.TokenTypeExclamationMark, Value: "!"}, nil
	case ':':
		bindStart := t.pos.Index
		t.pos.AdvanceRune(r, size)
		if t.pos.Index < len(t.input) {
			nxtR, nxtSize := utf8.DecodeRune(t.input[t.pos.Index:])
			if nxtR == ':' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeDoubleColon, Value: "::"}, nil
			}
			if nxtR == '=' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeAssignment, Value: ":="}, nil
			}
			// Oracle bind variables: positional :1, :2 and named :name (#520).
			// Gated to Oracle and SQLite (named :name and @name parameters)
			// because other dialects use ':' for array slices (arr[1:n]) and
			// Snowflake VARIANT paths (col:field).
			if t.dialect == keywords.DialectOracle || t.dialect == keywords.DialectSQLite {
				if nxtR >= '0' && nxtR <= '9' {
					for t.pos.Index < len(t.input) {
						c := t.input[t.pos.Index]
						if c < '0' || c > '9' {
							break
						}
						t.pos.AdvanceRune(rune(c), 1)
					}
					return models.Token{Type: models.TokenTypePlaceholder, Value: t.src[bindStart:t.pos.Index]}, nil
				}
				if isIdentifierStart(nxtR) {
					t.pos.AdvanceRune(nxtR, nxtSize)
					t.scanIdentifierTail()
					return models.Token{Type: models.TokenTypePlaceholder, Value: t.src[bindStart:t.pos.Index]}, nil
				}
			}
		}
		return models.Token{Type: models.TokenTypeColon, Value: ":"}, nil
	case '%':
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeMod, Value: "%"}, nil
	case '|':
		t.pos.AdvanceRune(r, size)
		if t.pos.Index < len(t.input) {
			nxtR, nxtSize := utf8.DecodeRune(t.input[t.pos.Index:])
			if nxtR == '|' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeStringConcat, Value: "||"}, nil
			}
		}
		return models.Token{Type: models.TokenTypePipe, Value: "|"}, nil
	case '\'':
		return t.readQuotedString('\'')
	case '&':
		t.pos.AdvanceRune(r, size)
		// Check for && (array overlap operator)
		if t.pos.Index < len(t.input) {
			nextR, nextSize := utf8.DecodeRune(t.input[t.pos.Index:])
			if nextR == '&' {
				t.pos.AdvanceRune(nextR, nextSize)
				return models.Token{Type: models.TokenTypeOverlap, Value: "&&"}, nil
			}
		}
		// Just a standalone & symbol
		return models.Token{Type: models.TokenTypeAmpersand, Value: "&"}, nil
	case '@':
		t.pos.AdvanceRune(r, size)
		// Check for PostgreSQL array operators and parameter syntax
		if t.pos.Index < len(t.input) {
			nextR, nextSize := utf8.DecodeRune(t.input[t.pos.Index:])

			// Check for @> (contains operator)
			if nextR == '>' {
				t.pos.AdvanceRune(nextR, nextSize)
				return models.Token{Type: models.TokenTypeAtArrow, Value: "@>"}, nil
			}

			// Check for @@ (full text search operator or SQL Server global variable)
			if nextR == '@' {
				t.pos.AdvanceRune(nextR, nextSize)
				// SQL Server dialect: @@NAME is a global variable identifier
				if t.dialect == keywords.DialectSQLServer && t.pos.Index < len(t.input) {
					peekR, _ := utf8.DecodeRune(t.input[t.pos.Index:])
					if isIdentifierStart(peekR) {
						identToken, err := t.readIdentifier()
						if err != nil {
							return models.Token{}, err
						}
						return models.Token{
							Type:  models.TokenTypeIdentifier,
							Value: "@@" + identToken.Value,
						}, nil
					}
				}
				return models.Token{Type: models.TokenTypeAtAt, Value: "@@"}, nil
			}

			// Check for parameter syntax (@variable)
			if isIdentifierStart(nextR) {
				// This is a parameter like @variable, read the identifier part
				identToken, err := t.readIdentifier()
				if err != nil {
					return models.Token{}, err
				}
				return models.Token{
					Type:  models.TokenTypePlaceholder,
					Value: "@" + identToken.Value,
				}, nil
			}
		}
		// Just a standalone @ symbol
		return models.Token{Type: models.TokenTypeAtSign, Value: "@"}, nil
	case '#':
		// SQL Server dialect: #temp and ##global temp table identifiers
		if t.dialect == keywords.DialectSQLServer {
			start := t.pos.Index
			t.pos.AdvanceRune(r, size) // consume first #
			// Check for ## (global temp table)
			if t.pos.Index < len(t.input) {
				nextR, nextSize := utf8.DecodeRune(t.input[t.pos.Index:])
				if nextR == '#' {
					t.pos.AdvanceRune(nextR, nextSize) // consume second #
				}
			}
			// Read the identifier part
			if t.pos.Index < len(t.input) {
				nextR, _ := utf8.DecodeRune(t.input[t.pos.Index:])
				if isIdentifierStart(nextR) {
					for t.pos.Index < len(t.input) {
						cr, cs := utf8.DecodeRune(t.input[t.pos.Index:])
						if !isIdentifierChar(cr) {
							break
						}
						t.pos.AdvanceRune(cr, cs)
					}
					return models.Token{
						Type:  models.TokenTypeIdentifier,
						Value: t.src[start:t.pos.Index],
					}, nil
				}
			}
			// Not followed by identifier - fall through to standalone #
			return models.Token{Type: models.TokenTypeSharp, Value: t.src[start:t.pos.Index]}, nil
		}
		t.pos.AdvanceRune(r, size)
		// Check for PostgreSQL JSON operators
		if t.pos.Index < len(t.input) {
			nextR, nextSize := utf8.DecodeRune(t.input[t.pos.Index:])

			// Check for #> (JSON path access)
			if nextR == '>' {
				t.pos.AdvanceRune(nextR, nextSize)
				// Check for #>> (JSON path access as text)
				if t.pos.Index < len(t.input) {
					thirdR, thirdSize := utf8.DecodeRune(t.input[t.pos.Index:])
					if thirdR == '>' {
						t.pos.AdvanceRune(thirdR, thirdSize)
						return models.Token{Type: models.TokenTypeHashLongArrow, Value: "#>>"}, nil
					}
				}
				return models.Token{Type: models.TokenTypeHashArrow, Value: "#>"}, nil
			}

			// Check for #- (delete at JSON path)
			if nextR == '-' {
				t.pos.AdvanceRune(nextR, nextSize)
				return models.Token{Type: models.TokenTypeHashMinus, Value: "#-"}, nil
			}
		}
		// Just a standalone # symbol
		return models.Token{Type: models.TokenTypeSharp, Value: "#"}, nil
	case '?':
		qStart := t.pos.Index
		t.pos.AdvanceRune(r, size)
		// MySQL, MariaDB, and SQLite use a bare ? as a positional parameter
		// placeholder (e.g. WHERE id = ?). These dialects have no JSON ?
		// existence operator, so emit a placeholder token before the JSON
		// operator lookahead below.
		if t.dialect == keywords.DialectMySQL ||
			t.dialect == keywords.DialectMariaDB ||
			t.dialect == keywords.DialectSQLite {
			// SQLite also numbers its parameters: ?1, ?2.
			if t.dialect == keywords.DialectSQLite {
				for t.pos.Index < len(t.input) && t.input[t.pos.Index] >= '0' && t.input[t.pos.Index] <= '9' {
					t.pos.Index++
					t.pos.Column++
				}
				return models.Token{Type: models.TokenTypePlaceholder, Value: t.src[qStart:t.pos.Index]}, nil
			}
			return models.Token{Type: models.TokenTypePlaceholder, Value: "?"}, nil
		}
		// Check for PostgreSQL JSON operators
		if t.pos.Index < len(t.input) {
			nextR, nextSize := utf8.DecodeRune(t.input[t.pos.Index:])

			// Check for ?| (any key exists)
			if nextR == '|' {
				t.pos.AdvanceRune(nextR, nextSize)
				return models.Token{Type: models.TokenTypeQuestionPipe, Value: "?|"}, nil
			}

			// Check for ?& (all keys exist)
			if nextR == '&' {
				t.pos.AdvanceRune(nextR, nextSize)
				return models.Token{Type: models.TokenTypeQuestionAnd, Value: "?&"}, nil
			}
		}
		// Just a standalone ? symbol (used for single key existence check)
		return models.Token{Type: models.TokenTypeQuestion, Value: "?"}, nil
	case '$':
		// Handle PostgreSQL positional parameters ($1, $2, etc.)
		t.pos.AdvanceRune(r, size)
		if t.pos.Index < len(t.input) {
			nextR, _ := utf8.DecodeRune(t.input[t.pos.Index:])
			// Check if followed by a digit (positional parameter)
			if nextR >= '0' && nextR <= '9' {
				// Read the number part
				start := t.pos.Index
				for t.pos.Index < len(t.input) {
					digitR, digitSize := utf8.DecodeRune(t.input[t.pos.Index:])
					if digitR < '0' || digitR > '9' {
						break
					}
					t.pos.AdvanceRune(digitR, digitSize)
				}
				// The '$' is the single byte just before start.
				return models.Token{Type: models.TokenTypePlaceholder, Value: t.src[start-1 : t.pos.Index]}, nil
			}
		}
		// PostgreSQL dollar-quoted strings: $$...$$ or $tag$...$tag$
		// Check if this starts a dollar-quoted string
		if t.pos.Index < len(t.input) {
			nextR, _ := utf8.DecodeRune(t.input[t.pos.Index:])
			if nextR == '$' || isIdentifierStart(nextR) {
				// Try to read the opening tag
				tagStart := t.pos.Index
				if nextR == '$' {
					// $$ case - empty tag
				} else {
					// $tag$ case - read identifier
					for t.pos.Index < len(t.input) {
						cr, cs := utf8.DecodeRune(t.input[t.pos.Index:])
						if cr == '$' || !isIdentifierChar(cr) {
							break
						}
						t.pos.AdvanceRune(cr, cs)
					}
				}
				// Without a closing '$' this is not a dollar-quote opener but a
				// named parameter or variable such as $name (Snowflake session
				// variables, SQL Server $action). Emit it as one placeholder
				// token that keeps the name, like @name and Oracle :name.
				if t.pos.Index >= len(t.input) || t.input[t.pos.Index] != '$' {
					return models.Token{Type: models.TokenTypePlaceholder, Value: t.src[tagStart-1 : t.pos.Index]}, nil
				}
				// The opening tag "$tag$" runs from the '$' just before
				// tagStart through the '$' at t.pos.Index.
				closingTag := t.src[tagStart-1 : t.pos.Index+1]
				t.pos.AdvanceRune('$', 1) // consume closing $ of opening tag

				// Now read content until we find $tag$
				contentStart := t.pos.Index
				for t.pos.Index < len(t.input) {
					if t.input[t.pos.Index] == '$' && t.pos.Index+len(closingTag) <= len(t.input) {
						candidate := t.src[t.pos.Index : t.pos.Index+len(closingTag)]
						if candidate == closingTag {
							content := t.src[contentStart:t.pos.Index]
							// Advance past the closing tag
							for i := 0; i < len(closingTag); {
								cr, cs := utf8.DecodeRuneInString(closingTag[i:])
								t.pos.AdvanceRune(cr, cs)
								i += cs
							}
							return models.Token{Type: models.TokenTypeDollarQuotedString, Value: content}, nil
						}
					}
					cr, cs := utf8.DecodeRune(t.input[t.pos.Index:])
					t.pos.AdvanceRune(cr, cs)
				}
				// Unterminated dollar-quoted string: report the opening
				// tag's leading '$', the byte just before tagStart.
				return models.Token{}, errors.UnterminatedStringError(
					t.toSQLPosition(Position{Index: tagStart - 1}),
					t.src,
				)
			}
		}
		// Standalone $ - treat as placeholder
		return models.Token{Type: models.TokenTypePlaceholder, Value: "$"}, nil
	case '^':
		t.pos.AdvanceRune(r, size)
		// ^@ is the PostgreSQL starts-with operator.
		if t.pos.Index < len(t.input) && t.input[t.pos.Index] == '@' {
			t.pos.Index++
			t.pos.Column++
			return models.Token{Type: models.TokenTypeCaretAt, Value: "^@"}, nil
		}
		return models.Token{Type: models.TokenTypeCaret, Value: "^"}, nil
	case '{':
		if t.dialect == keywords.DialectClickHouse {
			if end := t.clickHouseParamEnd(); end > 0 {
				start := t.pos.Index
				for t.pos.Index < end {
					cr, cs := utf8.DecodeRune(t.input[t.pos.Index:])
					t.pos.AdvanceRune(cr, cs)
				}
				return models.Token{Type: models.TokenTypePlaceholder, Value: t.src[start:end]}, nil
			}
		}
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeLBrace, Value: "{"}, nil
	case '}':
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeRBrace, Value: "}"}, nil
	case '~':
		// Handle PostgreSQL regex operators ~ and ~*
		t.pos.AdvanceRune(r, size)
		// Check for ~* (case-insensitive regex match)
		if t.pos.Index < len(t.input) {
			nextR, nextSize := utf8.DecodeRune(t.input[t.pos.Index:])
			if nextR == '*' {
				t.pos.AdvanceRune(nextR, nextSize)
				return models.Token{Type: models.TokenTypeTildeAsterisk, Value: "~*"}, nil
			}
		}
		// Just ~ (case-sensitive regex match)
		return models.Token{Type: models.TokenTypeTilde, Value: "~"}, nil
	}

	if isIdentifierStart(r) {
		return t.readIdentifier()
	}

	return models.Token{}, errors.UnexpectedCharError(r, t.getCurrentPosition(), t.src)
}

// lineIndexAt returns the index into t.lineStarts of the line containing the
// byte offset idx, i.e. the largest i with t.lineStarts[i] <= idx. It returns 0
// when lineStarts is empty or idx precedes the first line start.
//
// The hinted line (posCacheLine) and the line after it are checked first in
// O(1) because tokenization requests positions in (almost) increasing order;
// otherwise a binary search is used.
func (t *Tokenizer) lineIndexAt(idx int) int {
	n := len(t.lineStarts)
	if n == 0 {
		return 0
	}
	if li := t.posCacheLine; li >= 0 && li < n && t.lineStarts[li] <= idx {
		if li+1 == n || t.lineStarts[li+1] > idx {
			return li
		}
		if li+2 == n || t.lineStarts[li+2] > idx {
			return li + 1
		}
	}
	lo, hi := 0, n-1
	for lo < hi {
		mid := int(uint(lo+hi+1) >> 1)
		if t.lineStarts[mid] <= idx {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

// toSQLPosition converts an internal Position => a models.Location.
//
// Columns are 1-based and byte-based: every byte, a tab included, counts as
// one column, matching editors and LSP clients. The line is found with
// lineIndexAt, so the column is the distance from the line start in O(1). A
// position past the end of the input is clamped to the end.
func (t *Tokenizer) toSQLPosition(pos Position) models.Location {
	li := t.lineIndexAt(pos.Index)
	lineStart := 0
	if li < len(t.lineStarts) {
		lineStart = t.lineStarts[li]
	}

	// Remember the line so the next, usually monotone, request starts there.
	t.posCacheLine = li

	return lineLocation(li, lineStart, pos.Index, len(t.input))
}

// lineLocation is the column rule shared by toSQLPosition and locationAt: the
// byte offset pos, clamped to inputLen, on the line with 0-based index li that
// starts at byte lineStart. Columns are 1-based and never less than 1.
func lineLocation(li, lineStart, pos, inputLen int) models.Location {
	end := min(pos, inputLen)
	return models.Location{
		Line:   li + 1,
		Column: max(end-lineStart, 0) + 1,
	}
}

// getCurrentPosition returns the Location of the tokenizer's current byte index
func (t *Tokenizer) getCurrentPosition() models.Location {
	return t.toSQLPosition(t.pos)
}

// getLocation produces the 1-based {Line, Column} of a byte offset under the
// same rule as toSQLPosition.
func (t *Tokenizer) getLocation(pos int) models.Location {
	return locationAt(t.input, pos)
}

// locationAt computes the 1-based {Line, Column} of byte offset pos in input
// without the tokenizer's line index, using the same rule as toSQLPosition
// (see lineLocation). It is used off the hot path (Position.Location and the
// standalone StringLiteralReader), where no line index is available.
func locationAt(input []byte, pos int) models.Location {
	prefix := input[:min(max(pos, 0), len(input))]
	return lineLocation(bytes.Count(prefix, []byte{'\n'}), bytes.LastIndexByte(prefix, '\n')+1, pos, len(input))
}

func isIdentifierChar(r rune) bool {
	return isUnicodeIdentifierPart(r)
}

// scanIdentifierTail advances the cursor over identifier-part characters.
//
// ASCII bytes are classified directly from the input without decoding. For
// them, Index++/Column++ is exactly equivalent to Position.AdvanceRune because
// no ASCII identifier byte is '\n' (so Line and LastNL never change). Multi-byte
// runes fall back to utf8.DecodeRune. Do not reuse this for any character class
// that can contain a newline.
func (t *Tokenizer) scanIdentifierTail() {
	for t.pos.Index < len(t.input) {
		if c := t.input[t.pos.Index]; c < utf8.RuneSelf {
			if !asciiIdentPart[c] {
				// '$' continues a name (Oracle v$session, Snowflake
				// SYSTEM$TYPEOF, PostgreSQL a$b) and so does '#' in Oracle (a#).
				// Neither can start one; scanIdentifierTail is only called
				// after the first character.
				if c == '$' || (c == '#' && t.dialect == keywords.DialectOracle) {
					t.pos.Index++
					t.pos.Column++
					continue
				}
				return
			}
			t.pos.Index++
			t.pos.Column++
			continue
		}
		r, size := utf8.DecodeRune(t.input[t.pos.Index:])
		if !isIdentifierChar(r) {
			return
		}
		t.pos.AdvanceRune(r, size)
	}
}

// hasCodeBeforeOnLine checks if there are non-whitespace characters on the same
// line before the given byte index. Used to determine if a comment is inline.
//
// Comment starts are requested in increasing order, so the scan of a line is
// resumed from where the previous request on the same line stopped (and stops
// for good once non-whitespace is seen). Each byte of a line is therefore
// examined at most once per line, however many comments it holds.
func (t *Tokenizer) hasCodeBeforeOnLine(idx int) bool {
	// Find the start of the line containing idx
	lineStart, li := 0, 0
	if len(t.lineStarts) > 0 && t.lineStarts[0] <= idx {
		li = t.lineIndexAt(idx)
		lineStart = t.lineStarts[li]
	}
	// Restart the cursor on a new line or on a backwards request.
	if t.inlLine != li+1 || t.inlScan > idx {
		t.inlLine, t.inlScan, t.inlCode = li+1, lineStart, false
	}
	// Check for non-whitespace between the cursor and idx
	for ; !t.inlCode && t.inlScan < idx && t.inlScan < len(t.input); t.inlScan++ {
		if c := t.input[t.inlScan]; c != ' ' && c != '\t' && c != '\r' {
			t.inlCode = true
		}
	}
	return t.inlCode
}
