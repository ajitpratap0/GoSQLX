// Package tokenizer provides high-performance SQL tokenization with zero-copy operations.
// See doc.go for comprehensive package documentation.
package tokenizer

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ajitpratap0/GoSQLX/pkg/errors"
	"github.com/ajitpratap0/GoSQLX/pkg/metrics"
	"github.com/ajitpratap0/GoSQLX/pkg/models"
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
}

// Tokenizer provides high-performance SQL tokenization with zero-copy operations.
// It converts raw SQL bytes into a stream of tokens with precise position tracking.
//
// Features:
//   - Zero-copy operations on input byte slices (no string allocations)
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
//
// Usage:
//
//	// With pooling (recommended for production)
//	tkz := GetTokenizer()
//	defer PutTokenizer(tkz)
//	tokens, err := tkz.Tokenize([]byte(sql))
//
//	// Without pooling (simple usage)
//	tkz, _ := New()
//	tokens, err := tkz.Tokenize([]byte(sql))
type Tokenizer struct {
	input      []byte             // Input SQL bytes (zero-copy reference)
	pos        Position           // Current scanning position
	lineStart  Position           // Start of current line
	lineStarts []int              // Byte offsets of line starts (for position tracking)
	line       int                // Current line number (1-based)
	keywords   *keywords.Keywords // Keyword classifier for token type determination
	debugLog   DebugLogger        // Optional debug logger for verbose tracing
}

// SetDebugLogger sets a debug logger for verbose tracing during tokenization.
// The logger receives debug messages for each token produced, which is useful
// for diagnosing tokenization issues or understanding token stream structure.
//
// Pass nil to disable debug logging.
//
// Example:
//
//	type MyLogger struct{}
//	func (l *MyLogger) Debug(format string, args ...interface{}) {
//	    log.Printf("[TOKENIZER] "+format, args...)
//	}
//
//	tkz := GetTokenizer()
//	tkz.SetDebugLogger(&MyLogger{})
//	tokens, _ := tkz.Tokenize([]byte(sql))
func (t *Tokenizer) SetDebugLogger(logger DebugLogger) {
	t.debugLog = logger
}

// New creates a new Tokenizer with default configuration and keyword support.
// The returned tokenizer is ready to use for tokenizing SQL statements.
//
// For production use, prefer GetTokenizer() which uses object pooling for
// better performance and reduced allocations.
//
// Returns an error only if keyword initialization fails (extremely rare).
//
// Example:
//
//	tkz, err := tokenizer.New()
//	if err != nil {
//	    return err
//	}
//	tokens, err := tkz.Tokenize([]byte("SELECT * FROM users"))
func New() (*Tokenizer, error) {
	kw := keywords.NewKeywords()
	return &Tokenizer{
		keywords:   kw,
		pos:        NewPosition(1, 0),
		lineStarts: []int{0},
	}, nil
}

// NewWithKeywords initializes a Tokenizer with a custom keyword classifier.
// This allows you to customize keyword recognition for specific SQL dialects
// or to add custom keywords.
//
// The keywords parameter must not be nil.
//
// Returns an error if keywords is nil.
//
// Example:
//
//	kw := keywords.NewKeywords()
//	// Customize keywords as needed...
//	tkz, err := tokenizer.NewWithKeywords(kw)
//	if err != nil {
//	    return err
//	}
func NewWithKeywords(kw *keywords.Keywords) (*Tokenizer, error) {
	if kw == nil {
		return nil, errors.InvalidSyntaxError("keywords cannot be nil", models.Location{Line: 1, Column: 0}, "")
	}

	return &Tokenizer{
		keywords:   kw,
		pos:        NewPosition(1, 0),
		lineStarts: []int{0},
	}, nil
}

// Tokenize converts raw SQL bytes into a slice of tokens with position information.
//
// This is the main entry point for tokenization. It performs zero-copy tokenization
// directly on the input byte slice and returns tokens with precise start/end positions.
//
// Performance: 8M+ tokens/sec sustained throughput with zero-copy operations.
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
//   - input: Raw SQL bytes to tokenize (not modified, zero-copy reference)
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
	// Record start time for metrics
	startTime := time.Now()

	// Validate input size to prevent DoS attacks
	if len(input) > MaxInputSize {
		err := errors.InputTooLargeError(int64(len(input)), MaxInputSize, models.Location{Line: 1, Column: 0})
		metrics.RecordTokenization(time.Since(startTime), len(input), err)
		return nil, err
	}

	// Reset state
	t.Reset()
	t.input = input

	// Pre-allocate line starts slice - reuse if possible
	estimatedLines := len(input)/50 + 1 // Estimate 50 chars per line + 1 for initial 0
	if cap(t.lineStarts) < estimatedLines {
		t.lineStarts = make([]int, 0, estimatedLines)
	} else {
		t.lineStarts = t.lineStarts[:0]
	}
	t.lineStarts = append(t.lineStarts, 0)

	// Pre-scan input to build line start indices
	for i := 0; i < len(t.input); i++ {
		if t.input[i] == '\n' {
			t.lineStarts = append(t.lineStarts, i+1)
		}
	}

	// Pre-allocate token slice with better capacity estimation
	// More accurate estimation based on typical SQL token density
	estimatedTokens := len(input) / 4
	if estimatedTokens < 16 {
		estimatedTokens = 16 // At least 16 tokens
	}
	tokens := make([]models.TokenWithSpan, 0, estimatedTokens)

	// Get a buffer from the pool for string operations
	buf := getBuffer()
	defer putBuffer(buf)

	var tokenErr error
	func() {
		// Ensure proper cleanup even if we panic
		defer func() {
			if r := recover(); r != nil {
				tokenErr = errors.TokenizerPanicError(r, t.getCurrentPosition())
			}
		}()

		for t.pos.Index < len(t.input) {
			t.skipWhitespace()

			if t.pos.Index >= len(t.input) {
				break
			}

			// Check token count limit to prevent DoS attacks
			if len(tokens) >= MaxTokens {
				tokenErr = errors.TokenLimitReachedError(len(tokens)+1, MaxTokens, t.getCurrentPosition(), string(t.input))
				return
			}

			startPos := t.pos

			token, err := t.nextToken()
			if err != nil {
				// nextToken returns structured errors, pass through directly
				tokenErr = err
				return
			}

			tokens = append(tokens, models.TokenWithSpan{
				Token: token,
				Start: t.toSQLPosition(startPos),
				End:   t.getCurrentPosition(),
			})
		}
	}()

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

	// Record metrics for successful tokenization
	duration := time.Since(startTime)
	metrics.RecordTokenization(duration, len(input), nil)

	return tokens, nil
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

	// Record start time for metrics
	startTime := time.Now()

	// Validate input size to prevent DoS attacks
	if len(input) > MaxInputSize {
		err := errors.InputTooLargeError(int64(len(input)), MaxInputSize, models.Location{Line: 1, Column: 0})
		metrics.RecordTokenization(time.Since(startTime), len(input), err)
		return nil, err
	}

	// Reset state
	t.Reset()
	t.input = input

	// Pre-allocate line starts slice - reuse if possible
	estimatedLines := len(input)/50 + 1 // Estimate 50 chars per line + 1 for initial 0
	if cap(t.lineStarts) < estimatedLines {
		t.lineStarts = make([]int, 0, estimatedLines)
	} else {
		t.lineStarts = t.lineStarts[:0]
	}
	t.lineStarts = append(t.lineStarts, 0)

	// Pre-scan input to build line start indices
	for i := 0; i < len(t.input); i++ {
		if t.input[i] == '\n' {
			t.lineStarts = append(t.lineStarts, i+1)
		}
	}

	// Pre-allocate token slice with better capacity estimation
	estimatedTokens := len(input) / 4
	if estimatedTokens < 16 {
		estimatedTokens = 16 // At least 16 tokens
	}
	tokens := make([]models.TokenWithSpan, 0, estimatedTokens)

	// Get a buffer from the pool for string operations
	buf := getBuffer()
	defer putBuffer(buf)

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
			if len(tokens)%100 == 0 {
				if err := ctx.Err(); err != nil {
					tokenErr = err
					return
				}
			}

			t.skipWhitespace()

			if t.pos.Index >= len(t.input) {
				break
			}

			// Check token count limit to prevent DoS attacks
			if len(tokens) >= MaxTokens {
				tokenErr = errors.TokenLimitReachedError(len(tokens)+1, MaxTokens, t.getCurrentPosition(), string(t.input))
				return
			}

			startPos := t.pos

			token, err := t.nextToken()
			if err != nil {
				// nextToken returns structured errors, pass through directly
				tokenErr = err
				return
			}

			tokens = append(tokens, models.TokenWithSpan{
				Token: token,
				Start: t.toSQLPosition(startPos),
				End:   t.getCurrentPosition(),
			})
		}
	}()

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

	// Record metrics for successful tokenization
	duration := time.Since(startTime)
	metrics.RecordTokenization(duration, len(input), nil)

	return tokens, nil
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

// nextToken picks out the next token from the input
func (t *Tokenizer) nextToken() (models.Token, error) {
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

	// Slower path for punctuation and operators
	return t.readPunctuation()
}

// isIdentifierStart checks if a rune can start an identifier
func isIdentifierStart(r rune) bool {
	return isUnicodeIdentifierStart(r)
}

// readIdentifier reads an identifier (e.g. foo or foo.bar)
func (t *Tokenizer) readIdentifier() (models.Token, error) {
	start := t.pos.Index
	r, size := utf8.DecodeRune(t.input[t.pos.Index:])
	t.pos.AdvanceRune(r, size)

	// Read until we hit a non-identifier character
	for t.pos.Index < len(t.input) {
		r, size = utf8.DecodeRune(t.input[t.pos.Index:])
		if !isIdentifierChar(r) {
			_ = size // Mark as intentionally unused
			break
		}
		t.pos.AdvanceRune(r, size)
	}

	ident := string(t.input[start:t.pos.Index])
	word := &models.Word{
		Value: ident,
	}

	// Determine token type based on whether it's a keyword
	upperIdent := strings.ToUpper(ident)
	tokenType, isKeyword := keywordTokenTypes[upperIdent]
	if !isKeyword {
		tokenType = models.TokenTypeIdentifier
	}

	// Check if this could be the start of a compound keyword
	if isCompoundKeywordStart(upperIdent) {
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
				for t.pos.Index < len(t.input) {
					r, size = utf8.DecodeRune(t.input[t.pos.Index:])
					if !isIdentifierChar(r) {
						_ = size // Mark as intentionally unused
						break
					}
					t.pos.AdvanceRune(r, size)
				}

				nextIdent := string(t.input[nextStart:t.pos.Index])
				compoundKeyword := ident + " " + nextIdent
				upperCompound := strings.ToUpper(compoundKeyword)

				// Check if it's a valid compound keyword
				if compoundType, ok := compoundKeywordTypes[upperCompound]; ok {
					return models.Token{
						Type:  compoundType,
						Word:  word,
						Value: compoundKeyword,
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
	"GROUPING SETS":    models.TokenTypeGroupingSets, // SQL-99 grouping operation
}

// Helper function to check if a word can start a compound keyword
func isCompoundKeywordStart(word string) bool {
	return compoundKeywordStarts[word]
}

// readQuotedIdentifier reads something like "MyColumn" with support for Unicode quotes
func (t *Tokenizer) readQuotedIdentifier() (models.Token, error) {
	// Get and normalize opening quote
	r, size := utf8.DecodeRune(t.input[t.pos.Index:])
	quote := normalizeQuote(r)
	startPos := t.pos.Clone()

	// Skip opening quote
	t.pos.AdvanceRune(r, size)

	var buf bytes.Buffer
	for t.pos.Index < len(t.input) {
		r, size := utf8.DecodeRune(t.input[t.pos.Index:])
		r = normalizeQuote(r)

		if r == quote {
			// Check for escaped quote
			if t.pos.Index+size < len(t.input) {
				nextR, nextSize := utf8.DecodeRune(t.input[t.pos.Index+size:])
				nextR = normalizeQuote(nextR)
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

			word := &models.Word{
				Value:      buf.String(),
				QuoteStyle: quote,
			}

			// Double-quoted strings are identifiers in SQL
			return models.Token{
				Type:  models.TokenTypeDoubleQuotedString,
				Word:  word,
				Value: buf.String(),
				Quote: quote,
			}, nil
		}

		if r == '\n' {
			return models.Token{}, errors.UnterminatedStringError(
				models.Location{Line: startPos.Line, Column: startPos.Column},
				string(t.input),
			)
		}

		// Handle regular characters
		buf.WriteRune(r)
		t.pos.Index += size
		t.pos.Column++
	}

	return models.Token{}, errors.UnterminatedStringError(
		t.toSQLPosition(startPos),
		string(t.input),
	)
}

// readBacktickIdentifier reads MySQL-style backtick identifiers
func (t *Tokenizer) readBacktickIdentifier() (models.Token, error) {
	startPos := t.pos.Clone()

	// Skip opening backtick
	t.pos.Index++
	t.pos.Column++

	var buf bytes.Buffer
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
		string(t.input),
	)
}

// readQuotedString handles the actual scanning of a single/double-quoted string
func (t *Tokenizer) readQuotedString(quote rune) (models.Token, error) {
	// Store start position for error reporting
	startPos := t.pos

	// Check for triple quotes
	if t.pos.Index+2 < len(t.input) {
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

	var buf bytes.Buffer
	for t.pos.Index < len(t.input) {
		r, size := utf8.DecodeRune(t.input[t.pos.Index:])
		r = normalizeQuote(r)

		if r == quote {
			// Check for escaped quote
			if t.pos.Index+size < len(t.input) {
				nextR, nextSize := utf8.DecodeRune(t.input[t.pos.Index+size:])
				nextR = normalizeQuote(nextR)
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

			value := buf.String()
			// For test compatibility, use appropriate token types based on quote style
			var tokenType models.TokenType
			if originalQuote == '\'' || originalQuote == '\u2018' || originalQuote == '\u2019' ||
				originalQuote == '«' || originalQuote == '»' {
				tokenType = models.TokenTypeSingleQuotedString // 124
			} else if originalQuote == '"' || originalQuote == '\u201C' || originalQuote == '\u201D' {
				tokenType = models.TokenTypeDoubleQuotedString // 124
			} else {
				tokenType = models.TokenTypeString // 20
			}
			return models.Token{
				Type:  tokenType,
				Value: value,
				Quote: originalQuote,
			}, nil
		}

		if r == '\\' {
			// Handle escape sequences
			if err := t.handleEscapeSequence(&buf); err != nil {
				return models.Token{}, errors.InvalidSyntaxError(
					fmt.Sprintf("invalid escape sequence: %v", err),
					models.Location{Line: t.pos.Line, Column: t.pos.Column},
					string(t.input),
				)
			}
			continue
		}

		if r == '\n' {
			buf.WriteRune(r)
			t.pos.Index += size
			t.pos.Line++
			t.pos.Column = 1
			continue
		}

		// Handle regular characters
		buf.WriteRune(r)
		t.pos.Index += size
		t.pos.Column++
	}

	return models.Token{}, errors.UnterminatedStringError(
		t.toSQLPosition(startPos),
		string(t.input),
	)
}

// readTripleQuotedString reads a triple-quoted string (e.g. "'abc"' or """abc""")
func (t *Tokenizer) readTripleQuotedString(quote rune) (models.Token, error) {
	// Store start position for error reporting
	startPos := t.pos

	// Skip opening triple quotes
	for i := 0; i < 3; i++ {
		r, size := utf8.DecodeRune(t.input[t.pos.Index:])
		t.pos.AdvanceRune(r, size)
	}

	var buf bytes.Buffer
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

				value := buf.String()
				if quote == '\'' {
					return models.Token{
						Type:  models.TokenTypeTripleSingleQuotedString,
						Value: value,
						Quote: quote,
					}, nil
				}
				return models.Token{
					Type:  models.TokenTypeTripleDoubleQuotedString,
					Value: value,
					Quote: quote,
				}, nil
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
		string(t.input),
	)
}

// handleEscapeSequence handles escape sequences in string literals
func (t *Tokenizer) handleEscapeSequence(buf *bytes.Buffer) error {
	t.pos.Index++
	t.pos.Column++

	if t.pos.Index >= len(t.input) {
		return errors.IncompleteStatementError(t.getCurrentPosition(), string(t.input))
	}

	r, size := utf8.DecodeRune(t.input[t.pos.Index:])
	switch r {
	case '\\', '"', '\'', '`':
		buf.WriteRune(r)
	case 'n':
		buf.WriteRune('\n')
	case 'r':
		buf.WriteRune('\r')
	case 't':
		buf.WriteRune('\t')
	default:
		return errors.InvalidSyntaxError(
			fmt.Sprintf("invalid escape sequence '\\%c'", r),
			t.getCurrentPosition(),
			string(t.input),
		)
	}

	t.pos.Index += size
	t.pos.Column++
	return nil
}

// readNumber reads an integer/float
func (t *Tokenizer) readNumber(buf []byte) (models.Token, error) {
	var start int
	if buf == nil {
		start = t.pos.Index
	} else {
		start = t.pos.Index - len(buf)
	}

	// Read integer part
	for t.pos.Index < len(t.input) {
		r, size := utf8.DecodeRune(t.input[t.pos.Index:])
		if r < '0' || r > '9' {
			break
		}
		t.pos.AdvanceRune(r, size)
	}

	if t.pos.Index >= len(t.input) {
		return models.Token{
			Type:  models.TokenTypeNumber,
			Value: string(t.input[start:t.pos.Index]),
		}, nil
	}

	// Look for decimal point
	r, size := utf8.DecodeRune(t.input[t.pos.Index:])
	if r == '.' {
		t.pos.AdvanceRune(r, size)

		// Must have at least one digit after decimal
		if t.pos.Index >= len(t.input) {
			value := string(t.input[start:t.pos.Index])
			return models.Token{}, errors.InvalidNumberError(value+" (expected digit after decimal point)", t.getCurrentPosition(), string(t.input))
		}

		r, _ = utf8.DecodeRune(t.input[t.pos.Index:])
		if r < '0' || r > '9' {
			value := string(t.input[start:t.pos.Index])
			return models.Token{}, errors.InvalidNumberError(value+" (expected digit after decimal point)", t.getCurrentPosition(), string(t.input))
		}

		// Read fractional part
		for t.pos.Index < len(t.input) {
			r, size = utf8.DecodeRune(t.input[t.pos.Index:])
			if r < '0' || r > '9' {
				_ = size // Mark as intentionally unused
				break
			}
			t.pos.AdvanceRune(r, size)
		}
	}

	// Look for exponent
	if t.pos.Index < len(t.input) {
		r, size = utf8.DecodeRune(t.input[t.pos.Index:])
		if r == 'e' || r == 'E' {
			t.pos.AdvanceRune(r, size)

			// Optional sign
			if t.pos.Index < len(t.input) {
				r, size = utf8.DecodeRune(t.input[t.pos.Index:])
				if r == '+' || r == '-' {
					t.pos.AdvanceRune(r, size)
				}
			}

			// Must have at least one digit
			if t.pos.Index >= len(t.input) {
				value := string(t.input[start:t.pos.Index])
				return models.Token{}, errors.InvalidNumberError(value+" (expected digit in exponent)", t.getCurrentPosition(), string(t.input))
			}

			r, _ = utf8.DecodeRune(t.input[t.pos.Index:])
			if r < '0' || r > '9' {
				value := string(t.input[start:t.pos.Index])
				return models.Token{}, errors.InvalidNumberError(value+" (expected digit in exponent)", t.getCurrentPosition(), string(t.input))
			}

			// Read exponent part
			for t.pos.Index < len(t.input) {
				r, size = utf8.DecodeRune(t.input[t.pos.Index:])
				if r < '0' || r > '9' {
					_ = size // Mark as intentionally unused
					break
				}
				t.pos.AdvanceRune(r, size)
			}
		}
	}

	return models.Token{
		Type:  models.TokenTypeNumber,
		Value: string(t.input[start:t.pos.Index]),
	}, nil
}

// readPunctuation picks out punctuation or operator tokens
func (t *Tokenizer) readPunctuation() (models.Token, error) {
	if t.pos.Index >= len(t.input) {
		return models.Token{}, errors.IncompleteStatementError(t.getCurrentPosition(), string(t.input))
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
			// Check for line comment: --
			if nxtR == '-' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				// Skip until end of line or EOF
				for t.pos.Index < len(t.input) {
					cr, csize := utf8.DecodeRune(t.input[t.pos.Index:])
					if cr == '\n' {
						t.pos.AdvanceRune(cr, csize) // Skip the newline too
						break
					}
					t.pos.AdvanceRune(cr, csize)
				}
				// Return the next token (skip the comment)
				t.skipWhitespace()
				return t.nextToken()
			}
		}
		return models.Token{Type: models.TokenTypeMinus, Value: "-"}, nil
	case '*':
		t.pos.AdvanceRune(r, size)
		return models.Token{Type: models.TokenTypeMul, Value: "*"}, nil
	case '/':
		t.pos.AdvanceRune(r, size)
		if t.pos.Index < len(t.input) {
			nxtR, nxtSize := utf8.DecodeRune(t.input[t.pos.Index:])
			// Check for block comment: /*
			if nxtR == '*' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				// Skip until */ or EOF
				for t.pos.Index < len(t.input) {
					cr, csize := utf8.DecodeRune(t.input[t.pos.Index:])
					if cr == '*' {
						t.pos.AdvanceRune(cr, csize)
						if t.pos.Index < len(t.input) {
							nr, ns := utf8.DecodeRune(t.input[t.pos.Index:])
							if nr == '/' {
								t.pos.AdvanceRune(nr, ns) // End of block comment
								break
							}
						}
					} else {
						t.pos.AdvanceRune(cr, csize)
					}
				}
				// Return the next token (skip the comment)
				t.skipWhitespace()
				return t.nextToken()
			}
		}
		return models.Token{Type: models.TokenTypeDiv, Value: "/"}, nil
	case '=':
		t.pos.AdvanceRune(r, size)
		if t.pos.Index < len(t.input) {
			nxtR, nxtSize := utf8.DecodeRune(t.input[t.pos.Index:])
			if nxtR == '>' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeRArrow, Value: "=>"}, nil
			}
		}
		return models.Token{Type: models.TokenTypeEq, Value: "="}, nil
	case '<':
		t.pos.AdvanceRune(r, size)
		if t.pos.Index < len(t.input) {
			nxtR, nxtSize := utf8.DecodeRune(t.input[t.pos.Index:])
			if nxtR == '=' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeLtEq, Value: "<="}, nil
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
		t.pos.AdvanceRune(r, size)
		if t.pos.Index < len(t.input) {
			nxtR, nxtSize := utf8.DecodeRune(t.input[t.pos.Index:])
			if nxtR == ':' {
				t.pos.AdvanceRune(nxtR, nxtSize)
				return models.Token{Type: models.TokenTypeDoubleColon, Value: "::"}, nil
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

			// Check for @@ (full text search operator)
			if nextR == '@' {
				t.pos.AdvanceRune(nextR, nextSize)
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
		t.pos.AdvanceRune(r, size)
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
				paramNum := string(t.input[start:t.pos.Index])
				return models.Token{Type: models.TokenTypePlaceholder, Value: "$" + paramNum}, nil
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
						if cr == '$' {
							break
						}
						if !isIdentifierChar(cr) {
							// Not a valid tag, treat as standalone $
							return models.Token{Type: models.TokenTypePlaceholder, Value: "$"}, nil
						}
						t.pos.AdvanceRune(cr, cs)
					}
				}
				// Check for closing $ of the tag
				if t.pos.Index >= len(t.input) {
					return models.Token{Type: models.TokenTypePlaceholder, Value: "$"}, nil
				}
				closingR, closingSize := utf8.DecodeRune(t.input[t.pos.Index:])
				if closingR != '$' {
					return models.Token{Type: models.TokenTypePlaceholder, Value: "$"}, nil
				}
				tag := string(t.input[tagStart:t.pos.Index])
				t.pos.AdvanceRune(closingR, closingSize) // consume closing $ of opening tag

				// Now read content until we find $tag$
				closingTag := "$" + tag + "$"
				contentStart := t.pos.Index
				for t.pos.Index < len(t.input) {
					if t.input[t.pos.Index] == '$' && t.pos.Index+len(closingTag) <= len(t.input) {
						candidate := string(t.input[t.pos.Index : t.pos.Index+len(closingTag)])
						if candidate == closingTag {
							content := string(t.input[contentStart:t.pos.Index])
							// Advance past the closing tag
							for i := 0; i < len(closingTag); {
								cr, cs := utf8.DecodeRune([]byte(closingTag[i:]))
								t.pos.AdvanceRune(cr, cs)
								i += cs
							}
							return models.Token{Type: models.TokenTypeDollarQuotedString, Value: content}, nil
						}
					}
					cr, cs := utf8.DecodeRune(t.input[t.pos.Index:])
					t.pos.AdvanceRune(cr, cs)
				}
				// Unterminated dollar-quoted string
				return models.Token{}, errors.UnterminatedStringError(
					models.Location{Line: t.pos.Line, Column: t.pos.Column},
					string(t.input),
				)
			}
		}
		// Standalone $ - treat as placeholder
		return models.Token{Type: models.TokenTypePlaceholder, Value: "$"}, nil
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

	return models.Token{}, errors.UnexpectedCharError(r, t.getCurrentPosition(), string(t.input))
}

// toSQLPosition converts an internal Position => a models.Location
func (t *Tokenizer) toSQLPosition(pos Position) models.Location {
	// Find the line containing pos
	line := 1
	lineStart := 0

	// Find the line number using lineStarts
	for i := 0; i < len(t.lineStarts); i++ {
		if t.lineStarts[i] > pos.Index {
			break
		}
		line = i + 1
		lineStart = t.lineStarts[i]
	}

	// Calculate column by counting characters from line start
	// Column is 1-based, so we start at 1
	column := 1
	for i := lineStart; i < pos.Index && i < len(t.input); i++ {
		if t.input[i] == '\t' {
			column += 4 // Treat tab as 4 spaces
		} else {
			column++
		}
	}

	// Ensure column is never less than 1
	if column < 1 {
		column = 1
	}

	return models.Location{
		Line:   line,
		Column: column,
	}
}

// getCurrentPosition returns the Location of the tokenizer's current byte index
func (t *Tokenizer) getCurrentPosition() models.Location {
	return t.toSQLPosition(t.pos)
}

// getLocation produces 1-based {Line, Column} for a given byte offset
func (t *Tokenizer) getLocation(pos int) models.Location {
	// Find the line containing pos
	line := 1
	column := 1
	lineStart := 0

	// Find the line number and start of the line
	for i := 0; i < pos && i < len(t.input); i++ {
		if t.input[i] == '\n' {
			line++
			lineStart = i + 1
		}
	}

	// Calculate column as offset from line start
	if pos >= lineStart {
		column = pos - lineStart + 1
	}

	return models.Location{
		Line:   line,
		Column: column,
	}
}

func isIdentifierChar(r rune) bool {
	return isUnicodeIdentifierPart(r)
}
