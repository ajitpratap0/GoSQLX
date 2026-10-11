package tokenizer

// Tests for the allocation-free keyword upper-casing path in readIdentifier.
//
// They pin three things:
//   - every keyword key classifies the same however it is cased (lower/upper/mixed);
//   - identifiers at and just past the stack-buffer length still classify as
//     identifiers, and non-ASCII identifiers keep strings.ToUpper behaviour;
//   - folding an identifier's case no longer allocates once per word (the point of
//     the change: the old per-word strings.ToUpper allocated for every lowercase
//     table/column name).

import (
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

func kcAllTokens(t *testing.T, sql string) []models.Token {
	t.Helper()
	tkz, err := New()
	if err != nil {
		t.Fatalf("New(): %v", err)
	}
	toks, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Tokenize(%q): %v", sql, err)
	}
	out := make([]models.Token, 0, len(toks))
	for _, tok := range toks {
		if tok.Token.Type == models.TokenTypeEOF {
			continue
		}
		out = append(out, tok.Token)
	}
	return out
}

func kcTypes(t *testing.T, sql string) []models.TokenType {
	t.Helper()
	toks := kcAllTokens(t, sql)
	out := make([]models.TokenType, len(toks))
	for i, tok := range toks {
		out[i] = tok.Type
	}
	return out
}

func kcTypesEqual(a, b []models.TokenType) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestKeywordCaseParity checks that every keyword, whether written lower, upper or
// mixed case, produces the same sequence of token types.
func TestKeywordCaseParity(t *testing.T) {
	keys := make(map[string]struct{}, len(keywordTokenTypes)+len(compoundKeywordStarts))
	for k := range keywordTokenTypes {
		keys[k] = struct{}{}
	}
	for k := range compoundKeywordStarts {
		keys[k] = struct{}{}
	}

	for kw := range keys {
		mixed := strings.ToLower(kw[:1]) + strings.ToUpper(kw[1:])
		variants := []string{strings.ToLower(kw), strings.ToUpper(kw), mixed}
		base := kcTypes(t, variants[0])
		for _, v := range variants[1:] {
			got := kcTypes(t, v)
			if !kcTypesEqual(base, got) {
				t.Errorf("keyword %q: %q -> %v but %q -> %v", kw, variants[0], base, v, got)
			}
		}
		// A bare keyword should classify as its registered type.
		if want, ok := keywordTokenTypes[strings.ToUpper(kw)]; ok && len(base) == 1 && base[0] != want {
			t.Errorf("keyword %q: got type %v, want %v", kw, base[0], want)
		}
	}
}

// TestIdentifierLookupBufferBoundary checks an identifier exactly at the stack
// buffer length and one byte past it. Neither can be a keyword, so both must stay
// a single identifier token and keep their exact text.
func TestIdentifierLookupBufferBoundary(t *testing.T) {
	for _, n := range []int{upperKeywordBufLen, upperKeywordBufLen + 1} {
		ident := strings.Repeat("a", n)
		toks := kcAllTokens(t, ident)
		if len(toks) != 1 {
			t.Fatalf("len %d: got %d tokens, want 1", n, len(toks))
		}
		if toks[0].Type != models.TokenTypeIdentifier {
			t.Errorf("len %d: type = %v, want TokenTypeIdentifier", n, toks[0].Type)
		}
		if toks[0].Value != ident {
			t.Errorf("len %d: value = %q, want %q", n, toks[0].Value, ident)
		}
	}
}

// TestNonASCIIIdentifierCaseFolding pins the fallback behaviour: non-ASCII
// identifiers keep the strings.ToUpper path, so a plain non-ASCII name stays an
// identifier and the historical U+017F 'ſ' -> 'S' folding is unchanged.
func TestNonASCIIIdentifierCaseFolding(t *testing.T) {
	for _, name := range []string{"café", "CAFÉ", "Café", "naïve"} {
		toks := kcAllTokens(t, name)
		if len(toks) != 1 || toks[0].Type != models.TokenTypeIdentifier {
			t.Errorf("%q should be a single identifier, got %v", name, toks)
		}
	}
	// 'ſelect' has always been folded to SELECT via strings.ToUpper.
	if got := kcTypes(t, "ſelect"); len(got) != 1 || got[0] != models.TokenTypeSelect {
		t.Errorf("ſelect = %v, want [TokenTypeSelect]", got)
	}
}

// TestLowercaseIdentifiersDoNotAllocatePerWord is the regression guard for the
// change. The old code ran strings.ToUpper on every word, which allocates for each
// word containing a lowercase letter; the new path folds ASCII into a stack buffer
// and does not. So a lowercase query must not allocate materially more than the
// byte-for-byte equal uppercase query.
func TestLowercaseIdentifiersDoNotAllocatePerWord(t *testing.T) {
	const words = 60
	lower := strings.TrimSpace(strings.Repeat("alpha ", words))
	upper := strings.ToUpper(lower)

	measure := func(sql string) float64 {
		return testing.AllocsPerRun(50, func() {
			tkz, err := New()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tkz.Tokenize([]byte(sql)); err != nil {
				t.Fatal(err)
			}
		})
	}

	lowerAllocs := measure(lower)
	upperAllocs := measure(upper)
	// Before the change the gap is about one allocation per lowercase word
	// (~60 here); after it the two queries allocate the same amount.
	if lowerAllocs-upperAllocs >= 8 {
		t.Fatalf("lowercase query allocates %.0f more than the equal uppercase query (%.0f vs %.0f): the per-word strings.ToUpper in readIdentifier is back",
			lowerAllocs-upperAllocs, lowerAllocs, upperAllocs)
	}
}
