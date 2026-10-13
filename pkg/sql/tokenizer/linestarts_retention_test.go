package tokenizer

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
)

// spanProjection reduces tokens to the fields that must be identical between a
// recycled tokenizer and a fresh one.
type spanProjection struct {
	Type  models.TokenType
	Value string
	Start models.Location
	End   models.Location
}

func projectSpans(toks []models.TokenWithSpan) []spanProjection {
	out := make([]spanProjection, len(toks))
	for i, tk := range toks {
		out[i] = spanProjection{tk.Token.Type, tk.Token.Value, tk.Start, tk.End}
	}
	return out
}

func assertLineStartsReset(t *testing.T, tkz *Tokenizer) {
	t.Helper()
	if len(tkz.lineStarts) != 1 || tkz.lineStarts[0] != 0 {
		t.Fatalf("lineStarts after Reset = %v, want [0]", tkz.lineStarts)
	}
}

func TestReset_DropsLargeLineStarts(t *testing.T) {
	tkz, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// (a) A small multi-line input keeps its lineStarts capacity for reuse.
	if _, err := tkz.TokenizeString("SELECT\n  a,\n  b\nFROM t"); err != nil {
		t.Fatalf("TokenizeString: %v", err)
	}
	c := cap(tkz.lineStarts)
	tkz.Reset()
	assertLineStartsReset(t, tkz)
	if cap(tkz.lineStarts) != c {
		t.Errorf("small lineStarts cap changed across Reset: %d -> %d", c, cap(tkz.lineStarts))
	}

	// (b) An input with many lines grows lineStarts past the threshold; Reset
	// must drop it.
	big := "SELECT" + strings.Repeat("\n", 4*maxRetainedLineStarts) + " 1"
	if _, err := tkz.TokenizeString(big); err != nil {
		t.Fatalf("TokenizeString(big): %v", err)
	}
	if cap(tkz.lineStarts) <= maxRetainedLineStarts {
		t.Fatalf("precondition: cap(lineStarts) = %d, want > %d", cap(tkz.lineStarts), maxRetainedLineStarts)
	}
	tkz.Reset()
	assertLineStartsReset(t, tkz)
	if cap(tkz.lineStarts) > maxRetainedLineStarts {
		t.Errorf("cap(lineStarts) after Reset = %d, want <= %d", cap(tkz.lineStarts), maxRetainedLineStarts)
	}

	// (c) Positions after a drop match a fresh tokenizer.
	const sql = "SELECT\n  a,\n  b\nFROM t\nWHERE x = 1"
	got, err := tkz.TokenizeString(sql)
	if err != nil {
		t.Fatalf("TokenizeString after drop: %v", err)
	}
	gotProj := projectSpans(got)
	fresh, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	want, err := fresh.TokenizeString(sql)
	if err != nil {
		t.Fatalf("fresh TokenizeString: %v", err)
	}
	if !reflect.DeepEqual(gotProj, projectSpans(want)) {
		t.Errorf("tokens after lineStarts drop differ from a fresh tokenizer:\n got  %+v\n want %+v", gotProj, projectSpans(want))
	}
}

func TestReset_LineStartsRetentionThreshold(t *testing.T) {
	tests := []struct {
		name     string
		cap      int // 0 means a nil slice
		wantKeep bool
	}{
		{"nil", 0, false},
		{"cap1", 1, true},
		{"cap16", 16, true},
		{"belowMax", maxRetainedLineStarts - 1, true},
		{"atMax", maxRetainedLineStarts, true},
		{"aboveMax", maxRetainedLineStarts + 1, false},
		{"fourTimesMax", 4 * maxRetainedLineStarts, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tkz, err := New()
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			switch {
			case tt.cap == 0:
				tkz.lineStarts = nil
			case tt.cap == 1:
				tkz.lineStarts = make([]int, 1, 1)
			default:
				tkz.lineStarts = make([]int, 3, tt.cap)
			}
			tkz.Reset()
			assertLineStartsReset(t, tkz)
			switch {
			case tt.wantKeep && cap(tkz.lineStarts) != tt.cap:
				t.Errorf("cap = %d, want kept %d", cap(tkz.lineStarts), tt.cap)
			case !tt.wantKeep && cap(tkz.lineStarts) != 16:
				t.Errorf("cap = %d, want fresh 16", cap(tkz.lineStarts))
			}
		})
	}
}

// TestReset_LineStartsIssue614Repro is the scenario from issue #614: one
// input with millions of newlines must not leave a huge backing array in a
// pooled tokenizer. It allocates about 72 MB, so it is skipped in -short mode.
func TestReset_LineStartsIssue614Repro(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates ~72 MB; skipped in -short mode")
	}
	tk := GetTokenizer()
	defer PutTokenizer(tk)

	big := "SELECT" + strings.Repeat("\n", 8_000_000) + " 1"
	toks, err := tk.Tokenize([]byte(big))
	if err != nil {
		t.Fatalf("Tokenize: %v", err)
	}
	if len(toks) == 0 {
		t.Fatal("Tokenize returned no tokens")
	}
	if cap(tk.lineStarts) <= maxRetainedLineStarts {
		t.Fatalf("precondition: cap(lineStarts) = %d, want > %d", cap(tk.lineStarts), maxRetainedLineStarts)
	}
	tk.Reset()
	if cap(tk.lineStarts) > maxRetainedLineStarts {
		t.Errorf("cap(lineStarts) after Reset = %d, want <= %d", cap(tk.lineStarts), maxRetainedLineStarts)
	}
}
