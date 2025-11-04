package errors

import (
	"strings"
	"testing"
)

func TestSuggestKeyword(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "exact match",
			input: "SELECT",
			want:  "SELECT",
		},
		{
			name:  "single character typo",
			input: "SELCT",
			want:  "SELECT",
		},
		{
			name:  "transposed characters",
			input: "FORM",
			want:  "FROM",
		},
		{
			name:  "case insensitive",
			input: "form",
			want:  "FROM",
		},
		{
			name:  "multiple typos",
			input: "SLECT",
			want:  "SELECT",
		},
		{
			name:  "common typo - WAHER",
			input: "WAHER",
			want:  "WHERE",
		},
		{
			name:  "common typo - JION",
			input: "JION",
			want:  "JOIN",
		},
		{
			name:  "common typo - UPDTE",
			input: "UPDTE",
			want:  "UPDATE",
		},
		{
			name:  "completely unrelated word",
			input: "SOMETHING",
			want:  "", // Should not suggest anything
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SuggestKeyword(tt.input)
			if got != tt.want {
				t.Errorf("SuggestKeyword(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestLevenshteinDistance(t *testing.T) {
	tests := []struct {
		s1   string
		s2   string
		want int
	}{
		{s1: "kitten", s2: "sitting", want: 3},
		{s1: "SELECT", s2: "SELECT", want: 0},
		{s1: "FORM", s2: "FROM", want: 2},
		{s1: "SELCT", s2: "SELECT", want: 1},
		{s1: "", s2: "abc", want: 3},
		{s1: "abc", s2: "", want: 3},
	}

	for _, tt := range tests {
		t.Run(tt.s1+"_"+tt.s2, func(t *testing.T) {
			got := levenshteinDistance(tt.s1, tt.s2)
			if got != tt.want {
				t.Errorf("levenshteinDistance(%q, %q) = %d, want %d", tt.s1, tt.s2, got, tt.want)
			}
		})
	}
}

func TestGenerateHint(t *testing.T) {
	tests := []struct {
		name     string
		code     ErrorCode
		expected string
		found    string
		wantHint string // Substring that should be in the hint
	}{
		{
			name:     "expected token with typo",
			code:     ErrCodeExpectedToken,
			expected: "FROM",
			found:    "FORM",
			wantHint: "Did you mean 'FROM'",
		},
		{
			name:     "unexpected token with suggestion",
			code:     ErrCodeUnexpectedToken,
			expected: "",
			found:    "SELCT",
			wantHint: "Did you mean 'SELECT'",
		},
		{
			name:     "unterminated string",
			code:     ErrCodeUnterminatedString,
			expected: "",
			found:    "",
			wantHint: "string literals are properly closed",
		},
		{
			name:     "missing clause",
			code:     ErrCodeMissingClause,
			expected: "FROM",
			found:    "",
			wantHint: "FROM",
		},
		{
			name:     "unsupported feature",
			code:     ErrCodeUnsupportedFeature,
			expected: "",
			found:    "",
			wantHint: "not yet supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateHint(tt.code, tt.expected, tt.found)
			if !strings.Contains(got, tt.wantHint) {
				t.Errorf("GenerateHint() = %q, should contain %q", got, tt.wantHint)
			}
		})
	}
}

func TestGetCommonHint(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want string
	}{
		{
			name: "missing from clause",
			key:  "missing_from",
			want: "SELECT statements require a FROM clause",
		},
		{
			name: "invalid join",
			key:  "invalid_join",
			want: "JOIN clauses must include ON or USING",
		},
		{
			name: "non-existent key",
			key:  "nonexistent",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetCommonHint(tt.key)
			if tt.want != "" && !strings.Contains(got, tt.want) {
				t.Errorf("GetCommonHint(%q) = %q, should contain %q", tt.key, got, tt.want)
			}
			if tt.want == "" && got != "" {
				t.Errorf("GetCommonHint(%q) = %q, want empty string", tt.key, got)
			}
		})
	}
}

func BenchmarkSuggestKeyword(b *testing.B) {
	inputs := []string{"FORM", "SELCT", "WAHER", "JION", "UPDTE"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		input := inputs[i%len(inputs)]
		_ = SuggestKeyword(input)
	}
}

func BenchmarkLevenshteinDistance(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = levenshteinDistance("FORM", "FROM")
	}
}
