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

package models

import "testing"

func TestLocation(t *testing.T) {
	tests := []struct {
		name     string
		location Location
		wantLine int
		wantCol  int
	}{
		{
			name:     "zero location",
			location: Location{Line: 0, Column: 0},
			wantLine: 0,
			wantCol:  0,
		},
		{
			name:     "1-based location",
			location: Location{Line: 1, Column: 1},
			wantLine: 1,
			wantCol:  1,
		},
		{
			name:     "arbitrary location",
			location: Location{Line: 42, Column: 17},
			wantLine: 42,
			wantCol:  17,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.location.Line != tt.wantLine {
				t.Errorf("Location.Line = %d, want %d", tt.location.Line, tt.wantLine)
			}
			if tt.location.Column != tt.wantCol {
				t.Errorf("Location.Column = %d, want %d", tt.location.Column, tt.wantCol)
			}
		})
	}
}

func TestNewSpan(t *testing.T) {
	start := Location{Line: 1, Column: 10}
	end := Location{Line: 1, Column: 20}

	span := NewSpan(start, end)

	if span.Start != start {
		t.Errorf("NewSpan().Start = %v, want %v", span.Start, start)
	}
	if span.End != end {
		t.Errorf("NewSpan().End = %v, want %v", span.End, end)
	}
}

func TestEmptySpan(t *testing.T) {
	span := EmptySpan()

	if span.Start.Line != 0 || span.Start.Column != 0 {
		t.Errorf("EmptySpan().Start = %v, want zero location", span.Start)
	}
	if span.End.Line != 0 || span.End.Column != 0 {
		t.Errorf("EmptySpan().End = %v, want zero location", span.End)
	}
}

func TestSpan(t *testing.T) {
	tests := []struct {
		name  string
		span  Span
		start Location
		end   Location
	}{
		{
			name:  "single line span",
			span:  Span{Start: Location{Line: 1, Column: 5}, End: Location{Line: 1, Column: 10}},
			start: Location{Line: 1, Column: 5},
			end:   Location{Line: 1, Column: 10},
		},
		{
			name:  "multi-line span",
			span:  Span{Start: Location{Line: 1, Column: 5}, End: Location{Line: 3, Column: 15}},
			start: Location{Line: 1, Column: 5},
			end:   Location{Line: 3, Column: 15},
		},
		{
			name:  "zero-length span",
			span:  Span{Start: Location{Line: 5, Column: 10}, End: Location{Line: 5, Column: 10}},
			start: Location{Line: 5, Column: 10},
			end:   Location{Line: 5, Column: 10},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.span.Start != tt.start {
				t.Errorf("Span.Start = %v, want %v", tt.span.Start, tt.start)
			}
			if tt.span.End != tt.end {
				t.Errorf("Span.End = %v, want %v", tt.span.End, tt.end)
			}
		})
	}
}

func BenchmarkNewSpan(b *testing.B) {
	start := Location{Line: 1, Column: 10}
	end := Location{Line: 1, Column: 20}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewSpan(start, end)
	}
}

func BenchmarkEmptySpan(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EmptySpan()
	}
}
