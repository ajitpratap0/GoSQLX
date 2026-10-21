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

package highlight

import "strings"

// Style is the presentation of one category.
type Style struct {
	// Color is a CSS hex color, "#RRGGBB" or "#RGB". Empty or malformed
	// values mean "use the default foreground".
	Color     string
	Bold      bool
	Italic    bool
	Underline bool
}

// Theme maps categories to styles. Categories without an entry render with
// the default style.
type Theme struct {
	Name   string
	Styles map[Category]Style
}

// Style returns the style for c, or the zero Style when the theme has none.
func (t Theme) Style(c Category) Style {
	return t.Styles[c]
}

// DarkTheme returns the default theme, tuned for dark backgrounds.
// Each call returns a fresh copy that the caller may modify.
func DarkTheme() Theme {
	return Theme{Name: "dark", Styles: map[Category]Style{
		Keyword:          {Color: "#569CD6", Bold: true},
		Function:         {Color: "#DCDCAA"},
		DataType:         {Color: "#4EC9B0"},
		Identifier:       {Color: "#9CDCFE"},
		QuotedIdentifier: {Color: "#9CDCFE"},
		String:           {Color: "#CE9178"},
		Number:           {Color: "#B5CEA8"},
		Constant:         {Color: "#569CD6"},
		Operator:         {Color: "#D4D4D4"},
		Punctuation:      {Color: "#A0A0A0"},
		Comment:          {Color: "#6A9955", Italic: true},
		Placeholder:      {Color: "#C586C0"},
		Error:            {Color: "#F44747", Underline: true},
	}}
}

// LightTheme returns a theme tuned for light backgrounds.
// Each call returns a fresh copy that the caller may modify.
func LightTheme() Theme {
	return Theme{Name: "light", Styles: map[Category]Style{
		Keyword:          {Color: "#0000FF", Bold: true},
		Function:         {Color: "#795E26"},
		DataType:         {Color: "#267F99"},
		Identifier:       {Color: "#001080"},
		QuotedIdentifier: {Color: "#001080"},
		String:           {Color: "#A31515"},
		Number:           {Color: "#098658"},
		Constant:         {Color: "#0000FF"},
		Operator:         {Color: "#000000"},
		Punctuation:      {Color: "#444444"},
		Comment:          {Color: "#008000", Italic: true},
		Placeholder:      {Color: "#AF00DB"},
		Error:            {Color: "#CD3131", Underline: true},
	}}
}

// MonoTheme returns a colorless theme that uses only bold, italic and
// underline, for terminals or documents where color is unwanted.
// Each call returns a fresh copy that the caller may modify.
func MonoTheme() Theme {
	return Theme{Name: "mono", Styles: map[Category]Style{
		Keyword:  {Bold: true},
		Function: {Bold: true},
		Comment:  {Italic: true},
		Error:    {Underline: true},
	}}
}

// ThemeNames lists the built-in theme names accepted by ThemeByName.
func ThemeNames() []string {
	return []string{"dark", "light", "mono"}
}

// ThemeByName returns a fresh copy of the built-in theme with the given
// case-insensitive name.
func ThemeByName(name string) (Theme, bool) {
	switch strings.ToLower(name) {
	case "dark", "":
		return DarkTheme(), true
	case "light":
		return LightTheme(), true
	case "mono":
		return MonoTheme(), true
	}
	return Theme{}, false
}

// parseHex parses "#RRGGBB" or "#RGB". It rejects anything else so theme
// colors can never inject CSS or escape sequences.
func parseHex(s string) (r, g, b uint8, ok bool) {
	if len(s) != 7 && len(s) != 4 || s[0] != '#' {
		return 0, 0, 0, false
	}
	var v [6]uint8
	digits := s[1:]
	for i := 0; i < len(digits); i++ {
		c := digits[i]
		switch {
		case c >= '0' && c <= '9':
			v[i] = c - '0'
		case c >= 'a' && c <= 'f':
			v[i] = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v[i] = c - 'A' + 10
		default:
			return 0, 0, 0, false
		}
	}
	if len(digits) == 3 {
		return v[0] * 17, v[1] * 17, v[2] * 17, true
	}
	return v[0]<<4 | v[1], v[2]<<4 | v[3], v[4]<<4 | v[5], true
}
