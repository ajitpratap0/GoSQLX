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

package parser

import "github.com/ajitpratap0/GoSQLX/pkg/models"

// maintenanceEnd selects a complete dialect grammar. Without a dialect it
// accepts the union, choosing the longest successful form rather than mixing
// options from different dialects. The caller checks the remaining tokens.
func (p *Parser) maintenanceEnd(start int, postgres, redshift, sqlite func(*txnCursor) error) (int, error) {
	mask := p.alterMask()
	best := -1
	var firstErr error
	for _, form := range []struct {
		dialect alterDialects
		parse   func(*txnCursor) error
	}{{dialectPostgres, postgres}, {dialectRedshift, redshift}, {dialectSQLite, sqlite}} {
		if mask&form.dialect == 0 {
			continue
		}
		c := txnCursor{p: p, i: start + 1, mask: mask}
		if err := form.parse(&c); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		} else if c.i > best {
			best = c.i
		}
	}
	if best >= 0 {
		return best, nil
	}
	return 0, firstErr
}

func (p *Parser) vacuumEnd(start int) (int, error) {
	return p.maintenanceEnd(start, (*txnCursor).postgresVacuum, (*txnCursor).redshiftVacuum, (*txnCursor).sqliteVacuum)
}

func (p *Parser) analyzeEnd(start int) (int, error) {
	return p.maintenanceEnd(start, (*txnCursor).postgresAnalyze, (*txnCursor).redshiftAnalyze, (*txnCursor).sqliteAnalyze)
}

// maintenanceNameAt excludes statement starters so a bare maintenance command
// does not swallow a following statement's first word as its optional table.
func (c *txnCursor) maintenanceNameAt() bool {
	return c.p.isNamePartAt(c.i) && !implicitStartWords[c.word()]
}

// maintenanceGroup consumes balanced options or column lists. Their contents
// are kept as written, like the parenthesized COPY options.
func (c *txnCursor) maintenanceGroup() error {
	if c.typeAt(c.i) != models.TokenTypeLParen {
		return nil
	}
	end := c.p.groupEnd(c.i)
	if end < 0 {
		return c.fail(")")
	}
	c.i = end
	return nil
}

func (c *txnCursor) maintenanceTable(columns bool) error {
	if !c.maintenanceNameAt() {
		return c.fail("table name")
	}
	c.i = c.p.nameEnd(c.i)
	if columns {
		return c.maintenanceGroup()
	}
	return nil
}

// postgresTables consumes [ONLY] qualified_name [(columns)] [, ...].
func (c *txnCursor) postgresTables() error {
	if c.word() != "ONLY" && !c.maintenanceNameAt() {
		return nil
	}
	for {
		c.accept("ONLY")
		if err := c.maintenanceTable(true); err != nil {
			return err
		}
		if c.typeAt(c.i) != models.TokenTypeComma {
			return nil
		}
		c.i++
	}
}

func (c *txnCursor) postgresVacuum() error {
	if c.typeAt(c.i) == models.TokenTypeLParen {
		if err := c.maintenanceGroup(); err != nil {
			return err
		}
	} else {
		// Legacy options are accepted in any order, once each.
		var seen uint8
		for {
			var bit uint8
			switch c.word() {
			case "FULL":
				bit = 1
			case "FREEZE":
				bit = 2
			case "VERBOSE":
				bit = 4
			case "ANALYZE":
				bit = 8
			}
			if bit == 0 || seen&bit != 0 {
				break
			}
			seen |= bit
			c.i++
		}
	}
	return c.postgresTables()
}

func (c *txnCursor) postgresAnalyze() error {
	if c.typeAt(c.i) == models.TokenTypeLParen {
		if err := c.maintenanceGroup(); err != nil {
			return err
		}
	} else {
		c.accept("VERBOSE")
	}
	return c.postgresTables()
}

func (c *txnCursor) redshiftVacuum() error {
	switch c.word() {
	case "SORT", "DELETE":
		c.i++
		if err := c.expect("ONLY"); err != nil {
			return err
		}
	case "FULL", "REINDEX", "RECLUSTER":
		c.i++
	}
	if c.word() != "TO" && c.word() != "BOOST" && c.maintenanceNameAt() {
		if err := c.maintenanceTable(false); err != nil {
			return err
		}
	}
	if c.accept("TO") {
		if err := c.maintenanceNumber(); err != nil {
			return err
		}
		if err := c.expect("PERCENT"); err != nil {
			return err
		}
	}
	c.accept("BOOST")
	return nil
}

func (c *txnCursor) redshiftAnalyze() error {
	compression := c.accept("COMPRESSION")
	if !compression {
		c.accept("VERBOSE")
	}
	if c.word() != "PREDICATE" && c.word() != "ALL" && c.word() != "COMPROWS" && c.maintenanceNameAt() {
		if err := c.maintenanceTable(true); err != nil {
			return err
		}
	}
	if compression {
		if c.accept("COMPROWS") {
			return c.maintenanceNumber()
		}
	} else if c.accept("PREDICATE") || c.accept("ALL") {
		return c.expect("COLUMNS")
	}
	return nil
}

func (c *txnCursor) maintenanceNumber() error {
	if c.typeAt(c.i) != models.TokenTypeNumber {
		return c.fail("number")
	}
	c.i++
	return nil
}

func (c *txnCursor) sqliteVacuum() error {
	if c.word() != "INTO" && c.maintenanceNameAt() {
		c.i++ // SQLite accepts a single schema identifier here.
	}
	if c.accept("INTO") {
		switch {
		case c.copyString():
		case c.typeAt(c.i) == models.TokenTypePlaceholder:
			c.i++
		case c.maintenanceNameAt():
			c.i = c.p.nameEnd(c.i)
		default:
			return c.fail("string, placeholder or name")
		}
	}
	return nil
}

func (c *txnCursor) sqliteAnalyze() error {
	if c.maintenanceNameAt() {
		end := c.p.nameEnd(c.i)
		// SQLite permits only [schema.]object, unlike PostgreSQL names.
		if end > c.i+3 {
			end = c.i + 3
		}
		c.i = end
	}
	return nil
}

// listenEnd handles LISTEN, UNLISTEN and NOTIFY. Channels are single names;
// NOTIFY's only optional argument is a string payload.
func (p *Parser) listenEnd(start int) (int, error) {
	c := txnCursor{p: p, i: start + 1, mask: p.alterMask()}
	kind := p.utilityWord(start)
	if kind == "UNLISTEN" && (c.typeAt(c.i) == models.TokenTypeMul || c.typeAt(c.i) == models.TokenTypeAsterisk) {
		return c.i + 1, nil
	}
	if !c.maintenanceNameAt() {
		return 0, c.fail("channel name")
	}
	c.i++
	if kind == "NOTIFY" && c.typeAt(c.i) == models.TokenTypeComma {
		c.i++
		if !c.copyString() {
			return 0, c.fail("string payload")
		}
	}
	return c.i, nil
}
