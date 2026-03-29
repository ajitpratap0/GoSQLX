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

// render_ddl.go - formatter render handlers for DDL statements that have
// dedicated AST nodes but previously fell through to the stmtSQL() fallback.
// Covered: CREATE/ALTER/DROP SEQUENCE, SHOW, DESCRIBE.

package formatter

import (
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// renderCreateSequence renders a CREATE [OR REPLACE] SEQUENCE [IF NOT EXISTS] statement.
func renderCreateSequence(s *ast.CreateSequenceStatement, opts ast.FormatOptions) string {
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString(f.kw("CREATE"))
	if s.OrReplace {
		sb.WriteString(" ")
		sb.WriteString(f.kw("OR REPLACE"))
	}
	sb.WriteString(" ")
	sb.WriteString(f.kw("SEQUENCE"))
	if s.IfNotExists {
		sb.WriteString(" ")
		sb.WriteString(f.kw("IF NOT EXISTS"))
	}
	if s.Name != nil && s.Name.Name != "" {
		sb.WriteString(" ")
		sb.WriteString(s.Name.Name)
	}
	writeSequenceOptionsFormatted(sb, s.Options, f)
	return sb.String()
}

// renderAlterSequence renders an ALTER SEQUENCE [IF EXISTS] statement.
func renderAlterSequence(s *ast.AlterSequenceStatement, opts ast.FormatOptions) string {
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString(f.kw("ALTER SEQUENCE"))
	if s.IfExists {
		sb.WriteString(" ")
		sb.WriteString(f.kw("IF EXISTS"))
	}
	if s.Name != nil && s.Name.Name != "" {
		sb.WriteString(" ")
		sb.WriteString(s.Name.Name)
	}
	writeSequenceOptionsFormatted(sb, s.Options, f)
	return sb.String()
}

// renderDropSequence renders a DROP SEQUENCE [IF EXISTS] statement.
func renderDropSequence(s *ast.DropSequenceStatement, opts ast.FormatOptions) string {
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString(f.kw("DROP SEQUENCE"))
	if s.IfExists {
		sb.WriteString(" ")
		sb.WriteString(f.kw("IF EXISTS"))
	}
	if s.Name != nil && s.Name.Name != "" {
		sb.WriteString(" ")
		sb.WriteString(s.Name.Name)
	}
	return sb.String()
}

// renderShow renders a SHOW statement (e.g., SHOW TABLES, SHOW DATABASES, SHOW CREATE TABLE x).
func renderShow(s *ast.ShowStatement, opts ast.FormatOptions) string {
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString(f.kw("SHOW"))
	if s.ShowType != "" {
		sb.WriteString(" ")
		sb.WriteString(f.kw(strings.ToUpper(s.ShowType)))
	}
	if s.ObjectName != "" {
		sb.WriteString(" ")
		sb.WriteString(s.ObjectName)
	}
	if s.From != "" {
		sb.WriteString(" ")
		sb.WriteString(f.kw("FROM"))
		sb.WriteString(" ")
		sb.WriteString(s.From)
	}
	return sb.String()
}

// renderDescribe renders a DESCRIBE/DESC statement.
func renderDescribe(s *ast.DescribeStatement, opts ast.FormatOptions) string {
	f := newNodeFormatter(opts)
	sb := f.sb

	sb.WriteString(f.kw("DESCRIBE"))
	if s.TableName != "" {
		sb.WriteString(" ")
		sb.WriteString(s.TableName)
	}
	return sb.String()
}

// writeSequenceOptionsFormatted appends formatted sequence options to the builder.
// It mirrors the logic in ast/sql.go writeSequenceOptions but uses the nodeFormatter
// for keyword casing.
func writeSequenceOptionsFormatted(sb *strings.Builder, opts ast.SequenceOptions, f *nodeFormatter) {
	if opts.StartWith != nil {
		sb.WriteString(" ")
		sb.WriteString(f.kw("START WITH"))
		sb.WriteString(" ")
		sb.WriteString(opts.StartWith.TokenLiteral())
	}
	if opts.IncrementBy != nil {
		sb.WriteString(" ")
		sb.WriteString(f.kw("INCREMENT BY"))
		sb.WriteString(" ")
		sb.WriteString(opts.IncrementBy.TokenLiteral())
	}
	if opts.MinValue != nil {
		sb.WriteString(" ")
		sb.WriteString(f.kw("MINVALUE"))
		sb.WriteString(" ")
		sb.WriteString(opts.MinValue.TokenLiteral())
	}
	if opts.MaxValue != nil {
		sb.WriteString(" ")
		sb.WriteString(f.kw("MAXVALUE"))
		sb.WriteString(" ")
		sb.WriteString(opts.MaxValue.TokenLiteral())
	}
	if opts.Cache != nil {
		sb.WriteString(" ")
		sb.WriteString(f.kw("CACHE"))
		sb.WriteString(" ")
		sb.WriteString(opts.Cache.TokenLiteral())
	} else if opts.NoCache {
		sb.WriteString(" ")
		sb.WriteString(f.kw("NOCACHE"))
	}
	switch opts.CycleMode {
	case ast.CycleBehavior:
		sb.WriteString(" ")
		sb.WriteString(f.kw("CYCLE"))
	case ast.NoCycleBehavior:
		sb.WriteString(" ")
		sb.WriteString(f.kw("NOCYCLE"))
	}
	if opts.RestartWith != nil {
		sb.WriteString(" ")
		sb.WriteString(f.kw("RESTART WITH"))
		sb.WriteString(" ")
		sb.WriteString(opts.RestartWith.TokenLiteral())
	} else if opts.Restart {
		sb.WriteString(" ")
		sb.WriteString(f.kw("RESTART"))
	}
}
