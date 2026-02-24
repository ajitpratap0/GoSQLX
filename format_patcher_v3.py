import re

def main():
    with open("pkg/sql/ast/format.go", "r") as fn:
        content = fn.read()

    # Step 1: Replace inside methods, excluding formatExpr and formatStmt bodies
    def replacer(match):
        method_name = match.group(1)
        method_body = match.group(2)
        
        if method_name in ('formatExpr', 'formatStmt'):
            return f"func {method_name}{method_body}"
            
        # Does the method have opts FormatOptions or f *formatter?
        if 'opts FormatOptions' in method_body:
            arg = 'opts'
        else:
            arg = 'f.opts'
            
        method_body = re.sub(r'exprListSQL\(([^)]+)\)', lambda m: f'formatExprList({m.group(1)}, {arg})', method_body)
        method_body = re.sub(r'exprSQL\(([^)]+)\)', lambda m: f'formatExpr({m.group(1)}, {arg})', method_body)
        method_body = re.sub(r'stmtSQL\(([^)]+)\)', lambda m: f'formatStmt({m.group(1)}, {arg})', method_body)
        method_body = re.sub(r'tableRefSQL\(([^)]+)\)', lambda m: f'formatTableRef({m.group(1)}, f)', method_body)
        method_body = re.sub(r'joinSQL\(([^)]+)\)', lambda m: f'formatJoin({m.group(1)}, f)', method_body)
        method_body = re.sub(r'windowSpecSQL\(([^)]+)\)', lambda m: f'formatWindowSpec({m.group(1)}, f)', method_body)
        method_body = re.sub(r'windowFrameSQL\(([^)]+)\)', lambda m: f'formatWindowFrame({m.group(1)}, f)', method_body)
        method_body = re.sub(r'orderBySQL\(([^)]+)\)', lambda m: f'formatOrderBy({m.group(1)}, f)', method_body)
        method_body = re.sub(r'fetchSQL\(([^)]+)\)', lambda m: f'formatFetch({m.group(1)}, f)', method_body)
        method_body = re.sub(r'forSQL\(([^)]+)\)', lambda m: f'formatFor({m.group(1)}, f)', method_body)
        method_body = re.sub(r'onConflictSQL\(([^)]+)\)', lambda m: f'formatOnConflict({m.group(1)}, f)', method_body)
        method_body = re.sub(r'columnDefSQL\(([^)]+)\)', lambda m: f'formatColumnDef({m.group(1)}, f)', method_body)
        method_body = re.sub(r'tableConstraintSQL\(([^)]+)\)', lambda m: f'formatTableConstraint({m.group(1)}, f)', method_body)
        method_body = re.sub(r'columnConstraintSQL\(([^)]+)\)', lambda m: f'formatColumnConstraint({m.group(1)}, f)', method_body)
        method_body = re.sub(r'referenceSQL\(([^)]+)\)', lambda m: f'formatReference({m.group(1)}, f)', method_body)
        method_body = re.sub(r'alterActionSQL\(([^)]+)\)', lambda m: f'formatAlterAction({m.group(1)}, f)', method_body)
        method_body = re.sub(r'mergeActionSQL\(([^)]+)\)', lambda m: f'formatMergeAction({m.group(1)}, f)', method_body)
        # Note: formatCTE is already handled manually or we can inject it
        method_body = re.sub(r'cteSQL\(([^)]+)\)', lambda m: f'formatCTE({m.group(1)}, f)', method_body)
        
        return f"func {method_name}{method_body}"

    content = re.sub(r'func\s+([a-zA-Z0-9_]+)(\([^)]+\)\s*(?:[^{]+)?\s*\{.*?\n\})', replacer, content, flags=re.DOTALL)
    
    # Strip existing formatWith to replace with injected one
    idx = content.find("func formatWith(w *WithClause, f *formatter) string {")
    if idx != -1:
        content = content[:idx]

    helpers_ext = """
// ============================================================
// Formatter-aware Helper functions
// ============================================================

func formatExprList(exprs []Expression, opts FormatOptions) string {
	parts := make([]string, len(exprs))
	for i, e := range exprs {
		parts[i] = formatExpr(e, opts)
	}
	return strings.Join(parts, ", ")
}

func formatOrderBy(orders []OrderByExpression, f *formatter) string {
	parts := make([]string, len(orders))
	for i, o := range orders {
		s := formatExpr(o.Expression, f.opts)
		if !o.Ascending {
			s += " " + f.kw("DESC")
		}
		if o.NullsFirst != nil {
			if *o.NullsFirst {
				s += " " + f.kw("NULLS FIRST")
			} else {
				s += " " + f.kw("NULLS LAST")
			}
		}
		parts[i] = s
	}
	return strings.Join(parts, ", ")
}

func formatTableRef(t *TableReference, f *formatter) string {
	sb := &strings.Builder{}
	if t.Lateral {
		sb.WriteString(f.kw("LATERAL"))
		sb.WriteString(" ")
	}
	if t.Subquery != nil {
		sb.WriteString("(")
		sb.WriteString(formatStmt(t.Subquery, f.opts))
		sb.WriteString(")")
	} else {
		sb.WriteString(t.Name)
	}
	if t.Alias != "" {
		sb.WriteString(" ")
		sb.WriteString(t.Alias)
	}
	return sb.String()
}

func formatJoin(j *JoinClause, f *formatter) string {
	sb := &strings.Builder{}
	sb.WriteString(f.kw(j.Type))
	sb.WriteString(" ")
	sb.WriteString(f.kw("JOIN"))
	sb.WriteString(" ")
	sb.WriteString(formatTableRef(&j.Right, f))
	if j.Condition != nil {
		sb.WriteString(" ")
		sb.WriteString(f.kw("ON"))
		sb.WriteString(" ")
		sb.WriteString(formatExpr(j.Condition, f.opts))
	}
	return sb.String()
}

func formatWindowSpec(w *WindowSpec, f *formatter) string {
	var parts []string
	if w.Name != "" {
		parts = append(parts, w.Name)
	}
	if len(w.PartitionBy) > 0 {
		parts = append(parts, f.kw("PARTITION BY")+" "+formatExprList(w.PartitionBy, f.opts))
	}
	if len(w.OrderBy) > 0 {
		parts = append(parts, f.kw("ORDER BY")+" "+formatOrderBy(w.OrderBy, f))
	}
	if w.FrameClause != nil {
		parts = append(parts, formatWindowFrame(w.FrameClause, f))
	}
	return strings.Join(parts, " ")
}

func formatWindowFrame(wf *WindowFrame, f *formatter) string {
	if wf.End != nil {
		return fmt.Sprintf("%s %s %s %s %s", f.kw(wf.Type), f.kw("BETWEEN"), f.kw(wf.Start.Type), f.kw("AND"), f.kw(wf.End.Type))
	}
	return fmt.Sprintf("%s %s", f.kw(wf.Type), f.kw(wf.Start.Type))
}

func formatFetch(fc *FetchClause, f *formatter) string {
	sb := &strings.Builder{}
	if fc.OffsetValue != nil {
		fmt.Fprintf(sb, " %s %d %s", f.kw("OFFSET"), *fc.OffsetValue, f.kw("ROWS"))
	}
	fmt.Fprintf(sb, " %s %s", f.kw("FETCH"), f.kw(fc.FetchType))
	if fc.FetchValue != nil {
		fmt.Fprintf(sb, " %d", *fc.FetchValue)
	}
	if fc.IsPercent {
		sb.WriteString(" " + f.kw("PERCENT"))
	}
	sb.WriteString(" " + f.kw("ROWS"))
	if fc.WithTies {
		sb.WriteString(" " + f.kw("WITH TIES"))
	} else {
		sb.WriteString(" " + f.kw("ONLY"))
	}
	return sb.String()
}

func formatFor(fc *ForClause, f *formatter) string {
	sb := &strings.Builder{}
	sb.WriteString(" " + f.kw("FOR") + " ")
	sb.WriteString(f.kw(fc.LockType))
	if len(fc.Tables) > 0 {
		sb.WriteString(" " + f.kw("OF") + " ")
		sb.WriteString(strings.Join(fc.Tables, ", "))
	}
	if fc.NoWait {
		sb.WriteString(" " + f.kw("NOWAIT"))
	}
	if fc.SkipLocked {
		sb.WriteString(" " + f.kw("SKIP LOCKED"))
	}
	return sb.String()
}

func formatCTE(cte *CommonTableExpr, f *formatter) string {
	sb := &strings.Builder{}
	sb.WriteString(cte.Name)
	if len(cte.Columns) > 0 {
		sb.WriteString(" (")
		sb.WriteString(strings.Join(cte.Columns, ", "))
		sb.WriteString(")")
	}
	sb.WriteString(" " + f.kw("AS") + " ")
	if cte.Materialized != nil {
		if *cte.Materialized {
			sb.WriteString(f.kw("MATERIALIZED") + " ")
		} else {
			sb.WriteString(f.kw("NOT MATERIALIZED") + " ")
		}
	}
	sb.WriteString("(")
	sb.WriteString(formatStmt(cte.Statement, f.opts))
	sb.WriteString(")")
	return sb.String()
}

func formatOnConflict(oc *OnConflict, f *formatter) string {
	sb := &strings.Builder{}
	sb.WriteString(" " + f.kw("ON CONFLICT"))
	if len(oc.Target) > 0 {
		sb.WriteString(" (")
		sb.WriteString(formatExprList(oc.Target, f.opts))
		sb.WriteString(")")
	}
	if oc.Constraint != "" {
		sb.WriteString(" " + f.kw("ON CONSTRAINT") + " ")
		sb.WriteString(oc.Constraint)
	}
	if oc.Action.DoNothing {
		sb.WriteString(" " + f.kw("DO NOTHING"))
	} else if len(oc.Action.DoUpdate) > 0 {
		sb.WriteString(" " + f.kw("DO UPDATE SET") + " ")
		upds := make([]string, len(oc.Action.DoUpdate))
		for i, u := range oc.Action.DoUpdate {
			upds[i] = formatExpr(u.Column, f.opts) + " = " + formatExpr(u.Value, f.opts)
		}
		sb.WriteString(strings.Join(upds, ", "))
		if oc.Action.Where != nil {
			sb.WriteString(" " + f.kw("WHERE") + " ")
			sb.WriteString(formatExpr(oc.Action.Where, f.opts))
		}
	}
	return sb.String()
}

func formatColumnDef(c *ColumnDef, f *formatter) string {
	sb := &strings.Builder{}
	sb.WriteString(c.Name)
	sb.WriteString(" ")
	sb.WriteString(c.Type) // Should probably be upper based on kw()
	for _, con := range c.Constraints {
		con := con
		sb.WriteString(" ")
		sb.WriteString(formatColumnConstraint(&con, f))
	}
	return sb.String()
}

func formatColumnConstraint(c *ColumnConstraint, f *formatter) string {
	switch c.Type {
	case "NOT NULL", "UNIQUE", "PRIMARY KEY":
		return f.kw(c.Type)
	case "DEFAULT":
		return f.kw("DEFAULT") + " " + formatExpr(c.Default, f.opts)
	case "REFERENCES":
		if c.References != nil {
			return formatReference(c.References, f)
		}
		return f.kw("REFERENCES")
	case "CHECK":
		return f.kw("CHECK") + " (" + formatExpr(c.Check, f.opts) + ")"
	default:
		if c.AutoIncrement {
			return f.kw("AUTO_INCREMENT")
		}
		return f.kw(c.Type)
	}
}

func formatTableConstraint(tc *TableConstraint, f *formatter) string {
	sb := &strings.Builder{}
	if tc.Name != "" {
		sb.WriteString(f.kw("CONSTRAINT") + " ")
		sb.WriteString(tc.Name)
		sb.WriteString(" ")
	}
	switch tc.Type {
	case "PRIMARY KEY":
		sb.WriteString(f.kw("PRIMARY KEY") + " (")
		sb.WriteString(strings.Join(tc.Columns, ", "))
		sb.WriteString(")")
	case "UNIQUE":
		sb.WriteString(f.kw("UNIQUE") + " (")
		sb.WriteString(strings.Join(tc.Columns, ", "))
		sb.WriteString(")")
	case "FOREIGN KEY":
		sb.WriteString(f.kw("FOREIGN KEY") + " (")
		sb.WriteString(strings.Join(tc.Columns, ", "))
		sb.WriteString(") ")
		if tc.References != nil {
			sb.WriteString(formatReference(tc.References, f))
		}
	case "CHECK":
		sb.WriteString(f.kw("CHECK") + " (")
		sb.WriteString(formatExpr(tc.Check, f.opts))
		sb.WriteString(")")
	default:
		sb.WriteString(tc.Type)
	}
	return sb.String()
}

func formatReference(r *ReferenceDefinition, f *formatter) string {
	sb := &strings.Builder{}
	sb.WriteString(f.kw("REFERENCES") + " ")
	sb.WriteString(r.Table)
	if len(r.Columns) > 0 {
		sb.WriteString(" (")
		sb.WriteString(strings.Join(r.Columns, ", "))
		sb.WriteString(")")
	}
	if r.OnDelete != "" {
		sb.WriteString(" " + f.kw("ON DELETE") + " ")
		sb.WriteString(f.kw(r.OnDelete))
	}
	if r.OnUpdate != "" {
		sb.WriteString(" " + f.kw("ON UPDATE") + " ")
		sb.WriteString(f.kw(r.OnUpdate))
	}
	return sb.String()
}

func formatAlterAction(a *AlterTableAction, f *formatter) string {
	switch a.Type {
	case "ADD COLUMN":
		s := f.kw("ADD COLUMN") + " "
		if a.ColumnDef != nil {
			s += formatColumnDef(a.ColumnDef, f)
		}
		return s
	case "DROP COLUMN":
		return f.kw("DROP COLUMN") + " " + a.ColumnName
	case "ADD CONSTRAINT":
		if a.Constraint != nil {
			return f.kw("ADD") + " " + formatTableConstraint(a.Constraint, f)
		}
		return f.kw("ADD CONSTRAINT")
	default:
		return f.kw(a.Type)
	}
}

func formatMergeAction(a *MergeAction, f *formatter) string {
	switch a.ActionType {
	case "UPDATE":
		sets := make([]string, len(a.SetClauses))
		for i, s := range a.SetClauses {
			sets[i] = s.Column + " = " + formatExpr(s.Value, f.opts)
		}
		return f.kw("UPDATE SET") + " " + strings.Join(sets, ", ")
	case "INSERT":
		var sb strings.Builder
		sb.WriteString(f.kw("INSERT"))
		if a.DefaultValues {
			sb.WriteString(" " + f.kw("DEFAULT VALUES"))
		} else {
			if len(a.Columns) > 0 {
				sb.WriteString(" (")
				sb.WriteString(strings.Join(a.Columns, ", "))
				sb.WriteString(")")
			}
			if len(a.Values) > 0 {
				sb.WriteString(" " + f.kw("VALUES") + " (")
				vals := make([]string, len(a.Values))
				for i, v := range a.Values {
					vals[i] = formatExpr(v, f.opts)
				}
				sb.WriteString(strings.Join(vals, ", "))
				sb.WriteString(")")
			}
		}
		return sb.String()
	case "DELETE":
		return f.kw("DELETE")
	default:
		return f.kw(a.ActionType)
	}
}

func formatWith(w *WithClause, f *formatter) string {
	if w == nil {
		return ""
	}
	sb := &strings.Builder{}
	sb.WriteString(f.kw("WITH") + " ")
	if w.Recursive {
		sb.WriteString(f.kw("RECURSIVE") + " ")
	}
	ctes := make([]string, len(w.CTEs))
	for i, cte := range w.CTEs {
		ctes[i] = formatCTE(cte, f)
	}
	sb.WriteString(strings.Join(ctes, ", "))
	return sb.String()
}
"""

    with open("pkg/sql/ast/format.go", "w") as out:
        out.write(content + "\n" + helpers_ext)

if __name__ == "__main__":
    main()
