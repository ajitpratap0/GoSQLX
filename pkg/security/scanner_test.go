package security

import (
	"testing"
)

func TestTautologyRule(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		wantCount int
	}{
		{"or 1=1", "SELECT * FROM users WHERE id = 1 OR 1=1", 1},
		{"or 0=0", "SELECT * FROM users WHERE id = 1 OR 0=0", 1},
		{"or 'a'='a'", "SELECT * FROM users WHERE id = 1 OR 'a'='a'", 1},
		{"or true", "SELECT * FROM users WHERE active OR true", 1},
		{"clean", "SELECT * FROM users WHERE id = 1", 0},
		{"or with column", "SELECT * FROM users WHERE a = 1 OR b = 2", 0},
		{"case insensitive", "SELECT * FROM users WHERE id = 1 or 1=1", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &TautologyRule{}
			findings := r.Check(tt.sql)
			if len(findings) != tt.wantCount {
				t.Errorf("got %d findings, want %d; findings: %v", len(findings), tt.wantCount, findings)
			}
			for _, f := range findings {
				if f.RuleID != "SEC001" {
					t.Errorf("unexpected rule ID: %s", f.RuleID)
				}
				if f.Severity != SeverityCritical {
					t.Errorf("unexpected severity: %v", f.Severity)
				}
			}
		})
	}
}

func TestLikeInjectionRule(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		wantCount int
	}{
		{"concat plus", "SELECT * FROM users WHERE name LIKE '%' + @input + '%'", 1},
		{"concat pipe", "SELECT * FROM users WHERE name LIKE '%' || $input || '%'", 1},
		{"concat func", "SELECT * FROM users WHERE name LIKE CONCAT('%', input, '%')", 1},
		{"clean param", "SELECT * FROM users WHERE name LIKE $1", 0},
		{"clean literal", "SELECT * FROM users WHERE name LIKE '%test%'", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &LikeInjectionRule{}
			findings := r.Check(tt.sql)
			if len(findings) != tt.wantCount {
				t.Errorf("got %d findings, want %d; findings: %v", len(findings), tt.wantCount, findings)
			}
		})
	}
}

func TestUnionInjectionRule(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		wantCount int
	}{
		{"union select numbers", "SELECT id FROM users UNION SELECT 1, 2, 3", 1},
		{"union all select nulls", "SELECT id FROM users UNION ALL SELECT NULL, NULL, NULL", 1},
		{"union info schema", "SELECT id FROM users UNION SELECT table_name FROM information_schema.tables", 1},
		{"clean union", "SELECT id FROM users UNION SELECT id FROM admins", 0},
		{"no union", "SELECT * FROM users", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &UnionInjectionRule{}
			findings := r.Check(tt.sql)
			if len(findings) != tt.wantCount {
				t.Errorf("got %d findings, want %d; findings: %v", len(findings), tt.wantCount, findings)
			}
		})
	}
}

func TestScannerIntegration(t *testing.T) {
	scanner := NewScanner()

	// Clean SQL — no findings
	clean := "SELECT u.id, u.name FROM users u WHERE u.active = true ORDER BY u.name"
	findings := scanner.Scan(clean)
	if len(findings) != 0 {
		t.Errorf("expected no findings for clean SQL, got %d: %v", len(findings), findings)
	}

	// Vulnerable SQL — multiple findings
	vuln := "SELECT * FROM users WHERE id = 1 OR 1=1 UNION SELECT 1, 2, 3"
	findings = scanner.Scan(vuln)
	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings for vulnerable SQL, got %d: %v", len(findings), findings)
	}

	// Check line/column computation
	for _, f := range findings {
		if f.Line < 1 || f.Column < 1 {
			t.Errorf("finding %s has invalid position: line=%d col=%d", f.RuleID, f.Line, f.Column)
		}
	}
}

func TestScannerCustomRules(t *testing.T) {
	scanner := NewScannerWithRules(&TautologyRule{})
	if len(scanner.Rules()) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(scanner.Rules()))
	}

	findings := scanner.Scan("SELECT * FROM t WHERE 1=1 OR 1=1")
	if len(findings) == 0 {
		t.Error("expected findings")
	}
}

func TestScannerAddRule(t *testing.T) {
	scanner := NewScanner()
	initial := len(scanner.Rules())
	scanner.AddRule(&TautologyRule{})
	if len(scanner.Rules()) != initial+1 {
		t.Error("AddRule did not add rule")
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		s    Severity
		want string
	}{
		{SeverityInfo, "info"},
		{SeverityWarning, "warning"},
		{SeverityError, "error"},
		{SeverityCritical, "critical"},
		{Severity(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestPosToLineCol(t *testing.T) {
	sql := "SELECT *\nFROM users\nWHERE id = 1 OR 1=1"
	line, col := posToLineCol(sql, 0)
	if line != 1 || col != 1 {
		t.Errorf("pos 0: got line=%d col=%d, want 1,1", line, col)
	}

	// Position at 'F' in FROM (after newline)
	line, col = posToLineCol(sql, 9)
	if line != 2 || col != 1 {
		t.Errorf("pos 9: got line=%d col=%d, want 2,1", line, col)
	}
}

func BenchmarkScan(b *testing.B) {
	scanner := NewScanner()
	sql := "SELECT * FROM users WHERE id = 1 OR 1=1 UNION SELECT 1, 2, 3 FROM information_schema.tables WHERE name LIKE '%' + @input + '%'"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(sql)
	}
}

func BenchmarkScanClean(b *testing.B) {
	scanner := NewScanner()
	sql := "SELECT u.id, u.name, u.email FROM users u JOIN orders o ON u.id = o.user_id WHERE u.active = true ORDER BY o.created_at DESC LIMIT 50"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(sql)
	}
}
