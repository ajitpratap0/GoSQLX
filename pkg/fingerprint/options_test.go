// Copyright 2026 GoSQLX Authors
// SPDX-License-Identifier: Apache-2.0

package fingerprint_test

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ajitpratap0/GoSQLX/internal/benchcorpus"
	"github.com/ajitpratap0/GoSQLX/pkg/fingerprint"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/keywords"
)

func TestOptions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		opts    fingerprint.Options
		wantErr string
	}{
		{"default", fingerprint.Options{}, ""},
		{"legacy", fingerprint.Options{Mode: fingerprint.ModeLegacy}, ""},
		{"mysql", fingerprint.Options{Dialect: keywords.DialectMySQL}, ""},
		{"legacy_mysql", fingerprint.Options{Mode: fingerprint.ModeLegacy, Dialect: keywords.DialectMySQL}, ""},
		{"unknown_mode", fingerprint.Options{Mode: 255}, "fingerprint: unknown mode 255"},
		{"unsupported_dialect", fingerprint.Options{Dialect: "bogus"}, "fingerprint: unsupported dialect \"bogus\""},
		{"legacy_unsupported_dialect", fingerprint.Options{Mode: fingerprint.ModeLegacy, Dialect: "bogus"}, "fingerprint: unsupported dialect \"bogus\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, fn := range []struct {
				name string
				call func(string, fingerprint.Options) (string, error)
			}{{"normalize", fingerprint.NormalizeWithOptions}, {"fingerprint", fingerprint.FingerprintWithOptions}} {
				got, err := fn.call("SELECT 1", tc.opts)
				if tc.wantErr != "" {
					if err == nil || err.Error() != tc.wantErr || got != "" {
						t.Errorf("%s = (%q, %v), want empty and %q", fn.name, got, err, tc.wantErr)
					}
				} else if err != nil || got == "" {
					t.Errorf("%s = (%q, %v), want nonempty success", fn.name, got, err)
				}
			}
		})
	}
	for _, mode := range []fingerprint.Mode{fingerprint.ModeTokens, fingerprint.ModeLegacy} {
		t.Run("dialect_wiring", func(t *testing.T) {
			got, err := fingerprint.NormalizeWithOptions("SELECT 1 # mysql comment", fingerprint.Options{Mode: mode, Dialect: keywords.DialectMySQL})
			if err != nil || got != "SELECT ?" {
				t.Fatalf("MySQL normalization = (%q, %v), want SELECT ?", got, err)
			}
		})
		t.Run("sqlserver_parser_wiring", func(t *testing.T) {
			got, err := fingerprint.NormalizeWithOptions("SELECT TOP 10 a FROM t", fingerprint.Options{Mode: mode, Dialect: keywords.DialectSQLServer})
			if err != nil || got == "" {
				t.Fatalf("SQL Server normalization = (%q, %v), want nonempty success", got, err)
			}
		})
	}
}

func TestVersionOf(t *testing.T) {
	lower := strings.Repeat("0123456789abcdef", 4)
	for _, tc := range []struct {
		name, value string
		want        int
	}{
		{"v2", "v2:" + lower, 2},
		{"legacy", lower, 1},
		{"empty", "", 0},
		{"uppercase_legacy", strings.ToUpper(lower), 0},
		{"uppercase_v2", "v2:" + strings.ToUpper(lower), 0},
		{"short_legacy", lower[:63], 0},
		{"short_v2", "v2:" + lower[:63], 0},
		{"long_legacy", lower + "0", 0},
		{"long_v2", "v2:" + lower + "0", 0},
		{"unknown_version", "v3:" + lower, 0},
		{"bad_prefix", "V2:" + lower, 0},
		{"bad_hex", "v2:" + lower[:63] + "g", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := fingerprint.VersionOf(tc.value); got != tc.want {
				t.Errorf("VersionOf(%q) = %d, want %d", tc.value, got, tc.want)
			}
		})
	}
}

func TestFingerprintV2IsHashOfNormalize(t *testing.T) {
	set, err := benchcorpus.Default()
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range set.All() {
		for _, d := range []keywords.SQLDialect{"", keywords.SQLDialect(st.Dialect)} {
			if d == keywords.DialectGeneric {
				d = ""
			}
			opts := fingerprint.Options{Dialect: d}
			n, normErr := fingerprint.NormalizeWithOptions(st.SQL, opts)
			fp, fpErr := fingerprint.FingerprintWithOptions(st.SQL, opts)
			if normErr != nil {
				if fpErr == nil || normErr.Error() != fpErr.Error() {
					t.Errorf("%s/%s: normalize error %v, fingerprint error %v", st.Key(), d, normErr, fpErr)
				}
				continue
			}
			if fpErr != nil {
				t.Errorf("%s/%s: %v", st.Key(), d, fpErr)
				continue
			}
			h := sha256.Sum256([]byte(n))
			want := fingerprint.VersionPrefix + hex.EncodeToString(h[:])
			if fp != want || fingerprint.VersionOf(fp) != fingerprint.Version {
				t.Errorf("%s/%s: fingerprint = %q, want %q", st.Key(), d, fp, want)
			}
		}
	}
}
