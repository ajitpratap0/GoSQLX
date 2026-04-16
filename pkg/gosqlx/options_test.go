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

package gosqlx

import (
	"testing"
	"time"
)

func TestOptions_Defaults(t *testing.T) {
	cfg := applyOptions(nil)
	if cfg.dialect != "" {
		t.Errorf("default dialect = %q, want \"\"", cfg.dialect)
	}
	if cfg.strict {
		t.Error("default strict = true, want false")
	}
	if cfg.timeout != 0 {
		t.Errorf("default timeout = %v, want 0", cfg.timeout)
	}
	if cfg.recover {
		t.Error("default recover = true, want false")
	}
}

func TestOptions_WithDialect(t *testing.T) {
	cfg := applyOptions([]Option{WithDialect("postgresql")})
	if cfg.dialect != "postgresql" {
		t.Errorf("dialect = %q, want postgresql", cfg.dialect)
	}
}

func TestOptions_WithStrict(t *testing.T) {
	cfg := applyOptions([]Option{WithStrict()})
	if !cfg.strict {
		t.Error("strict = false, want true")
	}
}

func TestOptions_WithTimeout(t *testing.T) {
	cfg := applyOptions([]Option{WithTimeout(250 * time.Millisecond)})
	if cfg.timeout != 250*time.Millisecond {
		t.Errorf("timeout = %v, want 250ms", cfg.timeout)
	}
}

func TestOptions_WithRecovery(t *testing.T) {
	cfg := applyOptions([]Option{WithRecovery()})
	if !cfg.recover {
		t.Error("recover = false, want true")
	}
}

func TestOptions_OrderMatters(t *testing.T) {
	cfg := applyOptions([]Option{
		WithDialect("mysql"),
		WithDialect("postgresql"),
	})
	if cfg.dialect != "postgresql" {
		t.Errorf("dialect = %q, want postgresql (last wins)", cfg.dialect)
	}
}

func TestOptions_NilSafe(t *testing.T) {
	cfg := applyOptions([]Option{nil, WithStrict(), nil})
	if !cfg.strict {
		t.Error("strict = false after nil-sandwiched WithStrict, want true")
	}
}

func TestOptions_Combine(t *testing.T) {
	cfg := applyOptions([]Option{
		WithDialect("mysql"),
		WithStrict(),
		WithTimeout(time.Second),
		WithRecovery(),
	})
	if cfg.dialect != "mysql" {
		t.Errorf("dialect = %q", cfg.dialect)
	}
	if !cfg.strict {
		t.Error("strict not set")
	}
	if cfg.timeout != time.Second {
		t.Errorf("timeout = %v", cfg.timeout)
	}
	if !cfg.recover {
		t.Error("recover not set")
	}
}
