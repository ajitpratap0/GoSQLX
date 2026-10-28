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

package cmd

import (
	"strings"
	"testing"
)

func TestTranspileHelpSupportedDialects(t *testing.T) {
	res := runCLI(t, nil, "transpile", "--help")
	if res.err != nil {
		t.Fatal(res.err)
	}
	if strings.Contains(res.stdout, "Supported dialect pairs:") {
		t.Fatalf("help still presents an incomplete pair list:\n%s", res.stdout)
	}
	for _, name := range []string{"mysql", "postgresql", "sqlite", "sqlserver", "oracle", "snowflake", "clickhouse", "mariadb"} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseDialectFlag(name); err != nil {
				t.Fatalf("documented dialect rejected: %v", err)
			}
			if !strings.Contains(res.stdout, name) {
				t.Fatalf("help omits supported dialect %q:\n%s", name, res.stdout)
			}
		})
	}
}
