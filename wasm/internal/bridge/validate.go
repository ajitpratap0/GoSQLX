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

package bridge

import (
	"fmt"
	"strings"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
)

// Validate checks SQL syntax in the selected playground dialect.
func Validate(sql, dialect string) error {
	d := Dialect(dialect)
	if strings.TrimSpace(sql) == "" || d == "" {
		return gosqlx.Validate(sql)
	}
	if err := parser.ValidateWithDialect(sql, d); err != nil {
		return fmt.Errorf("%w: %w", gosqlx.ErrSyntax, err)
	}
	return nil
}
