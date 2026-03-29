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

package db

import "database/sql"

// Loader connects to a live database and reads its schema metadata.
// Dialect-specific implementations are provided in pkg/schema/postgres,
// pkg/schema/mysql, and pkg/schema/sqlite.
type Loader interface {
	// Load returns the full schema for all user tables in the database.
	// schemaName may be empty to use the database default.
	Load(db *sql.DB, schemaName string) (*DatabaseSchema, error)
	// LoadTable returns schema for a single named table.
	LoadTable(db *sql.DB, schemaName, tableName string) (*Table, error)
}
