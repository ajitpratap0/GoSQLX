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
	"database/sql"

	dbschema "github.com/ajitpratap0/GoSQLX/pkg/schema/db"
)

// LoadSchema connects to a live database and returns its schema metadata.
// Pass a dialect-specific loader from pkg/schema/postgres, pkg/schema/mysql,
// or pkg/schema/sqlite. schemaName may be empty to use the database default.
//
// Example - SQLite:
//
//	import (
//	    _ "modernc.org/sqlite"
//	    "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
//	    sqschema "github.com/ajitpratap0/GoSQLX/pkg/schema/sqlite"
//	)
//
//	db, _ := sql.Open("sqlite", ":memory:")
//	loader := sqschema.NewLoader()
//	s, err := gosqlx.LoadSchema(db, loader, "main")
//
// Example - PostgreSQL:
//
//	import (
//	    _ "github.com/lib/pq"
//	    pgschema "github.com/ajitpratap0/GoSQLX/pkg/schema/postgres"
//	)
//
//	db, _ := sql.Open("postgres", "host=localhost user=app dbname=mydb sslmode=disable")
//	loader := pgschema.NewLoader()
//	s, err := gosqlx.LoadSchema(db, loader, "public")
func LoadSchema(db *sql.DB, loader dbschema.Loader, schemaName string) (*dbschema.DatabaseSchema, error) {
	return loader.Load(db, schemaName)
}
