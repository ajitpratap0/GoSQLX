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

// Package db provides types and interfaces for live database schema introspection.
// Use dialect-specific loaders from pkg/schema/postgres, pkg/schema/mysql, or
// pkg/schema/sqlite to connect to a live database and retrieve structured schema
// metadata (tables, columns, indexes, foreign keys).
package db

// Column describes a single column in a table as read from a live database.
type Column struct {
	Name         string
	OrdinalPos   int
	DataType     string
	IsNullable   bool
	DefaultValue *string
	MaxLength    *int
	Precision    *int
	Scale        *int
	IsPrimary    bool
	IsUnique     bool
}

// Index describes a table index as read from a live database.
type Index struct {
	Name      string
	TableName string
	Columns   []string
	IsUnique  bool
	IsPrimary bool
}

// ForeignKey describes a foreign key constraint as read from a live database.
type ForeignKey struct {
	Name       string
	TableName  string
	Columns    []string
	RefTable   string
	RefColumns []string
	OnDelete   string
	OnUpdate   string
}

// Table describes a database table with its columns, indexes, and foreign keys
// as read from a live database.
type Table struct {
	Schema      string
	Name        string
	Columns     []Column
	Indexes     []Index
	ForeignKeys []ForeignKey
}

// DatabaseSchema is the top-level result from live schema introspection.
type DatabaseSchema struct {
	Name   string
	Tables []Table
}
