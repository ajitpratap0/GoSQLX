// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package ast

import (
	"fmt"
)

// CreateTableBuilder helps in building and accessing a create table statement with more ease.
// Example:
//
//	builder := NewCreateTableBuilder(ObjectName{Idents: []Ident{{Value: "table_name"}}}).
//	    SetIfNotExists(true).
//	    SetColumns([]ColumnDef{{
//	        Name:     Ident{Value: "c1"},
//	        DataType: &DataType{Variant: &Int32Type{}},
//	    }})
type CreateTableBuilder struct {
	OrReplace             bool
	Temporary             bool
	External              bool
	Global                *bool
	IfNotExists           bool
	Transient             bool
	Volatile              bool
	Iceberg               bool
	Name                  ObjectName
	Columns               []ColumnDef
	Constraints           []TableConstraint
	HiveDistribution      HiveDistributionStyle
	HiveFormats           *HiveFormat
	TableProperties       []SqlOption
	WithOptions           []SqlOption
	FileFormat            *FileFormat
	Location              *string
	Query                 *Query
	WithoutRowID          bool
	Like                  *ObjectName
	Clone                 *ObjectName
	Engine                *TableEngine
	Comment               *CommentDef
	AutoIncrementOffset   *uint32
	DefaultCharset        *string
	Collation             *string
	OnCommit              *OnCommit
	OnCluster             *Ident
	PrimaryKey            *Expr
	OrderBy               *OneOrManyWithParens[Expr]
	PartitionBy           *Expr
	ClusterBy             *WrappedCollection[[]Ident]
	ClusteredBy           *ClusteredBy
	Options               *[]SqlOption
	Strict                bool
	CopyGrants            bool
	EnableSchemaEvolution *bool
	ChangeTracking        *bool
	DataRetentionDays     *uint64
	MaxDataExtensionDays  *uint64
	DefaultDDLCollation   *string
	AggregationPolicy     *ObjectName
	RowAccessPolicy       *RowAccessPolicy
	Tags                  *[]Tag
	BaseLocation          *string
	ExternalVolume        *string
	Catalog               *string
	CatalogSync           *string
	SerializationPolicy   *StorageSerializationPolicy
}

// NewCreateTableBuilder creates a new CreateTableBuilder with default values
func NewCreateTableBuilder(name ObjectName) *CreateTableBuilder {
	return &CreateTableBuilder{
		Name:             name,
		HiveDistribution: HiveDistributionNone,
	}
}

// Build converts the builder into a CreateTable statement
func (b *CreateTableBuilder) Build() *StatementImpl {
	return &StatementImpl{
		Variant: &CreateTable{
			OrReplace:             b.OrReplace,
			Temporary:             b.Temporary,
			External:              b.External,
			Global:                b.Global,
			IfNotExists:           b.IfNotExists,
			Transient:             b.Transient,
			Volatile:              b.Volatile,
			Iceberg:               b.Iceberg,
			Name:                  b.Name,
			Columns:               b.Columns,
			Constraints:           b.Constraints,
			HiveDistribution:      b.HiveDistribution,
			HiveFormats:           b.HiveFormats,
			TableProperties:       b.TableProperties,
			WithOptions:           b.WithOptions,
			FileFormat:            b.FileFormat,
			Location:              b.Location,
			Query:                 b.Query,
			WithoutRowID:          b.WithoutRowID,
			Like:                  b.Like,
			Clone:                 b.Clone,
			Engine:                b.Engine,
			Comment:               b.Comment,
			AutoIncrementOffset:   b.AutoIncrementOffset,
			DefaultCharset:        b.DefaultCharset,
			Collation:             b.Collation,
			OnCommit:              b.OnCommit,
			OnCluster:             b.OnCluster,
			PrimaryKey:            b.PrimaryKey,
			OrderBy:               b.OrderBy,
			PartitionBy:           b.PartitionBy,
			ClusterBy:             b.ClusterBy,
			ClusteredBy:           b.ClusteredBy,
			Options:               b.Options,
			Strict:                b.Strict,
			CopyGrants:            b.CopyGrants,
			EnableSchemaEvolution: b.EnableSchemaEvolution,
			ChangeTracking:        b.ChangeTracking,
			DataRetentionDays:     b.DataRetentionDays,
			MaxDataExtensionDays:  b.MaxDataExtensionDays,
			DefaultDDLCollation:   b.DefaultDDLCollation,
			AggregationPolicy:     b.AggregationPolicy,
			RowAccessPolicy:       b.RowAccessPolicy,
			Tags:                  b.Tags,
			BaseLocation:          b.BaseLocation,
			ExternalVolume:        b.ExternalVolume,
			Catalog:               b.Catalog,
			CatalogSync:           b.CatalogSync,
			SerializationPolicy:   b.SerializationPolicy,
		},
	}
}

// FromStatement attempts to create a CreateTableBuilder from a Statement
func FromStatement(stmt *StatementImpl) (*CreateTableBuilder, error) {
	if createTable, ok := stmt.Variant.(*CreateTable); ok {
		return &CreateTableBuilder{
			OrReplace:             createTable.OrReplace,
			Temporary:             createTable.Temporary,
			External:              createTable.External,
			Global:                createTable.Global,
			IfNotExists:           createTable.IfNotExists,
			Transient:             createTable.Transient,
			Volatile:              createTable.Volatile,
			Iceberg:               createTable.Iceberg,
			Name:                  createTable.Name,
			Columns:               createTable.Columns,
			Constraints:           createTable.Constraints,
			HiveDistribution:      createTable.HiveDistribution,
			HiveFormats:           createTable.HiveFormats,
			TableProperties:       createTable.TableProperties,
			WithOptions:           createTable.WithOptions,
			FileFormat:            createTable.FileFormat,
			Location:              createTable.Location,
			Query:                 createTable.Query,
			WithoutRowID:          createTable.WithoutRowID,
			Like:                  createTable.Like,
			Clone:                 createTable.Clone,
			Engine:                createTable.Engine,
			Comment:               createTable.Comment,
			AutoIncrementOffset:   createTable.AutoIncrementOffset,
			DefaultCharset:        createTable.DefaultCharset,
			Collation:             createTable.Collation,
			OnCommit:              createTable.OnCommit,
			OnCluster:             createTable.OnCluster,
			PrimaryKey:            createTable.PrimaryKey,
			OrderBy:               createTable.OrderBy,
			PartitionBy:           createTable.PartitionBy,
			ClusterBy:             createTable.ClusterBy,
			ClusteredBy:           createTable.ClusteredBy,
			Options:               createTable.Options,
			Strict:                createTable.Strict,
			CopyGrants:            createTable.CopyGrants,
			EnableSchemaEvolution: createTable.EnableSchemaEvolution,
			ChangeTracking:        createTable.ChangeTracking,
			DataRetentionDays:     createTable.DataRetentionDays,
			MaxDataExtensionDays:  createTable.MaxDataExtensionDays,
			DefaultDDLCollation:   createTable.DefaultDDLCollation,
			AggregationPolicy:     createTable.AggregationPolicy,
			RowAccessPolicy:       createTable.RowAccessPolicy,
			Tags:                  createTable.Tags,
			BaseLocation:          createTable.BaseLocation,
			ExternalVolume:        createTable.ExternalVolume,
			Catalog:               createTable.Catalog,
			CatalogSync:           createTable.CatalogSync,
			SerializationPolicy:   createTable.SerializationPolicy,
		}, nil
	}
	return nil, fmt.Errorf("expected create table statement, but received: %v", stmt)
}

// Fluent builder methods
func (b *CreateTableBuilder) SetOrReplace(v bool) *CreateTableBuilder      { b.OrReplace = v; return b }
func (b *CreateTableBuilder) SetTemporary(v bool) *CreateTableBuilder      { b.Temporary = v; return b }
func (b *CreateTableBuilder) SetExternal(v bool) *CreateTableBuilder       { b.External = v; return b }
func (b *CreateTableBuilder) SetGlobal(v *bool) *CreateTableBuilder        { b.Global = v; return b }
func (b *CreateTableBuilder) SetIfNotExists(v bool) *CreateTableBuilder    { b.IfNotExists = v; return b }
func (b *CreateTableBuilder) SetTransient(v bool) *CreateTableBuilder      { b.Transient = v; return b }
func (b *CreateTableBuilder) SetVolatile(v bool) *CreateTableBuilder       { b.Volatile = v; return b }
func (b *CreateTableBuilder) SetIceberg(v bool) *CreateTableBuilder        { b.Iceberg = v; return b }
func (b *CreateTableBuilder) SetColumns(v []ColumnDef) *CreateTableBuilder { b.Columns = v; return b }
func (b *CreateTableBuilder) SetConstraints(v []TableConstraint) *CreateTableBuilder {
	b.Constraints = v
	return b
}
func (b *CreateTableBuilder) SetHiveDistribution(v HiveDistributionStyle) *CreateTableBuilder {
	b.HiveDistribution = v
	return b
}
func (b *CreateTableBuilder) SetHiveFormats(v *HiveFormat) *CreateTableBuilder {
	b.HiveFormats = v
	return b
}
func (b *CreateTableBuilder) SetTableProperties(v []SqlOption) *CreateTableBuilder {
	b.TableProperties = v
	return b
}
func (b *CreateTableBuilder) SetWithOptions(v []SqlOption) *CreateTableBuilder {
	b.WithOptions = v
	return b
}
func (b *CreateTableBuilder) SetFileFormat(v *FileFormat) *CreateTableBuilder {
	b.FileFormat = v
	return b
}
func (b *CreateTableBuilder) SetLocation(v *string) *CreateTableBuilder { b.Location = v; return b }
func (b *CreateTableBuilder) SetQuery(v *Query) *CreateTableBuilder     { b.Query = v; return b }
func (b *CreateTableBuilder) SetWithoutRowID(v bool) *CreateTableBuilder {
	b.WithoutRowID = v
	return b
}
func (b *CreateTableBuilder) SetLike(v *ObjectName) *CreateTableBuilder    { b.Like = v; return b }
func (b *CreateTableBuilder) SetClone(v *ObjectName) *CreateTableBuilder   { b.Clone = v; return b }
func (b *CreateTableBuilder) SetEngine(v *TableEngine) *CreateTableBuilder { b.Engine = v; return b }
func (b *CreateTableBuilder) SetComment(v *CommentDef) *CreateTableBuilder { b.Comment = v; return b }
func (b *CreateTableBuilder) SetAutoIncrementOffset(v *uint32) *CreateTableBuilder {
	b.AutoIncrementOffset = v
	return b
}
func (b *CreateTableBuilder) SetDefaultCharset(v *string) *CreateTableBuilder {
	b.DefaultCharset = v
	return b
}
func (b *CreateTableBuilder) SetCollation(v *string) *CreateTableBuilder  { b.Collation = v; return b }
func (b *CreateTableBuilder) SetOnCommit(v *OnCommit) *CreateTableBuilder { b.OnCommit = v; return b }
func (b *CreateTableBuilder) SetOnCluster(v *Ident) *CreateTableBuilder   { b.OnCluster = v; return b }
func (b *CreateTableBuilder) SetPrimaryKey(v *Expr) *CreateTableBuilder   { b.PrimaryKey = v; return b }
func (b *CreateTableBuilder) SetOrderBy(v *OneOrManyWithParens[Expr]) *CreateTableBuilder {
	b.OrderBy = v
	return b
}
func (b *CreateTableBuilder) SetPartitionBy(v *Expr) *CreateTableBuilder { b.PartitionBy = v; return b }
func (b *CreateTableBuilder) SetClusterBy(v *WrappedCollection[[]Ident]) *CreateTableBuilder {
	b.ClusterBy = v
	return b
}
func (b *CreateTableBuilder) SetClusteredBy(v *ClusteredBy) *CreateTableBuilder {
	b.ClusteredBy = v
	return b
}
func (b *CreateTableBuilder) SetOptions(v *[]SqlOption) *CreateTableBuilder { b.Options = v; return b }
func (b *CreateTableBuilder) SetStrict(v bool) *CreateTableBuilder          { b.Strict = v; return b }
func (b *CreateTableBuilder) SetCopyGrants(v bool) *CreateTableBuilder      { b.CopyGrants = v; return b }
func (b *CreateTableBuilder) SetEnableSchemaEvolution(v *bool) *CreateTableBuilder {
	b.EnableSchemaEvolution = v
	return b
}
func (b *CreateTableBuilder) SetChangeTracking(v *bool) *CreateTableBuilder {
	b.ChangeTracking = v
	return b
}
func (b *CreateTableBuilder) SetDataRetentionDays(v *uint64) *CreateTableBuilder {
	b.DataRetentionDays = v
	return b
}
func (b *CreateTableBuilder) SetMaxDataExtensionDays(v *uint64) *CreateTableBuilder {
	b.MaxDataExtensionDays = v
	return b
}
func (b *CreateTableBuilder) SetDefaultDDLCollation(v *string) *CreateTableBuilder {
	b.DefaultDDLCollation = v
	return b
}
func (b *CreateTableBuilder) SetAggregationPolicy(v *ObjectName) *CreateTableBuilder {
	b.AggregationPolicy = v
	return b
}
func (b *CreateTableBuilder) SetRowAccessPolicy(v *RowAccessPolicy) *CreateTableBuilder {
	b.RowAccessPolicy = v
	return b
}
func (b *CreateTableBuilder) SetTags(v *[]Tag) *CreateTableBuilder { b.Tags = v; return b }
func (b *CreateTableBuilder) SetBaseLocation(v *string) *CreateTableBuilder {
	b.BaseLocation = v
	return b
}
func (b *CreateTableBuilder) SetExternalVolume(v *string) *CreateTableBuilder {
	b.ExternalVolume = v
	return b
}
func (b *CreateTableBuilder) SetCatalog(v *string) *CreateTableBuilder { b.Catalog = v; return b }
func (b *CreateTableBuilder) SetCatalogSync(v *string) *CreateTableBuilder {
	b.CatalogSync = v
	return b
}
func (b *CreateTableBuilder) SetSerializationPolicy(v *StorageSerializationPolicy) *CreateTableBuilder {
	b.SerializationPolicy = v
	return b
}
