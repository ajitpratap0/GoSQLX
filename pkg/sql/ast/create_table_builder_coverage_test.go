package ast

import (
	"testing"
)

func TestNewCreateTableBuilder(t *testing.T) {
	name := ObjectName{Name: "users"}
	b := NewCreateTableBuilder(name)
	if b == nil {
		t.Fatal("should not be nil")
	}
	if b.Name.Name != "users" {
		t.Error("name should be set")
	}
	if b.HiveDistribution != HiveDistributionNone {
		t.Error("default HiveDistribution should be None")
	}
}

func TestCreateTableBuilder_Build(t *testing.T) {
	name := ObjectName{Name: "orders"}
	b := NewCreateTableBuilder(name).
		SetIfNotExists(true).
		SetTemporary(true).
		SetColumns([]ColumnDef{{Name: "id", Type: "INT"}})
	stmt := b.Build()
	if stmt == nil {
		t.Fatal("Build should return non-nil")
	}
	ct, ok := stmt.Variant.(*CreateTable)
	if !ok {
		t.Fatal("should be CreateTable")
	}
	if !ct.IfNotExists {
		t.Error("IfNotExists should be true")
	}
	if !ct.Temporary {
		t.Error("Temporary should be true")
	}
	if len(ct.Columns) != 1 {
		t.Error("should have 1 column")
	}
}

func TestFromStatement(t *testing.T) {
	name := ObjectName{Name: "test"}
	b := NewCreateTableBuilder(name).SetOrReplace(true)
	stmt := b.Build()

	b2, err := FromStatement(stmt)
	if err != nil {
		t.Fatalf("FromStatement failed: %v", err)
	}
	if !b2.OrReplace {
		t.Error("OrReplace should be true")
	}

	// Test error case - need a type that implements StatementVariant but isn't CreateTable
	badStmt := &StatementImpl{Variant: &SelectStatement{}}
	_, err = FromStatement(badStmt)
	if err == nil {
		t.Error("should error on non-CreateTable")
	}
}

func TestCreateTableBuilder_AllSetters(t *testing.T) {
	name := ObjectName{Name: "t"}
	boolTrue := true
	boolFalse := false
	strVal := "test"
	u32 := uint32(10)
	u64 := uint64(30)

	b := NewCreateTableBuilder(name).
		SetOrReplace(true).
		SetTemporary(true).
		SetExternal(true).
		SetGlobal(&boolTrue).
		SetIfNotExists(true).
		SetTransient(true).
		SetVolatile(true).
		SetIceberg(true).
		SetColumns([]ColumnDef{}).
		SetConstraints([]TableConstraint{}).
		SetHiveDistribution(HiveDistributionNone).
		SetHiveFormats(nil).
		SetTableProperties(nil).
		SetWithOptions(nil).
		SetFileFormat(nil).
		SetLocation(&strVal).
		SetQuery(nil).
		SetWithoutRowID(true).
		SetLike(nil).
		SetClone(nil).
		SetEngine(nil).
		SetComment(nil).
		SetAutoIncrementOffset(&u32).
		SetDefaultCharset(&strVal).
		SetCollation(&strVal).
		SetOnCommit(nil).
		SetOnCluster(nil).
		SetPrimaryKey(nil).
		SetOrderBy(nil).
		SetPartitionBy(nil).
		SetClusterBy(nil).
		SetClusteredBy(nil).
		SetOptions(nil).
		SetStrict(true).
		SetCopyGrants(true).
		SetEnableSchemaEvolution(&boolTrue).
		SetChangeTracking(&boolFalse).
		SetDataRetentionDays(&u64).
		SetMaxDataExtensionDays(&u64).
		SetDefaultDDLCollation(&strVal).
		SetAggregationPolicy(nil).
		SetRowAccessPolicy(nil).
		SetTags(nil).
		SetBaseLocation(&strVal).
		SetExternalVolume(&strVal).
		SetCatalog(&strVal).
		SetCatalogSync(&strVal).
		SetSerializationPolicy(nil)

	if !b.OrReplace || !b.Strict || !b.CopyGrants {
		t.Error("setters should work")
	}
	if b.AutoIncrementOffset == nil || *b.AutoIncrementOffset != 10 {
		t.Error("AutoIncrementOffset should be set")
	}
}
