package parser

import (
	"testing"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func TestParser_BasicMerge_WhenMatched_Update(t *testing.T) {
	sql := `MERGE INTO target_table t USING source_table s ON t.id = s.id WHEN MATCHED THEN UPDATE SET t.name = s.name`

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	parser := &Parser{}
	astObj, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse MERGE: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	mergeStmt, ok := astObj.Statements[0].(*ast.MergeStatement)
	if !ok {
		t.Fatalf("Expected MergeStatement, got %T", astObj.Statements[0])
	}

	// Verify target table
	if mergeStmt.TargetTable.Name != "target_table" {
		t.Errorf("Expected target table 'target_table', got '%s'", mergeStmt.TargetTable.Name)
	}

	// Verify target alias
	if mergeStmt.TargetAlias != "t" {
		t.Errorf("Expected target alias 't', got '%s'", mergeStmt.TargetAlias)
	}

	// Verify source table
	if mergeStmt.SourceTable.Name != "source_table" {
		t.Errorf("Expected source table 'source_table', got '%s'", mergeStmt.SourceTable.Name)
	}

	// Verify source alias
	if mergeStmt.SourceAlias != "s" {
		t.Errorf("Expected source alias 's', got '%s'", mergeStmt.SourceAlias)
	}

	// Verify ON condition exists
	if mergeStmt.OnCondition == nil {
		t.Error("Expected ON condition")
	}

	// Verify WHEN clause
	if len(mergeStmt.WhenClauses) != 1 {
		t.Fatalf("Expected 1 WHEN clause, got %d", len(mergeStmt.WhenClauses))
	}

	whenClause := mergeStmt.WhenClauses[0]
	if whenClause.Type != "MATCHED" {
		t.Errorf("Expected WHEN clause type 'MATCHED', got '%s'", whenClause.Type)
	}

	if whenClause.Action.ActionType != "UPDATE" {
		t.Errorf("Expected action type 'UPDATE', got '%s'", whenClause.Action.ActionType)
	}

	if len(whenClause.Action.SetClauses) == 0 {
		t.Error("Expected SET clauses in UPDATE action")
	}
}

func TestParser_Merge_WhenNotMatched_Insert(t *testing.T) {
	sql := `MERGE INTO target t USING source s ON t.id = s.id WHEN NOT MATCHED THEN INSERT (id, name) VALUES (s.id, s.name)`

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	parser := &Parser{}
	astObj, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse MERGE: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	mergeStmt, ok := astObj.Statements[0].(*ast.MergeStatement)
	if !ok {
		t.Fatalf("Expected MergeStatement, got %T", astObj.Statements[0])
	}

	if len(mergeStmt.WhenClauses) != 1 {
		t.Fatalf("Expected 1 WHEN clause, got %d", len(mergeStmt.WhenClauses))
	}

	whenClause := mergeStmt.WhenClauses[0]
	if whenClause.Type != "NOT_MATCHED" {
		t.Errorf("Expected WHEN clause type 'NOT_MATCHED', got '%s'", whenClause.Type)
	}

	if whenClause.Action.ActionType != "INSERT" {
		t.Errorf("Expected action type 'INSERT', got '%s'", whenClause.Action.ActionType)
	}

	if len(whenClause.Action.Columns) != 2 {
		t.Errorf("Expected 2 columns, got %d", len(whenClause.Action.Columns))
	}

	if len(whenClause.Action.Values) != 2 {
		t.Errorf("Expected 2 values, got %d", len(whenClause.Action.Values))
	}
}

func TestParser_Merge_WhenMatched_Delete(t *testing.T) {
	sql := `MERGE INTO target t USING source s ON t.id = s.id WHEN MATCHED THEN DELETE`

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	parser := &Parser{}
	astObj, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse MERGE: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	mergeStmt, ok := astObj.Statements[0].(*ast.MergeStatement)
	if !ok {
		t.Fatalf("Expected MergeStatement, got %T", astObj.Statements[0])
	}

	if len(mergeStmt.WhenClauses) != 1 {
		t.Fatalf("Expected 1 WHEN clause, got %d", len(mergeStmt.WhenClauses))
	}

	whenClause := mergeStmt.WhenClauses[0]
	if whenClause.Type != "MATCHED" {
		t.Errorf("Expected WHEN clause type 'MATCHED', got '%s'", whenClause.Type)
	}

	if whenClause.Action.ActionType != "DELETE" {
		t.Errorf("Expected action type 'DELETE', got '%s'", whenClause.Action.ActionType)
	}
}

func TestParser_Merge_MultipleWhenClauses(t *testing.T) {
	sql := `MERGE INTO target t USING source s ON t.id = s.id
		WHEN MATCHED THEN UPDATE SET t.name = s.name
		WHEN NOT MATCHED THEN INSERT (id, name) VALUES (s.id, s.name)`

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	parser := &Parser{}
	astObj, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse MERGE: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	mergeStmt, ok := astObj.Statements[0].(*ast.MergeStatement)
	if !ok {
		t.Fatalf("Expected MergeStatement, got %T", astObj.Statements[0])
	}

	if len(mergeStmt.WhenClauses) != 2 {
		t.Fatalf("Expected 2 WHEN clauses, got %d", len(mergeStmt.WhenClauses))
	}

	// First clause: WHEN MATCHED THEN UPDATE
	if mergeStmt.WhenClauses[0].Type != "MATCHED" {
		t.Errorf("First clause: expected type 'MATCHED', got '%s'", mergeStmt.WhenClauses[0].Type)
	}
	if mergeStmt.WhenClauses[0].Action.ActionType != "UPDATE" {
		t.Errorf("First clause: expected action 'UPDATE', got '%s'", mergeStmt.WhenClauses[0].Action.ActionType)
	}

	// Second clause: WHEN NOT MATCHED THEN INSERT
	if mergeStmt.WhenClauses[1].Type != "NOT_MATCHED" {
		t.Errorf("Second clause: expected type 'NOT_MATCHED', got '%s'", mergeStmt.WhenClauses[1].Type)
	}
	if mergeStmt.WhenClauses[1].Action.ActionType != "INSERT" {
		t.Errorf("Second clause: expected action 'INSERT', got '%s'", mergeStmt.WhenClauses[1].Action.ActionType)
	}
}

func TestParser_Merge_WithAndCondition(t *testing.T) {
	sql := `MERGE INTO target t USING source s ON t.id = s.id WHEN MATCHED AND t.status = 1 THEN UPDATE SET t.name = s.name`

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	parser := &Parser{}
	astObj, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse MERGE with AND condition: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	mergeStmt, ok := astObj.Statements[0].(*ast.MergeStatement)
	if !ok {
		t.Fatalf("Expected MergeStatement, got %T", astObj.Statements[0])
	}

	if len(mergeStmt.WhenClauses) != 1 {
		t.Fatalf("Expected 1 WHEN clause, got %d", len(mergeStmt.WhenClauses))
	}

	whenClause := mergeStmt.WhenClauses[0]
	if whenClause.Condition == nil {
		t.Error("Expected AND condition in WHEN clause")
	}
}

func TestParser_Merge_NotMatchedBySource(t *testing.T) {
	sql := `MERGE INTO target t USING source s ON t.id = s.id WHEN NOT MATCHED BY SOURCE THEN DELETE`

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	parser := &Parser{}
	astObj, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse MERGE NOT MATCHED BY SOURCE: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	mergeStmt, ok := astObj.Statements[0].(*ast.MergeStatement)
	if !ok {
		t.Fatalf("Expected MergeStatement, got %T", astObj.Statements[0])
	}

	if len(mergeStmt.WhenClauses) != 1 {
		t.Fatalf("Expected 1 WHEN clause, got %d", len(mergeStmt.WhenClauses))
	}

	whenClause := mergeStmt.WhenClauses[0]
	if whenClause.Type != "NOT_MATCHED_BY_SOURCE" {
		t.Errorf("Expected WHEN clause type 'NOT_MATCHED_BY_SOURCE', got '%s'", whenClause.Type)
	}
}

func TestParser_Merge_InsertDefaultValues(t *testing.T) {
	sql := `MERGE INTO target t USING source s ON t.id = s.id WHEN NOT MATCHED THEN INSERT DEFAULT VALUES`

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	parser := &Parser{}
	astObj, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse MERGE with DEFAULT VALUES: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	mergeStmt, ok := astObj.Statements[0].(*ast.MergeStatement)
	if !ok {
		t.Fatalf("Expected MergeStatement, got %T", astObj.Statements[0])
	}

	if len(mergeStmt.WhenClauses) != 1 {
		t.Fatalf("Expected 1 WHEN clause, got %d", len(mergeStmt.WhenClauses))
	}

	whenClause := mergeStmt.WhenClauses[0]
	if !whenClause.Action.DefaultValues {
		t.Error("Expected DefaultValues to be true")
	}
}

func TestParser_Merge_WithASKeyword(t *testing.T) {
	sql := `MERGE INTO target AS t USING source AS s ON t.id = s.id WHEN MATCHED THEN UPDATE SET t.name = s.name`

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	parser := &Parser{}
	astObj, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse MERGE with AS keyword: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	mergeStmt, ok := astObj.Statements[0].(*ast.MergeStatement)
	if !ok {
		t.Fatalf("Expected MergeStatement, got %T", astObj.Statements[0])
	}

	// Verify aliases are correctly parsed with AS keyword
	if mergeStmt.TargetAlias != "t" {
		t.Errorf("Expected target alias 't', got '%s'", mergeStmt.TargetAlias)
	}
	if mergeStmt.SourceAlias != "s" {
		t.Errorf("Expected source alias 's', got '%s'", mergeStmt.SourceAlias)
	}
}

func TestParser_Merge_MultipleSetClauses(t *testing.T) {
	sql := `MERGE INTO target t USING source s ON t.id = s.id WHEN MATCHED THEN UPDATE SET t.name = s.name, t.status = s.status, t.updated = s.updated`

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	parser := &Parser{}
	astObj, err := parser.ParseFromModelTokens(tokens)
	if err != nil {
		t.Fatalf("Failed to parse MERGE with multiple SET clauses: %v", err)
	}
	defer ast.ReleaseAST(astObj)

	if len(astObj.Statements) == 0 {
		t.Fatal("No statements parsed")
	}

	mergeStmt, ok := astObj.Statements[0].(*ast.MergeStatement)
	if !ok {
		t.Fatalf("Expected MergeStatement, got %T", astObj.Statements[0])
	}

	if len(mergeStmt.WhenClauses) != 1 {
		t.Fatalf("Expected 1 WHEN clause, got %d", len(mergeStmt.WhenClauses))
	}

	action := mergeStmt.WhenClauses[0].Action
	if len(action.SetClauses) != 3 {
		t.Errorf("Expected 3 SET clauses, got %d", len(action.SetClauses))
	}
}

func TestParser_Merge_Error_NoWhenClause(t *testing.T) {
	sql := `MERGE INTO target t USING source s ON t.id = s.id`

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	parser := &Parser{}
	_, err = parser.ParseFromModelTokens(tokens)
	if err == nil {
		t.Error("Expected error for MERGE without WHEN clause")
	}
}

func TestParser_Merge_Error_InsertInMatchedClause(t *testing.T) {
	sql := `MERGE INTO target t USING source s ON t.id = s.id WHEN MATCHED THEN INSERT (id) VALUES (1)`

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	parser := &Parser{}
	_, err = parser.ParseFromModelTokens(tokens)
	if err == nil {
		t.Error("Expected error for INSERT in WHEN MATCHED clause")
	}
}

func TestParser_Merge_Error_DeleteInNotMatchedClause(t *testing.T) {
	sql := `MERGE INTO target t USING source s ON t.id = s.id WHEN NOT MATCHED THEN DELETE`

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, err := tkz.Tokenize([]byte(sql))
	if err != nil {
		t.Fatalf("Failed to tokenize: %v", err)
	}

	parser := &Parser{}
	_, err = parser.ParseFromModelTokens(tokens)
	if err == nil {
		t.Error("Expected error for DELETE in WHEN NOT MATCHED clause")
	}
}

// Benchmark for MERGE statement parsing
func BenchmarkParser_Merge_Simple(b *testing.B) {
	sql := `MERGE INTO target t USING source s ON t.id = s.id WHEN MATCHED THEN UPDATE SET t.name = s.name`
	sqlBytes := []byte(sql)

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, _ := tkz.Tokenize(sqlBytes)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		parser := &Parser{}
		astObj, err := parser.ParseFromModelTokens(tokens)
		if err != nil {
			b.Fatalf("Parse error: %v", err)
		}
		ast.ReleaseAST(astObj)
	}
}

func BenchmarkParser_Merge_Complex(b *testing.B) {
	sql := `MERGE INTO target t USING source s ON t.id = s.id
		WHEN MATCHED AND t.status = 1 THEN UPDATE SET t.name = s.name, t.status = s.status
		WHEN NOT MATCHED THEN INSERT (id, name, status) VALUES (s.id, s.name, s.status)
		WHEN NOT MATCHED BY SOURCE THEN DELETE`
	sqlBytes := []byte(sql)

	tkz := tokenizer.GetTokenizer()
	defer tokenizer.PutTokenizer(tkz)

	tokens, _ := tkz.Tokenize(sqlBytes)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		parser := &Parser{}
		astObj, err := parser.ParseFromModelTokens(tokens)
		if err != nil {
			b.Fatalf("Parse error: %v", err)
		}
		ast.ReleaseAST(astObj)
	}
}
