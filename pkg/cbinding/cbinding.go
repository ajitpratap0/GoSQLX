package main

// #include <stdlib.h>
import "C"
import (
	"encoding/json"
	"unsafe"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

// ParseResult represents the result of parsing SQL.
type ParseResult struct {
	Success   bool     `json:"success"`
	Error     string   `json:"error,omitempty"`
	StmtCount int      `json:"statement_count"`
	StmtTypes []string `json:"statement_types"`
}

// ValidationResult represents the result of validating SQL.
type ValidationResult struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

//export gosqlx_parse
func gosqlx_parse(sql *C.char) *C.char {
	goSQL := C.GoString(sql)

	tree, err := gosqlx.Parse(goSQL)
	if err != nil {
		result := ParseResult{Success: false, Error: err.Error()}
		jsonBytes, _ := json.Marshal(result)
		return C.CString(string(jsonBytes))
	}

	// Extract statement types
	stmtTypes := make([]string, 0, len(tree.Statements))
	for _, stmt := range tree.Statements {
		switch stmt.(type) {
		case *ast.SelectStatement:
			stmtTypes = append(stmtTypes, "SELECT")
		case *ast.InsertStatement:
			stmtTypes = append(stmtTypes, "INSERT")
		case *ast.UpdateStatement:
			stmtTypes = append(stmtTypes, "UPDATE")
		case *ast.DeleteStatement:
			stmtTypes = append(stmtTypes, "DELETE")
		case *ast.CreateTableStatement:
			stmtTypes = append(stmtTypes, "CREATE_TABLE")
		case *ast.CreateViewStatement:
			stmtTypes = append(stmtTypes, "CREATE_VIEW")
		case *ast.CreateIndexStatement:
			stmtTypes = append(stmtTypes, "CREATE_INDEX")
		case *ast.AlterTableStatement:
			stmtTypes = append(stmtTypes, "ALTER_TABLE")
		case *ast.DropStatement:
			stmtTypes = append(stmtTypes, "DROP")
		case *ast.MergeStatement:
			stmtTypes = append(stmtTypes, "MERGE")
		case *ast.TruncateStatement:
			stmtTypes = append(stmtTypes, "TRUNCATE")
		default:
			stmtTypes = append(stmtTypes, "OTHER")
		}
	}

	result := ParseResult{
		Success:   true,
		StmtCount: len(tree.Statements),
		StmtTypes: stmtTypes,
	}
	jsonBytes, _ := json.Marshal(result)
	return C.CString(string(jsonBytes))
}

//export gosqlx_validate
func gosqlx_validate(sql *C.char) *C.char {
	goSQL := C.GoString(sql)

	err := gosqlx.Validate(goSQL)
	result := ValidationResult{Valid: err == nil}
	if err != nil {
		result.Error = err.Error()
	}

	jsonBytes, _ := json.Marshal(result)
	return C.CString(string(jsonBytes))
}

//export gosqlx_extract_tables
func gosqlx_extract_tables(sql *C.char) *C.char {
	goSQL := C.GoString(sql)

	tree, err := gosqlx.Parse(goSQL)
	if err != nil {
		errResult, _ := json.Marshal(map[string]interface{}{"error": err.Error()})
		return C.CString(string(errResult))
	}

	tables := gosqlx.ExtractTables(tree)
	jsonBytes, _ := json.Marshal(map[string]interface{}{"tables": tables})
	return C.CString(string(jsonBytes))
}

//export gosqlx_free
func gosqlx_free(ptr *C.char) {
	C.free(unsafe.Pointer(ptr))
}

//export gosqlx_version
func gosqlx_version() *C.char {
	return C.CString("1.7.0")
}

func main() {}
