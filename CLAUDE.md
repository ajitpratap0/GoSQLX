# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GoSQLX is a **production-ready**, **race-free**, high-performance SQL parsing SDK for Go that provides lexing, parsing, and AST generation with zero-copy optimizations. The library is designed for enterprise use with comprehensive object pooling for memory efficiency.

**Requirements**: Go 1.24+ (toolchain go1.25.0)

**Production Status**: ✅ Validated for production deployment (v1.6.0+)
- Thread-safe with zero race conditions (20,000+ concurrent operations tested)
- 1.38M+ ops/sec sustained, 1.5M peak with memory-efficient object pooling
- ~80-85% SQL-99 compliance (window functions, CTEs, set operations, MERGE, etc.)
- Multi-dialect support: PostgreSQL, MySQL, SQL Server, Oracle, SQLite

## Architecture

### Core Components

- **Tokenizer** (`pkg/sql/tokenizer/`): Zero-copy SQL lexer with full UTF-8 support
- **Parser** (`pkg/sql/parser/`): Recursive descent parser with one-token lookahead
- **AST** (`pkg/sql/ast/`): Abstract Syntax Tree nodes with visitor pattern support
- **Keywords** (`pkg/sql/keywords/`): Multi-dialect SQL keyword definitions
- **Models** (`pkg/models/`): Core data structures (tokens, spans, locations)
- **Errors** (`pkg/errors/`): Structured error handling with position tracking
- **Metrics** (`pkg/metrics/`): Production performance monitoring
- **Security** (`pkg/sql/security/`): SQL injection detection with severity classification
- **Linter** (`pkg/linter/`): SQL linting engine with 10 built-in rules (L001-L010)
- **LSP** (`pkg/lsp/`): Language Server Protocol for IDE integration
- **GoSQLX** (`pkg/gosqlx/`): High-level simple API (recommended for most users)
- **Compatibility** (`pkg/compatibility/`): API stability testing

### Token Processing Pipeline

```
Raw SQL bytes → tokenizer.Tokenize() → []models.TokenWithSpan
             → parser.ConvertTokensForParser() → []token.Token
             → parser.Parse() → *ast.AST
```

### Object Pooling (Critical for Performance)

The codebase uses extensive sync.Pool for all major data structures:
- `ast.NewAST()` / `ast.ReleaseAST()` - AST container
- `tokenizer.GetTokenizer()` / `tokenizer.PutTokenizer()` - Tokenizer instances
- Individual pools for SELECT, INSERT, UPDATE, DELETE statements
- Expression pools for identifiers, binary expressions, literals

### Module Dependencies

Clean hierarchy with minimal coupling:
```
models → (no deps)
errors → models
keywords → models
tokenizer → models, keywords, metrics
ast → token
parser → tokenizer, ast, token, errors
gosqlx → all (high-level wrapper)
```

## Development Commands

This project uses [Task](https://taskfile.dev) as the task runner:
```bash
go install github.com/go-task/task/v3/cmd/task@latest
# Or: brew install go-task (macOS)
```

### Essential Commands
```bash
task                    # Show all available tasks
task build              # Build all packages
task build:cli          # Build CLI binary
task install            # Install CLI globally
task test               # Run all tests
task test:race          # Run tests with race detection (CRITICAL)
task test:pkg PKG=./pkg/sql/parser  # Test specific package
task bench              # Run benchmarks with memory tracking
task coverage           # Generate coverage report
task quality            # Run fmt, vet, lint
task check              # Full suite: format, vet, lint, test:race
task ci                 # Full CI pipeline
```

### Running a Single Test
```bash
go test -v -run TestSpecificName ./pkg/sql/parser/
go test -v -run "TestParser_Window.*" ./pkg/sql/parser/
```

### CLI Tool
```bash
./gosqlx validate "SELECT * FROM users"
./gosqlx format -i query.sql
./gosqlx analyze "SELECT COUNT(*) FROM orders GROUP BY status"
./gosqlx parse -f json query.sql
./gosqlx lsp                    # Start LSP server
./gosqlx lint query.sql         # Run linter
```

## Key Implementation Patterns

### Memory Management (MANDATORY)
Always use `defer` with pool return functions:

```go
// High-level API (recommended for most use cases)
ast, err := gosqlx.Parse("SELECT * FROM users")
// No cleanup needed - handled automatically

// Low-level API (for fine-grained control)
tkz := tokenizer.GetTokenizer()
defer tokenizer.PutTokenizer(tkz)  // MANDATORY

astObj := ast.NewAST()
defer ast.ReleaseAST(astObj)       // MANDATORY
```

### Parser Architecture
- Recursive descent with one-token lookahead
- Main file: `pkg/sql/parser/parser.go`
- Window functions: `parseFunctionCall()`, `parseWindowSpec()`, `parseWindowFrame()`
- CTEs: WITH clause with RECURSIVE support
- Set operations: UNION/EXCEPT/INTERSECT with left-associative parsing
- JOINs: All types with proper left-associative tree logic

### Error Handling
- Always check errors from tokenizer and parser
- Errors include position information (`models.Location`)
- Error codes: E1001-E3004 for tokenizer, parser, semantic errors
- Use `pkg/errors/` for structured error creation

## Testing Requirements

### Race Detection is Mandatory
```bash
task test:race                           # Primary method
go test -race -timeout 60s ./...         # Direct command
```

### Coverage by Package
- `pkg/models/`: 100% - All core data structures
- `pkg/sql/ast/`: 73.4% - AST nodes
- `pkg/sql/tokenizer/`: 76.1% - Zero-copy operations
- `pkg/sql/parser/`: 76.1% - All SQL features
- `pkg/errors/`: 95.6% - Error handling

### Benchmarking
```bash
task bench                                                    # All benchmarks
go test -bench=BenchmarkName -benchmem ./pkg/sql/parser/     # Specific benchmark
go test -bench=. -benchmem -cpuprofile=cpu.prof ./pkg/...    # With profiling
```

## Common Workflows

### Adding a New SQL Feature
1. Update tokens in `pkg/models/token.go` (if needed)
2. Add keywords to `pkg/sql/keywords/` (if needed)
3. Extend AST nodes in `pkg/sql/ast/`
4. Add parsing logic in `pkg/sql/parser/parser.go`
5. Write comprehensive tests
6. Run: `task test:race && task bench`
7. Update CHANGELOG.md

### Debugging Parsing Issues
```bash
go test -v -run TestTokenizer_YourTest ./pkg/sql/tokenizer/
go test -v -run TestParser_YourTest ./pkg/sql/parser/
```

Use the visitor pattern in `pkg/sql/ast/visitor.go` to traverse and inspect AST.

## Release Workflow

**CRITICAL**: Main branch is protected. Never create tags in feature branches.

```bash
# 1. Develop in feature branch
git checkout -b feature/branch-name
# ... make changes, update CHANGELOG.md as [Unreleased] ...
git push origin feature/branch-name

# 2. Create PR and get it merged

# 3. After merge, create docs PR for release finalization
git checkout main && git pull
git checkout -b docs/vX.Y.Z-release
# Update CHANGELOG.md with version and date
git push origin docs/vX.Y.Z-release

# 4. After docs PR merged, create tag
git checkout main && git pull
git tag vX.Y.Z -a -m "vX.Y.Z: Release notes"
git push origin vX.Y.Z

# 5. Create GitHub release
gh release create vX.Y.Z --title "vX.Y.Z: Title" --notes "..."
```

## Pre-commit Hooks

The repository has pre-commit hooks that run:
1. `go fmt` - Code formatting
2. `go vet` - Static analysis
3. `go test -short` - Short test suite

Install with: `task hooks:install`

## Additional Documentation

- `docs/GETTING_STARTED.md` - Quick start guide
- `docs/USAGE_GUIDE.md` - Comprehensive usage patterns
- `docs/LSP_GUIDE.md` - LSP server and IDE integration
- `docs/LINTING_RULES.md` - All 10 linting rules reference
- `docs/SQL_COMPATIBILITY.md` - SQL dialect compatibility matrix
- `docs/ARCHITECTURE.md` - Detailed system design
