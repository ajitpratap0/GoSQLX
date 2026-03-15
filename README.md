# GoSQLX

<div align="center">

<img src="https://raw.githubusercontent.com/ajitpratap0/GoSQLX/main/.github/logo.png" alt="GoSQLX Logo" width="200" onerror="this.style.display='none'"/>

<h3>High-Performance SQL Parser for Go</h3>

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=for-the-badge&logo=go)](https://go.dev)
[![Release](https://img.shields.io/github/v/release/ajitpratap0/GoSQLX?style=for-the-badge&color=orange)](https://github.com/ajitpratap0/GoSQLX/releases)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg?style=for-the-badge)](https://www.apache.org/licenses/LICENSE-2.0)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=for-the-badge)](http://makeapullrequest.com)

[![Website](https://img.shields.io/badge/Website-gosqlx.dev-blue?style=for-the-badge&logo=google-chrome)](https://gosqlx.dev)
[![VS Code](https://img.shields.io/visual-studio-marketplace/v/ajitpratap0.gosqlx?style=for-the-badge&logo=visual-studio-code&label=VS%20Code)](https://marketplace.visualstudio.com/items?itemName=ajitpratap0.gosqlx)
[![MCP Server](https://img.shields.io/badge/MCP-Remote%20Server-blue?style=for-the-badge&logo=cloud)](https://mcp.gosqlx.dev/health)
[![GitHub Marketplace](https://img.shields.io/badge/Lint%20Action-GitHub-blue?style=for-the-badge&logo=github)](https://github.com/marketplace/actions/gosqlx-lint-action)

[![Tests](https://img.shields.io/github/actions/workflow/status/ajitpratap0/GoSQLX/test.yml?branch=main&label=Tests&style=flat-square)](https://github.com/ajitpratap0/GoSQLX/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/ajitpratap0/GoSQLX?style=flat-square)](https://goreportcard.com/report/github.com/ajitpratap0/GoSQLX)
[![GoDoc](https://pkg.go.dev/badge/github.com/ajitpratap0/GoSQLX?style=flat-square)](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX)

**[Try the Playground](https://gosqlx.dev/playground/)** · **[Read the Docs](https://gosqlx.dev/docs/)** · **[Get Started](docs/GETTING_STARTED.md)** · **[Benchmarks](https://gosqlx.dev/benchmarks/)**

</div>

---

Production-ready SQL parsing SDK for Go with zero-copy tokenization, object pooling, and multi-dialect support. Parse SQL at **1.25M+ ops/sec** with **<1μs latency** and **~85% SQL-99 compliance** across 6 dialects.

## Key Features

- **Blazing Fast** — 1.25M+ ops/sec, zero-copy tokenization, <1μs latency
- **Multi-Dialect** — PostgreSQL, MySQL, SQL Server, Oracle, SQLite, Snowflake
- **Thread-Safe** — Zero race conditions, linear scaling to 128+ cores
- **Memory Efficient** — 60-80% reduction via sync.Pool object pooling
- **Complete SQL Support** — JOINs, CTEs, window functions, MERGE, set operations, GROUPING SETS
- **Security Scanner** — SQL injection detection with severity classification
- **AST Formatter** — Configurable SQL formatter with roundtrip fidelity
- **Linter** — 10 built-in rules (L001–L010) for SQL best practices
- **Query Transforms** — Programmatic SQL rewriting (add WHERE, JOINs, pagination)
- **[VS Code Extension](https://marketplace.visualstudio.com/items?itemName=ajitpratap0.gosqlx)** — Real-time validation, formatting, and linting in your editor
- **[Remote MCP Server](https://mcp.gosqlx.dev/health)** — 7 SQL tools accessible from Claude, Cursor, or any MCP client
- **[WASM Playground](https://gosqlx.dev/playground/)** — Try GoSQLX in the browser, no installation needed
- **[Python Bindings](python/README.md)** — Use GoSQLX from Python via ctypes FFI

## Quick Start

```bash
go get github.com/ajitpratap0/GoSQLX
```

```go
package main

import (
    "fmt"
    "github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

func main() {
    // Parse
    ast, _ := gosqlx.Parse("SELECT u.name, COUNT(*) FROM users u GROUP BY u.name")
    fmt.Printf("Statements: %d\n", len(ast.Statements))

    // Format
    formatted, _ := gosqlx.Format("select id,name from users where active=true",
        gosqlx.DefaultFormatOptions())
    fmt.Println(formatted)

    // Validate
    if err := gosqlx.Validate("SELECT * FROM"); err != nil {
        fmt.Println("Invalid:", err)
    }
}
```

## Installation

### Go Library
```bash
go get github.com/ajitpratap0/GoSQLX
```

### CLI
```bash
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
gosqlx validate "SELECT * FROM users"
gosqlx format query.sql
gosqlx lint query.sql
gosqlx analyze "SELECT COUNT(*) FROM orders GROUP BY status"
```

### VS Code Extension
```bash
code --install-extension ajitpratap0.gosqlx
```
Or search **"GoSQLX"** in the Extensions panel. Bundles the binary — no separate install needed. [Learn more →](https://gosqlx.dev/vscode/)

### MCP Server (AI Integration)

Connect 7 SQL tools to Claude, Cursor, or any MCP client — no installation required:

```bash
# Claude Code
claude mcp add --transport http gosqlx https://mcp.gosqlx.dev/mcp

# Or run locally
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx-mcp@latest
gosqlx-mcp
```

Tools: `validate_sql`, `format_sql`, `parse_sql`, `extract_metadata`, `security_scan`, `lint_sql`, `analyze_sql`. [Full guide →](https://gosqlx.dev/docs/mcp_guide/)

## Documentation

| Resource | Link |
|---|---|
| Website & Playground | [gosqlx.dev](https://gosqlx.dev) |
| Getting Started | [5-minute quickstart](https://gosqlx.dev/docs/getting_started/) |
| Usage Guide | [Comprehensive patterns](https://gosqlx.dev/docs/usage_guide/) |
| API Reference | [Full API docs](https://gosqlx.dev/docs/api_reference/) |
| CLI Guide | [Command reference](https://gosqlx.dev/docs/cli_guide/) |
| SQL Compatibility | [Dialect matrix](https://gosqlx.dev/docs/sql_compatibility/) |
| Architecture | [System design](https://gosqlx.dev/docs/architecture/) |
| Benchmarks | [Performance data](https://gosqlx.dev/benchmarks/) |
| Release Notes | [Changelog](https://gosqlx.dev/blog/) |
| GoDoc | [pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX) |

## Performance

<div align="center">

| **1.25M+** | **<1μs** | **85%** | **6** |
|:---------:|:-------:|:-------:|:---------:|
| ops/sec | latency | SQL-99 | dialects |

</div>

See detailed benchmarks at [gosqlx.dev/benchmarks](https://gosqlx.dev/benchmarks/).

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
git clone https://github.com/ajitpratap0/GoSQLX.git
cd GoSQLX
go test -race ./...      # Run tests
task check               # Full CI suite (fmt, vet, lint, test)
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
