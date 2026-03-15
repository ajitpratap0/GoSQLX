# GoSQLX

<div align="center">

<img src="https://raw.githubusercontent.com/ajitpratap0/GoSQLX/main/.github/logo.png" alt="GoSQLX Logo" width="180"/>

### Parse SQL at the speed of Go

[![Go Version](https://img.shields.io/badge/Go-1.23+-00ADD8?style=for-the-badge&logo=go)](https://go.dev)
[![Release](https://img.shields.io/github/v/release/ajitpratap0/GoSQLX?style=for-the-badge&color=orange)](https://github.com/ajitpratap0/GoSQLX/releases)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg?style=for-the-badge)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=for-the-badge)](http://makeapullrequest.com)

[![Website](https://img.shields.io/badge/gosqlx.dev-Website-blue?style=for-the-badge&logo=google-chrome)](https://gosqlx.dev)
[![VS Code](https://img.shields.io/visual-studio-marketplace/v/ajitpratap0.gosqlx?style=for-the-badge&logo=visual-studio-code&label=VS%20Code)](https://marketplace.visualstudio.com/items?itemName=ajitpratap0.gosqlx)
[![MCP](https://img.shields.io/badge/MCP-Remote%20Server-blue?style=for-the-badge&logo=cloud)](https://mcp.gosqlx.dev/health)
[![Lint Action](https://img.shields.io/badge/Lint%20Action-GitHub-blue?style=for-the-badge&logo=github)](https://github.com/marketplace/actions/gosqlx-lint-action)

[![Tests](https://img.shields.io/github/actions/workflow/status/ajitpratap0/GoSQLX/test.yml?branch=main&label=Tests&style=flat-square)](https://github.com/ajitpratap0/GoSQLX/actions)
[![Go Report](https://goreportcard.com/badge/github.com/ajitpratap0/GoSQLX?style=flat-square)](https://goreportcard.com/report/github.com/ajitpratap0/GoSQLX)
[![GoDoc](https://pkg.go.dev/badge/github.com/ajitpratap0/GoSQLX?style=flat-square)](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX)
[![Stars](https://img.shields.io/github/stars/ajitpratap0/GoSQLX?style=social)](https://github.com/ajitpratap0/GoSQLX)

<br/>

**[🌐 Try the Playground](https://gosqlx.dev/playground/)** &nbsp;·&nbsp; **[📖 Read the Docs](https://gosqlx.dev/docs/)** &nbsp;·&nbsp; **[🚀 Get Started](docs/GETTING_STARTED.md)** &nbsp;·&nbsp; **[📊 Benchmarks](https://gosqlx.dev/benchmarks/)**

<br/>

| **1.25M+ ops/sec** | **<1μs latency** | **85% SQL-99** | **6 dialects** | **0 race conditions** |
|:---:|:---:|:---:|:---:|:---:|

</div>

<br/>

## What is GoSQLX?

GoSQLX is a **production-ready SQL parsing SDK** for Go. It tokenizes, parses, and generates ASTs from SQL with zero-copy optimizations and intelligent object pooling - handling **1.25M+ operations per second** with sub-microsecond latency.

```go
ast, _ := gosqlx.Parse("SELECT u.name, COUNT(*) FROM users u JOIN orders o ON u.id = o.user_id GROUP BY u.name")
// → Full AST with statements, columns, joins, grouping - ready for analysis, transformation, or formatting
```

### Why GoSQLX?

- **Not an ORM** - a parser. You get the AST, you decide what to do with it.
- **Not slow** - zero-copy tokenization, sync.Pool recycling, no allocations on hot paths.
- **Not limited** - PostgreSQL, MySQL, SQL Server, Oracle, SQLite, Snowflake. CTEs, window functions, MERGE, set operations.
- **Not just a library** - CLI, VS Code extension, GitHub Action, MCP server, WASM playground, Python bindings.

<br/>

## Get Started in 60 Seconds

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
    // Parse any SQL dialect
    ast, _ := gosqlx.Parse("SELECT * FROM users WHERE active = true")
    fmt.Printf("%d statement(s)\n", len(ast.Statements))

    // Format messy SQL
    clean, _ := gosqlx.Format("select id,name from users where id=1", gosqlx.DefaultFormatOptions())
    fmt.Println(clean)
    // SELECT
    //   id,
    //   name
    // FROM users
    // WHERE id = 1

    // Catch errors before production
    if err := gosqlx.Validate("SELECT * FROM"); err != nil {
        fmt.Println(err) // → expected table name
    }
}
```

<br/>

## Install Everywhere

<table>
<tr>
<td width="50%">

### 📦 Go Library
```bash
go get github.com/ajitpratap0/GoSQLX
```

### 🖥️ CLI Tool
```bash
go install github.com/ajitpratap0/GoSQLX/cmd/gosqlx@latest
gosqlx validate "SELECT * FROM users"
gosqlx format query.sql
gosqlx lint query.sql
```

</td>
<td width="50%">

### 💻 VS Code Extension
```bash
code --install-extension ajitpratap0.gosqlx
```
Bundles the binary - zero setup. [Learn more →](https://gosqlx.dev/vscode/)

### 🤖 MCP Server (AI Integration)
```bash
claude mcp add --transport http gosqlx \
  https://mcp.gosqlx.dev/mcp
```
7 SQL tools in Claude, Cursor, or any MCP client. [Guide →](https://gosqlx.dev/docs/mcp_guide/)

</td>
</tr>
</table>

<br/>

## Features at a Glance

<table>
<tr>
<td align="center" width="33%"><h3>⚡ Parser</h3>Zero-copy tokenizer<br/>Recursive descent parser<br/>Full AST generation<br/>Multi-dialect engine</td>
<td align="center" width="33%"><h3>🛡️ Analysis</h3>SQL injection scanner<br/>10 lint rules (L001–L010)<br/>Query complexity scoring<br/>Metadata extraction</td>
<td align="center" width="33%"><h3>🔧 Tooling</h3>AST-based formatter<br/>Query transforms API<br/>VS Code extension<br/>GitHub Action</td>
</tr>
<tr>
<td align="center"><h3>🌐 Multi-Dialect</h3>PostgreSQL · MySQL<br/>SQL Server · Oracle<br/>SQLite · Snowflake</td>
<td align="center"><h3>🤖 AI-Ready</h3>MCP server (7 tools)<br/>Public remote endpoint<br/>Streamable HTTP</td>
<td align="center"><h3>🧪 Battle-Tested</h3>20K+ concurrent ops<br/>Zero race conditions<br/>~85% SQL-99 compliance</td>
</tr>
</table>

<br/>

## Documentation

| | Resource | Description |
|---|---|---|
| 🌐 | **[gosqlx.dev](https://gosqlx.dev)** | Website with interactive playground |
| 🚀 | **[Getting Started](https://gosqlx.dev/docs/getting_started/)** | Parse your first SQL in 5 minutes |
| 📖 | **[Usage Guide](https://gosqlx.dev/docs/usage_guide/)** | Comprehensive patterns and examples |
| 📄 | **[API Reference](https://gosqlx.dev/docs/api_reference/)** | Complete API documentation |
| 🖥️ | **[CLI Guide](https://gosqlx.dev/docs/cli_guide/)** | Command-line tool reference |
| 🌍 | **[SQL Compatibility](https://gosqlx.dev/docs/sql_compatibility/)** | Dialect support matrix |
| 🤖 | **[MCP Guide](https://gosqlx.dev/docs/mcp_guide/)** | AI assistant integration |
| 🏗️ | **[Architecture](https://gosqlx.dev/docs/architecture/)** | System design deep-dive |
| 📊 | **[Benchmarks](https://gosqlx.dev/benchmarks/)** | Performance data and methodology |
| 📝 | **[Release Notes](https://gosqlx.dev/blog/)** | What's new in each version |

<br/>

## Contributing

GoSQLX is built by contributors like you. Whether it's a bug fix, new feature, documentation improvement, or just a typo - every contribution matters.

```bash
git clone https://github.com/ajitpratap0/GoSQLX.git && cd GoSQLX
task check    # fmt → vet → lint → test (with race detection)
```

1. **Fork & branch** from `main`
2. **Write tests** - we use TDD and require race-free code
3. **Run `task check`** - must pass before PR
4. **Open a PR** - we review within 24 hours

📋 [Contributing Guide](CONTRIBUTING.md) · 📜 [Code of Conduct](CODE_OF_CONDUCT.md) · 🏛️ [Governance](GOVERNANCE.md)

<br/>

## Community

<div align="center">

**Got questions? Ideas? Found a bug?**

<a href="https://github.com/ajitpratap0/GoSQLX/discussions"><img src="https://img.shields.io/badge/💬_Discussions-Ask_&_Share-purple?style=for-the-badge" alt="Discussions"></a>
<a href="https://github.com/ajitpratap0/GoSQLX/issues/new/choose"><img src="https://img.shields.io/badge/🐛_Issues-Report_&_Request-red?style=for-the-badge" alt="Issues"></a>
<a href="https://gosqlx.dev/blog/"><img src="https://img.shields.io/badge/📝_Blog-Release_Notes-green?style=for-the-badge" alt="Blog"></a>

</div>

<br/>

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

---

<div align="center">

<sub>Built with ❤️ by the GoSQLX community</sub>

**[gosqlx.dev](https://gosqlx.dev)** · **[Playground](https://gosqlx.dev/playground/)** · **[Docs](https://gosqlx.dev/docs/)** · **[MCP Server](https://mcp.gosqlx.dev/mcp)** · **[VS Code](https://marketplace.visualstudio.com/items?itemName=ajitpratap0.gosqlx)**

<br/>

If GoSQLX helps your project, consider giving it a ⭐

</div>
