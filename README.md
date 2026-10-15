<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset=".github/logo-light.svg">
  <img src=".github/logo-light.svg" alt="GoSQLX" width="360">
</picture>

# GoSQLX

**Pure-Go SQL parser, formatter, linter and security scanner for 8 dialects.**

[![CI](https://img.shields.io/github/actions/workflow/status/ajitpratap0/GoSQLX/test.yml?branch=main&label=CI&style=flat-square)](https://github.com/ajitpratap0/GoSQLX/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ajitpratap0/GoSQLX.svg)](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX)
[![Release](https://img.shields.io/github/v/release/ajitpratap0/GoSQLX?style=flat-square)](https://github.com/ajitpratap0/GoSQLX/releases)
[![License](https://img.shields.io/github/license/ajitpratap0/GoSQLX?style=flat-square)](LICENSE)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/ajitpratap0/GoSQLX/badge)](https://securityscorecards.dev/viewer/?uri=github.com/ajitpratap0/GoSQLX)
[![Codecov](https://img.shields.io/codecov/c/github/ajitpratap0/GoSQLX?style=flat-square)](https://codecov.io/gh/ajitpratap0/GoSQLX)

**[Playground](https://gosqlx.dev/playground/)** &nbsp;·&nbsp; **[Docs](https://gosqlx.dev/docs/)** &nbsp;·&nbsp; **[Benchmarks](https://gosqlx.dev/benchmarks/)** &nbsp;·&nbsp; **[VS Code](https://marketplace.visualstudio.com/items?itemName=ajitpratap0.gosqlx)** &nbsp;·&nbsp; **[MCP server](#-mcp-server-ai-integration)**

<br/>

<!-- metrics:start -->
| **~3.1M parses/sec†** | **318 ns parse latency†** | **~80–85% SQL-99 (est.)** | **8 dialects** | **0 race conditions** |
|:---:|:---:|:---:|:---:|:---:|

<sub>† Parse stage only (pre-tokenized input to AST), `SELECT id, name FROM users`, Apple M4, Go 1.27, median of 10 runs of `BenchmarkPerformanceBaseline`. Complex queries take longer (see `performance_baselines.json`). Reproduce: `go test -run ^$ -bench BenchmarkPerformanceBaseline -benchmem -count=10 ./pkg/sql/parser/`.</sub>
<!-- metrics:end -->

</div>

<br/>

## What is GoSQLX?

GoSQLX is a **production-ready SQL parsing SDK** for Go. It tokenizes, parses, and generates ASTs from SQL with zero-copy optimizations and intelligent object pooling - parsing a simple SELECT in about <!-- metrics-inline:start -->**318 ns (~3.1M parses/sec)**<!-- metrics-inline:end -->.

```go
package main

import (
	"context"
	"fmt"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
)

func main() {
	// ParseTree returns an opaque Tree, so you don't need to import
	// pkg/sql/ast just to get started.
	tree, _ := gosqlx.ParseTree(context.Background(),
		"SELECT u.name, COUNT(*) FROM users u JOIN orders o ON u.id = o.user_id GROUP BY u.name",
		gosqlx.WithDialect("postgresql"))
	fmt.Println("Tables:", tree.Tables())
	fmt.Println(tree.Format(gosqlx.WithIndent(2), gosqlx.WithUppercaseKeywords(true)))
}
```

### Why GoSQLX?

- **Not an ORM** - a parser. You get the AST, you decide what to do with it.
- **Not slow** - zero-copy tokenization, sync.Pool recycling, no allocations on hot paths.
- **Not limited** - PostgreSQL, MySQL, MariaDB, SQL Server, Oracle, SQLite, Snowflake, ClickHouse. CTEs, window functions, MERGE, set operations.
- **Not just a library** - CLI, VS Code extension, GitHub Action, MCP server, WASM playground, Python bindings.

<br/>

## Get Started in 60 Seconds

```bash
go get github.com/ajitpratap0/GoSQLX
```

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/ajitpratap0/GoSQLX/pkg/gosqlx"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
)

func main() {
	ctx := context.Background()

	// ParseTree is the recommended entry point. It returns an
	// opaque handle with built-in helpers.
	tree, err := gosqlx.ParseTree(ctx, "SELECT id, name FROM users WHERE active = true",
		gosqlx.WithDialect("postgresql"))
	if err != nil {
		// Sentinel errors work with errors.Is
		if errors.Is(err, gosqlx.ErrSyntax) {
			log.Fatalf("syntax error: %v", err)
		}
		log.Fatal(err)
	}
	fmt.Println("Tables:", tree.Tables())
	fmt.Println(tree.Format(gosqlx.WithIndent(2), gosqlx.WithUppercaseKeywords(true)))

	// Walk the AST - typed walkers avoid the type-assertion dance:
	tree.WalkSelects(func(s *ast.SelectStatement) bool {
		fmt.Printf("  SELECT with %d columns\n", len(s.Columns))
		return true
	})

	// The legacy Parse/Format/Validate API still works for v1.x code.
	// See docs/MIGRATION.md for the Tree migration guide.
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

[![MCP](https://img.shields.io/badge/MCP-Remote%20Server-blue?style=flat-square)](https://mcp.gosqlx.dev/health)
[![Glama MCP Server](https://glama.ai/mcp/servers/ajitpratap0/GoSQLX/badges/score.svg)](https://glama.ai/mcp/servers/ajitpratap0/GoSQLX)

</td>
</tr>
</table>

<br/>

## Features at a Glance

<table>
<tr>
<td align="center" width="33%"><h3>⚡ Parser</h3>Zero-copy tokenizer<br/>Recursive descent parser<br/>Full AST generation<br/>Multi-dialect engine</td>
<td align="center" width="33%"><h3>🛡️ Analysis</h3>SQL injection scanner<br/>30 lint rules (L001–L030)<br/>20 optimizer rules<br/>Metadata extraction</td>
<td align="center" width="33%"><h3>🔧 Tooling</h3>AST-based formatter<br/>Query transforms API<br/>VS Code extension<br/>GitHub Action</td>
</tr>
<tr>
<td align="center"><h3>🌐 Multi-Dialect</h3>PostgreSQL · MySQL · MariaDB<br/>SQL Server · Oracle<br/>SQLite · Snowflake · ClickHouse</td>
<td align="center"><h3>🤖 AI-Ready</h3>MCP server (7 tools)<br/>Public remote endpoint<br/>Streamable HTTP</td>
<td align="center"><h3>🧪 Battle-Tested</h3>Race-detector clean in CI<br/>~80–85% SQL-99 (estimated)</td>
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

## Who's Using GoSQLX?

GoSQLX is downloaded and cloned by developers worldwide -- 595 unique cloners in just 14 days. If you're using GoSQLX in your project or organization, we'd love to hear about it!

| Project / Company | Use Case |
|---|---|
| *Your project here* | [Add yourself via PR](https://github.com/ajitpratap0/GoSQLX/edit/main/README.md) or [tell us in Discussions](https://github.com/ajitpratap0/GoSQLX/discussions) |

Using GoSQLX at work? Building something cool with it? Share your story in [GitHub Discussions](https://github.com/ajitpratap0/GoSQLX/discussions) -- it helps the community grow and motivates continued development.

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
