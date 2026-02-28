# Support

## How to Get Help

### 🐛 Found a bug?

Open a [bug report](https://github.com/ajitpratap0/GoSQLX/issues/new?template=bug_report.md). Include:
- GoSQLX version (`gosqlx --version` or `const Version` in `pkg/gosqlx/gosqlx.go`)
- Go version (`go version`)
- Minimal reproducing SQL and Go snippet
- Expected vs actual behavior

### 💡 Feature request?

Open a [feature request](https://github.com/ajitpratap0/GoSQLX/issues/new?template=feature_request.md). Describe the SQL pattern you need parsed and the use case.

### ❓ Questions and discussions

For usage questions, design discussions, and "how do I…" questions, use [GitHub Discussions](https://github.com/ajitpratap0/GoSQLX/discussions):

| Category | Use for |
|----------|---------|
| **Q&A** | Usage questions, API help |
| **Ideas** | Feature proposals before filing an issue |
| **Show and Tell** | Projects built with GoSQLX |
| **General** | Anything else |

### 🚀 Performance issues?

Open a [performance issue](https://github.com/ajitpratap0/GoSQLX/issues/new?template=performance_issue.md) with benchmark output (`go test -bench=. -benchmem ./...`).

### 🔒 Security vulnerabilities?

**Do not open a public issue.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

## Self-Help Resources

| Resource | What it covers |
|----------|---------------|
| [Getting Started](docs/GETTING_STARTED.md) | Install and first parse in 5 minutes |
| [Usage Guide](docs/USAGE_GUIDE.md) | All API patterns with examples |
| [CLI Guide](docs/CLI_GUIDE.md) | Every CLI command and flag |
| [API Reference](docs/API_REFERENCE.md) | Complete function/type reference |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common errors and solutions |
| [Error Codes](docs/ERROR_CODES.md) | E1xxx / E2xxx / E3xxx reference |
| [SQL Compatibility](docs/SQL_COMPATIBILITY.md) | What SQL is supported per dialect |
| [Migration Guide](docs/MIGRATION.md) | Upgrading between versions |
| [pkg.go.dev](https://pkg.go.dev/github.com/ajitpratap0/GoSQLX) | Generated Go API docs |

## Response Times

This is an open source project maintained in spare time. Typical response times:

| Channel | Expected response |
|---------|------------------|
| Bug reports (with reproduction) | 1–3 business days |
| Feature requests | 1–2 weeks (discussion first) |
| Security vulnerabilities | 48 hours |
| GitHub Discussions | best-effort |

## Supported Versions

| Version | Status | Go requirement |
|---------|--------|----------------|
| v1.9.x | ✅ Active (current) | Go 1.21+ |
| v1.8.x | ⚠️ Security fixes only | Go 1.21+ |
| < v1.8 | ❌ End of life | — |

Upgrade with: `go get github.com/ajitpratap0/GoSQLX@latest`
