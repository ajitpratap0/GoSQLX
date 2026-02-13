# GoSQLX – VS Code Extension

## Install from Marketplace

Search for **GoSQLX** in the VS Code Extensions panel, or install from the command line:

```bash
code --install-extension ajitpratap0.gosqlx
```

## Prerequisites

- [GoSQLX](https://github.com/ajitpratap0/GoSQLX) installed and available on your `$PATH`

## Features

- **Real-time SQL validation** – syntax errors highlighted as you type
- **SQL formatting** – format with `Cmd+Shift+F` (Mac) / `Ctrl+Shift+F`
- **SQL analysis** – right-click → "Analyze SQL"
- **Multi-dialect support** – PostgreSQL, MySQL, SQL Server, Oracle, SQLite

## Configuration

Open **Settings** and search for `gosqlx`:

| Setting | Default | Description |
|---------|---------|-------------|
| `gosqlx.dialect` | `generic` | SQL dialect |
| `gosqlx.executablePath` | `gosqlx` | Path to the `gosqlx` binary |
| `gosqlx.format.indentSize` | `2` | Indent size for formatting |
| `gosqlx.format.uppercaseKeywords` | `true` | Uppercase SQL keywords |
| `gosqlx.validation.enable` | `true` | Enable real-time validation |

## Troubleshooting

Run **GoSQLX: Validate Configuration** from the Command Palette to check your setup.
