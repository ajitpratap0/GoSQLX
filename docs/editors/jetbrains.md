# GoSQLX – JetBrains IDE LSP Setup

Supported IDEs: IntelliJ IDEA, GoLand, DataGrip, WebStorm, PyCharm, and others (2023.2+).

## Prerequisites

- [GoSQLX](https://github.com/ajitpratap0/GoSQLX) installed and available on your `$PATH`
- JetBrains IDE version **2023.2** or later (built-in LSP support)

## Configuration

1. Open **Settings** → **Languages & Frameworks** → **Language Servers** (or search for "LSP" in Settings).
2. Click **+** to add a new server.
3. Configure:
   - **Name**: `GoSQLX`
   - **Command**: `gosqlx lsp`
   - **File patterns**: `*.sql`, `*.pgsql`, `*.mysql`
4. Click **OK** / **Apply**.

## Manual Configuration (settings.json)

If your IDE supports custom LSP definitions via JSON, add:

```json
{
  "lsp": {
    "gosqlx": {
      "command": ["gosqlx", "lsp"],
      "fileTypes": ["sql"],
      "initializationOptions": {
        "dialect": "postgresql"
      }
    }
  }
}
```

## Verify

Open any `.sql` file. You should see GoSQLX diagnostics and formatting available via the editor's code actions.

## Troubleshooting

- Ensure `gosqlx` is on your `$PATH` by running `gosqlx --version` in the terminal.
- Check **Help** → **Diagnostic Tools** → **Debug Log Settings** and add `#lsp` for LSP debug logging.
