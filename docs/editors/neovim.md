# GoSQLX – Neovim LSP Setup

## Prerequisites

- [GoSQLX](https://github.com/ajitpratap0/GoSQLX) installed and available on your `$PATH`
- [nvim-lspconfig](https://github.com/neovim/nvim-lspconfig)

## Configuration

Add the following to your Neovim configuration (e.g. `init.lua`):

```lua
local lspconfig = require('lspconfig')
local configs = require('lspconfig.configs')

-- Register GoSQLX as a custom LSP server
if not configs.gosqlx then
  configs.gosqlx = {
    default_config = {
      cmd = { 'gosqlx', 'lsp' },
      filetypes = { 'sql', 'mysql', 'pgsql' },
      root_dir = lspconfig.util.root_pattern('.git', '.gosqlx.yaml'),
      settings = {},
    },
  }
end

lspconfig.gosqlx.setup{}
```

### With Custom Options

```lua
lspconfig.gosqlx.setup{
  cmd = { 'gosqlx', 'lsp' },
  settings = {
    gosqlx = {
      dialect = 'postgresql',
      format = {
        indentSize = 2,
        uppercaseKeywords = true,
      },
    },
  },
}
```

## Verify

Open a `.sql` file and run:

```vim
:LspInfo
```

You should see `gosqlx` listed as an active client.
