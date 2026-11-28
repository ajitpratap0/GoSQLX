- Claude Code plugin (`plugins/gosqlx`): prepared for Anthropic's plugin
  directory. Added a listing icon and `privacyPolicyUrl`, and the MCP server
  URL is now the literal `https://mcp.gosqlx.dev/mcp` as the directory
  requires. The `GOSQLX_MCP_URL` override is gone; for local mode add
  `gosqlx-mcp` as its own MCP server (see the plugin README). The README now
  states everything the plugin runs and sends.
