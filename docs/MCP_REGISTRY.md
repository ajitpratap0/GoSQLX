# MCP Registry publication

The public remote server at `https://mcp.gosqlx.dev/mcp` is listed as
`io.github.ajitpratap0/gosqlx` in the [official MCP Registry](https://registry.modelcontextprotocol.io/).
Its listing is defined in the repository root `server.json`. Keep its version
in step with the GoSQLX release and the deployed server's `/health` version.

After GoReleaser creates a stable GitHub release, `release.yml` dispatches
`publish-mcp.yml`. A release published outside GoReleaser also triggers the
publisher directly. The workflow checks that the release tag belongs to main,
the manifest name, version and remote URL match, and the deployed endpoint
reports that version. It then validates and publishes with GitHub Actions OIDC;
no registry token or PAT is stored. A deployment that has not reached the
release version within two minutes fails the workflow; rerun it after deployment.

For an existing stable release such as `v1.16.0`, run **Publish MCP Registry
entry** with `tag=v1.16.0` from the Actions tab after `server.json` is present
on main and the live endpoint reports `1.16.0`. The publisher reads the
manifest from main so this initial backfill works even though the old tag did
not contain `server.json`. Keep the manifest at the intended release version
until publication finishes. A repeated run may be rejected by the registry if
that version is already published; check the registry entry before retrying.

The workflow pins `mcp-publisher` v1.8.1 and verifies the official Linux amd64
release asset's SHA-256 before executing it. Update both the version and digest
together when upgrading the publisher. See the [registry's GitHub Actions guide](https://github.com/modelcontextprotocol/registry/blob/main/docs/modelcontextprotocol-io/github-actions.mdx)
for the OIDC publishing flow.
