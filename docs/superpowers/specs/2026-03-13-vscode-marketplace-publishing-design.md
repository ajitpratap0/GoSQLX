# VSCode Extension Marketplace Publishing — Design Spec

> **Goal:** Publish the GoSQLX VSCode extension to the VS Code Marketplace with bundled platform-specific binaries and automated CI-driven releases.

**Version:** 1.10.1 (aligned with GoSQLX, patch bump for extension publishing)

**Platforms:** linux-x64, linux-arm64, darwin-x64, darwin-arm64, win32-x64

**Approach:** Platform-specific extensions — separate VSIXs per target, VS Code auto-downloads the correct one.

---

## 1. Publisher & Marketplace Setup

Before any code changes:

1. Create Azure DevOps organization at dev.azure.com (free, required for PAT generation)
2. Generate Personal Access Token (PAT) with "Marketplace (Manage)" scope, all accessible organizations
3. Create publisher `ajitpratap0` at marketplace.visualstudio.com/manage using the PAT
4. Verify the publisher (email or domain verification)
5. Store the PAT as GitHub Actions secret `VSCE_PAT`

## 2. Extension Package Changes

### `vscode-extension/package.json`

- Version: `"0.1.0"` → `"1.10.1"`
- Add `"icon": "images/icon.png"` (icon already exists at `vscode-extension/images/icon.png`)
- Add `"repository"`: `{ "type": "git", "url": "https://github.com/ajitpratap0/GoSQLX" }`
- Add `"bugs"`: `{ "url": "https://github.com/ajitpratap0/GoSQLX/issues" }`
- Add `"homepage"`: `"https://github.com/ajitpratap0/GoSQLX#readme"`
- Add `"categories"`: `["Programming Languages", "Linters", "Formatters"]`
- Add `"keywords"`: `["sql", "parser", "linter", "formatter", "gosqlx"]`
- Ensure `"engines.vscode"` is set to `"^1.85.0"` (reasonable minimum)
- Update default for `gosqlx.executablePath` setting: default becomes `""` (empty = use bundled binary)

**Backward compatibility note:** Changing the default from `"gosqlx"` to `""` is safe because the resolution logic falls back to PATH lookup. Existing users without an explicit setting will see: bundled binary check (not found for older installs) → PATH lookup (finds their existing `gosqlx`) → works as before.

### `vscode-extension/src/extension.ts`

Add a `getBinaryPath()` function with resolution logic:

```
1. Check user setting `gosqlx.executablePath` (explicit override)
2. If not set → resolve <extensionPath>/bin/gosqlx (bundled)
3. If bundled not found → fall back to PATH lookup for "gosqlx"
4. If nothing found → show error with install instructions
```

- On Windows, append `.exe` automatically
- Verify binary is executable via `fs.access` with execute permission
- **All binary spawn sites must use `getBinaryPath()`** — this includes `startLanguageServer`, `analyzeCommand`, `validateExecutable`, and any other function that spawns the binary directly

### `vscode-extension/CHANGELOG.md`

Update with 1.10.1 entry documenting binary bundling and Marketplace publishing.

### `.vscodeignore`

Ensure `bin/` directory is NOT ignored (binary must be included in VSIX). Exclude test files (`out/test/**`), `node_modules/` dev dependencies, source maps, `.ts` source files, etc.

## 3. Cross-Compilation & Binary Bundling

### Build matrix

| VS Code Platform | GOOS    | GOARCH | Binary Name   |
|------------------|---------|--------|---------------|
| linux-x64        | linux   | amd64  | `gosqlx`      |
| linux-arm64      | linux   | arm64  | `gosqlx`      |
| darwin-x64       | darwin  | amd64  | `gosqlx`      |
| darwin-arm64     | darwin  | arm64  | `gosqlx`      |
| win32-x64        | windows | amd64  | `gosqlx.exe`  |

**Future platforms:** `win32-arm64` can be added when demand warrants.

### Build command

```bash
GOOS=<os> GOARCH=<arch> go build -ldflags="-s -w" -o vscode-extension/bin/gosqlx ./cmd/gosqlx
```

Flags `-s -w` strip debug symbols, reducing binary size to ~8-10MB.

### Package command

```bash
cd vscode-extension
vsce package --target <vscode-platform>
# Produces: gosqlx-<vscode-platform>-1.10.1.vsix
```

## 4. GitHub Actions Workflow

### New file: `.github/workflows/vscode-publish.yml`

**Trigger:** Tag push matching `v*`

**Note:** This runs in parallel with the existing `release.yml` (which handles GoReleaser for Go binary releases). They are independent workflows.

### Job 1: `build` (matrix: 5 platforms)

1. Checkout repository
2. Setup Go 1.24
3. Cross-compile binary for target platform into `vscode-extension/bin/`
4. Setup Node 20
5. `npm ci` in `vscode-extension/`
6. Extract version from git tag and patch `package.json`:
   ```bash
   VERSION=${GITHUB_REF_NAME#v}
   npm version $VERSION --no-git-tag-version
   ```
7. `npx vsce package --target <platform>` (vsce installed as devDependency via npm ci)
8. Upload `.vsix` as artifact

### Job 2: `publish` (depends on `build`)

1. Setup Node 20
2. `npm install -g @vscode/vsce` (separate job, needs its own vsce install)
3. Download all 5 `.vsix` artifacts
4. `vsce publish --packagePath *.vsix` (atomic multi-platform publish)
5. Authenticates with `VSCE_PAT` GitHub Actions secret

**Key design decision:** Version is derived from the git tag (`v1.10.1` → `1.10.1`) and patched into `package.json` during CI. This means the extension version always matches the GoSQLX release version without manual bumping.

### Smoke test (native platform only)

In the build job, for the matrix entry matching the runner's native platform (linux-x64), run a quick sanity check:
```bash
./vscode-extension/bin/gosqlx version
```

## 5. Testing & First Publish

### Local verification (before first automated publish)

1. Build one platform VSIX locally:
   ```bash
   go build -o vscode-extension/bin/gosqlx ./cmd/gosqlx
   cd vscode-extension && npx vsce package --target darwin-arm64
   ```
2. Install from VSIX in VS Code
3. Verify: LSP starts, all 7 tools work, status bar shows connection

### First release flow

1. Merge all extension changes to `main`
2. Bump version to `v1.10.1` (patch — v1.10.0 tag already exists)
3. Tag push triggers CI workflow
4. CI builds 5 platform VSIXs and publishes to Marketplace

### Subsequent releases

Every GoSQLX version tag automatically rebuilds and publishes the extension with the matching version and updated binary.

## 6. Version Strategy

- Extension version is aligned 1:1 with GoSQLX version
- Extension-only fixes (no binary change) use patch bumps
- Version is always derived from git tag in CI — no manual version management
- `package.json` version in the repo can stay at a base value; CI overrides it

## 7. Files Changed

| File | Action |
|------|--------|
| `vscode-extension/package.json` | Modify — version, icon, metadata, categories, keywords |
| `vscode-extension/src/extension.ts` | Modify — add `getBinaryPath()`, update all binary spawn sites |
| `vscode-extension/CHANGELOG.md` | Modify — add 1.10.1 entry |
| `vscode-extension/.vscodeignore` | Modify — ensure `bin/` included, exclude `out/test/**` |
| `.github/workflows/vscode-publish.yml` | Create — CI workflow |
| `vscode-extension/bin/` | Created by CI — not committed to repo |
| `pkg/gosqlx/gosqlx.go` | Modify — version bump to 1.10.1 |
| `cmd/gosqlx/cmd/root.go` | Modify — version bump to 1.10.1 |
| `CHANGELOG.md` | Modify — add 1.10.1 entry |
