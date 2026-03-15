# VSCode Marketplace Publishing Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish the GoSQLX VSCode extension to the VS Code Marketplace with bundled platform-specific binaries and automated CI-driven releases.

**Architecture:** Add a `getBinaryPath()` function to resolve bundled/user/PATH binaries, update all spawn sites, create a GitHub Actions workflow that cross-compiles Go for 5 platforms, packages platform-specific VSIXs, and publishes atomically to the Marketplace on tag push.

**Tech Stack:** TypeScript (VS Code extension), Go (cross-compilation), GitHub Actions, `@vscode/vsce`, `npm`

**Spec:** `docs/superpowers/specs/2026-03-13-vscode-marketplace-publishing-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `vscode-extension/src/extension.ts` | Modify | Add `getBinaryPath()`, update 3 spawn sites |
| `vscode-extension/package.json` | Modify | Version bump, default change |
| `vscode-extension/.vscodeignore` | Modify | Include `bin/`, exclude `out/test/**` |
| `vscode-extension/CHANGELOG.md` | Modify | Add 1.10.1 entry |
| `vscode-extension/.gitignore` | Modify | Ignore `bin/` directory (CI-only artifact) |
| `.github/workflows/vscode-publish.yml` | Create | CI: cross-compile, package, publish |
| `pkg/gosqlx/gosqlx.go` | Modify | Version `1.10.0` → `1.10.1` |
| `cmd/gosqlx/cmd/root.go` | Modify | Version `1.10.0` → `1.10.1` (3 places) |
| `cmd/gosqlx/doc.go` | Modify | Version `1.10.0` → `1.10.1` |
| `cmd/gosqlx/cmd/doc.go` | Modify | Version `1.10.0` → `1.10.1` |
| `doc.go` | Modify | Version `1.10.0` → `1.10.1` |
| `pkg/mcp/server.go` | Modify | Version `1.10.0` → `1.10.1` |
| `CHANGELOG.md` | Modify | Add 1.10.1 entry |
| `performance_baselines.json` | Modify | Version `1.10.0` → `1.10.1` |
| `llms.txt` | Modify | Version `1.10.0` → `1.10.1` |

---

## Chunk 1: Binary Resolution

### Task 1: Add `getBinaryPath()` function to extension.ts

This function resolves the gosqlx binary path using a 4-step fallback chain: user setting → bundled binary → PATH lookup → error.

**Files:**
- Modify: `vscode-extension/src/extension.ts:1-10` (imports), new function after line 35

- [ ] **Step 1: Add the `getBinaryPath()` function**

Add `fs` import at the top of `vscode-extension/src/extension.ts` and add the `getBinaryPath()` function after the module-level variables (after line 34):

```typescript
// Add to imports (line 3 area):
import * as fs from 'fs';

// Add after line 34 (after `let metrics: MetricsCollector;`):

/**
 * Resolves the gosqlx binary path using a fallback chain:
 * 1. User-configured explicit path (gosqlx.executablePath setting, if non-empty)
 * 2. Bundled binary at <extensionPath>/bin/gosqlx[.exe]
 * 3. PATH lookup ("gosqlx" — the old default behavior)
 * 4. undefined if nothing found
 */
async function getBinaryPath(): Promise<string | undefined> {
    const config = vscode.workspace.getConfiguration('gosqlx');
    const userPath = config.get<string>('executablePath', '');

    // 1. Explicit user setting (non-empty means user override)
    if (userPath && userPath !== '') {
        return userPath;
    }

    // 2. Bundled binary
    if (extensionContext) {
        const binaryName = process.platform === 'win32' ? 'gosqlx.exe' : 'gosqlx';
        const bundledPath = path.join(extensionContext.extensionPath, 'bin', binaryName);
        try {
            await fs.promises.access(bundledPath, fs.constants.X_OK);
            return bundledPath;
        } catch {
            // Bundled binary not found or not executable, fall through
        }
    }

    // 3. Fall back to PATH lookup (backward compat for users who installed gosqlx globally)
    return 'gosqlx';
}
```

- [ ] **Step 2: Update `startLanguageServer()` to use `getBinaryPath()`**

In `vscode-extension/src/extension.ts`, replace line 206:

```typescript
// OLD (line 206):
const executablePath = config.get<string>('executablePath', 'gosqlx');

// NEW:
const executablePath = await getBinaryPath() || 'gosqlx';
```

The rest of the function already uses `executablePath` in `validateExecutable()`, `serverOptions.run.command`, and `serverOptions.debug.command` — no other changes needed.

- [ ] **Step 3: Update `analyzeCommand()` to use `getBinaryPath()`**

In `vscode-extension/src/extension.ts`, replace lines 555-556:

```typescript
// OLD (lines 555-556):
const config = vscode.workspace.getConfiguration('gosqlx');
const executablePath = config.get<string>('executablePath', 'gosqlx');

// NEW:
const config = vscode.workspace.getConfiguration('gosqlx');
const executablePath = await getBinaryPath() || 'gosqlx';
```

- [ ] **Step 4: Update `validateAndWarnConfiguration()` to use resolved path**

In `vscode-extension/src/extension.ts`, in the `validateAndWarnConfiguration()` function (line 125-169), the function reads `executablePath` from config for validation purposes. This is fine as-is because it validates the raw setting value. No change needed here.

- [ ] **Step 5: Verify TypeScript compiles**

Run:
```bash
cd vscode-extension && npm run compile
```
Expected: No errors. The `out/` directory is updated.

- [ ] **Step 6: Commit**

```bash
git add vscode-extension/src/extension.ts
git commit -m "feat(vscode): add getBinaryPath() with bundled binary resolution

Resolves binary using fallback chain: user setting → bundled → PATH.
Updates startLanguageServer and analyzeCommand to use new resolver.
Supports platform-specific binary bundling for Marketplace publishing."
```

---

### Task 2: Update package.json defaults and version

**Files:**
- Modify: `vscode-extension/package.json:5,75-80`

- [ ] **Step 1: Update version and executablePath default**

In `vscode-extension/package.json`:

1. Change line 5: `"version": "0.1.0"` → `"version": "1.10.1"`

2. Change the `gosqlx.executablePath` default (line 77): `"default": "gosqlx"` → `"default": ""`

3. Update the description (line 79): `"description": "Path to the gosqlx executable"` → `"description": "Path to the gosqlx executable. Leave empty to use the bundled binary."`

- [ ] **Step 2: Verify package.json is valid JSON**

Run:
```bash
cd vscode-extension && node -e "JSON.parse(require('fs').readFileSync('package.json', 'utf8')); console.log('Valid JSON')"
```
Expected: `Valid JSON`

- [ ] **Step 3: Commit**

```bash
git add vscode-extension/package.json
git commit -m "feat(vscode): bump version to 1.10.1, default to bundled binary

Change executablePath default from 'gosqlx' to '' (empty = use bundled).
Backward compatible: falls back to PATH lookup if no bundled binary found."
```

---

### Task 3: Update .vscodeignore and .gitignore

**Files:**
- Modify: `vscode-extension/.vscodeignore`
- Modify or create: `vscode-extension/.gitignore`

- [ ] **Step 1: Update .vscodeignore**

Replace the contents of `vscode-extension/.vscodeignore` with:

```
.vscode/**
.vscode-test/**
src/**
out/test/**
.gitignore
.yarnrc
vsc-extension-quickstart.md
**/tsconfig.json
**/.eslintrc.json
**/*.map
**/*.ts
!bin/**
node_modules/**
.github/**
```

Key changes:
- Added `out/test/**` — exclude test output from VSIX
- Added `!bin/**` — explicitly include the bundled binary directory
- Kept all existing exclusions

- [ ] **Step 2: Add bin/ to vscode-extension .gitignore**

Check if `vscode-extension/.gitignore` exists. If it does, add `bin/` to it. If not, create it:

```bash
ls vscode-extension/.gitignore 2>/dev/null || echo "not found"
```

Create or append:
```
bin/
```

The `bin/` directory is created by CI only — it should not be committed to the repo.

- [ ] **Step 3: Commit**

```bash
git add vscode-extension/.vscodeignore vscode-extension/.gitignore
git commit -m "chore(vscode): update ignore files for binary bundling

Include bin/ in VSIX package, exclude from git.
Exclude out/test/ from published VSIX."
```

---

## Chunk 2: GitHub Actions Workflow

### Task 4: Create the vscode-publish workflow

**Files:**
- Create: `.github/workflows/vscode-publish.yml`

- [ ] **Step 1: Create the workflow file**

Create `.github/workflows/vscode-publish.yml` with the following content:

```yaml
name: Publish VSCode Extension

on:
  push:
    tags:
      - 'v*'

permissions:
  contents: read

jobs:
  build:
    name: Build VSIX (${{ matrix.target }})
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - target: linux-x64
            goos: linux
            goarch: amd64
            binary: gosqlx
          - target: linux-arm64
            goos: linux
            goarch: arm64
            binary: gosqlx
          - target: darwin-x64
            goos: darwin
            goarch: amd64
            binary: gosqlx
          - target: darwin-arm64
            goos: darwin
            goarch: arm64
            binary: gosqlx
          - target: win32-x64
            goos: windows
            goarch: amd64
            binary: gosqlx.exe
    steps:
      - uses: actions/checkout@v4

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.24'

      - name: Cross-compile binary
        env:
          GOOS: ${{ matrix.goos }}
          GOARCH: ${{ matrix.goarch }}
        run: |
          mkdir -p vscode-extension/bin
          go build -ldflags="-s -w" -o "vscode-extension/bin/${{ matrix.binary }}" ./cmd/gosqlx

      - name: Smoke test binary
        if: matrix.target == 'linux-x64'
        run: |
          chmod +x vscode-extension/bin/${{ matrix.binary }}
          ./vscode-extension/bin/${{ matrix.binary }} version

      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install dependencies
        working-directory: vscode-extension
        run: npm ci

      - name: Patch version from tag
        working-directory: vscode-extension
        run: |
          VERSION="${GITHUB_REF_NAME#v}"
          npm version "$VERSION" --no-git-tag-version

      - name: Package VSIX
        working-directory: vscode-extension
        run: npx vsce package --target ${{ matrix.target }}

      - name: Upload VSIX artifact
        uses: actions/upload-artifact@v4
        with:
          name: vsix-${{ matrix.target }}
          path: vscode-extension/*.vsix

  publish:
    name: Publish to Marketplace
    needs: build
    runs-on: ubuntu-latest
    steps:
      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install vsce
        run: npm install -g @vscode/vsce

      - name: Download all VSIX artifacts
        uses: actions/download-artifact@v4
        with:
          pattern: vsix-*
          merge-multiple: true
          path: vsix

      - name: Publish all platforms
        env:
          VSCE_PAT: ${{ secrets.VSCE_PAT }}
        run: vsce publish --packagePath vsix/*.vsix
```

- [ ] **Step 2: Validate the YAML syntax**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/vscode-publish.yml')); print('Valid YAML')"
```
Expected: `Valid YAML`

If `pyyaml` is not available:
```bash
node -e "const fs = require('fs'); const y = fs.readFileSync('.github/workflows/vscode-publish.yml', 'utf8'); console.log('File exists, length:', y.length)"
```

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/vscode-publish.yml
git commit -m "ci: add GitHub Actions workflow for VSCode extension publishing

Cross-compiles gosqlx for 5 platforms (linux-x64, linux-arm64,
darwin-x64, darwin-arm64, win32-x64), packages platform-specific
VSIXs, and publishes atomically to VS Code Marketplace on tag push.
Runs in parallel with existing release.yml (GoReleaser)."
```

---

## Chunk 3: Extension CHANGELOG and Version Bumps

### Task 5: Update extension CHANGELOG

**Files:**
- Modify: `vscode-extension/CHANGELOG.md`

- [ ] **Step 1: Add 1.10.1 entry**

Add the following entry at the top of `vscode-extension/CHANGELOG.md`, after the header and before the `[0.1.0]` entry:

```markdown
## [1.10.1] - 2026-03-13

### Added
- **Bundled binary** — GoSQLX binary is now included in the extension package; no separate installation needed
- **Platform-specific packages** — optimized downloads for linux-x64, linux-arm64, darwin-x64, darwin-arm64, win32-x64
- **Smart binary resolution** — automatically uses bundled binary, falls back to user setting or PATH

### Changed
- Version aligned with GoSQLX core (1.10.1)
- `gosqlx.executablePath` default changed from `"gosqlx"` to `""` (empty = use bundled binary)
- Automated CI publishing via GitHub Actions on every GoSQLX release tag

```

- [ ] **Step 2: Commit**

```bash
git add vscode-extension/CHANGELOG.md
git commit -m "docs(vscode): add 1.10.1 changelog entry for Marketplace publishing"
```

---

### Task 6: Bump GoSQLX version to 1.10.1 across all files

**Files:**
- Modify: `pkg/gosqlx/gosqlx.go:31`
- Modify: `cmd/gosqlx/cmd/root.go:31,36,124`
- Modify: `cmd/gosqlx/doc.go:27`
- Modify: `cmd/gosqlx/cmd/doc.go:344`
- Modify: `doc.go:19,281`
- Modify: `pkg/mcp/server.go:38`
- Modify: `performance_baselines.json:2`
- Modify: `llms.txt:10`
- Modify: `CHANGELOG.md:8`

- [ ] **Step 1: Bump version in Go source files**

In each file, replace `1.10.0` with `1.10.1`:

1. `pkg/gosqlx/gosqlx.go` line 31:
   ```go
   const Version = "1.10.1"
   ```

2. `cmd/gosqlx/cmd/root.go` line 31:
   ```go
   //   - Version 1.10.1 includes:
   ```

3. `cmd/gosqlx/cmd/root.go` line 36:
   ```go
   var Version = "1.10.1"
   ```

4. `cmd/gosqlx/cmd/root.go` line 124:
   ```go
   Version: "1.10.1",
   ```

5. `cmd/gosqlx/doc.go` line 27:
   ```go
   // Current version: 1.10.1
   ```

6. `cmd/gosqlx/cmd/doc.go` line 344:
   ```go
   //	Version = "1.10.1" - Current CLI version
   ```

7. `doc.go` line 19:
   ```go
   // GoSQLX v1.10.1 includes both a powerful Go SDK ...
   ```

8. `doc.go` line 281:
   ```go
   // v1.10.1: VS Code Marketplace publishing with bundled platform-specific binaries
   ```
   (Add this as a NEW line before the v1.10.0 entry, don't replace it)

9. `pkg/mcp/server.go` line 38:
   ```go
   "1.10.1",
   ```

- [ ] **Step 2: Bump version in non-Go files**

1. `performance_baselines.json` line 2:
   ```json
   "version": "1.10.1",
   ```

2. `llms.txt` line 10:
   ```
   Current stable version: v1.10.1 (2026-03-13)
   ```

3. `CHANGELOG.md` — add a new entry. Insert before the `[1.10.0]` entry (before line 8):
   ```markdown
   ## [1.10.1] - 2026-03-13 — VS Code Marketplace Publishing

   ### ✨ New Features
   - **VS Code Extension on Marketplace**: Extension now published with bundled platform-specific binaries
     - 5 platforms: linux-x64, linux-arm64, darwin-x64, darwin-arm64, win32-x64
     - Smart binary resolution: bundled → user setting → PATH fallback
     - Automated CI publishing on every GoSQLX release tag

   ---

   ```

- [ ] **Step 3: Verify Go code compiles**

Run:
```bash
task build
```
Expected: No errors.

- [ ] **Step 4: Run tests**

Run:
```bash
task test
```
Expected: All tests pass.

- [ ] **Step 5: Commit**

```bash
git add pkg/gosqlx/gosqlx.go cmd/gosqlx/cmd/root.go cmd/gosqlx/doc.go cmd/gosqlx/cmd/doc.go doc.go pkg/mcp/server.go performance_baselines.json llms.txt CHANGELOG.md
git commit -m "chore: bump version to 1.10.1 for VS Code Marketplace publishing

Updates version across all Go source files, docs, and configuration.
Adds CHANGELOG entry for v1.10.1 with VS Code Marketplace details."
```

---

## Chunk 4: Local Verification & Final Steps

### Task 7: Local build and verification

**Files:** No files modified — verification only.

- [ ] **Step 1: Build the binary for local platform**

Run:
```bash
go build -ldflags="-s -w" -o vscode-extension/bin/gosqlx ./cmd/gosqlx
```
Expected: Binary created at `vscode-extension/bin/gosqlx`, ~8-10MB.

- [ ] **Step 2: Verify binary works**

Run:
```bash
./vscode-extension/bin/gosqlx version
```
Expected: `1.10.1` or similar version output.

- [ ] **Step 3: Package a local VSIX**

Run:
```bash
cd vscode-extension && npx vsce package --target darwin-arm64
```
Expected: `gosqlx-darwin-arm64-1.10.1.vsix` created. Note the file size — should be ~8-12MB (mostly the Go binary).

If this fails with a publisher error, run:
```bash
npx vsce package --target darwin-arm64 --allow-missing-repository
```

- [ ] **Step 4: Verify VSIX contents**

Run:
```bash
cd vscode-extension && unzip -l gosqlx-darwin-arm64-1.10.1.vsix | head -30
```
Expected: Should see `extension/bin/gosqlx` in the listing. Should NOT see `src/` or `out/test/` files.

- [ ] **Step 5: Clean up local build artifacts**

Run:
```bash
rm -rf vscode-extension/bin vscode-extension/*.vsix
```

- [ ] **Step 6: Run full quality check**

Run:
```bash
task check
```
Expected: All formatting, vet, lint, and tests pass.

---

### Task 8: Push and create PR

**Files:** No files modified — git operations only.

- [ ] **Step 1: Push the branch**

Run:
```bash
git push -u origin feat/vscode-marketplace-publishing
```

- [ ] **Step 2: Create the PR**

Run:
```bash
gh pr create --title "feat: VS Code Marketplace publishing with bundled binaries" --body "$(cat <<'EOF'
## Summary

- Add `getBinaryPath()` function with 3-step fallback: bundled binary → user setting → PATH
- Update all binary spawn sites (`startLanguageServer`, `analyzeCommand`) to use new resolver
- Create GitHub Actions workflow for automated cross-compilation and Marketplace publishing
- Support 5 platforms: linux-x64, linux-arm64, darwin-x64, darwin-arm64, win32-x64
- Bump version to 1.10.1 across all files

## Before First Publish

1. Create VS Code Marketplace publisher `ajitpratap0` at https://marketplace.visualstudio.com/manage
2. Generate Azure DevOps PAT with "Marketplace (Manage)" scope
3. Add `VSCE_PAT` as GitHub Actions secret
4. Merge this PR → tag `v1.10.1` → CI publishes to Marketplace

## Test Plan

- [ ] TypeScript compiles: `cd vscode-extension && npm run compile`
- [ ] Go builds: `task build`
- [ ] All tests pass: `task test`
- [ ] Local VSIX packages correctly (verified bin/ included, src/ excluded)
- [ ] Binary resolves bundled path when extensionPath/bin/gosqlx exists
- [ ] Binary falls back to PATH when no bundled binary found

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 3: Note the PAT setup reminder**

After PR is merged and before tagging `v1.10.1`, the user must:
1. Create publisher at marketplace.visualstudio.com/manage
2. Generate PAT at dev.azure.com
3. Add `VSCE_PAT` secret to the GitHub repo settings
