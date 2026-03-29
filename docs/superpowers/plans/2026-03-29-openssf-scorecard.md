# OpenSSF Scorecard Setup #443 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add OpenSSF Scorecard GitHub Action workflow, display the scorecard badge in README, and achieve an initial score ≥ 6/10 to establish security credibility for enterprise evaluators.

**Architecture:** Single new GitHub Actions workflow file triggers on push to main, weekly schedule, and PRs. Results are published to GitHub's security dashboard as SARIF. Badge in README links to the public scorecard entry. No code changes — configuration only.

**Tech Stack:** GitHub Actions, ossf/scorecard-action v2, github/codeql-action v3, SARIF

---

## File Map

- Create: `.github/workflows/scorecard.yml` — OpenSSF Scorecard CI workflow
- Modify: `README.md` — add scorecard badge below existing badges
- Verify: `.github/dependabot.yml` — already configured (no changes needed)
- Verify: `SECURITY.md` — already exists (no changes needed)

---

### Task 1: Audit prerequisites

**Files:**
- Read: `.github/workflows/` directory
- Read: `README.md` badge section
- Read: `SECURITY.md`

- [ ] **Step 1: List existing workflows**

```bash
ls .github/workflows/
```

Expected: existing workflows like `ci.yml`, `security.yml`, `release.yml`, etc.
Confirm: no `scorecard.yml` yet.

- [ ] **Step 2: Check README badge section**

```bash
head -20 README.md
```

Expected: existing badges like Go version, license, test status. Note the badge format used.

- [ ] **Step 3: Verify SECURITY.md exists**

```bash
ls SECURITY.md
```

Expected: file exists. The OpenSSF Scorecard checks for SECURITY.md — it already passes.

- [ ] **Step 4: Verify dependabot.yml exists**

```bash
cat .github/dependabot.yml
```

Expected: file exists with `package-ecosystem: gomod` and `package-ecosystem: github-actions`. Both are required for Scorecard's "Dependency-Update-Tool" check.

---

### Task 2: Create the OpenSSF Scorecard workflow

**Files:**
- Create: `.github/workflows/scorecard.yml`

- [ ] **Step 1: Create the workflow file**

```yaml
# .github/workflows/scorecard.yml
name: OpenSSF Scorecard

on:
  # Run on every push to the default branch
  push:
    branches: [main]
  # Run weekly on Saturday at 01:30 UTC to keep results fresh
  schedule:
    - cron: '30 1 * * 6'
  # Allow manual trigger
  workflow_dispatch:

# Restrict permissions to least-privilege
permissions: read-all

jobs:
  analysis:
    name: Scorecard analysis
    runs-on: ubuntu-latest
    permissions:
      # Needed for OIDC token for publishing results
      id-token: write
      # Needed to upload SARIF results to GitHub Code Scanning
      security-events: write
      # Needed to read actions configuration
      actions: read
      # Needed to check out code
      contents: read

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Run OpenSSF Scorecard analysis
        uses: ossf/scorecard-action@v2.4.0
        with:
          results_file: results.sarif
          results_format: sarif
          # Publish results to the OpenSSF public dashboard
          publish_results: true

      - name: Upload SARIF artifact for debugging
        uses: actions/upload-artifact@v4
        with:
          name: SARIF file
          path: results.sarif
          retention-days: 5

      - name: Upload results to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

- [ ] **Step 2: Verify YAML syntax**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/scorecard.yml'))" && echo "YAML valid"
```

Expected: `YAML valid`

- [ ] **Step 3: Commit the workflow**

```bash
git add .github/workflows/scorecard.yml
git commit -m "ci: add OpenSSF Scorecard GitHub Actions workflow (#443)"
```

---

### Task 3: Add scorecard badge to README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Identify badge placement**

```bash
grep -n "!\[" README.md | head -10
```

Expected: existing badges on lines 1-5. Note the line number of the last existing badge.

- [ ] **Step 2: Add the OpenSSF Scorecard badge**

The badge URL format for OpenSSF Scorecard is:
`https://api.securityscorecards.dev/projects/github.com/ajitpratap0/GoSQLX/badge`

The link URL is:
`https://securityscorecards.dev/viewer/?uri=github.com/ajitpratap0/GoSQLX`

Find the badge block in README.md and add after the existing badges:

```markdown
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/ajitpratap0/GoSQLX/badge)](https://securityscorecards.dev/viewer/?uri=github.com/ajitpratap0/GoSQLX)
```

Add it adjacent to existing security/quality badges. Use the Edit tool to insert it in the right position.

- [ ] **Step 3: Verify README renders correctly**

```bash
grep -n "OpenSSF" README.md
```

Expected: one line with the badge markdown.

- [ ] **Step 4: Commit the badge**

```bash
git add README.md
git commit -m "docs: add OpenSSF Scorecard badge to README (#443)"
```

---

### Task 4: Push and verify the workflow runs

- [ ] **Step 1: Push the branch**

```bash
git push origin HEAD
```

- [ ] **Step 2: Check workflow triggered**

```bash
gh run list --workflow=scorecard.yml --limit=3
```

Expected: one run in `queued` or `in_progress` state.

- [ ] **Step 3: Watch the run complete**

```bash
gh run watch
```

Expected: run completes in ~2 minutes. Exit code 0.

- [ ] **Step 4: Check SARIF uploaded to Code Scanning**

```bash
gh api repos/ajitpratap0/GoSQLX/code-scanning/sarifs --jq '.[0].state'
```

Expected: `"uploaded"` or `"complete"`

- [ ] **Step 5: View initial score**

After the run completes, the results appear at:
`https://securityscorecards.dev/viewer/?uri=github.com/ajitpratap0/GoSQLX`

The initial score should be ≥ 6/10 because:
- SECURITY.md exists ✅
- dependabot.yml exists (gomod + github-actions) ✅
- GitHub Actions workflows exist ✅
- Branch protection on main ✅
- License file exists ✅
- No critical CVEs (govulncheck in CI) ✅

Expected failing checks initially:
- `Signed-Releases` (not signing releases yet — address separately)
- `Binary-Artifacts` (if any pre-built binaries committed)

---

### Task 5: Create PR and close issue

- [ ] **Step 1: Create PR**

```bash
gh pr create \
  --title "ci: add OpenSSF Scorecard workflow and README badge (#443)" \
  --body "Closes #443.

## Changes
- Adds \`.github/workflows/scorecard.yml\` (ossf/scorecard-action@v2.4.0)
- Publishes SARIF results to GitHub Code Scanning dashboard
- Adds OpenSSF Scorecard badge to README

## Initial Score
Expected ≥ 6/10. SECURITY.md, dependabot, branch protection, license, govulncheck all passing.

## Remaining Items
- Signed releases (Scorecard: Signed-Releases) — future work
"
```

---

## Self-Review Checklist

- [x] Workflow uses `persist-credentials: false` (Scorecard requirement)
- [x] Workflow uses `permissions: read-all` at top level + per-job overrides (least privilege)
- [x] `publish_results: true` enables the public badge
- [x] SARIF uploaded to GitHub Code Scanning for dashboard visibility
- [x] Badge URL uses official `api.securityscorecards.dev` endpoint
- [x] No code changes — config + docs only
- [x] SECURITY.md existence verified (already satisfies that check)
- [x] dependabot.yml existence verified (already satisfies Dependency-Update-Tool)
