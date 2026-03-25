#!/usr/bin/env python3
"""
Sentry Issues -> GitHub Issues sync script.

Polls the Sentry API for newly created issues within the polling window
and creates corresponding GitHub issues, skipping duplicates.
"""

import os
import sys
import time
import json
from datetime import datetime, timezone, timedelta

import requests

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
SENTRY_AUTH_TOKEN = os.environ["SENTRY_AUTH_TOKEN"]
SENTRY_ORG = os.environ["SENTRY_ORG"]
SENTRY_PROJECT = os.environ["SENTRY_PROJECT"]
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
GITHUB_REPO = os.environ["GITHUB_REPO"]
POLLING_MINUTES = int(os.environ.get("POLLING_MINUTES", "31"))

SENTRY_API = "https://sentry.io/api/0"
GITHUB_API = "https://api.github.com"

SENTRY_HEADERS = {"Authorization": f"Bearer {SENTRY_AUTH_TOKEN}"}
GITHUB_HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

# Sentry level -> GitHub severity label
LEVEL_TO_SEVERITY = {
    "fatal":   "severity: critical",
    "error":   "severity: high",
    "warning": "severity: medium",
    "info":    "severity: low",
    "debug":   "severity: low",
}

LABELS_TO_BOOTSTRAP = [
    {"name": "sentry",             "color": "6f42c1", "description": "Automatically created from Sentry error monitoring"},
    {"name": "severity: critical", "color": "b60205", "description": "Fatal errors — immediate attention required"},
    {"name": "severity: high",     "color": "e11d48", "description": "Errors affecting users"},
    {"name": "severity: medium",   "color": "f59e0b", "description": "Warnings with user impact"},
    {"name": "severity: low",      "color": "6b7280", "description": "Informational or debug-level issues"},
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ensure_label(name: str, color: str, description: str) -> None:
    """Create a GitHub label if it does not already exist."""
    url = f"{GITHUB_API}/repos/{GITHUB_REPO}/labels"
    resp = requests.post(
        url,
        headers=GITHUB_HEADERS,
        json={"name": name, "color": color, "description": description},
    )
    if resp.status_code == 201:
        print(f"  Created label: {name}")
    elif resp.status_code == 422:
        pass  # Already exists
    else:
        print(f"  Warning: unexpected status {resp.status_code} creating label '{name}': {resp.text}")


def bootstrap_labels() -> None:
    for label in LABELS_TO_BOOTSTRAP:
        ensure_label(**label)


def fetch_sentry_issues(cutoff: datetime) -> list[dict]:
    """Return all unresolved Sentry issues first seen after cutoff."""
    url = f"{SENTRY_API}/projects/{SENTRY_ORG}/{SENTRY_PROJECT}/issues/"
    params = {"query": "is:unresolved", "limit": 100, "sort": "date"}
    resp = requests.get(url, headers=SENTRY_HEADERS, params=params)
    if resp.status_code != 200:
        print(f"ERROR: Sentry API returned {resp.status_code}: {resp.text}", file=sys.stderr)
        sys.exit(1)

    issues = resp.json()
    new_issues = []
    for issue in issues:
        first_seen = datetime.fromisoformat(issue["firstSeen"].replace("Z", "+00:00"))
        if first_seen >= cutoff:
            new_issues.append(issue)
    return new_issues


def github_issue_exists(sentry_id: str) -> bool:
    """Return True if a GitHub issue with this Sentry ID already exists."""
    url = f"{GITHUB_API}/search/issues"
    query = f'repo:{GITHUB_REPO} label:sentry in:body "SENTRY_ID:{sentry_id}"'
    resp = requests.get(url, headers=GITHUB_HEADERS, params={"q": query, "per_page": 1})
    if resp.status_code != 200:
        print(f"  Warning: GitHub search returned {resp.status_code}: {resp.text}")
        return False
    return resp.json().get("total_count", 0) > 0


def build_issue_body(issue: dict) -> str:
    sentry_id = issue["id"]
    level = issue.get("level", "error")
    count = issue.get("count", "?")
    user_count = issue.get("userCount", "?")
    first_seen = issue.get("firstSeen", "?")
    last_seen = issue.get("lastSeen", "?")
    culprit = issue.get("culprit", "?")
    permalink = issue.get("permalink", f"https://{SENTRY_ORG}.sentry.io/issues/{sentry_id}/")

    return f"""\
## Sentry Issue: {issue['title']}

**Sentry ID:** `{sentry_id}`
**Culprit:** `{culprit}`
**Level:** {level}

---

| Field | Value |
|-------|-------|
| First Seen | {first_seen} |
| Last Seen | {last_seen} |
| Occurrences | {count} |
| Affected Users | {user_count} |

**Sentry URL:** {permalink}

---

> This issue was automatically created by the Sentry monitoring workflow.
> To resolve, fix the underlying error and mark the Sentry issue as resolved.

<!-- SENTRY_ID:{sentry_id} -->
"""


def create_github_issue(issue: dict) -> None:
    level = issue.get("level", "error")
    severity_label = LEVEL_TO_SEVERITY.get(level, "severity: high")
    labels = ["sentry", "bug", severity_label]

    title = f"[Sentry] {issue['title']}"
    body = build_issue_body(issue)

    url = f"{GITHUB_API}/repos/{GITHUB_REPO}/issues"
    resp = requests.post(
        url,
        headers=GITHUB_HEADERS,
        json={"title": title, "body": body, "labels": labels},
    )
    if resp.status_code == 201:
        data = resp.json()
        print(f"  Created GitHub issue #{data['number']}: {data['html_url']}")
    else:
        print(f"ERROR: GitHub issue creation failed ({resp.status_code}): {resp.text}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=POLLING_MINUTES)
    print(f"Polling for Sentry issues first seen after {cutoff.isoformat()}")

    print("Bootstrapping GitHub labels...")
    bootstrap_labels()

    print(f"Fetching unresolved Sentry issues for {SENTRY_ORG}/{SENTRY_PROJECT}...")
    new_issues = fetch_sentry_issues(cutoff)
    print(f"Found {len(new_issues)} new issue(s) in the last {POLLING_MINUTES} minutes.")

    if not new_issues:
        print("Nothing to do.")
        return

    for issue in new_issues:
        sentry_id = issue["id"]
        title = issue["title"]
        print(f"\nProcessing Sentry issue {sentry_id}: {title[:80]}")

        # Rate-limit guard for GitHub search API (30 req/min authenticated)
        time.sleep(2)

        if github_issue_exists(sentry_id):
            print(f"  Skipping — GitHub issue already exists for SENTRY_ID:{sentry_id}")
            continue

        create_github_issue(issue)

    print("\nDone.")


if __name__ == "__main__":
    main()
