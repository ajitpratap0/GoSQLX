# Governance

## Overview

GoSQLX is an open source project. This document describes how the project is governed, how decisions are made, and how contributors can take on more responsibility over time.

## Roles

### Users
Anyone who uses GoSQLX. Users are the most important people in the project - feedback through issues, questions in Discussions, and bug reports directly shapes development priorities.

### Contributors
Anyone who has submitted a merged pull request, a bug report that led to a fix, or substantive documentation improvements. Contributors are credited in release notes and the CHANGELOG.

### Committers
Contributors who have demonstrated sustained, high-quality contributions across multiple areas of the codebase. Committers can:
- Merge pull requests after review
- Triage and label issues
- Cut release branches

**Current committers**: [@ajitpratap0](https://github.com/ajitpratap0)

To become a committer: contribute consistently for at least 3 months, demonstrate understanding of the architecture, and express interest in a GitHub Discussion or issue.

### Maintainers
Responsible for the overall technical direction, release management, and final decisions on breaking changes. Maintainers are committers who have committed to long-term stewardship.

**Current maintainer**: [@ajitpratap0](https://github.com/ajitpratap0)

## Decision Making

### Everyday decisions (bug fixes, docs, minor features)
Open a PR. If CI passes and a committer reviews it positively, it can be merged. No formal vote needed.

### Significant features (new AST nodes, new dialect support, new packages)
1. Open an issue tagged `feature` with a design proposal (what, why, API sketch)
2. Allow 5 business days for community feedback
3. A committer signals approval (thumbs-up, "LGTM" comment, or review approval)
4. Proceed with implementation PR

### Breaking changes
1. Open an issue tagged `breaking-change` - mandatory minimum 14-day comment period
2. Document the migration path in `docs/MIGRATION.md` before merge
3. Requires explicit maintainer approval
4. Semantic versioning: breaking changes increment the minor version (v1.x.0)

### Governance changes
Changes to this document require a GitHub Discussion open for at least 7 days with no unresolved objections.

## Release Process

GoSQLX follows [Semantic Versioning](https://semver.org/):
- **Patch** (v1.9.x): bug fixes, security patches, documentation - no API changes
- **Minor** (v1.x.0): new features, new dialect support, new AST nodes - backward compatible
- **Major** (vX.0.0): breaking API changes - rare, requires 14-day notice

Release cadence: ad-hoc driven by feature readiness and bug severity, roughly monthly.

Releases are tagged on `main` and built automatically by GoReleaser. See `CONTRIBUTING.md` for the tagging workflow.

## Conflict Resolution

Disagreements on technical direction are resolved by:
1. Discussion in the relevant issue/PR (preferred)
2. A GitHub Discussion for broader input
3. Maintainer decision as a tiebreaker

The goal is always rough consensus - not unanimity, but no strong unaddressed objections.

## Code of Conduct

All participants are expected to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Acknowledgements

This governance model is inspired by the [Node.js](https://github.com/nodejs/node/blob/main/GOVERNANCE.md) and [Go project](https://github.com/golang/proposal) governance models, simplified for a single-maintainer open source library.
