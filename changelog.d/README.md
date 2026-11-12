# Changelog fragments

Add a fragment for each user-visible change instead of editing `CHANGELOG.md`.
Name it `<slug>.<section>.md`, where the slug matches `[a-z0-9][a-z0-9-]*`
(for example, `w5-07-lowercase-table.fixed.md`). A PR may add several fragments,
typically one per section.

Sections, in release order: `breaking-changes`, `added`, `changed`, `performance`,
`behavior-changes`, `deprecated`, `removed`, `fixed`, `security`.

Start the body with a Markdown list item (`- `), use no headings, and end the file
with a newline. Nested bullets and continuation lines are supported. For example:

```markdown
- Fix lowercase table names in SQL output.
  - Preserve quoted identifiers.
```

Run `task changelog:check` to validate and `task changelog:preview` to see the
combined Unreleased section without writing files. At release time, run
`task changelog:collect` before setting the version and date. Collection appends
fragments in filename order within each section and removes collected files.
Existing Unreleased entries stay in place; README.md is ignored by the tool.

CI warns when a PR adds lines to the Unreleased section of `CHANGELOG.md`; once
the repository variable `CHANGELOG_FRAGMENTS_ENFORCE` is `true` it fails instead.
That includes fixing a typo in an existing Unreleased entry, so make such fixes
in a release-finalization (`docs/v*`) PR. Files whose names start with `.` are ignored.
