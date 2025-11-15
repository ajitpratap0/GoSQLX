# GitHub Marketplace Publishing Guide

This guide explains how to publish the GoSQLX GitHub Action to the GitHub Marketplace.

## Prerequisites

Before publishing, ensure:

- ✅ Action is fully tested (see [ACTION_TESTING_GUIDE.md](ACTION_TESTING_GUIDE.md))
- ✅ `action.yml` is complete and validated
- ✅ README documentation is comprehensive
- ✅ Examples work correctly
- ✅ Repository has proper LICENSE file
- ✅ All security considerations are addressed

## Publishing Steps

### 1. Prepare the Repository

```bash
# Ensure you're on main branch
git checkout main
git pull origin main

# Verify action.yml is valid
cat action.yml

# Test locally first
# (See ACTION_TESTING_GUIDE.md)
```

### 2. Create a Release

GitHub Actions are published via releases. Create a release with a version tag:

```bash
# Create and push version tag
git tag -a v1.0.0 -m "v1.0.0: Initial GoSQLX GitHub Action release"
git push origin v1.0.0

# Also create/update major version tag for convenience
git tag -fa v1 -m "v1: Latest v1.x.x release"
git push -f origin v1
```

**Version Tags Best Practices:**
- Use semantic versioning (v1.0.0, v1.1.0, v2.0.0)
- Maintain major version tags (v1, v2) for latest patch
- Users can reference `@v1` for latest v1.x.x or `@v1.0.0` for specific version

### 3. Create GitHub Release

#### Via GitHub Web Interface:

1. Go to your repository on GitHub
2. Click "Releases" in the right sidebar
3. Click "Draft a new release"
4. Fill in the release information:

**Release Form:**
```
Tag version: v1.0.0
Release title: v1.0.0: GoSQLX GitHub Action - Ultra-Fast SQL Validation

Description:
## GoSQLX GitHub Action v1.0.0

### 🚀 Features

- **Ultra-Fast Validation**: 100-1000x faster than SQLFluff
- **Multi-Dialect Support**: PostgreSQL, MySQL, SQL Server, Oracle, SQLite
- **Format Checking**: Ensure consistent SQL formatting
- **Comprehensive Analysis**: Security and performance checks
- **Zero Configuration**: Works out of the box

### 📊 Performance

- **Throughput**: 1.38M+ operations/second
- **Validation Speed**: <10ms for typical queries
- **Batch Processing**: 100+ files/second

### 📖 Documentation

See [ACTION_README.md](ACTION_README.md) for complete documentation and examples.

### 🎯 Quick Start

```yaml
- uses: ajitpratap0/GoSQLX@v1
  with:
    files: '**/*.sql'
    validate: true
```

### 🔗 Links

- [Documentation](https://github.com/ajitpratap0/GoSQLX#readme)
- [Examples](.github/workflows/examples/)
- [Testing Guide](.github/ACTION_TESTING_GUIDE.md)

### 🐛 Known Issues

None at this time.

### 🙏 Acknowledgments

Built with GitHub Actions and Go.
```

5. Check "Publish this Action to the GitHub Marketplace"
6. Select appropriate categories:
   - **Primary**: Continuous integration
   - **Secondary**: Code quality
7. Click "Publish release"

#### Via GitHub CLI:

```bash
gh release create v1.0.0 \
  --title "v1.0.0: GoSQLX GitHub Action - Ultra-Fast SQL Validation" \
  --notes-file RELEASE_NOTES.md \
  --verify-tag
```

### 4. Configure Marketplace Listing

After creating the release, configure your Marketplace listing:

1. **Action Icon & Color** (in `action.yml`):
```yaml
branding:
  icon: 'check-circle'  # Available icons: https://feathericons.com/
  color: 'blue'         # Available colors: white, yellow, blue, green, orange, red, purple, gray-dark
```

2. **Categories** (during release):
   - Primary category: Continuous integration
   - Secondary category: Code quality

3. **Marketplace README**:
   - The `ACTION_README.md` content should be the main documentation
   - Consider copying it to root README or having a marketplace-specific version

### 5. Version Management Strategy

**Semantic Versioning:**
- **Major (v2.0.0)**: Breaking changes
- **Minor (v1.1.0)**: New features, backwards compatible
- **Patch (v1.0.1)**: Bug fixes, backwards compatible

**Tag Strategy:**
```bash
# For new patch release v1.0.1
git tag v1.0.1
git push origin v1.0.1

# Update v1 to point to latest v1.x.x
git tag -fa v1 -m "Update v1 to v1.0.1"
git push -f origin v1

# For new minor release v1.1.0
git tag v1.1.0
git push origin v1.1.0

# Update v1 to point to latest
git tag -fa v1 -m "Update v1 to v1.1.0"
git push -f origin v1
```

This allows users to use:
- `@v1.0.0` - specific version (never changes)
- `@v1` - latest v1.x.x (receives updates)
- `@main` - bleeding edge (not recommended for production)

### 6. Update Repository Settings

1. **About section**:
   - Description: "Ultra-fast SQL validation, linting, and formatting - 100x faster than SQLFluff"
   - Website: Link to documentation
   - Topics: `sql`, `validation`, `github-actions`, `linting`, `formatting`, `parser`, `golang`

2. **Repository settings**:
   - Enable "Require contributors to sign off on web-based commits"
   - Protect main branch
   - Enable security alerts

## Post-Publishing Checklist

### Verification

- [ ] Action appears in GitHub Marketplace
- [ ] Can be searched for in Marketplace
- [ ] README displays correctly
- [ ] Icon and branding appear correctly
- [ ] Can be referenced as `@v1` and `@v1.0.0`

### Documentation

- [ ] Add Marketplace badge to main README
- [ ] Update documentation with usage examples
- [ ] Link to Marketplace listing in docs

```markdown
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-GoSQLX%20Validator-blue.svg?colorA=24292e&colorB=0366d6&style=flat&longCache=true&logo=github)](https://github.com/marketplace/actions/gosqlx-sql-validator)
```

### Testing

- [ ] Test installation from Marketplace
- [ ] Verify all examples work with published version
- [ ] Test on fresh repository

```yaml
# Test in a separate repo
name: Test Published Action
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ajitpratap0/GoSQLX@v1
        with:
          files: '**/*.sql'
```

### Communication

- [ ] Announce release on project README
- [ ] Update CHANGELOG.md
- [ ] Consider blog post or announcement
- [ ] Tweet/social media (optional)

## Marketplace Optimization

### SEO & Discoverability

**Good README structure:**
1. Clear description in first paragraph
2. Feature list with emojis for visual appeal
3. Quick start example
4. Performance metrics
5. Comprehensive documentation
6. Troubleshooting section
7. Links to resources

**Keywords to include:**
- SQL validation
- SQL linting
- SQL formatting
- GitHub Actions
- CI/CD
- PostgreSQL, MySQL, etc.
- Fast/Performance
- Security

### Badges

Add relevant badges to increase trust:

```markdown
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-GoSQLX-blue.svg)](...)
[![GitHub Release](https://img.shields.io/github/release/ajitpratap0/GoSQLX.svg)](...)
[![GitHub Stars](https://img.shields.io/github/stars/ajitpratap0/GoSQLX.svg)](...)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/ajitpratap0/GoSQLX)](...)
```

## Updating the Action

### For Breaking Changes (Major Version)

```bash
# Create v2.0.0
git tag v2.0.0 -m "v2.0.0: Major update with breaking changes"
git push origin v2.0.0

# Create v2 tracking tag
git tag v2 -m "v2: Latest v2.x.x"
git push origin v2

# Keep v1 for existing users
# Do NOT force-update v1 tag
```

### For New Features (Minor Version)

```bash
# Create v1.1.0
git tag v1.1.0 -m "v1.1.0: Add new features"
git push origin v1.1.0

# Update v1 tracking tag
git tag -fa v1 -m "Update v1 to v1.1.0"
git push -f origin v1
```

### For Bug Fixes (Patch Version)

```bash
# Create v1.0.1
git tag v1.0.1 -m "v1.0.1: Bug fixes"
git push origin v1.0.1

# Update v1 tracking tag
git tag -fa v1 -m "Update v1 to v1.0.1"
git push -f origin v1
```

## Marketplace Analytics

Monitor your action's performance:

1. **Insights tab** on GitHub:
   - Traffic (views, clones)
   - Popular content
   - Referring sites

2. **Marketplace statistics**:
   - Installation count
   - Workflow runs
   - User feedback

3. **GitHub API** for programmatic access:
```bash
# Get action statistics
gh api repos/ajitpratap0/GoSQLX/actions
```

## Support & Maintenance

### Issue Management

Set up issue templates for action-specific issues:

```yaml
# .github/ISSUE_TEMPLATE/action-bug.yml
name: Action Bug Report
description: Report a bug with the GitHub Action
labels: ["github-action", "bug"]
body:
  - type: textarea
    attributes:
      label: Action Configuration
      description: Your action.yml configuration
      render: yaml
  - type: textarea
    attributes:
      label: Expected Behavior
  - type: textarea
    attributes:
      label: Actual Behavior
  - type: textarea
    attributes:
      label: Logs
      description: Relevant GitHub Actions logs
```

### Responding to Issues

- Monitor issues tagged with `github-action`
- Provide timely responses
- Ask for workflow examples and logs
- Create reproductions when possible

### Deprecation Policy

If deprecating features:

1. Announce in release notes
2. Add deprecation warnings in action output
3. Provide migration guide
4. Maintain old versions for 6-12 months
5. Clearly document end-of-life dates

## Security Considerations

### Action Security

- ✅ No secrets in action code
- ✅ Use pinned versions for dependencies
- ✅ Regular security updates
- ✅ SARIF upload for code scanning (if applicable)

### Permissions

Document required permissions:

```yaml
permissions:
  contents: read        # For checkout
  pull-requests: write  # For PR comments (optional)
```

### Security Policy

Create `.github/SECURITY.md`:

```markdown
# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting Vulnerabilities

Please report security vulnerabilities to security@example.com
```

## Resources

### Official Documentation

- [GitHub Actions: Publishing actions](https://docs.github.com/en/actions/creating-actions/publishing-actions-in-github-marketplace)
- [GitHub Actions: Metadata syntax](https://docs.github.com/en/actions/creating-actions/metadata-syntax-for-github-actions)
- [GitHub Actions: Branding](https://docs.github.com/en/actions/creating-actions/metadata-syntax-for-github-actions#branding)

### Tools

- [actionlint](https://github.com/rhysd/actionlint) - Linter for GitHub Actions
- [act](https://github.com/nektos/act) - Run actions locally
- [GitHub CLI](https://cli.github.com/) - Manage releases

### Examples

- [actions/checkout](https://github.com/actions/checkout)
- [actions/setup-go](https://github.com/actions/setup-go)
- [tj-actions/changed-files](https://github.com/tj-actions/changed-files)

## Troubleshooting

### Action Not Appearing in Marketplace

- Verify `action.yml` is in repository root
- Check release is marked "Publish to Marketplace"
- Ensure repository is public
- Wait 5-10 minutes for indexing

### Branding Not Showing

- Verify icon name from [Feather Icons](https://feathericons.com/)
- Check color is one of the allowed values
- Clear browser cache

### Version Tags Not Working

```bash
# Verify tags exist
git tag -l

# Push all tags
git push origin --tags

# Force update tag
git tag -fa v1 -m "Update v1"
git push -f origin v1
```

## Checklist for v1.0.0 Release

- [ ] Action code is complete and tested
- [ ] Documentation is comprehensive
- [ ] Examples are working
- [ ] Version tag v1.0.0 created
- [ ] Version tag v1 created
- [ ] Release created on GitHub
- [ ] Marketplace checkbox enabled
- [ ] Categories selected
- [ ] Branding configured
- [ ] README is polished
- [ ] License file exists
- [ ] Security policy created
- [ ] Post-release testing completed
- [ ] Announcement prepared

Ready to publish! 🚀
