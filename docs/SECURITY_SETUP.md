# Security Scanning Setup Guide

This document provides instructions for maintainers on the security scanning infrastructure implemented for GoSQLX.

## Overview

GoSQLX implements a comprehensive security scanning system with four key components:

1. **GoSec** - Static security analysis for Go code
2. **Trivy** - Vulnerability scanner for dependencies and configurations
3. **GovulnCheck** - Official Go vulnerability database checker
4. **Dependabot** - Automated dependency update management

## Workflow Configuration

### Security Workflow (`.github/workflows/security.yml`)

**Triggers:**
- Push to `main` and `develop` branches
- Pull requests to `main` branch
- Weekly schedule (Sundays at midnight UTC)
- Manual dispatch via GitHub Actions UI

**Jobs:**

1. **GoSec Security Scanner**
   - Scans Go code for security issues
   - Uploads SARIF results to GitHub Security tab
   - Fails on high/critical severity issues
   - Uses: `securego/gosec@v2.21.4`

2. **Trivy Repository Scan**
   - Scans filesystem for vulnerabilities in dependencies
   - Checks for CRITICAL, HIGH, and MEDIUM severity issues
   - Uploads results to GitHub Code Scanning
   - Uses: `aquasecurity/trivy-action@0.28.0`

3. **Trivy Config Scan**
   - Scans configuration files for security issues
   - Checks GitHub Actions workflows, Dockerfiles, etc.
   - Fails on high/critical configuration issues
   - Uses: `aquasecurity/trivy-action@0.28.0`

4. **Dependency Review** (PR only)
   - Reviews new dependencies introduced in PRs
   - Checks license compatibility
   - Allowed licenses: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC
   - Uses: `actions/dependency-review-action@v4`

5. **GovulnCheck**
   - Official Go vulnerability checker
   - Scans all Go dependencies against vulnerability database
   - Provides detailed vulnerability information
   - Fails on any known vulnerabilities

6. **Security Summary**
   - Aggregates all scan results
   - Generates GitHub Actions summary
   - Fails if any scanner reports issues

### Dependabot Configuration (`.github/dependabot.yml`)

**Go Modules Updates:**
- **Schedule**: Daily at 3:00 AM EST
- **Limit**: 10 open PRs maximum
- **Grouping**: Minor and patch updates grouped together
- **Major Updates**: Separated for careful review
- **Labels**: `dependencies`, `automated`, `go`
- **Commit Prefix**: `chore(deps)`

**GitHub Actions Updates:**
- **Schedule**: Weekly on Mondays at 3:00 AM EST
- **Limit**: 5 open PRs maximum
- **Grouping**: Minor and patch updates grouped together
- **Labels**: `dependencies`, `automated`, `github-actions`
- **Commit Prefix**: `chore(ci)`

## Enabling Security Features

### Step 1: Enable GitHub Security Features

1. Navigate to repository **Settings** → **Security & analysis**
2. Enable the following features:
   - ✅ **Dependency graph** (usually enabled by default)
   - ✅ **Dependabot alerts**
   - ✅ **Dependabot security updates**
   - ✅ **Code scanning** (CodeQL analysis)
   - ✅ **Secret scanning**
   - ✅ **Secret scanning push protection**

### Step 2: Configure Branch Protection

1. Navigate to **Settings** → **Branches**
2. Add branch protection rule for `main`:
   - ✅ Require status checks to pass before merging
   - Select required checks:
     - `GoSec Security Scanner`
     - `Trivy Repository Scan`
     - `Trivy Config Scan`
     - `Go Vulnerability Check`
   - ✅ Require branches to be up to date before merging
   - ✅ Require signed commits (recommended)

### Step 3: Configure Security Notifications

1. Navigate to **Settings** → **Notifications**
2. Configure security alert preferences:
   - ✅ Email notifications for security advisories
   - ✅ Web notifications for Dependabot alerts
   - ✅ Email notifications for code scanning alerts

### Step 4: Review Initial Scan Results

After merging the security workflow:

1. Navigate to **Actions** tab
2. Manually trigger the "Security Scanning" workflow
3. Review results in the workflow run summary
4. Address any findings before enabling required checks

## Using Security Features

### Viewing Security Alerts

**Code Scanning Alerts:**
1. Navigate to **Security** → **Code scanning**
2. Review alerts by severity
3. Click on alerts for detailed information
4. Dismiss false positives with justification

**Dependabot Alerts:**
1. Navigate to **Security** → **Dependabot**
2. Review vulnerable dependencies
3. Accept Dependabot PR to update dependency
4. Or dismiss alert if not applicable

**Secret Scanning:**
1. Navigate to **Security** → **Secret scanning**
2. Review detected secrets
3. Rotate compromised credentials immediately
4. Close alert after rotation

### Handling Dependabot PRs

**Auto-Merge Guidelines:**

Safe to auto-merge:
- ✅ Patch version updates (1.2.3 → 1.2.4)
- ✅ Minor version updates with passing tests (1.2.0 → 1.3.0)
- ✅ Security patch updates (urgent)

Requires manual review:
- ⚠️ Major version updates (1.x.x → 2.0.0)
- ⚠️ Updates with failing tests
- ⚠️ Updates to core dependencies

**Review Process:**
1. Check Dependabot PR description for changelog
2. Review compatibility notes
3. Ensure all CI checks pass
4. Review security implications
5. Merge or request changes

### Responding to Security Findings

**Critical/High Severity:**
1. Create immediate hotfix branch
2. Apply security patch
3. Expedite review and merge
4. Create security advisory if user-facing
5. Release patch version within 24-48 hours

**Medium Severity:**
1. Create issue for tracking
2. Schedule for next minor release
3. Apply fix in regular development cycle
4. Document in changelog

**Low Severity:**
1. Create issue for tracking
2. Schedule for maintenance release
3. May be deferred if low impact

## Manual Security Testing

### Running GoSec Locally

```bash
# Install gosec
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Run full scan
gosec -fmt=json -out=results.json ./...

# Run with specific severity
gosec -severity=medium -confidence=medium ./...

# Exclude specific checks
gosec -exclude=G104,G107 ./...
```

### Running Trivy Locally

```bash
# Install trivy (macOS)
brew install aquasecurity/trivy/trivy

# Scan repository
trivy fs --severity CRITICAL,HIGH,MEDIUM .

# Scan specific Go modules
trivy fs --scanners vuln --severity HIGH,CRITICAL ./go.mod

# Generate report
trivy fs --format json --output trivy-report.json .
```

### Running GovulnCheck Locally

```bash
# Install govulncheck
go install golang.org/x/vuln/cmd/govulncheck@latest

# Scan project
govulncheck ./...

# Verbose output
govulncheck -show verbose ./...

# Check specific packages
govulncheck ./pkg/sql/parser/
```

## Security Metrics and Monitoring

### Key Metrics to Track

1. **Vulnerability Resolution Time**
   - Target: < 7 days for high/critical
   - Target: < 30 days for medium/low

2. **Dependabot PR Merge Rate**
   - Target: > 80% within 7 days
   - Monitor for outdated dependencies

3. **Security Alert Backlog**
   - Target: < 5 open security alerts
   - Weekly review of all alerts

4. **False Positive Rate**
   - Track dismissed alerts
   - Improve scanning configuration

### Security Dashboard

Create a security dashboard tracking:
- Number of open security alerts by severity
- Time to resolution for security issues
- Dependency freshness metrics
- Compliance with security policies

## Troubleshooting

### Common Issues

**Issue: GoSec false positives**
```bash
# Add exclusion comment in code
// #nosec G104 -- Intentional: error handling not required here
_, _ = fmt.Fprintf(w, "output")
```

**Issue: Trivy scanning timeout**
```yaml
# Increase timeout in workflow
- uses: aquasecurity/trivy-action@0.28.0
  with:
    timeout: '10m'
```

**Issue: Dependabot PRs failing tests**
1. Review test failures
2. Update tests if API changes
3. Comment on Dependabot PR to trigger rebase
4. Close PR if update incompatible

**Issue: Too many Dependabot PRs**
```yaml
# Reduce frequency in dependabot.yml
schedule:
  interval: "weekly"  # Change from "daily"
```

## Best Practices

### For Maintainers

1. **Review Weekly Scans**
   - Check Sunday scan results every Monday
   - Prioritize security findings

2. **Keep Actions Updated**
   - Accept Dependabot PRs for GitHub Actions
   - Review action changelogs

3. **Document Security Decisions**
   - Add comments when dismissing alerts
   - Document risk acceptance in issues

4. **Regular Security Audits**
   - Quarterly review of security posture
   - Annual penetration testing consideration

### For Contributors

1. **Run Security Checks Locally**
   - Run gosec before submitting PRs
   - Check for obvious security issues

2. **Security-Conscious Coding**
   - Avoid hardcoded credentials
   - Use secure defaults
   - Follow OWASP guidelines

3. **Dependency Management**
   - Minimize new dependencies
   - Justify dependency additions
   - Check dependency security history

## References

- [GoSec Documentation](https://github.com/securego/gosec)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)
- [GovulnCheck Documentation](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
- [Dependabot Documentation](https://docs.github.com/en/code-security/dependabot)
- [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)

## Support

For questions about security scanning:
- Review existing security documentation in `SECURITY.md`
- Open a discussion in GitHub Discussions
- Contact maintainers for urgent security matters
