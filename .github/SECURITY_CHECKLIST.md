# Security Feature Activation Guide

This guide provides steps to enable security features for GoSQLX after merging the security workflow.

## Prerequisites

- Security workflow PR merged to main branch
- Repository administrator access
- GitHub Advanced Security enabled (for private repos)

## GitHub Security Settings

### Enable Security Features

Navigate to: **Settings** → **Security & analysis**

Enable the following features:
- Dependency graph (usually enabled by default)
- Dependabot alerts
- Dependabot security updates
- Grouped security updates
- Code scanning (CodeQL)
- Secret scanning
- Secret scanning push protection

### Configure Branch Protection

Navigate to: **Settings** → **Branches** → **Branch protection rules**

For the `main` branch, configure:
- Require status checks before merging
  - Require branches to be up to date
  - Required status checks: `GoSec Security Scanner`, `Trivy Repository Scan`, `Trivy Config Scan`, `Go Vulnerability Check`
- Require pull request reviews (minimum 1 approval)
- Require conversation resolution before merging
- Require signed commits (recommended)
- Include administrators (recommended)

### Configure Notifications

Navigate to: **Settings** → **Notifications** → **Security alerts**

Enable notifications for:
- Email notifications for Dependabot alerts
- Email notifications for code scanning alerts
- Email notifications for secret scanning alerts
- Web notifications for all security events

### Initial Workflow Run

Navigate to: **Actions** → **Security Scanning**

1. Run workflow manually (click "Run workflow")
2. Wait for all jobs to complete
3. Review security summary
4. Address any critical/high findings before enabling required checks

### Review Security Tab

Navigate to: **Security** tab

Review the following sections:
- **Overview** for security posture summary
- **Code scanning alerts** (should be 0 initially)
- **Dependabot alerts** (if any)
- **Secret scanning alerts** (should be 0)

## Dependabot Configuration

### Configure Auto-Merge (Optional)

Navigate to: **Settings** → **General** → **Pull Requests**

- Enable "Allow auto-merge"
- Set up auto-merge rules in repository settings
- Configure required status checks for auto-merge

### Review Dependabot Settings

Navigate to: **Insights** → **Dependency graph** → **Dependabot**

Verify:
- Go modules monitoring enabled
- GitHub Actions monitoring enabled
- Update schedule (daily for Go, weekly for Actions)
- Reviewer assignment working

## Testing and Validation

### Test Security Scanning

1. Create test branch with intentional vulnerability
2. Push branch and create PR
3. Verify security scans run automatically
4. Verify scans detect the test vulnerability
5. Close/delete test PR and branch

### Test Dependabot

1. Wait for first Dependabot PR (may take 24 hours)
2. Review Dependabot PR format
3. Verify labels applied correctly
4. Verify reviewer assigned
5. Test merge process
6. Verify workflow runs on merged PR

### Monitor Weekly Scans

- Note next Sunday's scan schedule
- Review Monday scan results
- Set up recurring calendar reminder for Monday review

## Documentation

### Update Repository README

Add security badges to README.md:

```markdown
[![Security Scanning](https://github.com/ajitpratap0/GoSQLX/actions/workflows/security.yml/badge.svg)](https://github.com/ajitpratap0/GoSQLX/actions/workflows/security.yml)
[![Dependabot Status](https://img.shields.io/badge/Dependabot-enabled-success)](https://github.com/ajitpratap0/GoSQLX/security/dependabot)
```

Additional documentation updates:
- Add link to SECURITY.md in README
- Update contributing guidelines with security requirements

### Team Communication

- Notify team about new security features
- Share docs/SECURITY_SETUP.md with maintainers
- Schedule security training/review session
- Document security incident response process

## Ongoing Maintenance

### Weekly Tasks

- Review Sunday security scan results (every Monday)
- Check for new Dependabot PRs
- Triage any new security alerts

### Monthly Tasks

- Review security metrics and trends
- Update security documentation if needed
- Audit dismissed security alerts
- Review dependency update patterns

### Quarterly Tasks

- Comprehensive security audit
- Review and update security policies
- Test incident response procedures
- Update security training materials

## Rollback Plan

If you need to temporarily disable security features:

1. **Disable Required Checks**: Settings → Branches → Edit rule → Uncheck security checks
2. **Disable Workflow**: Edit `.github/workflows/security.yml` and change triggers to only `workflow_dispatch`
3. **Pause Dependabot**: Rename `.github/dependabot.yml` to `.github/dependabot.yml.disabled`
4. **Document Issues**: Create issue tracking the problem, document why features were disabled, and set deadline for re-enabling

## Success Criteria

Security implementation is successful when:
- All GitHub security features enabled
- Weekly scans running successfully
- Dependabot creating PRs regularly
- No critical/high vulnerabilities in codebase
- Team trained on security processes
- Security metrics being tracked
- Zero security alert backlog

## Support Resources

- **Documentation**: See `docs/SECURITY_SETUP.md` for detailed instructions
- **Security Policy**: See `SECURITY.md` for reporting procedures
- **GitHub Docs**: https://docs.github.com/en/code-security
- **GoSec Docs**: https://github.com/securego/gosec
- **Trivy Docs**: https://aquasecurity.github.io/trivy/

## Notes

Date Completed: _______________
Completed By: _______________
Issues Encountered: _______________
Follow-up Required: _______________
