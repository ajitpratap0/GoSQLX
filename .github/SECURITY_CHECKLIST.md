# Security Feature Activation Checklist

Use this checklist to enable all security features for GoSQLX after merging the security workflow PR.

## Prerequisites
- [ ] Security workflow PR merged to main branch
- [ ] Repository administrator access
- [ ] GitHub Advanced Security enabled (for private repos)

## GitHub Security Settings

### Step 1: Enable Security Features
Navigate to: **Settings** → **Security & analysis**

- [ ] Enable **Dependency graph** (usually enabled by default)
- [ ] Enable **Dependabot alerts**
- [ ] Enable **Dependabot security updates**
- [ ] Enable **Grouped security updates** (new feature)
- [ ] Enable **Code scanning** (CodeQL)
- [ ] Enable **Secret scanning**
- [ ] Enable **Secret scanning push protection**

### Step 2: Configure Branch Protection
Navigate to: **Settings** → **Branches** → **Branch protection rules**

#### For `main` branch:
- [ ] Require status checks before merging
  - [ ] Require branches to be up to date
  - [ ] Select required status checks:
    - [ ] `GoSec Security Scanner`
    - [ ] `Trivy Repository Scan`
    - [ ] `Trivy Config Scan`
    - [ ] `Go Vulnerability Check`
- [ ] Require pull request reviews (1 approval minimum)
- [ ] Require conversation resolution before merging
- [ ] Require signed commits (recommended)
- [ ] Include administrators (recommended)

### Step 3: Configure Notifications
Navigate to: **Settings** → **Notifications** → **Security alerts**

- [ ] Email notifications for Dependabot alerts
- [ ] Email notifications for code scanning alerts
- [ ] Email notifications for secret scanning alerts
- [ ] Web notifications for all security events

### Step 4: Initial Workflow Run
Navigate to: **Actions** → **Security Scanning**

- [ ] Run workflow manually (click "Run workflow")
- [ ] Wait for all jobs to complete
- [ ] Review security summary
- [ ] Address any critical/high findings before enabling required checks

### Step 5: Review Security Tab
Navigate to: **Security** tab

- [ ] Check **Overview** for security posture summary
- [ ] Review **Code scanning alerts** (should be 0 initially)
- [ ] Review **Dependabot alerts** (if any)
- [ ] Review **Secret scanning alerts** (should be 0)

## Dependabot Configuration

### Step 6: Configure Auto-Merge (Optional)
Navigate to: **Settings** → **General** → **Pull Requests**

- [ ] Enable "Allow auto-merge"
- [ ] Set up auto-merge rules in repository settings
- [ ] Configure required status checks for auto-merge

### Step 7: Review Dependabot Settings
Navigate to: **Insights** → **Dependency graph** → **Dependabot**

- [ ] Verify Go modules monitoring enabled
- [ ] Verify GitHub Actions monitoring enabled
- [ ] Check update schedule (daily for Go, weekly for Actions)
- [ ] Verify reviewer assignment working

## Testing and Validation

### Step 8: Test Security Scanning
- [ ] Create test branch with intentional vulnerability
- [ ] Push branch and create PR
- [ ] Verify security scans run automatically
- [ ] Verify scans detect the test vulnerability
- [ ] Close/delete test PR
- [ ] Delete test branch

### Step 9: Test Dependabot
- [ ] Wait for first Dependabot PR (may take 24 hours)
- [ ] Review Dependabot PR format
- [ ] Verify labels applied correctly
- [ ] Verify reviewer assigned
- [ ] Test merge process
- [ ] Verify workflow runs on merged PR

### Step 10: Monitor Weekly Scans
- [ ] Note next Sunday's scan schedule
- [ ] Review Monday scan results
- [ ] Set up recurring calendar reminder for Monday review

## Documentation

### Step 11: Update Repository README
- [ ] Add security badges to README.md:
  ```markdown
  [![Security Scanning](https://github.com/ajitpratap0/GoSQLX/actions/workflows/security.yml/badge.svg)](https://github.com/ajitpratap0/GoSQLX/actions/workflows/security.yml)
  [![Dependabot Status](https://img.shields.io/badge/Dependabot-enabled-success)](https://github.com/ajitpratap0/GoSQLX/security/dependabot)
  ```
- [ ] Add link to SECURITY.md in README
- [ ] Update contributing guidelines with security requirements

### Step 12: Team Communication
- [ ] Notify team about new security features
- [ ] Share SECURITY_SETUP.md with maintainers
- [ ] Schedule security training/review session
- [ ] Document security incident response process

## Ongoing Maintenance

### Weekly Tasks
- [ ] Review Sunday security scan results (every Monday)
- [ ] Check for new Dependabot PRs
- [ ] Triage any new security alerts

### Monthly Tasks
- [ ] Review security metrics and trends
- [ ] Update security documentation if needed
- [ ] Audit dismissed security alerts
- [ ] Review dependency update patterns

### Quarterly Tasks
- [ ] Comprehensive security audit
- [ ] Review and update security policies
- [ ] Test incident response procedures
- [ ] Update security training materials

## Rollback Plan (If Issues Occur)

If you need to temporarily disable security features:

1. **Disable Required Checks**:
   - Settings → Branches → Edit rule → Uncheck security checks

2. **Disable Workflow**:
   - Edit `.github/workflows/security.yml`
   - Change triggers to only `workflow_dispatch`

3. **Pause Dependabot**:
   - Rename `.github/dependabot.yml` to `.github/dependabot.yml.disabled`

4. **Document Issues**:
   - Create issue tracking the problem
   - Document why features were disabled
   - Set deadline for re-enabling

## Success Criteria

Security implementation is successful when:
- [ ] All GitHub security features enabled
- [ ] Weekly scans running successfully
- [ ] Dependabot creating PRs regularly
- [ ] No critical/high vulnerabilities in codebase
- [ ] Team trained on security processes
- [ ] Security metrics being tracked
- [ ] Zero security alert backlog

## Support Resources

- **Documentation**: See `SECURITY_SETUP.md` for detailed instructions
- **Security Policy**: See `SECURITY.md` for reporting procedures
- **GitHub Docs**: https://docs.github.com/en/code-security
- **GoSec Docs**: https://github.com/securego/gosec
- **Trivy Docs**: https://aquasecurity.github.io/trivy/

## Notes

Date Completed: _______________
Completed By: _______________
Issues Encountered: _______________
Follow-up Required: _______________
