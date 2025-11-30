#!/bin/bash
# validate-security-setup.sh
# Validates that security scanning infrastructure is properly configured

set -e

echo "🔍 GoSQLX Security Setup Validation"
echo "===================================="
echo ""

ERRORS=0
WARNINGS=0

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

check_file() {
    local file="$1"
    local desc="$2"

    if [ -f "$file" ]; then
        echo -e "${GREEN}✓${NC} $desc: ${BLUE}$file${NC}"
        return 0
    else
        echo -e "${RED}✗${NC} $desc: ${RED}$file (MISSING)${NC}"
        ERRORS=$((ERRORS + 1))
        return 1
    fi
}

check_file_content() {
    local file="$1"
    local pattern="$2"
    local desc="$3"

    if grep -q "$pattern" "$file" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} $desc"
        return 0
    else
        echo -e "${YELLOW}⚠${NC} $desc ${YELLOW}(NOT FOUND)${NC}"
        WARNINGS=$((WARNINGS + 1))
        return 1
    fi
}

echo "📁 Checking Required Files..."
echo "----------------------------"
check_file ".github/workflows/security.yml" "Security workflow"
check_file ".github/dependabot.yml" "Dependabot config"
check_file "SECURITY.md" "Security policy"
check_file "docs/SECURITY_SETUP.md" "Setup guide"
check_file ".github/SECURITY_CHECKLIST.md" "Setup checklist"
echo ""

echo "🔧 Validating Security Workflow..."
echo "-----------------------------------"
if [ -f ".github/workflows/security.yml" ]; then
    check_file_content ".github/workflows/security.yml" "gosec" "GoSec scanner configured"
    check_file_content ".github/workflows/security.yml" "trivy-action" "Trivy scanner configured"
    check_file_content ".github/workflows/security.yml" "govulncheck" "GovulnCheck configured"
    check_file_content ".github/workflows/security.yml" "dependency-review" "Dependency review configured"
    check_file_content ".github/workflows/security.yml" "cron:.*0 0 \* \* 0" "Weekly schedule configured"
fi
echo ""

echo "📦 Validating Dependabot Config..."
echo "-----------------------------------"
if [ -f ".github/dependabot.yml" ]; then
    check_file_content ".github/dependabot.yml" "package-ecosystem.*gomod" "Go modules updates enabled"
    check_file_content ".github/dependabot.yml" "package-ecosystem.*github-actions" "GitHub Actions updates enabled"
    check_file_content ".github/dependabot.yml" "schedule:" "Update schedule configured"
    check_file_content ".github/dependabot.yml" "reviewers:" "Reviewers assigned"
fi
echo ""

echo "📝 Validating Security Documentation..."
echo "---------------------------------------"
if [ -f "SECURITY.md" ]; then
    check_file_content "SECURITY.md" "Automated Security Scanning" "Security scanning section"
    check_file_content "SECURITY.md" "Reporting a Vulnerability" "Vulnerability reporting"
    check_file_content "SECURITY.md" "Supported Versions" "Supported versions table"
fi
echo ""

echo "🧪 Checking Tool Availability..."
echo "--------------------------------"
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}')
    echo -e "${GREEN}✓${NC} Go installed: ${BLUE}$GO_VERSION${NC}"
else
    echo -e "${RED}✗${NC} Go not installed"
    ERRORS=$((ERRORS + 1))
fi

if command -v gosec &> /dev/null; then
    GOSEC_VERSION=$(gosec -version 2>&1 | head -1)
    echo -e "${GREEN}✓${NC} gosec installed: ${BLUE}$GOSEC_VERSION${NC}"
else
    echo -e "${YELLOW}⚠${NC} gosec not installed (optional for local testing)"
    echo "  Install: go install github.com/securego/gosec/v2/cmd/gosec@latest"
fi

if command -v trivy &> /dev/null; then
    TRIVY_VERSION=$(trivy --version | head -1)
    echo -e "${GREEN}✓${NC} trivy installed: ${BLUE}$TRIVY_VERSION${NC}"
else
    echo -e "${YELLOW}⚠${NC} trivy not installed (optional for local testing)"
    echo "  Install (macOS): brew install aquasecurity/trivy/trivy"
fi

if command -v govulncheck &> /dev/null; then
    echo -e "${GREEN}✓${NC} govulncheck installed"
else
    echo -e "${YELLOW}⚠${NC} govulncheck not installed (optional for local testing)"
    echo "  Install: go install golang.org/x/vuln/cmd/govulncheck@latest"
fi
echo ""

echo "🔒 Checking Go Module Configuration..."
echo "---------------------------------------"
if [ -f "go.mod" ]; then
    check_file_content "go.mod" "module github.com/ajitpratap0/GoSQLX" "Module name correct"
    GO_MOD_VERSION=$(grep "^go " go.mod | awk '{print $2}')
    echo -e "${GREEN}✓${NC} Go version in go.mod: ${BLUE}$GO_MOD_VERSION${NC}"
else
    echo -e "${RED}✗${NC} go.mod not found"
    ERRORS=$((ERRORS + 1))
fi
echo ""

echo "📊 Summary"
echo "=========="
if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Review .github/SECURITY_CHECKLIST.md"
    echo "2. Enable GitHub security features in repository settings"
    echo "3. Run the security workflow manually to test"
    echo "4. Configure branch protection rules"
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠ $WARNINGS warning(s) found${NC}"
    echo ""
    echo "The setup is functional but some optional components are missing."
    echo "Review the warnings above and install optional tools if needed."
    exit 0
else
    echo -e "${RED}✗ $ERRORS error(s) found${NC}"
    if [ $WARNINGS -gt 0 ]; then
        echo -e "${YELLOW}⚠ $WARNINGS warning(s) found${NC}"
    fi
    echo ""
    echo "Please fix the errors above before proceeding."
    exit 1
fi
