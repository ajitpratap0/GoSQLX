#!/bin/bash
# Script to install Git hooks for GoSQLX

set -e

HOOKS_DIR=".git/hooks"

echo "Installing pre-commit hook for GoSQLX..."

# Check if .git directory exists
if [ ! -d ".git" ]; then
    echo "Error: .git directory not found. Are you in the repository root?"
    exit 1
fi

# Create hooks directory if it doesn't exist
mkdir -p "$HOOKS_DIR"

# Create pre-commit hook
cat > "$HOOKS_DIR/pre-commit" << 'HOOK'
#!/bin/bash
# Pre-commit hook for GoSQLX
# This hook runs code quality checks before allowing a commit

set -e

echo "=========================================="
echo "Running GoSQLX pre-commit checks..."
echo "=========================================="

# Get list of Go files that are staged for commit
STAGED_GO_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep '\.go$' || true)

if [ -z "$STAGED_GO_FILES" ]; then
    echo "No Go files staged for commit. Skipping checks."
    exit 0
fi

echo ""
echo "Staged Go files:"
echo "$STAGED_GO_FILES"
echo ""

# Check 1: go fmt
echo "=========================================="
echo "Check 1/3: Running go fmt..."
echo "=========================================="
UNFORMATTED=$(gofmt -l . 2>&1)
if [ -n "$UNFORMATTED" ]; then
    echo "Error: The following files need formatting:"
    echo "$UNFORMATTED"
    echo ""
    echo "To fix, run: gofmt -w ."
    echo "Or use: make fmt"
    exit 1
fi
echo "✓ Code formatting check passed"
echo ""

# Check 2: go vet
echo "=========================================="
echo "Check 2/3: Running go vet..."
echo "=========================================="
if ! go vet ./... 2>&1; then
    echo ""
    echo "Error: go vet found issues"
    echo "Please fix the issues above before committing"
    exit 1
fi
echo "✓ Static analysis check passed"
echo ""

# Check 3: go test (short mode)
echo "=========================================="
echo "Check 3/3: Running tests (short mode)..."
echo "=========================================="
if ! go test -short ./... 2>&1; then
    echo ""
    echo "Error: Tests failed"
    echo "Please fix the failing tests before committing"
    exit 1
fi
echo "✓ Tests passed"
echo ""

echo "=========================================="
echo "✓ All pre-commit checks passed!"
echo "=========================================="
echo ""
echo "Note: Full tests with race detection will run in CI/CD"
echo "To run full tests locally: go test -race ./..."
echo ""
HOOK

# Make pre-commit hook executable
chmod +x "$HOOKS_DIR/pre-commit"

echo ""
echo "=========================================="
echo "✓ Pre-commit hook installed successfully!"
echo "=========================================="
echo ""
echo "The following checks will run before each commit:"
echo "  1. go fmt  - Code formatting"
echo "  2. go vet  - Static analysis"
echo "  3. go test - Tests (short mode)"
echo ""
echo "To bypass hooks (not recommended):"
echo "  git commit --no-verify"
echo ""
echo "To uninstall:"
echo "  rm .git/hooks/pre-commit"
echo ""
