# GitHub Action Integration Guide

This guide shows how to integrate the GoSQLX GitHub Action with other popular actions and tools.

## Table of Contents

- [Pull Request Comments](#pull-request-comments)
- [Slack Notifications](#slack-notifications)
- [Code Coverage Integration](#code-coverage-integration)
- [Changed Files Detection](#changed-files-detection)
- [Matrix Builds](#matrix-builds)
- [Artifact Upload](#artifact-upload)
- [Status Checks](#status-checks)
- [Deployment Gates](#deployment-gates)

## Pull Request Comments

### Basic PR Comment

```yaml
name: SQL Validation with PR Comments

on: pull_request

permissions:
  contents: read
  pull-requests: write

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Validate SQL
        uses: ajitpratap0/GoSQLX@v1
        id: validate
        with:
          files: '**/*.sql'
          validate: true
          show-stats: true

      - name: Comment PR
        uses: actions/github-script@v7
        if: github.event_name == 'pull_request'
        with:
          script: |
            const comment = `## SQL Validation Results

            - **Files**: ${{ steps.validate.outputs.validated-files }}
            - **Errors**: ${{ steps.validate.outputs.invalid-files }}
            - **Time**: ${{ steps.validate.outputs.validation-time }}ms

            ${{ steps.validate.outputs.invalid-files == '0' ? 'All SQL files valid!' : 'Please fix SQL errors' }}`;

            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

### PR Comment with File Annotations

```yaml
- name: Annotate PR
  uses: actions/github-script@v7
  if: steps.validate.outputs.invalid-files != '0'
  with:
    script: |
      // Create review comments on specific files
      const review = await github.rest.pulls.createReview({
        owner: context.repo.owner,
        repo: context.repo.repo,
        pull_number: context.issue.number,
        event: 'REQUEST_CHANGES',
        body: 'SQL validation found errors. Please review and fix.'
      });
```

## Slack Notifications

### Notify on Failure

```yaml
- name: Notify Slack on failure
  if: failure()
  uses: slackapi/slack-github-action@v1
  with:
    payload: |
      {
        "text": "SQL Validation Failed",
        "blocks": [
          {
            "type": "section",
            "text": {
              "type": "mrkdwn",
              "text": "SQL validation failed\n*Repository:* ${{ github.repository }}\n*Branch:* ${{ github.ref_name }}"
            }
          }
        ]
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

### Detailed Slack Report

```yaml
- name: Send detailed Slack report
  uses: slackapi/slack-github-action@v1
  if: always()
  with:
    payload: |
      {
        "text": "SQL Validation Complete",
        "blocks": [
          {
            "type": "section",
            "text": {
              "type": "mrkdwn",
              "text": "*SQL Validation Results*\n\n• Files: ${{ steps.validate.outputs.validated-files }}\n• Errors: ${{ steps.validate.outputs.invalid-files }}\n• Time: ${{ steps.validate.outputs.validation-time }}ms\n• Status: ${{ steps.validate.outputs.invalid-files == '0' && 'Passed' || 'Failed' }}"
            }
          },
          {
            "type": "actions",
            "elements": [
              {
                "type": "button",
                "text": {
                  "type": "plain_text",
                  "text": "View Workflow"
                },
                "url": "${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
              }
            ]
          }
        ]
      }
  env:
    SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
```

## Code Coverage Integration

### With Codecov

```yaml
- name: Generate coverage report
  run: |
    # Your test coverage generation
    go test -coverprofile=coverage.out ./...

- name: Upload coverage
  uses: codecov/codecov-action@v3
  with:
    files: ./coverage.out

- name: Validate SQL in tests
  uses: ajitpratap0/GoSQLX@v1
  with:
    files: 'testdata/**/*.sql'
```

## Changed Files Detection

### Validate Only Changed SQL Files

```yaml
name: Validate Changed SQL

on: pull_request

jobs:
  validate-changed:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Get changed SQL files
        id: changed
        uses: tj-actions/changed-files@v40
        with:
          files: |
            **/*.sql
          separator: ' '

      - name: List changed files
        if: steps.changed.outputs.any_changed == 'true'
        run: |
          echo "Changed SQL files:"
          echo "${{ steps.changed.outputs.all_changed_files }}"

      - name: Validate changed files
        if: steps.changed.outputs.any_changed == 'true'
        uses: ajitpratap0/GoSQLX@v1
        with:
          files: ${{ steps.changed.outputs.all_changed_files }}
          validate: true
          strict: true

      - name: No SQL changes
        if: steps.changed.outputs.any_changed != 'true'
        run: echo "No SQL files changed, skipping validation"
```

### Compare Against Base Branch

```yaml
- name: Get changed files vs base
  uses: tj-actions/changed-files@v40
  with:
    files: '**/*.sql'
    base_sha: ${{ github.event.pull_request.base.sha }}
    sha: ${{ github.event.pull_request.head.sha }}
```

## Matrix Builds

### Multi-Dialect Matrix

```yaml
name: Multi-Dialect Validation

on: [push, pull_request]

jobs:
  validate-matrix:
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest]
        dialect: [postgresql, mysql, sqlite]
        include:
          - dialect: postgresql
            files: 'sql/pg/**/*.sql'
          - dialect: mysql
            files: 'sql/mysql/**/*.sql'
          - dialect: sqlite
            files: 'sql/sqlite/**/*.sql'

    steps:
      - uses: actions/checkout@v4

      - name: Validate ${{ matrix.dialect }} on ${{ matrix.os }}
        uses: ajitpratap0/GoSQLX@v1
        with:
          files: ${{ matrix.files }}
          dialect: ${{ matrix.dialect }}
          strict: true
```

### Environment Matrix

```yaml
strategy:
  matrix:
    environment: [development, staging, production]
    include:
      - environment: development
        strict: false
        dialect: postgresql
      - environment: staging
        strict: true
        dialect: postgresql
      - environment: production
        strict: true
        dialect: postgresql
        config: '.gosqlx.production.yml'
```

## Artifact Upload

### Upload Validation Results

```yaml
- name: Validate SQL
  uses: ajitpratap0/GoSQLX@v1
  id: validate
  continue-on-error: true
  with:
    files: '**/*.sql'
    validate: true

- name: Create validation report
  if: always()
  run: |
    cat > validation-report.json << EOF
    {
      "validated_files": "${{ steps.validate.outputs.validated-files }}",
      "invalid_files": "${{ steps.validate.outputs.invalid-files }}",
      "validation_time": "${{ steps.validate.outputs.validation-time }}",
      "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    }
    EOF

- name: Upload report
  uses: actions/upload-artifact@v4
  if: always()
  with:
    name: sql-validation-report
    path: validation-report.json
    retention-days: 30
```

### Download and Compare Reports

```yaml
- name: Download previous report
  uses: actions/download-artifact@v4
  continue-on-error: true
  with:
    name: sql-validation-report
    path: previous-report

- name: Compare with previous
  run: |
    if [ -f previous-report/validation-report.json ]; then
      echo "Comparing with previous run..."
      # Your comparison logic
    fi
```

## Status Checks

### Required Status Check

```yaml
name: SQL Quality Gate

on:
  pull_request:
    types: [opened, synchronize]

jobs:
  sql-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: SQL Validation (Required)
        uses: ajitpratap0/GoSQLX@v1
        with:
          files: '**/*.sql'
          validate: true
          strict: true
          fail-on-error: true

      - name: Format Check (Required)
        uses: ajitpratap0/GoSQLX@v1
        with:
          files: '**/*.sql'
          format-check: true
          fail-on-error: true
```

### Create Check Run

```yaml
- name: Create check run
  uses: actions/github-script@v7
  with:
    script: |
      const check = await github.rest.checks.create({
        owner: context.repo.owner,
        repo: context.repo.repo,
        name: 'SQL Validation',
        head_sha: context.sha,
        status: 'completed',
        conclusion: '${{ steps.validate.outputs.invalid-files == "0" && "success" || "failure" }}',
        output: {
          title: 'SQL Validation Results',
          summary: `Validated ${{ steps.validate.outputs.validated-files }} files`,
          text: `Invalid files: ${{ steps.validate.outputs.invalid-files }}`
        }
      });
```

## Deployment Gates

### Block Deployment on Validation Failure

```yaml
name: Deploy with SQL Gate

on:
  push:
    branches: [main]

jobs:
  validate:
    runs-on: ubuntu-latest
    outputs:
      sql-valid: ${{ steps.validate.outputs.invalid-files == '0' }}
    steps:
      - uses: actions/checkout@v4

      - name: Validate SQL
        id: validate
        uses: ajitpratap0/GoSQLX@v1
        with:
          files: '**/*.sql'
          validate: true
          strict: true

  deploy:
    needs: validate
    if: needs.validate.outputs.sql-valid == 'true'
    runs-on: ubuntu-latest
    steps:
      - name: Deploy application
        run: echo "Deploying..."
```

### Pre-deployment Validation

```yaml
name: Production Deployment

on:
  workflow_dispatch:
    inputs:
      environment:
        description: 'Environment'
        required: true
        type: choice
        options: [staging, production]

jobs:
  pre-deploy-validation:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Validate SQL for ${{ inputs.environment }}
        uses: ajitpratap0/GoSQLX@v1
        with:
          files: 'migrations/**/*.sql'
          config: '.gosqlx.${{ inputs.environment }}.yml'
          validate: true
          strict: true
          fail-on-error: true

      - name: Validate rollback scripts
        uses: ajitpratap0/GoSQLX@v1
        with:
          files: 'rollback/**/*.sql'
          validate: true
          strict: true
```

## Caching

### Cache GoSQLX Binary

```yaml
# Built-in caching in the action
- uses: ajitpratap0/GoSQLX@v1
  with:
    files: '**/*.sql'
  # Binary is automatically cached
```

### Cache Validation Results

```yaml
- name: Cache validation results
  uses: actions/cache@v4
  with:
    path: .gosqlx-cache
    key: sql-validation-${{ hashFiles('**/*.sql') }}

- name: Validate if not cached
  if: steps.cache.outputs.cache-hit != 'true'
  uses: ajitpratap0/GoSQLX@v1
  with:
    files: '**/*.sql'
```

## Conditional Execution

### Run on Specific Branches

```yaml
- name: Validate SQL
  if: github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/heads/release/')
  uses: ajitpratap0/GoSQLX@v1
  with:
    files: '**/*.sql'
```

### Run on Label

```yaml
name: SQL Validation

on:
  pull_request:
    types: [opened, synchronize, labeled]

jobs:
  validate:
    if: contains(github.event.pull_request.labels.*.name, 'sql-changes')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ajitpratap0/GoSQLX@v1
        with:
          files: '**/*.sql'
```

## Parallel Execution

### Split Validation Across Jobs

```yaml
jobs:
  validate-queries:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ajitpratap0/GoSQLX@v1
        with:
          files: 'queries/**/*.sql'

  validate-migrations:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ajitpratap0/GoSQLX@v1
        with:
          files: 'migrations/**/*.sql'
          strict: true

  validate-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ajitpratap0/GoSQLX@v1
        with:
          files: 'test/**/*.sql'
          fail-on-error: false
```

## Reusable Workflows

### Create Reusable Workflow

```yaml
# .github/workflows/sql-validation-reusable.yml
name: Reusable SQL Validation

on:
  workflow_call:
    inputs:
      files:
        required: true
        type: string
      dialect:
        required: false
        type: string
        default: ''
      strict:
        required: false
        type: boolean
        default: false
    outputs:
      validated-files:
        value: ${{ jobs.validate.outputs.validated }}
      invalid-files:
        value: ${{ jobs.validate.outputs.invalid }}

jobs:
  validate:
    runs-on: ubuntu-latest
    outputs:
      validated: ${{ steps.validate.outputs.validated-files }}
      invalid: ${{ steps.validate.outputs.invalid-files }}
    steps:
      - uses: actions/checkout@v4

      - name: Validate SQL
        id: validate
        uses: ajitpratap0/GoSQLX@v1
        with:
          files: ${{ inputs.files }}
          dialect: ${{ inputs.dialect }}
          strict: ${{ inputs.strict }}
```

### Use Reusable Workflow

```yaml
# .github/workflows/main-validation.yml
name: Main Validation

on: [push, pull_request]

jobs:
  validate-postgresql:
    uses: ./.github/workflows/sql-validation-reusable.yml
    with:
      files: 'sql/pg/**/*.sql'
      dialect: 'postgresql'
      strict: true

  validate-mysql:
    uses: ./.github/workflows/sql-validation-reusable.yml
    with:
      files: 'sql/mysql/**/*.sql'
      dialect: 'mysql'
      strict: true
```

## Best Practices

1. **Use specific file patterns** to reduce processing time
2. **Enable caching** for better performance
3. **Fail fast** in CI/CD pipelines with `fail-on-error: true`
4. **Use matrix builds** for multi-dialect projects
5. **Validate changed files only** in PRs for large repositories
6. **Set timeouts** to prevent hung jobs
7. **Use artifacts** to store validation reports
8. **Enable PR comments** for better developer experience

## Complete Integration Example

```yaml
name: Complete SQL CI/CD

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      # Get changed files for PRs
      - name: Get changed SQL files
        if: github.event_name == 'pull_request'
        id: changed
        uses: tj-actions/changed-files@v40
        with:
          files: '**/*.sql'

      # Validate changed files (PR)
      - name: Validate changed SQL
        if: github.event_name == 'pull_request' && steps.changed.outputs.any_changed == 'true'
        uses: ajitpratap0/GoSQLX@v1
        id: validate-pr
        with:
          files: ${{ steps.changed.outputs.all_changed_files }}
          validate: true
          format-check: true
          strict: true

      # Validate all files (push to main)
      - name: Validate all SQL
        if: github.event_name == 'push'
        uses: ajitpratap0/GoSQLX@v1
        id: validate-all
        with:
          files: '**/*.sql'
          validate: true
          strict: true
          show-stats: true

      # Comment on PR
      - name: PR Comment
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const validated = '${{ steps.validate-pr.outputs.validated-files }}';
            const invalid = '${{ steps.validate-pr.outputs.invalid-files }}';
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `### SQL Validation\n\nFiles: ${validated}\nErrors: ${invalid}`
            });

      # Slack notification on failure
      - name: Slack notification
        if: failure() && github.event_name == 'push'
        uses: slackapi/slack-github-action@v1
        with:
          payload: '{"text": "SQL validation failed on main branch"}'
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}
```
