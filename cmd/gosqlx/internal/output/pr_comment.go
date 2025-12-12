package output

import (
	"fmt"
	"strings"
)

// FormatPRComment formats validation results as a GitHub PR comment with markdown.
//
// Generates a comprehensive, well-formatted Markdown comment suitable for
// posting to GitHub Pull Requests. The comment includes summary statistics,
// detailed error information, and performance metrics.
//
// Parameters:
//   - result: Validation results to format
//
// Returns:
//   - Markdown-formatted string ready for PR comment
//
// Output includes:
//   - Header with validation status (✅ success or ❌ failure)
//   - Summary statistics table (total files, valid/invalid counts, duration)
//   - Performance metrics (throughput)
//   - Detailed error listing for each invalid file
//   - Footer with tool attribution
//
// Example:
//
//	result := &ValidationResult{
//	    TotalFiles:   2,
//	    ValidFiles:   1,
//	    InvalidFiles: 1,
//	    Duration:     10 * time.Millisecond,
//	    Files: []FileValidationResult{
//	        {Path: "broken.sql", Valid: false, Error: errors.New("syntax error")},
//	    },
//	}
//	comment := FormatPRComment(result)
//	// Post comment to GitHub PR via API
//
// Usage in GitHub Actions:
//
//   - name: Validate SQL
//     id: validate
//     run: gosqlx validate ./sql/ > results.txt
//   - name: Comment PR
//     uses: actions/github-script@v6
//     with:
//     script: |
//     const comment = require('fs').readFileSync('results.txt', 'utf8');
//     github.rest.issues.createComment({...});
//
// FormatPRComment formats validation results as a GitHub PR comment with markdown
func FormatPRComment(result *ValidationResult) string {
	var sb strings.Builder

	// Header
	sb.WriteString("## 🔍 GoSQLX SQL Validation Results\n\n")

	// Summary section
	if result.InvalidFiles == 0 {
		sb.WriteString("### ✅ All SQL files are valid!\n\n")
		sb.WriteString(fmt.Sprintf("**%d** file(s) validated successfully in **%v**\n\n",
			result.ValidFiles, result.Duration))
	} else {
		sb.WriteString(fmt.Sprintf("### ❌ Found issues in **%d** file(s)\n\n", result.InvalidFiles))
	}

	// Statistics table
	sb.WriteString("| Metric | Value |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Total Files | %d |\n", result.TotalFiles))
	sb.WriteString(fmt.Sprintf("| ✅ Valid | %d |\n", result.ValidFiles))
	sb.WriteString(fmt.Sprintf("| ❌ Invalid | %d |\n", result.InvalidFiles))
	sb.WriteString(fmt.Sprintf("| ⏱️ Duration | %v |\n", result.Duration))

	if result.TotalFiles > 0 && result.Duration.Seconds() > 0 {
		throughput := float64(result.TotalFiles) / result.Duration.Seconds()
		sb.WriteString(fmt.Sprintf("| 🚀 Throughput | %.1f files/sec |\n", throughput))
	}

	sb.WriteString("\n")

	// Detailed errors section
	if result.InvalidFiles > 0 {
		sb.WriteString("### 📋 Validation Errors\n\n")

		for _, file := range result.Files {
			if file.Error != nil {
				// File header with error icon
				sb.WriteString(fmt.Sprintf("#### ❌ `%s`\n\n", file.Path))

				// Error details in a code block
				sb.WriteString("```\n")
				sb.WriteString(file.Error.Error())
				sb.WriteString("\n```\n\n")
			}
		}
	}

	// Footer
	sb.WriteString("---\n")
	sb.WriteString("*Powered by [GoSQLX](https://github.com/ajitpratap0/GoSQLX) - ")
	sb.WriteString("Ultra-fast SQL validation (100x faster than SQLFluff)*\n")

	return sb.String()
}

// FormatPRCommentCompact formats validation results as a compact PR comment.
//
// Generates a concise PR comment with limited error display, suitable for
// large validation runs where the full comment would be too long.
//
// Parameters:
//   - result: Validation results to format
//   - maxErrors: Maximum number of errors to display in the comment
//
// Returns:
//   - Compact Markdown-formatted string for PR comment
//
// The compact format includes:
//   - Single-line header with status
//   - Brief error listing (up to maxErrors)
//   - Truncation notice if more errors exist
//   - Performance metrics footer
//
// This format is useful when:
//   - Validating large numbers of files (100+)
//   - Many files have errors (10+)
//   - GitHub's comment size limits may be reached
//   - Quick overview is preferred over detailed breakdown
//
// Example:
//
//	result := &ValidationResult{
//	    TotalFiles:   100,
//	    InvalidFiles: 25,
//	}
//	comment := FormatPRCommentCompact(result, 5)  // Show only first 5 errors
//	// Posts "## ❌ GoSQLX: Found issues in 25/100 files" with top 5 errors
//
// FormatPRCommentCompact formats validation results as a compact PR comment
// Useful for large validation runs to avoid overly long comments
func FormatPRCommentCompact(result *ValidationResult, maxErrors int) string {
	var sb strings.Builder

	// Header with summary
	if result.InvalidFiles == 0 {
		sb.WriteString("## ✅ GoSQLX: All SQL files valid\n\n")
		sb.WriteString(fmt.Sprintf("Validated **%d** file(s) in **%v**\n",
			result.ValidFiles, result.Duration))
	} else {
		sb.WriteString(fmt.Sprintf("## ❌ GoSQLX: Found issues in %d/%d files\n\n",
			result.InvalidFiles, result.TotalFiles))

		// Show limited errors
		errorCount := 0
		for _, file := range result.Files {
			if file.Error != nil && errorCount < maxErrors {
				sb.WriteString(fmt.Sprintf("- ❌ `%s`: %s\n", file.Path, file.Error.Error()))
				errorCount++
			}
		}

		// Show truncation message if needed
		if result.InvalidFiles > maxErrors {
			remaining := result.InvalidFiles - maxErrors
			sb.WriteString(fmt.Sprintf("\n*...and %d more error(s). Run locally for full details.*\n", remaining))
		}
	}

	sb.WriteString("\n---\n")
	sb.WriteString(fmt.Sprintf("⏱️ %v | ", result.Duration))
	if result.TotalFiles > 0 && result.Duration.Seconds() > 0 {
		throughput := float64(result.TotalFiles) / result.Duration.Seconds()
		sb.WriteString(fmt.Sprintf("🚀 %.1f files/sec", throughput))
	}

	return sb.String()
}
