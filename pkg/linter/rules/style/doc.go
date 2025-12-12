// Package style provides linting rules for SQL style and formatting conventions.
//
// This package includes rules that enforce consistent style patterns across SQL
// code, including column alignment, comma placement, and aliasing conventions.
// These rules focus on readability and team coding standards rather than syntax.
//
// # Rules in this Package
//
// L006: Column Alignment (no auto-fix)
//   - Checks that SELECT columns are properly aligned
//   - Detects misaligned columns in multi-line SELECT statements
//   - Severity: Info
//   - Requires manual formatting adjustment
//
// L008: Comma Placement (no auto-fix)
//   - Enforces consistent comma placement: trailing or leading
//   - Configurable style: CommaTrailing or CommaLeading
//   - Severity: Info
//   - Requires manual restructuring
//
// L009: Aliasing Consistency (no auto-fix)
//   - Checks for consistent table and column alias usage
//   - Detects mixed use of full names and aliases
//   - Configurable: prefer explicit AS keyword or implicit aliases
//   - Severity: Warning
//   - Requires manual refactoring
//
// # Usage Examples
//
// Column Alignment (L006):
//
//	import "github.com/ajitpratap0/GoSQLX/pkg/linter/rules/style"
//
//	rule := style.NewColumnAlignmentRule()
//	violations, _ := rule.Check(ctx)
//	// Detects:
//	// SELECT
//	//     column1,
//	//   column2,      <- Not aligned with column1
//	//     column3
//	// FROM table
//
// Comma Placement - Trailing Style (L008):
//
//	rule := style.NewCommaPlacementRule(style.CommaTrailing)
//	violations, _ := rule.Check(ctx)
//	// Enforces:
//	// SELECT
//	//     column1,     <- Comma at end (trailing)
//	//     column2,
//	//     column3
//	// FROM table
//
// Comma Placement - Leading Style (L008):
//
//	rule := style.NewCommaPlacementRule(style.CommaLeading)
//	violations, _ := rule.Check(ctx)
//	// Enforces:
//	// SELECT
//	//     column1
//	//     , column2    <- Comma at start (leading)
//	//     , column3
//	// FROM table
//
// Aliasing Consistency with Explicit AS (L009):
//
//	rule := style.NewAliasingConsistencyRule(true)  // Prefer explicit AS
//	violations, _ := rule.Check(ctx)
//	// Enforces:
//	// SELECT u.name
//	// FROM users AS u              <- Explicit AS keyword
//	// JOIN orders AS o ON u.id = o.user_id
//
// Aliasing Consistency with Implicit Aliases (L009):
//
//	rule := style.NewAliasingConsistencyRule(false)  // Allow implicit
//	violations, _ := rule.Check(ctx)
//	// Allows:
//	// SELECT u.name
//	// FROM users u                 <- Implicit alias (no AS)
//	// JOIN orders o ON u.id = o.user_id
//
// # Style Conventions
//
// Column Alignment:
//   - Improves readability in multi-line SELECT statements
//   - Helps identify column relationships
//   - Makes diffs cleaner in version control
//
// Comma Placement:
//   - Trailing (recommended for most teams):
//   - Traditional SQL style
//   - Easier to add columns at end
//   - Matches most code formatters
//   - Leading:
//   - Makes it obvious when comma is forgotten
//   - Easier to comment out last column
//   - Preferred by some functional programming teams
//
// Aliasing Consistency:
//   - Explicit AS (recommended):
//   - Clearer intent, no ambiguity
//   - Easier for SQL beginners to understand
//   - Matches most SQL documentation
//   - Implicit (allowed in SQL standard):
//   - More concise, less verbose
//   - Common in ad-hoc queries
//   - Preferred in some codebases for brevity
//
// # Rule Limitations
//
// None of the style rules support auto-fixing because they require:
//
// L006 (Column Alignment):
//   - Complex indentation calculation
//   - Semantic understanding of SELECT structure
//   - Preservation of comments and formatting
//   - Manual alignment is more reliable
//
// L008 (Comma Placement):
//   - Multi-line restructuring
//   - Potential comment relocation
//   - Context-sensitive placement decisions
//   - Manual editing ensures correct results
//
// L009 (Aliasing Consistency):
//   - AST analysis of all table references
//   - Renaming references throughout query
//   - Risk of breaking query semantics
//   - Manual refactoring is safer
//
// These rules provide guidance and detect violations but require developer
// intervention to fix properly.
//
// # Configuration Recommendations
//
// Standard enterprise style:
//
//	style.NewColumnAlignmentRule()                        // Enforce alignment
//	style.NewCommaPlacementRule(style.CommaTrailing)      // Traditional style
//	style.NewAliasingConsistencyRule(true)                // Explicit AS
//
// Modern application style:
//
//	style.NewColumnAlignmentRule()                        // Still align columns
//	style.NewCommaPlacementRule(style.CommaLeading)       // Leading commas
//	style.NewAliasingConsistencyRule(false)               // Allow implicit
//
// Relaxed style (minimal enforcement):
//
//	// Skip L006 if alignment not important
//	style.NewCommaPlacementRule(style.CommaTrailing)      // Just be consistent
//	// Skip L009 if aliasing flexibility desired
//
// Legacy codebase (detection only):
//
//	// Enable all rules to detect inconsistencies
//	style.NewColumnAlignmentRule()
//	style.NewCommaPlacementRule(style.CommaTrailing)
//	style.NewAliasingConsistencyRule(true)
//	// Review violations, don't enforce immediately
//	// Gradually refactor hot paths first
//
// # Integration with Linter
//
// Style rules integrate with the linter framework:
//
//	linter := linter.New(
//	    style.NewColumnAlignmentRule(),
//	    style.NewCommaPlacementRule(style.CommaTrailing),
//	    style.NewAliasingConsistencyRule(true),
//	    // other rules...
//	)
//	result := linter.LintFile("query.sql")
//
// CLI usage:
//
//	# Check style
//	gosqlx lint query.sql
//
//	# Style rules don't support --fix
//	# Violations must be fixed manually
//
// Configuration file (.gosqlx.yml):
//
//	linter:
//	  rules:
//	    - id: L006
//	      enabled: true
//	    - id: L008
//	      enabled: true
//	      config:
//	        comma_style: trailing  # or 'leading'
//	    - id: L009
//	      enabled: true
//	      config:
//	        prefer_explicit_as: true  # or false
//
// # AST vs Text-Based Analysis
//
// L006 and L008 are text-based rules:
//   - Analyze raw line content
//   - Fast, no parsing required
//   - Work even on syntactically invalid SQL
//   - Pattern-based detection
//
// L009 is hybrid (AST-preferred, text-fallback):
//   - Prefers AST analysis for accuracy
//   - Falls back to text analysis if parsing fails
//   - More accurate violation detection with AST
//   - Handles complex query structures
//
// # Performance Characteristics
//
// All style rules are efficient with linear complexity:
//
// L006 (Column Alignment):
//   - Speed: 80,000+ lines/sec
//   - Complexity: O(n) line scanning
//   - Memory: Minimal state tracking
//
// L008 (Comma Placement):
//   - Speed: 100,000+ lines/sec
//   - Complexity: O(n) line scanning
//   - Memory: No allocation in check phase
//
// L009 (Aliasing Consistency):
//   - With AST: 50,000+ lines/sec (AST traversal)
//   - Without AST: 80,000+ lines/sec (text analysis)
//   - Complexity: O(n) nodes or lines
//   - Memory: Maps for alias tracking
//
// # Thread Safety
//
// All rule types in this package are stateless and thread-safe.
// Rule instances can be shared across goroutines safely.
//
// # Example Violations and Fixes
//
// L006 - Column Alignment:
//
//	-- Bad (misaligned)
//	SELECT
//	    user_id,
//	  username,        <- Wrong indent
//	    email
//	FROM users
//
//	-- Good (aligned)
//	SELECT
//	    user_id,
//	    username,
//	    email
//	FROM users
//
// L008 - Comma Placement (Trailing):
//
//	-- Bad (leading commas when trailing expected)
//	SELECT
//	    user_id
//	    , username       <- Comma at start
//	FROM users
//
//	-- Good (trailing)
//	SELECT
//	    user_id,
//	    username
//	FROM users
//
// L009 - Aliasing Consistency:
//
//	-- Bad (mixing aliases and full names)
//	SELECT u.name, orders.total
//	FROM users u
//	JOIN orders ON users.id = orders.user_id
//	                ^^^^^^                      <- Using full table name instead of alias
//
//	-- Good (consistent aliases)
//	SELECT u.name, o.total
//	FROM users u
//	JOIN orders o ON u.id = o.user_id
package style
