# Contributing to GoSQLX

Thank you for your interest in contributing to GoSQLX! This document provides comprehensive guidelines for contributing to the project.

## 🎯 Project Mission

GoSQLX aims to be the **fastest, most reliable, and most comprehensive SQL parsing library for Go**, suitable for production use in enterprise environments.

## 🤝 Ways to Contribute

### 1. Code Contributions
- **Bug fixes**: Resolve issues in tokenization, parsing, or performance
- **Feature development**: Implement new SQL dialect support or optimizations
- **Performance improvements**: Optimize hot paths and memory usage
- **Test coverage**: Add comprehensive tests for edge cases

### 2. Documentation
- **API documentation**: Improve godoc coverage and examples
- **Tutorials**: Create guides for specific use cases
- **Performance guides**: Document optimization techniques
- **Integration examples**: Add real-world usage examples

### 3. Testing & Quality Assurance
- **Bug reports**: Report issues with detailed reproduction steps
- **Performance testing**: Benchmark new features and optimizations
- **Security testing**: Identify potential vulnerabilities
- **Compatibility testing**: Test across different Go versions and platforms

### 4. Community Support
- **Answer questions**: Help users in GitHub Issues and Discussions
- **Code reviews**: Review pull requests from other contributors
- **Feature discussions**: Participate in RFC discussions for new features

---

## 🛠️ Development Setup

### Prerequisites
- **Go 1.19+** (latest stable version recommended)
- **Git** for version control
- **Task** for task automation (optional) - Install with `go install github.com/go-task/task/v3/cmd/task@latest`

### Getting Started
```bash
# 1. Fork the repository on GitHub
# 2. Clone your fork
git clone https://github.com/YOUR_USERNAME/GoSQLX.git
cd GoSQLX

# 3. Add upstream remote
git remote add upstream https://github.com/ajitpratap0/GoSQLX.git

# 4. Install dependencies
go mod download

# 5. Run tests to verify setup
go test ./...

# 6. Run tests with race detection (REQUIRED)
go test -race ./...

# 7. Install Git hooks (RECOMMENDED)
task hooks:install
# or
./scripts/install-hooks.sh
```

### Installing Git Hooks

GoSQLX provides pre-commit hooks to catch code quality issues before they reach CI/CD:

```bash
# Install hooks using Task
task hooks:install

# Or run the script directly
./scripts/install-hooks.sh
```

The pre-commit hooks automatically run:
- **go fmt**: Checks code formatting
- **go vet**: Performs static analysis
- **go test -short**: Runs tests in short mode

To bypass hooks (not recommended):
```bash
git commit --no-verify
```

### Development Workflow
```bash
# 1. Create a feature branch
git checkout -b feature/your-feature-name

# 2. Make your changes
# ... edit files ...

# 3. Run tests frequently
go test -race ./...

# 4. Run linting and formatting
go fmt ./...
go vet ./...

# 5. Commit your changes
git add .
git commit -m "feat: add support for PostgreSQL JSON operators"

# 6. Push to your fork
git push origin feature/your-feature-name

# 7. Create a Pull Request
```

---

## 📋 Contribution Guidelines

### Code Quality Standards

#### 🔍 Testing Requirements
- **100% test coverage** for new code (use `go test -cover`)
- **Race detection** must pass: `go test -race ./...`
- **Performance tests** for optimization changes
- **Integration tests** for new SQL features

```go
// Example: Comprehensive test structure
func TestNewFeature(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected interface{}
        wantErr  bool
    }{
        {"valid case", "SELECT * FROM users", expectedTokens, false},
        {"edge case", "", nil, true},
        {"unicode", "SELECT 名前 FROM ユーザー", expectedUnicodeTokens, false},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}

// Benchmark for performance-sensitive code
func BenchmarkNewFeature(b *testing.B) {
    for i := 0; i < b.N; i++ {
        // Benchmark implementation
    }
}
```

#### 📝 Code Style
- **Go fmt**: All code must be formatted with `go fmt`
- **Go vet**: Must pass `go vet` without warnings
- **Golint**: Follow Go naming conventions
- **Comments**: Public functions require godoc comments

```go
// ✅ GOOD: Proper function documentation
// TokenizeSQL parses the provided SQL query and returns a slice of tokens.
// It supports multiple SQL dialects and provides detailed error information.
//
// The input must be valid UTF-8. Large queries (>1MB) may impact performance.
//
// Example:
//   tokens, err := TokenizeSQL([]byte("SELECT * FROM users"))
//   if err != nil {
//       return fmt.Errorf("tokenization failed: %w", err)
//   }
func TokenizeSQL(sql []byte) ([]Token, error) {
    // Implementation
}

// ❌ BAD: Missing documentation
func TokenizeSQL(sql []byte) ([]Token, error) {
    // Implementation
}
```

#### 🔒 Security Guidelines
- **Input validation**: Always validate external input
- **Memory safety**: Use Go's memory safety features correctly
- **Resource limits**: Implement bounds checking for large inputs
- **Error handling**: Never leak sensitive information in error messages

```go
// ✅ GOOD: Proper input validation and error handling
func ProcessSQL(sql []byte) error {
    if len(sql) > MaxSQLSize {
        return errors.New("SQL query too large")
    }
    
    if !utf8.Valid(sql) {
        return errors.New("invalid UTF-8 input")
    }
    
    // Safe processing
    return nil
}

// ❌ BAD: No input validation
func ProcessSQL(sql []byte) error {
    // Direct processing without validation
}
```

### Performance Requirements

#### ⚡ Performance Standards
- **No performance regression**: New features must not slow down existing functionality
- **Memory efficiency**: Minimize allocations in hot paths
- **Concurrency safety**: All public APIs must be thread-safe
- **Benchmarking**: Include benchmarks for performance-critical code

```go
// Example: Memory-efficient implementation
func OptimizedFunction() {
    // ✅ GOOD: Reuse objects
    tkz := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(tkz)
    
    // ❌ BAD: Creates new objects repeatedly
    // tkz := &tokenizer.Tokenizer{}
}
```

### Git Commit Guidelines

#### 📝 Commit Message Format
```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `perf`: Performance improvement
- `docs`: Documentation changes
- `test`: Adding or fixing tests
- `refactor`: Code refactoring
- `style`: Formatting changes
- `chore`: Maintenance tasks

**Examples:**
```bash
feat(tokenizer): add support for PostgreSQL JSON operators

Implement @>, @@, and #> operators for PostgreSQL JSON/JSONB data types.
Includes comprehensive tests and performance benchmarks.

Fixes #123
```

```bash
fix(parser): correct column position calculation in error messages

The error location was off by one character due to incorrect position
tracking in Unicode sequences.

Breaking change: ErrorLocation.Column now uses 1-based indexing
```

---

## 🧪 Testing Guidelines

### Test Organization
```
pkg/
├── sql/
│   ├── tokenizer/
│   │   ├── tokenizer.go
│   │   ├── tokenizer_test.go          # Unit tests
│   │   ├── integration_test.go        # Integration tests
│   │   ├── benchmark_test.go          # Performance tests
│   │   └── fuzz_test.go              # Fuzz tests
│   └── parser/
│       └── ...
└── ...
```

### Test Categories

#### 1. Unit Tests
```go
func TestTokenizerBasicFunctionality(t *testing.T) {
    tkz := tokenizer.New()
    tokens, err := tkz.Tokenize([]byte("SELECT * FROM users"))
    
    assert.NoError(t, err)
    assert.Equal(t, 6, len(tokens))
    assert.Equal(t, "SELECT", tokens[0].Value)
}
```

#### 2. Integration Tests
```go
func TestEndToEndSQLProcessing(t *testing.T) {
    // Test complete workflow from SQL input to final result
}
```

#### 3. Performance Tests
```go
func BenchmarkTokenizeComplexQuery(b *testing.B) {
    sql := generateComplexSQL(1000) // 1000 tokens
    tkz := tokenizer.New()
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := tkz.Tokenize(sql)
        if err != nil {
            b.Fatal(err)
        }
    }
}
```

#### 4. Fuzz Tests
```go
func FuzzTokenizer(f *testing.F) {
    f.Add([]byte("SELECT * FROM users"))
    f.Add([]byte(""))
    f.Add([]byte("🚀💖"))
    
    f.Fuzz(func(t *testing.T, sql []byte) {
        tkz := tokenizer.New()
        _, err := tkz.Tokenize(sql)
        // Should never panic, errors are acceptable
    })
}
```

### Test Requirements
- **Race detection**: All tests must pass with `-race` flag
- **Coverage**: New code requires >95% test coverage
- **Performance**: Benchmarks for performance-critical paths
- **Edge cases**: Test boundary conditions and error cases

---

## 🚀 Feature Development Process

### 1. RFC (Request for Comments)
For significant features, create an RFC:

```markdown
# RFC: PostgreSQL JSON Operators Support

## Summary
Add support for PostgreSQL JSON/JSONB operators (@>, @@, #>, etc.)

## Motivation
Many applications use PostgreSQL's JSON features extensively...

## Detailed Design
1. Extend tokenizer to recognize JSON operators
2. Add token types for each operator
3. Update parser grammar...

## Alternatives Considered
1. Generic operator approach...
2. Plugin-based system...

## Implementation Plan
1. Phase 1: Tokenizer changes
2. Phase 2: Parser integration
3. Phase 3: Testing and documentation
```

### 2. Implementation
- Start with comprehensive tests (TDD approach)
- Implement minimal viable feature
- Add performance optimizations
- Complete documentation

### 3. Review Process
- Self-review using the checklist below
- Request review from maintainers
- Address feedback promptly
- Ensure CI/CD passes

---

## 📋 Pull Request Checklist

### Before Submitting
- [ ] **Git Hooks**: Pre-commit hooks installed and passing (`task hooks:install`)
- [ ] **Tests**: All tests pass with `go test -race ./...`
- [ ] **Coverage**: New code has >95% test coverage
- [ ] **Performance**: No performance regression
- [ ] **Documentation**: Public APIs have godoc comments
- [ ] **Examples**: Complex features include usage examples
- [ ] **Formatting**: Code is formatted with `go fmt`
- [ ] **Linting**: Passes `go vet` and `golint`
- [ ] **Commit messages**: Follow conventional commit format
- [ ] **Security**: No security vulnerabilities introduced

### Pull Request Description Template
```markdown
## Summary
Brief description of changes

## Motivation
Why is this change needed?

## Changes
- List of specific changes
- Breaking changes (if any)

## Testing
- Unit tests added/updated
- Integration tests added/updated
- Performance testing results

## Documentation
- [ ] API documentation updated
- [ ] Examples added/updated
- [ ] CHANGELOG.md updated (if applicable)

## Security
- [ ] No sensitive information exposed
- [ ] Input validation added
- [ ] No new attack vectors introduced

## Performance
- [ ] Benchmarks show no regression
- [ ] Memory usage verified
- [ ] Concurrent safety verified
```

---

## 🐛 Bug Reports

### Issue Template
```markdown
**Bug Description**
A clear description of the bug

**Reproduction Steps**
1. Step 1
2. Step 2
3. Step 3

**Expected Behavior**
What should happen

**Actual Behavior**
What actually happens

**Environment**
- Go version: 
- GoSQLX version:
- OS:
- Architecture:

**SQL Query**
```sql
SELECT * FROM users WHERE ...
```

**Error Output**
```
Error message or stack trace
```

**Additional Context**
Any other relevant information
```

### Bug Report Guidelines
- **Minimal reproduction**: Provide the smallest possible SQL that reproduces the issue
- **Complete environment**: Include Go version, OS, and architecture
- **Error details**: Include full error messages and stack traces
- **Security**: For security issues, report privately first

---

## 🏗️ Architecture Guidelines

### Project Structure
```
GoSQLX/
├── cmd/                    # Command-line tools
├── examples/               # Integration examples
├── pkg/                    # Library code
│   ├── sql/
│   │   ├── tokenizer/     # Tokenization logic
│   │   ├── parser/        # Parsing logic
│   │   ├── ast/           # AST definitions
│   │   └── keywords/      # SQL keywords
│   ├── models/            # Data models
│   └── metrics/           # Performance metrics
├── docs/                  # Documentation
├── benchmarks/            # Performance benchmarks
└── tools/                 # Development tools
```

### Design Principles
- **Performance**: Optimize for speed and memory usage
- **Safety**: Thread-safe and memory-safe by default
- **Modularity**: Clean separation of concerns
- **Extensibility**: Easy to add new SQL dialects
- **Maintainability**: Clear, readable, and well-documented code

### Adding New Features

#### 1. SQL Dialect Support
```go
// 1. Add dialect-specific tokens
const (
    TokenTypeJSONExtract = iota + 1000 // PostgreSQL ->
    TokenTypeJSONPath                   // PostgreSQL #>
)

// 2. Extend tokenizer recognition
func (t *Tokenizer) recognizeOperator() (Token, error) {
    // Implementation
}

// 3. Add comprehensive tests
func TestPostgreSQLJSONOperators(t *testing.T) {
    // Test cases
}
```

#### 2. Performance Optimizations
```go
// 1. Add benchmarks first
func BenchmarkOptimization(b *testing.B) {
    // Baseline measurement
}

// 2. Implement optimization
func OptimizedFunction() {
    // Optimized implementation
}

// 3. Verify improvement
func BenchmarkOptimizationImproved(b *testing.B) {
    // Should show measurable improvement
}
```

---

## 📈 Performance Contribution Guidelines

### Optimization Principles
- **Measure first**: Always benchmark before optimizing
- **Profile-guided**: Use CPU and memory profiling to identify bottlenecks
- **Incremental**: Make small, measurable improvements
- **Validate**: Ensure optimizations don't break functionality

### Profiling Tools
```bash
# CPU profiling
go test -cpuprofile=cpu.prof -bench=BenchmarkFunction ./pkg/sql/tokenizer
go tool pprof cpu.prof

# Memory profiling
go test -memprofile=mem.prof -bench=BenchmarkFunction ./pkg/sql/tokenizer
go tool pprof mem.prof

# Race detection
go test -race ./...

# Escape analysis
go build -gcflags="-m -l" ./pkg/sql/tokenizer
```

### Performance Testing
```go
func BenchmarkMemoryEfficiency(b *testing.B) {
    b.ReportAllocs()
    
    for i := 0; i < b.N; i++ {
        // Code to benchmark
    }
}

func TestMemoryLeak(t *testing.T) {
    var m1, m2 runtime.MemStats
    runtime.GC()
    runtime.ReadMemStats(&m1)
    
    // Perform operations
    for i := 0; i < 10000; i++ {
        // Operations that might leak
    }
    
    runtime.GC()
    runtime.ReadMemStats(&m2)
    
    if m2.Alloc > m1.Alloc+threshold {
        t.Errorf("Memory leak detected: %d bytes", m2.Alloc-m1.Alloc)
    }
}
```

---

## 🌟 Recognition

### Contributors
All contributors are recognized in:
- **CONTRIBUTORS.md**: Comprehensive list of contributors
- **Release notes**: Major contributions highlighted
- **Git history**: All commits attributed properly

### Levels of Contribution
- **Core Maintainer**: Regular significant contributions
- **Active Contributor**: Multiple merged PRs
- **Community Helper**: Active in discussions and support
- **One-time Contributor**: Single merged PR

---

## 📞 Getting Help

### Communication Channels
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and ideas
- **Code Reviews**: In-depth technical discussions

### Mentorship
New contributors can request mentorship for:
- **First contribution**: Guidance on getting started
- **Complex features**: Architecture and design advice
- **Performance optimization**: Profiling and optimization techniques

### Office Hours
Core maintainers hold virtual office hours:
- **When**: First Friday of each month, 3 PM UTC
- **Where**: GitHub Discussions
- **Topics**: Architecture decisions, feature planning, Q&A

---

## 🎯 Contribution Goals

### Short-term (3 months)
- **50+ contributors**: Grow the contributor base
- **95% test coverage**: Maintain high code quality
- **Zero security issues**: Address any security concerns

### Medium-term (6 months)
- **Multi-language bindings**: Python, Node.js wrappers
- **IDE integrations**: VS Code extension
- **Cloud-native optimizations**: Serverless deployments

### Long-term (12 months)
- **1000+ GitHub stars**: Community recognition
- **Enterprise adoption**: Production deployments
- **Performance leadership**: Fastest SQL parser for Go

---

## 📄 Legal

### License
By contributing to GoSQLX, you agree that your contributions will be licensed under the same license as the project.

### Copyright
Contributors retain copyright of their contributions while granting the project rights to use and distribute the code.

### Code of Conduct
All contributors must follow our [Code of Conduct](CODE_OF_CONDUCT.md), which promotes:
- **Respectful communication**
- **Inclusive environment**
- **Professional behavior**
- **Constructive feedback**

---

**Thank you for contributing to GoSQLX!** 🚀

Together, we're building the future of high-performance SQL parsing in Go.

*For questions about contributing, please open a GitHub Discussion or Issue.*