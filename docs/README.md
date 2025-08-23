# GoSQLX Documentation

Comprehensive documentation for the GoSQLX SQL parsing SDK.

## 📚 Documentation Index

### Core Documentation

| Document | Description | Audience |
|----------|-------------|----------|
| [**API_REFERENCE.md**](API_REFERENCE.md) | Complete API documentation with method signatures, parameters, and examples | Developers |
| [**USAGE_GUIDE.md**](USAGE_GUIDE.md) | Detailed usage patterns, best practices, and real-world examples | All Users |
| [**ARCHITECTURE.md**](ARCHITECTURE.md) | System design, component architecture, and internal implementation | Contributors/Advanced |
| [**TROUBLESHOOTING.md**](TROUBLESHOOTING.md) | Common issues, error messages, debugging techniques, and FAQ | Support/Debug |

### Deployment & Operations

| Document | Description | Audience |
|----------|-------------|----------|
| [**PRODUCTION_GUIDE.md**](PRODUCTION_GUIDE.md) | Production deployment, monitoring, and performance optimization | DevOps/SRE |
| [**SQL_COMPATIBILITY.md**](SQL_COMPATIBILITY.md) | SQL dialect support matrix and feature compatibility | Architects |
| [**SECURITY.md**](SECURITY.md) | Security analysis, vulnerability assessment, and best practices | Security Teams |

### Release Information

| Document | Description | Version |
|----------|-------------|---------|
| [**RELEASE_v1.0.md**](RELEASE_v1.0.md) | v1.0.0 release notes, features, and validation results | v1.0.0 |

## 🚀 Quick Start Guides

### For New Users
1. Start with [USAGE_GUIDE.md](USAGE_GUIDE.md) - Basic usage patterns
2. Review [Examples](../examples/) - Working code samples
3. Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md#faq) - Common questions

### For Developers
1. Read [API_REFERENCE.md](API_REFERENCE.md) - Complete API docs
2. Study [ARCHITECTURE.md](ARCHITECTURE.md) - System design
3. Review [USAGE_GUIDE.md](USAGE_GUIDE.md#advanced-patterns) - Advanced patterns

### For Production Deployment
1. Follow [PRODUCTION_GUIDE.md](PRODUCTION_GUIDE.md) - Deployment guide
2. Review [SECURITY.md](SECURITY.md) - Security considerations
3. Check [SQL_COMPATIBILITY.md](SQL_COMPATIBILITY.md) - Dialect support

## 📖 Documentation Structure

```
docs/
├── API_REFERENCE.md        # API documentation
├── USAGE_GUIDE.md          # Usage patterns and examples
├── ARCHITECTURE.md         # System architecture
├── TROUBLESHOOTING.md      # Problem solving guide
├── PRODUCTION_GUIDE.md     # Production deployment
├── SQL_COMPATIBILITY.md    # SQL dialect matrix
├── SECURITY.md            # Security analysis
├── RELEASE_v1.0.md        # Release notes
└── README.md              # This file
```

## 🔍 Finding Information

### By Topic

**Installation & Setup**
- [Installation](USAGE_GUIDE.md#installation)
- [Prerequisites](PRODUCTION_GUIDE.md#prerequisites)
- [Quick Start](../README.md#-quick-start)

**Basic Usage**
- [Simple Tokenization](USAGE_GUIDE.md#simple-tokenization)
- [Parsing to AST](USAGE_GUIDE.md#parsing-to-ast)
- [Error Handling](USAGE_GUIDE.md#error-handling-with-position-info)

**Advanced Topics**
- [Concurrent Processing](USAGE_GUIDE.md#concurrent-processing)
- [Memory Optimization](ARCHITECTURE.md#memory-optimization-strategies)
- [Performance Tuning](PRODUCTION_GUIDE.md#performance-optimization)

**Troubleshooting**
- [Common Issues](TROUBLESHOOTING.md#common-issues)
- [Error Messages](TROUBLESHOOTING.md#error-messages)
- [FAQ](TROUBLESHOOTING.md#faq)

**SQL Dialects**
- [PostgreSQL](USAGE_GUIDE.md#postgresql-specific-features)
- [MySQL](USAGE_GUIDE.md#mysql-specific-features)
- [SQL Server](USAGE_GUIDE.md#sql-server-specific-features)
- [Oracle](USAGE_GUIDE.md#oracle-specific-features)

### By Use Case

**"I want to tokenize SQL"**
→ See [USAGE_GUIDE.md#simple-tokenization](USAGE_GUIDE.md#simple-tokenization)

**"I want to parse SQL to AST"**
→ See [USAGE_GUIDE.md#parsing-to-ast](USAGE_GUIDE.md#parsing-to-ast)

**"I want to validate SQL syntax"**
→ See [USAGE_GUIDE.md#sql-validator](USAGE_GUIDE.md#sql-validator)

**"I want to support Unicode SQL"**
→ See [USAGE_GUIDE.md#unicode-and-international-support](USAGE_GUIDE.md#unicode-and-international-support)

**"I'm getting an error"**
→ See [TROUBLESHOOTING.md#error-messages](TROUBLESHOOTING.md#error-messages)

**"My application is slow"**
→ See [TROUBLESHOOTING.md#performance-issues](TROUBLESHOOTING.md#performance-issues)

**"I found a memory leak"**
→ See [TROUBLESHOOTING.md#memory-leaks](TROUBLESHOOTING.md#memory-leaks)

## 📊 Coverage Matrix

| Topic | API Ref | Usage | Architecture | Troubleshooting | Production |
|-------|---------|-------|--------------|-----------------|------------|
| Installation | ✓ | ✓ | | | ✓ |
| Basic Usage | ✓ | ✓ | | ✓ | |
| Advanced Patterns | ✓ | ✓ | ✓ | | ✓ |
| Error Handling | ✓ | ✓ | | ✓ | |
| Performance | | ✓ | ✓ | ✓ | ✓ |
| Memory Management | ✓ | ✓ | ✓ | ✓ | ✓ |
| Concurrency | ✓ | ✓ | ✓ | ✓ | |
| SQL Dialects | | ✓ | | ✓ | |
| Unicode Support | | ✓ | | ✓ | |
| Debugging | | | | ✓ | |
| Monitoring | | | | | ✓ |
| Security | | | | | ✓ |

## 💡 Contributing to Documentation

We welcome documentation improvements! To contribute:

1. **Fix Typos/Errors**: Direct PRs welcome
2. **Add Examples**: Include working code samples
3. **Improve Clarity**: Simplify complex explanations
4. **Add Diagrams**: Visual representations help
5. **Update for Changes**: Keep docs in sync with code

### Documentation Standards

- Use clear, concise language
- Include code examples for all features
- Provide both simple and advanced examples
- Cross-reference related documentation
- Keep formatting consistent
- Test all code examples

## 📞 Getting Help

If you can't find what you need:

1. **Search**: Use GitHub's search in the repository
2. **Issues**: Check [existing issues](https://github.com/ajitpratap0/GoSQLX/issues)
3. **Ask**: Open a [new issue](https://github.com/ajitpratap0/GoSQLX/issues/new)
4. **Discuss**: Join [discussions](https://github.com/ajitpratap0/GoSQLX/discussions)

## 🔄 Documentation Updates

| Document | Last Updated | Version |
|----------|--------------|---------|
| API_REFERENCE.md | 2024-08 | v1.0.0 |
| USAGE_GUIDE.md | 2024-08 | v1.0.0 |
| ARCHITECTURE.md | 2024-08 | v1.0.0 |
| TROUBLESHOOTING.md | 2024-08 | v1.0.0 |
| PRODUCTION_GUIDE.md | 2024-08 | v1.0.0 |
| SQL_COMPATIBILITY.md | 2024-08 | v1.0.0 |
| SECURITY.md | 2024-08 | v1.0.0 |

---

*For the main project documentation, see the [root README](../README.md)*