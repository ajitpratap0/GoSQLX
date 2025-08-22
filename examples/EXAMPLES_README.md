# GoSQLX Examples Documentation

This directory contains comprehensive examples demonstrating all aspects of the GoSQLX SQL tokenization library. Each example is designed to be both educational and practical, showing real-world usage patterns and best practices.

## 📚 Example Overview

### Core Examples
- **[Original Example](cmd/example.go)** - Basic Unicode tokenization demonstration
- **[Basic Operations](basic_operations_example.go)** - Comprehensive SQL operations (SELECT, INSERT, UPDATE, DELETE)
- **[Complex Queries](complex_queries_example.go)** - Advanced SQL features (JOINs, subqueries, CTEs, window functions)
- **[DDL Examples](ddl_examples.go)** - Data Definition Language statements (CREATE, ALTER, DROP)

### International Support
- **[International SQL](international_sql_example.go)** - Multi-language SQL support (Chinese, Arabic, Japanese, Korean, etc.)

### Production Readiness
- **[Error Handling](error_handling_example.go)** - Comprehensive error handling and recovery patterns
- **[Concurrent Usage](concurrent_usage_example.go)** - Thread-safe concurrent usage patterns
- **[Memory Management](memory_management_example.go)** - Resource pooling and memory optimization
- **[Production Usage](production_usage_example.go)** - Production-ready patterns and monitoring

### Test Infrastructure
- **[Example Test Runner](run_all_examples.go)** - Comprehensive test suite for all examples

## 🚀 Quick Start

### Running Individual Examples

```bash
# Basic operations
go run basic_operations_example.go

# Complex queries
go run complex_queries_example.go

# Error handling patterns
go run error_handling_example.go

# Production usage patterns
go run production_usage_example.go
```

### Running All Examples

```bash
# Run comprehensive test suite
go run run_all_examples.go
```

### Original Example Tests

```bash
cd cmd/
go run example.go
go test -v example_test.go
```

## 🛠️ Example Categories

### 1. Basic Usage (🔰 Getting Started)

**Original Example** - Start here for basic understanding
- Unicode character support
- Basic resource management
- Simple error handling

**Basic Operations** - Core SQL operations
- SELECT, INSERT, UPDATE, DELETE
- Performance measurements
- Token analysis

### 2. Advanced Features (🚀 Advanced)

**Complex Queries** - Advanced SQL constructs
- Common Table Expressions (CTEs)
- Window functions
- Nested subqueries
- Multi-table JOINs
- Complex aggregations

**DDL Examples** - Schema operations
- Table creation with constraints
- Index management
- View definitions
- Trigger and procedure creation

### 3. International Support (🌍 Unicode)

**International SQL** - Multi-language support
- Japanese (Hiragana, Katakana, Kanji)
- Chinese (Simplified/Traditional)
- Arabic (RTL text)
- Russian (Cyrillic)
- Korean (Hangul)
- Hindi (Devanagari)
- Greek alphabet
- Emoji and symbols

### 4. Reliability (🛡️ Error Handling)

**Error Handling** - Comprehensive error management
- Syntax error detection
- Unicode error handling
- Recovery patterns
- Graceful degradation
- Detailed error reporting

**Memory Management** - Resource optimization
- Pool vs non-pool comparison
- Memory leak detection
- Large query processing
- Garbage collection analysis

### 5. Performance (⚡ High Performance)

**Concurrent Usage** - Thread-safe patterns
- Basic concurrency
- High-load stress testing
- Worker pool patterns
- Pipeline processing
- Resource contention handling

**Production Usage** - Production-ready patterns
- Web server request handling
- Background worker processing
- High-throughput API services
- Database migration tools
- Comprehensive monitoring

## 📊 Performance Characteristics

### Typical Performance Metrics

| Example Category | Avg Tokens/Query | Throughput (ops/sec) | Memory Usage |
|------------------|------------------|---------------------|--------------|
| Basic Operations | 42.7            | 82K - 648K          | Low          |
| Complex Queries  | 209.5           | 6 - 962K            | Medium       |
| DDL Examples     | 183.0           | 103 - 1944          | Medium       |
| International    | 133.4           | 68K - 208K          | Low-Medium   |
| Error Handling   | Varies          | 6 - 963K            | Low          |
| Concurrent Usage | Varies          | 374 - 773K          | Medium-High  |
| Production       | Varies          | 1.9K - 89K          | Medium       |

### Memory Usage Patterns
- **Resource Pooling**: Efficient memory usage with object pools
- **Large Queries**: Handles 50K+ field queries efficiently
- **Concurrent Load**: Stable memory usage under high concurrency
- **International Text**: Minimal overhead for Unicode processing

## 🔧 Usage Patterns

### Resource Management Pattern
```go
func processSQL(query string) ([]models.TokenWithSpan, error) {
    // Always get from pool
    t := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(t) // Always return to pool
    
    // Process query
    tokens, err := t.Tokenize([]byte(query))
    if err != nil {
        return nil, fmt.Errorf("tokenization failed: %v", err)
    }
    
    return tokens, nil
}
```

### Error Handling Pattern
```go
func robustTokenization(query string) ([]models.TokenWithSpan, error) {
    const maxRetries = 3
    
    for retry := 0; retry < maxRetries; retry++ {
        t := tokenizer.GetTokenizer()
        tokens, err := t.Tokenize([]byte(query))
        tokenizer.PutTokenizer(t)
        
        if err == nil {
            return tokens, nil
        }
        
        // Handle specific error types
        if strings.Contains(err.Error(), "unterminated") {
            return nil, fmt.Errorf("syntax error: %v", err)
        }
        
        // Retry for transient errors
        if retry < maxRetries-1 {
            time.Sleep(time.Duration(retry+1) * 100 * time.Millisecond)
        }
    }
    
    return nil, fmt.Errorf("all retries exhausted")
}
```

### Concurrent Usage Pattern
```go
func processConcurrently(queries []string) error {
    const numWorkers = runtime.NumCPU()
    jobs := make(chan string, len(queries))
    results := make(chan error, len(queries))
    
    // Start workers
    var wg sync.WaitGroup
    for i := 0; i < numWorkers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for query := range jobs {
                t := tokenizer.GetTokenizer()
                _, err := t.Tokenize([]byte(query))
                tokenizer.PutTokenizer(t)
                results <- err
            }
        }()
    }
    
    // Send jobs
    go func() {
        defer close(jobs)
        for _, query := range queries {
            jobs <- query
        }
    }()
    
    // Wait and collect results
    go func() {
        wg.Wait()
        close(results)
    }()
    
    for err := range results {
        if err != nil {
            return err
        }
    }
    
    return nil
}
```

## 🎯 Choosing the Right Example

### For Learning
1. **Start with**: Original Example (cmd/example.go)
2. **Next**: Basic Operations Example
3. **Then**: Complex Queries or DDL Examples
4. **Advanced**: International SQL, Error Handling

### For Production Integration
1. **Error Handling Example** - Implement robust error management
2. **Memory Management Example** - Optimize resource usage
3. **Concurrent Usage Example** - Handle high-load scenarios
4. **Production Usage Example** - Complete production patterns

### For Specific Use Cases

| Use Case | Recommended Examples |
|----------|---------------------|
| Web API Backend | Production Usage, Concurrent Usage, Error Handling |
| Database Migration Tool | DDL Examples, Error Handling, Memory Management |
| Query Analysis Service | Complex Queries, International SQL, Production Usage |
| ETL Pipeline | Basic Operations, Concurrent Usage, Memory Management |
| International Application | International SQL, Error Handling |
| High-Performance Service | Concurrent Usage, Memory Management, Production Usage |

## 🐛 Troubleshooting

### Common Issues

**Memory Growth**
- Ensure proper use of `tokenizer.GetTokenizer()` / `tokenizer.PutTokenizer()`
- Check Memory Management Example for patterns
- Monitor GC behavior in production

**Performance Issues**
- Use worker pools for high concurrency (see Concurrent Usage Example)
- Implement proper error handling to avoid retries
- Consider query complexity and size limits

**Unicode Handling**
- See International SQL Example for multi-language support
- Check Error Handling Example for Unicode-specific error cases
- Ensure proper character encoding in your application

**Error Handling**
- Implement comprehensive error categorization
- Use circuit breakers for fault tolerance
- See Error Handling Example for patterns

### Performance Tuning

**For High Throughput**
- Use worker pools with bounded concurrency
- Implement connection pooling properly
- Monitor memory usage and GC behavior
- Set appropriate timeouts and circuit breakers

**For Large Queries**
- Test with realistic query sizes
- Monitor memory allocation patterns
- Consider streaming for very large inputs
- Set reasonable limits on query complexity

**For International Text**
- Test with actual multi-language data
- Monitor Unicode processing overhead
- Handle RTL text appropriately
- Consider normalization requirements

## 📈 Testing and Validation

### Running Tests
```bash
# Run all examples with validation
go run run_all_examples.go

# Run specific example tests
cd cmd/
go test -v example_test.go

# Run with benchmarks
go test -bench=. -benchmem ./...
```

### Performance Benchmarking
```bash
# Tokenizer benchmarks
go test -bench=BenchmarkTokenizer ./pkg/sql/tokenizer/

# Parser benchmarks  
go test -bench=BenchmarkParser ./pkg/sql/parser/

# Memory profiling
go test -memprofile=mem.prof -bench=. ./pkg/sql/tokenizer/
go tool pprof mem.prof
```

### Validation Criteria
- All examples should run without errors
- Performance should meet expected benchmarks
- Memory usage should be stable over time
- International text should be handled correctly
- Error conditions should be handled gracefully

## 🔗 Related Documentation

- [Main README](../README.md) - Project overview and setup
- [CLAUDE.md](../CLAUDE.md) - Project architecture and development guide
- [Package Documentation](../pkg/) - API reference
- [Test Reports](../test-results/) - Automated test results

## 🤝 Contributing

When adding new examples:

1. Follow existing naming conventions
2. Include comprehensive error handling
3. Add performance measurements
4. Test with realistic data
5. Document usage patterns
6. Update this README

### Example Template
```go
package main

import (
    "fmt"
    "time"
    "github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

func YourExample() {
    fmt.Println("Your Example Description")
    
    // Always use proper resource management
    t := tokenizer.GetTokenizer()
    defer tokenizer.PutTokenizer(t)
    
    // Process your SQL
    query := `YOUR SQL HERE`
    start := time.Now()
    tokens, err := t.Tokenize([]byte(query))
    duration := time.Since(start)
    
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }
    
    fmt.Printf("Success: %d tokens in %v\n", len(tokens), duration)
}

func main() {
    YourExample()
}
```

---

**Note**: All examples are designed to be self-contained and can be run independently. They demonstrate production-ready patterns and best practices for using GoSQLX in real-world applications.