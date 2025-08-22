package main

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/parser"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// Comprehensive Race Detection Test Suite for GoSQLX
// Run with: go test -race -timeout 60s -v race_detection_comprehensive_test.go

// Test concurrent tokenizer usage across multiple goroutines
func TestConcurrentTokenizerUsage(t *testing.T) {
	const numGoroutines = 100
	const operationsPerGoroutine = 50
	
	var wg sync.WaitGroup
	var successCount int64
	var errorCount int64
	
	// Test SQL queries of varying complexity
	testQueries := []string{
		"SELECT id, name FROM users WHERE age > 18",
		"SELECT u.id, u.name, COUNT(o.id) as order_count FROM users u LEFT JOIN orders o ON u.id = o.user_id GROUP BY u.id, u.name HAVING COUNT(o.id) > 5",
		"INSERT INTO products (name, price, category) VALUES ('Test Product', 19.99, 'Electronics')",
		"UPDATE users SET last_login = NOW() WHERE id = 123",
		"DELETE FROM logs WHERE created_at < '2023-01-01'",
		"CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
		"ALTER TABLE users ADD COLUMN email VARCHAR(255) UNIQUE",
		"WITH RECURSIVE category_tree AS (SELECT id, name, parent_id FROM categories WHERE parent_id IS NULL UNION ALL SELECT c.id, c.name, c.parent_id FROM categories c JOIN category_tree ct ON c.parent_id = ct.id) SELECT * FROM category_tree",
	}

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			
			for j := 0; j < operationsPerGoroutine; j++ {
				// Get tokenizer from pool
				tkz := tokenizer.GetTokenizer()
				
				// Use different query for each operation
				query := testQueries[(goroutineID*operationsPerGoroutine+j)%len(testQueries)]
				
				// Tokenize
				tokens, err := tkz.Tokenize([]byte(query))
				if err != nil {
					atomic.AddInt64(&errorCount, 1)
					t.Errorf("Goroutine %d, Operation %d: Tokenization failed: %v", goroutineID, j, err)
				} else if len(tokens) == 0 {
					atomic.AddInt64(&errorCount, 1)
					t.Errorf("Goroutine %d, Operation %d: No tokens produced", goroutineID, j)
				} else {
					atomic.AddInt64(&successCount, 1)
				}
				
				// Return tokenizer to pool
				tokenizer.PutTokenizer(tkz)
				
				// Small delay to increase chance of race conditions
				if j%10 == 0 {
					runtime.Gosched()
				}
			}
		}(i)
	}
	
	wg.Wait()
	
	totalOperations := int64(numGoroutines * operationsPerGoroutine)
	t.Logf("Concurrent tokenizer test completed:")
	t.Logf("  Total operations: %d", totalOperations)
	t.Logf("  Successful: %d", successCount)
	t.Logf("  Errors: %d", errorCount)
	t.Logf("  Success rate: %.2f%%", float64(successCount)/float64(totalOperations)*100)
	
	if errorCount > 0 {
		t.Errorf("Found %d errors out of %d operations", errorCount, totalOperations)
	}
}

// Test concurrent parser usage with token conversion
func TestConcurrentParserUsage(t *testing.T) {
	const numGoroutines = 50
	const operationsPerGoroutine = 20
	
	var wg sync.WaitGroup
	var successCount int64
	var errorCount int64
	
	// Test SQL statements for parsing
	testStatements := []string{
		"SELECT * FROM users",
		"SELECT id, name, email FROM users WHERE status = 'active'",
		"INSERT INTO logs (message, level, created_at) VALUES ('Test message', 'INFO', NOW())",
		"UPDATE users SET email = 'new@email.com' WHERE id = 1",
		"DELETE FROM temp_data WHERE created_at < DATE_SUB(NOW(), INTERVAL 1 DAY)",
	}

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			
			for j := 0; j < operationsPerGoroutine; j++ {
				// Get tokenizer and create parser
				tkz := tokenizer.GetTokenizer()
				p := parser.NewParser()
				
				// Use different statement for each operation
				statement := testStatements[(goroutineID*operationsPerGoroutine+j)%len(testStatements)]
				
				// Tokenize
				tokens, err := tkz.Tokenize([]byte(statement))
				if err != nil {
					atomic.AddInt64(&errorCount, 1)
					tokenizer.PutTokenizer(tkz)
					p.Release()
					continue
				}
				
				// Convert to parser tokens
				parserTokens := make([]token.Token, len(tokens))
				for k, t := range tokens {
					parserTokens[k] = token.Token{
						Type:    token.Type(t.Token.Value), // Use token value as type
						Literal: t.Token.Value,
					}
				}
				
				// Parse
				astResult, err := p.Parse(parserTokens)
				if err != nil {
					atomic.AddInt64(&errorCount, 1)
					t.Errorf("Goroutine %d, Operation %d: Parsing failed: %v", goroutineID, j, err)
				} else if astResult == nil || len(astResult.Statements) == 0 {
					atomic.AddInt64(&errorCount, 1)
					t.Errorf("Goroutine %d, Operation %d: No AST statements produced", goroutineID, j)
				} else {
					atomic.AddInt64(&successCount, 1)
					// Release AST back to pool
					ast.ReleaseAST(astResult)
				}
				
				// Clean up
				tokenizer.PutTokenizer(tkz)
				p.Release()
				
				// Yield occasionally
				if j%5 == 0 {
					runtime.Gosched()
				}
			}
		}(i)
	}
	
	wg.Wait()
	
	totalOperations := int64(numGoroutines * operationsPerGoroutine)
	t.Logf("Concurrent parser test completed:")
	t.Logf("  Total operations: %d", totalOperations)
	t.Logf("  Successful: %d", successCount)
	t.Logf("  Errors: %d", errorCount)
	t.Logf("  Success rate: %.2f%%", float64(successCount)/float64(totalOperations)*100)
	
	if errorCount > 0 {
		t.Errorf("Found %d errors out of %d operations", errorCount, totalOperations)
	}
}

// Test object pool behavior under concurrent stress
func TestConcurrentPoolStress(t *testing.T) {
	const numGoroutines = 200
	const operationsPerGoroutine = 100
	const testDuration = 5 * time.Second
	
	var wg sync.WaitGroup
	var totalOperations int64
	var poolGetOperations int64
	var poolPutOperations int64
	
	ctx, cancel := context.WithTimeout(context.Background(), testDuration)
	defer cancel()

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			
			for j := 0; j < operationsPerGoroutine; j++ {
				select {
				case <-ctx.Done():
					return
				default:
				}
				
				// Test AST pool
				astObj := ast.NewAST()
				atomic.AddInt64(&poolGetOperations, 1)
				
				// Do some work with the AST
				astObj.Statements = make([]ast.Statement, 0, 1)
				
				// Return to pool
				ast.ReleaseAST(astObj)
				atomic.AddInt64(&poolPutOperations, 1)
				
				// Test tokenizer pool
				tkz := tokenizer.GetTokenizer()
				atomic.AddInt64(&poolGetOperations, 1)
				
				// Use the tokenizer briefly
				_, _ = tkz.Tokenize([]byte("SELECT 1"))
				
				// Return to pool
				tokenizer.PutTokenizer(tkz)
				atomic.AddInt64(&poolPutOperations, 1)
				
				atomic.AddInt64(&totalOperations, 1)
				
				// Yield control occasionally to increase contention
				if j%20 == 0 {
					runtime.Gosched()
				}
			}
		}(i)
	}
	
	wg.Wait()
	
	t.Logf("Concurrent pool stress test completed:")
	t.Logf("  Total operations: %d", totalOperations)
	t.Logf("  Pool get operations: %d", poolGetOperations)
	t.Logf("  Pool put operations: %d", poolPutOperations)
	t.Logf("  Pool balance: %d", poolGetOperations - poolPutOperations)
	
	// Pool operations should be balanced
	if poolGetOperations != poolPutOperations {
		t.Errorf("Pool operations not balanced: %d gets vs %d puts", poolGetOperations, poolPutOperations)
	}
}

// Test concurrent access to shared resources with context cancellation
func TestConcurrentWithCancellation(t *testing.T) {
	const numGoroutines = 50
	const maxOperations = 1000
	
	var wg sync.WaitGroup
	var completedOperations int64
	var cancelledOperations int64
	
	// Create a context that will be cancelled partway through
	ctx, cancel := context.WithCancel(context.Background())
	
	// Cancel after a short time to test cleanup
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(goroutineID int) {
			defer wg.Done()
			
			for j := 0; j < maxOperations; j++ {
				select {
				case <-ctx.Done():
					atomic.AddInt64(&cancelledOperations, 1)
					return
				default:
				}
				
				// Get resources
				tkz := tokenizer.GetTokenizer()
				astObj := ast.NewAST()
				
				// Simulate some work
				query := fmt.Sprintf("SELECT %d FROM test_table WHERE id = %d", j, goroutineID)
				tokens, err := tkz.Tokenize([]byte(query))
				if err == nil && len(tokens) > 0 {
					// Success - clean up properly
					atomic.AddInt64(&completedOperations, 1)
				}
				
				// Always clean up resources
				tokenizer.PutTokenizer(tkz)
				ast.ReleaseAST(astObj)
			}
		}(i)
	}
	
	wg.Wait()
	
	t.Logf("Concurrent cancellation test completed:")
	t.Logf("  Completed operations: %d", completedOperations)
	t.Logf("  Cancelled operations: %d", cancelledOperations)
	t.Logf("  Total goroutines: %d", numGoroutines)
	
	// Verify that some operations completed before cancellation
	if completedOperations == 0 {
		t.Error("No operations completed - test setup may be incorrect")
	}
	
	// Verify that cancellation occurred
	if cancelledOperations == 0 {
		t.Error("No operations were cancelled - cancellation may not be working")
	}
}

// Test memory stability under concurrent load
func TestMemoryStabilityUnderLoad(t *testing.T) {
	const testDuration = 3 * time.Second
	const numWorkers = 20
	
	var wg sync.WaitGroup
	var totalOperations int64
	
	ctx, cancel := context.WithTimeout(context.Background(), testDuration)
	defer cancel()
	
	// Record initial memory stats
	var m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m1)
	
	// Start workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			
			queries := []string{
				"SELECT * FROM users WHERE id = ?",
				"INSERT INTO logs (message) VALUES (?)",
				"UPDATE users SET last_seen = NOW() WHERE id = ?",
				"DELETE FROM temp WHERE created_at < ?",
				"SELECT COUNT(*) FROM orders WHERE status = 'pending'",
			}
			
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				
				// Process a query
				query := queries[atomic.LoadInt64(&totalOperations) % int64(len(queries))]
				
				tkz := tokenizer.GetTokenizer()
				tokens, err := tkz.Tokenize([]byte(query))
				if err == nil && len(tokens) > 0 {
					// Convert and parse
					parserTokens := make([]token.Token, len(tokens))
					for j, t := range tokens {
						parserTokens[j] = token.Token{
							Type:    token.Type(t.Token.Value),
							Literal: t.Token.Value,
						}
					}
					
					p := parser.NewParser()
					astResult, err := p.Parse(parserTokens)
					if err == nil && astResult != nil {
						ast.ReleaseAST(astResult)
					}
					p.Release()
				}
				tokenizer.PutTokenizer(tkz)
				
				atomic.AddInt64(&totalOperations, 1)
			}
		}(i)
	}
	
	wg.Wait()
	
	// Force garbage collection and read final memory stats
	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	
	// Calculate memory usage difference
	allocDiff := int64(m2.TotalAlloc - m1.TotalAlloc)
	sysDiff := int64(m2.Sys - m1.Sys)
	
	t.Logf("Memory stability test completed:")
	t.Logf("  Total operations: %d", totalOperations)
	t.Logf("  Operations per second: %.0f", float64(totalOperations)/testDuration.Seconds())
	t.Logf("  Total alloc difference: %d bytes", allocDiff)
	t.Logf("  System memory difference: %d bytes", sysDiff)
	t.Logf("  Bytes per operation: %.2f", float64(allocDiff)/float64(totalOperations))
	
	// Check for reasonable memory usage
	bytesPerOp := float64(allocDiff) / float64(totalOperations)
	if bytesPerOp > 10000 { // More than 10KB per operation seems excessive
		t.Errorf("High memory usage per operation: %.2f bytes", bytesPerOp)
	}
	
	if totalOperations < 1000 {
		t.Error("Too few operations completed - performance may be degraded")
	}
}

// Benchmark concurrent tokenizer performance
func BenchmarkConcurrentTokenizer(b *testing.B) {
	query := []byte("SELECT u.id, u.name, COUNT(o.id) as order_count FROM users u LEFT JOIN orders o ON u.id = o.user_id WHERE u.status = 'active' AND o.created_at > '2023-01-01' GROUP BY u.id, u.name HAVING COUNT(o.id) > 5 ORDER BY order_count DESC LIMIT 100")
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tkz := tokenizer.GetTokenizer()
			tokens, err := tkz.Tokenize(query)
			if err != nil {
				b.Error(err)
			}
			if len(tokens) == 0 {
				b.Error("No tokens produced")
			}
			tokenizer.PutTokenizer(tkz)
		}
	})
}

// Benchmark concurrent parser performance
func BenchmarkConcurrentParser(b *testing.B) {
	// Pre-tokenize the query
	tkz := tokenizer.GetTokenizer()
	tokens, err := tkz.Tokenize([]byte("SELECT id, name FROM users WHERE status = 'active' ORDER BY created_at DESC"))
	tokenizer.PutTokenizer(tkz)
	
	if err != nil {
		b.Fatal(err)
	}
	
	parserTokens := make([]token.Token, len(tokens))
	for i, t := range tokens {
		parserTokens[i] = token.Token{
			Type:    token.Type(t.Token.Value),
			Literal: t.Token.Value,
		}
	}
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			p := parser.NewParser()
			astResult, err := p.Parse(parserTokens)
			if err != nil {
				b.Error(err)
			}
			if astResult != nil {
				ast.ReleaseAST(astResult)
			}
			p.Release()
		}
	})
}

// Test runner function
func main() {
	fmt.Println("🔍 GoSQLX Comprehensive Race Detection Test Suite")
	fmt.Println("================================================")
	fmt.Println("⚠️  IMPORTANT: Run with 'go test -race -timeout 60s -v race_detection_comprehensive_test.go'")
	fmt.Println("   This test suite is designed to detect race conditions and validate thread safety.")
	fmt.Println()
}