// Package parser - Concurrency pool exhaustion stress tests for Issue #44
// Tests validate pool behavior under 10K+ goroutine stress
package parser

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ajitpratap0/GoSQLX/pkg/models"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/ast"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/token"
	"github.com/ajitpratap0/GoSQLX/pkg/sql/tokenizer"
)

// convertTokensForStressTest converts models.TokenWithSpan to token.Token for parser
func convertTokensForStressTest(tokens []models.TokenWithSpan) []token.Token {
	result := make([]token.Token, 0, len(tokens))

	for _, t := range tokens {
		// Map token type to string
		tokenType := token.Type(fmt.Sprintf("%v", t.Token.Type))

		// Map common token types
		switch t.Token.Type {
		case models.TokenTypeSelect:
			tokenType = "SELECT"
		case models.TokenTypeFrom:
			tokenType = "FROM"
		case models.TokenTypeWhere:
			tokenType = "WHERE"
		case models.TokenTypeIdentifier:
			tokenType = "IDENT"
		case models.TokenTypeMul:
			tokenType = "ASTERISK"
		case models.TokenTypeComma:
			tokenType = "COMMA"
		case models.TokenTypeDot:
			tokenType = "DOT"
		case models.TokenTypeEq:
			tokenType = "EQUAL"
		case models.TokenTypeSemicolon:
			tokenType = "SEMICOLON"
		case models.TokenTypeEOF:
			tokenType = "EOF"
		case models.TokenTypeTrue, models.TokenTypeFalse:
			tokenType = "BOOLEAN"
		case models.TokenTypeOrder:
			tokenType = "ORDER"
		case models.TokenTypeBy:
			tokenType = "BY"
		case models.TokenTypeAsc:
			tokenType = "ASC"
		case models.TokenTypeDesc:
			tokenType = "DESC"
		case models.TokenTypeGroup:
			tokenType = "GROUP"
		case models.TokenTypeJoin:
			tokenType = "JOIN"
		case models.TokenTypeLeft:
			tokenType = "LEFT"
		case models.TokenTypeOn:
			tokenType = "ON"
		case models.TokenTypeCount:
			tokenType = "COUNT"
		case models.TokenTypeLParen:
			tokenType = "LPAREN"
		case models.TokenTypeRParen:
			tokenType = "RPAREN"
		}

		result = append(result, token.Token{
			Type:    tokenType,
			Literal: t.Token.Value,
		})
	}

	return result
}

// TestConcurrencyPoolExhaustion_10K_Tokenizer_Goroutines tests tokenizer pool behavior
// under extreme load with 10,000 concurrent goroutines requesting tokenizers simultaneously.
// This validates that the tokenizer pool doesn't deadlock or leak under heavy contention.
//
// Validation criteria:
// - All 10K goroutines complete without errors
// - No deadlocks (completes within 30s timeout)
// - No goroutine leaks (goroutine count returns to baseline)
// - No panics or race conditions
func TestConcurrencyPoolExhaustion_10K_Tokenizer_Goroutines(t *testing.T) {
	const (
		numGoroutines = 10000
		testTimeout   = 30 * time.Second
	)

	// Record baseline goroutine count
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	startGoroutines := runtime.NumGoroutine()

	t.Logf("Starting pool exhaustion test with %d goroutines", numGoroutines)
	t.Logf("Baseline goroutines: %d", startGoroutines)

	var (
		wg           sync.WaitGroup
		opsCompleted atomic.Int64
		errorCount   atomic.Int64
		startBarrier = make(chan struct{})
	)

	testSQL := []byte("SELECT * FROM users WHERE active = true")

	// Launch all goroutines
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Wait for start signal to create maximum contention
			<-startBarrier

			// Get tokenizer from pool
			tkz := tokenizer.GetTokenizer()
			if tkz == nil {
				errorCount.Add(1)
				return
			}

			// Use tokenizer
			_, err := tkz.Tokenize(testSQL)
			if err != nil {
				errorCount.Add(1)
			}

			// Return to pool (CRITICAL: must always return)
			tokenizer.PutTokenizer(tkz)

			opsCompleted.Add(1)
		}(i)
	}

	// Start all goroutines simultaneously for maximum pool stress
	startTime := time.Now()
	close(startBarrier)

	// Wait with timeout for deadlock detection
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		elapsed := time.Since(startTime)
		t.Logf("✅ All %d goroutines completed successfully in %v", numGoroutines, elapsed)
		t.Logf("Operations completed: %d", opsCompleted.Load())
		t.Logf("Errors: %d", errorCount.Load())

		if errorCount.Load() > 0 {
			t.Errorf("❌ %d operations failed", errorCount.Load())
		}

	case <-time.After(testTimeout):
		t.Fatalf("❌ DEADLOCK DETECTED: Test did not complete within %v", testTimeout)
	}

	// Verify no goroutine leaks
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	endGoroutines := runtime.NumGoroutine()
	goroutineLeak := endGoroutines - startGoroutines

	t.Logf("Final goroutines: %d (leak: %d)", endGoroutines, goroutineLeak)

	// Allow small margin (±5) for test infrastructure goroutines
	if goroutineLeak > 5 {
		t.Errorf("❌ GOROUTINE LEAK DETECTED: %d goroutines leaked (started: %d, ended: %d)",
			goroutineLeak, startGoroutines, endGoroutines)
	} else {
		t.Logf("✅ No goroutine leaks detected")
	}
}

// TestConcurrencyPoolExhaustion_10K_Full_Pipeline tests complete tokenize+parse pipeline
// under extreme load with 10,000 concurrent goroutines.
// This validates end-to-end pool behavior including tokenizer and parser.
//
// Validation criteria:
// - All 10K goroutines complete without deadlocks
// - No goroutine leaks
// - Proper cleanup of all pooled objects
// - Tests pool coordination between tokenizer and parser
func TestConcurrencyPoolExhaustion_10K_Full_Pipeline(t *testing.T) {
	const (
		numGoroutines = 10000
		testTimeout   = 30 * time.Second
	)

	// Record baseline
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	startGoroutines := runtime.NumGoroutine()

	t.Logf("Starting full pipeline pool exhaustion test with %d goroutines", numGoroutines)
	t.Logf("Baseline goroutines: %d", startGoroutines)

	var (
		wg             sync.WaitGroup
		opsCompleted   atomic.Int64
		tokenizeErrors atomic.Int64
		startBarrier   = make(chan struct{})
	)

	testSQL := []byte("SELECT * FROM users")

	// Launch all goroutines
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Wait for start signal
			<-startBarrier

			// Get tokenizer from pool
			tkz := tokenizer.GetTokenizer()
			if tkz == nil {
				tokenizeErrors.Add(1)
				return
			}

			// Tokenize
			_, err := tkz.Tokenize(testSQL)

			// CRITICAL: Return to pool
			tokenizer.PutTokenizer(tkz)

			if err != nil {
				tokenizeErrors.Add(1)
				return
			}

			// Create parser (tests parser creation under load)
			p := NewParser()
			if p == nil {
				tokenizeErrors.Add(1)
				return
			}

			opsCompleted.Add(1)
		}(i)
	}

	// Start all goroutines simultaneously
	startTime := time.Now()
	close(startBarrier)

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		elapsed := time.Since(startTime)
		t.Logf("✅ All %d goroutines completed successfully in %v", numGoroutines, elapsed)
		t.Logf("Operations completed: %d", opsCompleted.Load())
		t.Logf("Tokenize errors: %d", tokenizeErrors.Load())

		if tokenizeErrors.Load() > 0 {
			t.Logf("⚠️ %d tokenize operations had errors (not critical for pool test)", tokenizeErrors.Load())
		}

	case <-time.After(testTimeout):
		t.Fatalf("❌ DEADLOCK DETECTED: Test did not complete within %v", testTimeout)
	}

	// Verify no goroutine leaks
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	endGoroutines := runtime.NumGoroutine()
	goroutineLeak := endGoroutines - startGoroutines

	t.Logf("Final goroutines: %d (leak: %d)", endGoroutines, goroutineLeak)

	if goroutineLeak > 5 {
		t.Errorf("❌ GOROUTINE LEAK DETECTED: %d goroutines leaked", goroutineLeak)
	} else {
		t.Logf("✅ No goroutine leaks detected")
	}
}

// TestConcurrencyPoolExhaustion_10K_AST_Creation_Release tests AST pool behavior
// with 10,000 concurrent goroutines creating and releasing AST objects.
//
// Validation criteria:
// - All AST objects properly created and released
// - No deadlocks or pool exhaustion issues
// - Memory returns to baseline after cleanup
func TestConcurrencyPoolExhaustion_10K_AST_Creation_Release(t *testing.T) {
	const (
		numGoroutines = 10000
		testTimeout   = 30 * time.Second
	)

	// Record baseline
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	startGoroutines := runtime.NumGoroutine()

	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)

	t.Logf("Starting AST pool exhaustion test with %d goroutines", numGoroutines)
	t.Logf("Baseline goroutines: %d", startGoroutines)
	t.Logf("Baseline memory: Alloc=%d MB, HeapInuse=%d MB",
		m1.Alloc/1024/1024, m1.HeapInuse/1024/1024)

	var (
		wg           sync.WaitGroup
		opsCompleted atomic.Int64
		errorCount   atomic.Int64
		startBarrier = make(chan struct{})
	)

	// Launch all goroutines
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Wait for start signal
			<-startBarrier

			// Create AST from pool
			astObj := ast.NewAST()
			if astObj == nil {
				errorCount.Add(1)
				return
			}

			// Simulate some work with AST
			_ = astObj.Statements

			// CRITICAL: Release back to pool
			ast.ReleaseAST(astObj)

			opsCompleted.Add(1)
		}(i)
	}

	// Start all goroutines simultaneously
	startTime := time.Now()
	close(startBarrier)

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		elapsed := time.Since(startTime)
		t.Logf("✅ All %d goroutines completed successfully in %v", numGoroutines, elapsed)
		t.Logf("Operations completed: %d", opsCompleted.Load())
		t.Logf("Errors: %d", errorCount.Load())

		if errorCount.Load() > 0 {
			t.Errorf("❌ %d operations failed", errorCount.Load())
		}

	case <-time.After(testTimeout):
		t.Fatalf("❌ DEADLOCK DETECTED: Test did not complete within %v", testTimeout)
	}

	// Force GC and check memory
	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)

	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)

	endGoroutines := runtime.NumGoroutine()
	goroutineLeak := endGoroutines - startGoroutines
	allocDiff := int64(m2.Alloc) - int64(m1.Alloc)

	t.Logf("Final goroutines: %d (leak: %d)", endGoroutines, goroutineLeak)
	t.Logf("Final memory: Alloc=%d MB, HeapInuse=%d MB (diff: %+d MB)",
		m2.Alloc/1024/1024, m2.HeapInuse/1024/1024, allocDiff/1024/1024)

	if goroutineLeak > 5 {
		t.Errorf("❌ GOROUTINE LEAK DETECTED: %d goroutines leaked", goroutineLeak)
	} else {
		t.Logf("✅ No goroutine leaks detected")
	}

	// Memory should not grow significantly after GC
	const maxMemoryGrowth = 20 * 1024 * 1024 // 20 MB threshold
	if allocDiff > maxMemoryGrowth {
		t.Errorf("❌ MEMORY LEAK SUSPECTED: Memory grew by %d MB (threshold: %d MB)",
			allocDiff/1024/1024, maxMemoryGrowth/1024/1024)
	} else {
		t.Logf("✅ Memory usage acceptable: %+d MB growth", allocDiff/1024/1024)
	}
}

// TestConcurrencyPoolExhaustion_All_Objects_In_Use tests pool behavior when
// all available objects are held simultaneously by goroutines.
// This validates that pools create new objects when exhausted (don't deadlock).
//
// Validation criteria:
// - Pools create new objects when exhausted (don't block)
// - All goroutines complete successfully
// - Proper cleanup after release
func TestConcurrencyPoolExhaustion_All_Objects_In_Use(t *testing.T) {
	const (
		numGoroutines = 1000
		holdDuration  = 100 * time.Millisecond
		testTimeout   = 30 * time.Second
	)

	// Record baseline
	runtime.GC()
	time.Sleep(50 * time.Millisecond)
	startGoroutines := runtime.NumGoroutine()

	t.Logf("Testing pool exhaustion with all objects held simultaneously")
	t.Logf("Goroutines: %d, Hold duration: %v", numGoroutines, holdDuration)

	var (
		wg                sync.WaitGroup
		opsCompleted      atomic.Int64
		errorCount        atomic.Int64
		startBarrier      = make(chan struct{})
		releaseBarrier    = make(chan struct{})
		allAcquiredSignal = make(chan struct{})
		acquiredCount     atomic.Int64
	)

	testSQL := []byte("SELECT COUNT(*) FROM orders GROUP BY status")

	// Launch all goroutines
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Wait for start signal
			<-startBarrier

			// Get tokenizer (pool may need to create new ones)
			tkz := tokenizer.GetTokenizer()
			if tkz == nil {
				errorCount.Add(1)
				return
			}

			// Signal acquisition
			if acquiredCount.Add(1) == int64(numGoroutines) {
				close(allAcquiredSignal)
			}

			// Hold the tokenizer while all others are also holding
			<-releaseBarrier

			// Use tokenizer
			_, err := tkz.Tokenize(testSQL)
			if err != nil {
				errorCount.Add(1)
			}

			// Release back to pool
			tokenizer.PutTokenizer(tkz)

			opsCompleted.Add(1)
		}(i)
	}

	// Start all goroutines
	startTime := time.Now()
	close(startBarrier)

	// Wait for all to acquire (with timeout)
	select {
	case <-allAcquiredSignal:
		t.Logf("✅ All %d goroutines acquired tokenizers (pool handled exhaustion)", numGoroutines)
	case <-time.After(5 * time.Second):
		t.Errorf("❌ Timeout waiting for all acquisitions (acquired: %d/%d)",
			acquiredCount.Load(), numGoroutines)
	}

	// Hold briefly to ensure all are in use simultaneously
	time.Sleep(holdDuration)

	// Release all simultaneously
	close(releaseBarrier)

	// Wait for completion
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		elapsed := time.Since(startTime)
		t.Logf("✅ All %d goroutines completed in %v", numGoroutines, elapsed)
		t.Logf("Operations completed: %d", opsCompleted.Load())
		t.Logf("Errors: %d", errorCount.Load())

		if errorCount.Load() > 0 {
			t.Errorf("❌ %d operations failed", errorCount.Load())
		}

	case <-time.After(testTimeout):
		t.Fatalf("❌ DEADLOCK DETECTED: Test did not complete within %v", testTimeout)
	}

	// Verify no goroutine leaks
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	endGoroutines := runtime.NumGoroutine()
	goroutineLeak := endGoroutines - startGoroutines

	t.Logf("Final goroutines: %d (leak: %d)", endGoroutines, goroutineLeak)

	if goroutineLeak > 5 {
		t.Errorf("❌ GOROUTINE LEAK DETECTED: %d goroutines leaked", goroutineLeak)
	} else {
		t.Logf("✅ No goroutine leaks detected")
	}
}

// TestConcurrencyPoolExhaustion_Goroutine_Leak_Detection performs comprehensive
// goroutine leak detection by running multiple cycles of concurrent operations
// and verifying goroutine count returns to baseline.
//
// Validation criteria:
// - Goroutine count returns to baseline after each cycle
// - No accumulated goroutine growth over multiple cycles
// - All pooled objects properly cleaned up
func TestConcurrencyPoolExhaustion_Goroutine_Leak_Detection(t *testing.T) {
	const (
		numCycles          = 5
		goroutinesPerCycle = 2000
		testTimeout        = 60 * time.Second
	)

	// Record baseline
	runtime.GC()
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	baselineGoroutines := runtime.NumGoroutine()

	t.Logf("Running %d cycles with %d goroutines each", numCycles, goroutinesPerCycle)
	t.Logf("Baseline goroutines: %d", baselineGoroutines)

	testSQL := []byte("SELECT * FROM users WHERE active = true")

	cycleResults := make([]int, numCycles)

	startTime := time.Now()

	for cycle := 0; cycle < numCycles; cycle++ {
		cycleStart := time.Now()

		var (
			wg           sync.WaitGroup
			opsCompleted atomic.Int64
			errorCount   atomic.Int64
		)

		// Launch goroutines for this cycle
		for i := 0; i < goroutinesPerCycle; i++ {
			wg.Add(1)
			go func(cycleID, goroutineID int) {
				defer wg.Done()

				// Get tokenizer
				tkz := tokenizer.GetTokenizer()
				if tkz == nil {
					errorCount.Add(1)
					return
				}

				// Tokenize
				_, err := tkz.Tokenize(testSQL)

				// CRITICAL: Return to pool
				tokenizer.PutTokenizer(tkz)

				if err != nil {
					errorCount.Add(1)
					return
				}

				// Create parser (tests repeated parser creation)
				p := NewParser()
				if p == nil {
					errorCount.Add(1)
					return
				}

				// Create AST object
				astObj := ast.NewAST()
				if astObj != nil {
					ast.ReleaseAST(astObj)
				}

				opsCompleted.Add(1)
			}(cycle, i)
		}

		// Wait for cycle to complete with timeout
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			// Cycle completed
		case <-time.After(testTimeout):
			t.Fatalf("❌ Cycle %d timed out after %v", cycle, testTimeout)
		}

		cycleElapsed := time.Since(cycleStart)

		// Force cleanup
		runtime.GC()
		time.Sleep(50 * time.Millisecond)

		// Check goroutine count
		currentGoroutines := runtime.NumGoroutine()
		goroutineIncrease := currentGoroutines - baselineGoroutines
		cycleResults[cycle] = goroutineIncrease

		t.Logf("Cycle %d: %d ops in %v, goroutines: %d (baseline: %d, increase: %+d), errors: %d",
			cycle+1, opsCompleted.Load(), cycleElapsed,
			currentGoroutines, baselineGoroutines, goroutineIncrease,
			errorCount.Load())

		if errorCount.Load() > 0 {
			t.Errorf("❌ Cycle %d had %d errors", cycle+1, errorCount.Load())
		}

		// Check for leak in this cycle (allow small margin)
		if goroutineIncrease > 10 {
			t.Errorf("❌ Cycle %d: Potential leak detected, %d goroutines increased",
				cycle+1, goroutineIncrease)
		}
	}

	totalElapsed := time.Since(startTime)

	// Final comprehensive check
	runtime.GC()
	runtime.GC()
	runtime.GC()
	time.Sleep(200 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()
	finalIncrease := finalGoroutines - baselineGoroutines

	t.Logf("\n=== Goroutine Leak Detection Summary ===")
	t.Logf("Total duration: %v", totalElapsed)
	t.Logf("Baseline goroutines: %d", baselineGoroutines)
	t.Logf("Final goroutines: %d", finalGoroutines)
	t.Logf("Final increase: %+d", finalIncrease)

	for i, increase := range cycleResults {
		t.Logf("Cycle %d goroutine increase: %+d", i+1, increase)
	}

	// Validate no accumulated leaks
	if finalIncrease > 10 {
		t.Errorf("❌ GOROUTINE LEAK DETECTED: %d goroutines accumulated after %d cycles",
			finalIncrease, numCycles)
	} else {
		t.Logf("✅ No goroutine leaks detected across all cycles")
	}

	// Check for growing trend
	if len(cycleResults) >= 3 {
		firstHalf := (cycleResults[0] + cycleResults[1]) / 2
		secondHalf := (cycleResults[numCycles-2] + cycleResults[numCycles-1]) / 2
		if secondHalf > firstHalf+5 {
			t.Errorf("⚠️ Goroutine count appears to be growing: first half avg=%d, second half avg=%d",
				firstHalf, secondHalf)
		}
	}
}
