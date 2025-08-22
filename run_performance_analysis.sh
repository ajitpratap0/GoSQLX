#!/bin/bash

# GoSQLX Performance Analysis Runner
# This script runs comprehensive performance benchmarks and generates detailed reports

set -e

echo "🚀 GoSQLX Performance Analysis Suite"
echo "====================================="
echo "Starting comprehensive performance benchmarks..."
echo ""

# Create reports directory
mkdir -p reports
cd reports

# Clean up any existing reports
rm -f *.prof *.log *.txt *.html

echo "📊 Phase 1: Tokenizer Performance Analysis"
echo "-------------------------------------------"
echo "Testing tokenizer performance across different query sizes..."
go test -run=^$ -bench=BenchmarkTokenizer.*Performance.* ../ -benchmem -count=3 > tokenizer_performance.txt 2>&1
echo "✅ Tokenizer performance analysis complete"

echo ""
echo "🔍 Phase 2: Parser Performance Analysis" 
echo "---------------------------------------"
echo "Testing parser performance with various SQL complexities..."
go test -run=^$ -bench=BenchmarkParser.*Performance.* ../ -benchmem -count=3 > parser_performance.txt 2>&1
echo "✅ Parser performance analysis complete"

echo ""
echo "🧠 Phase 3: Memory Management Analysis"
echo "--------------------------------------"
echo "Testing memory allocation patterns and leak detection..."
go test -run=^$ -bench=BenchmarkMemoryManagement.* ../ -benchmem -count=3 > memory_analysis.txt 2>&1
echo "✅ Memory management analysis complete"

echo ""
echo "📈 Phase 4: Scalability Analysis"
echo "--------------------------------"
echo "Testing performance scaling across different concurrency levels..."
go test -run=^$ -bench=BenchmarkScalability.* ../ -benchmem -count=3 > scalability_analysis.txt 2>&1
echo "✅ Scalability analysis complete"

echo ""
echo "🏊 Phase 5: Pool Efficiency Analysis"
echo "------------------------------------"
echo "Testing object pool utilization and effectiveness..."
go test -run=^$ -bench=BenchmarkPoolEfficiency.* ../ -benchmem -count=3 > pool_analysis.txt 2>&1
echo "✅ Pool efficiency analysis complete"

echo ""
echo "⚡ Phase 6: Throughput Analysis"
echo "------------------------------"
echo "Testing queries per second under various load conditions..."
go test -run=^$ -bench=BenchmarkThroughput.* ../ -benchmem -count=3 > throughput_analysis.txt 2>&1
echo "✅ Throughput analysis complete"

echo ""
echo "🔧 Phase 7: CPU Profiling"
echo "-------------------------"
echo "Generating CPU profile for hotspot identification..."
go test -run=^$ -bench=BenchmarkFullPipeline -cpuprofile=cpu.prof ../ -benchmem > cpu_profile.txt 2>&1
echo "✅ CPU profiling complete"

echo ""
echo "💾 Phase 8: Memory Profiling"
echo "----------------------------"
echo "Generating memory profile for allocation pattern analysis..."
go test -run=^$ -bench=BenchmarkMemoryEfficiency -memprofile=mem.prof ../ -benchmem > memory_profile.txt 2>&1
echo "✅ Memory profiling complete"

echo ""
echo "🧪 Phase 9: Comprehensive Test Suite"
echo "------------------------------------"
echo "Running the comprehensive performance suite..."
go test -run=^$ -bench=Benchmark.*Analysis ../ -benchmem -count=3 > comprehensive_analysis.txt 2>&1
echo "✅ Comprehensive analysis complete"

echo ""
echo "📋 Generating Performance Summary Report..."
echo "==========================================="

cat > performance_summary.md << 'EOF'
# GoSQLX Performance Analysis Report

## Overview

This report contains comprehensive performance analysis results for the GoSQLX SQL parsing library.

## Test Environment

- **Date**: $(date)
- **Go Version**: $(go version)
- **OS**: $(uname -s) $(uname -r)
- **Architecture**: $(uname -m)
- **CPU Cores**: $(nproc)

## Analysis Results

### 1. Tokenizer Performance
EOF

echo ""
echo "Processing tokenizer results..."
if [ -f "tokenizer_performance.txt" ]; then
    echo "- **Best Performance**: $(grep -E 'BenchmarkTokenizer.*-[0-9]+' tokenizer_performance.txt | sort -k3 -nr | head -1 | awk '{print $1 ": " $3 " ops/sec, " $5 " bytes/op, " $4 " allocs/op"}')" >> performance_summary.md
    echo "- **Memory Efficiency**: $(grep -E 'bytes/op' tokenizer_performance.txt | sort -k5 -n | head -1 | awk '{print $1 ": " $5 " bytes/op"}')" >> performance_summary.md
    echo "- **Full Results**: See tokenizer_performance.txt" >> performance_summary.md
else
    echo "- **Status**: No tokenizer performance data available" >> performance_summary.md
fi

cat >> performance_summary.md << 'EOF'

### 2. Parser Performance
EOF

echo "Processing parser results..."
if [ -f "parser_performance.txt" ]; then
    echo "- **Best Performance**: $(grep -E 'BenchmarkParser.*-[0-9]+' parser_performance.txt | sort -k3 -nr | head -1 | awk '{print $1 ": " $3 " ops/sec, " $5 " bytes/op, " $4 " allocs/op"}')" >> performance_summary.md
    echo "- **Memory Efficiency**: $(grep -E 'bytes/op' parser_performance.txt | sort -k5 -n | head -1 | awk '{print $1 ": " $5 " bytes/op"}')" >> performance_summary.md
    echo "- **Full Results**: See parser_performance.txt" >> performance_summary.md
else
    echo "- **Status**: No parser performance data available" >> performance_summary.md
fi

cat >> performance_summary.md << 'EOF'

### 3. Memory Management Analysis
EOF

echo "Processing memory results..."
if [ -f "memory_analysis.txt" ]; then
    echo "- **Memory Leak Detection**: $(grep -E 'memory_growth_bytes|object_growth_count' memory_analysis.txt | head -2 | tr '\n' ', ')" >> performance_summary.md
    echo "- **GC Analysis**: $(grep -E 'gc_cycles|avg_gc_pause_ms|allocation_rate_mb' memory_analysis.txt | head -3 | tr '\n' ', ')" >> performance_summary.md
    echo "- **Full Results**: See memory_analysis.txt" >> performance_summary.md
else
    echo "- **Status**: No memory analysis data available" >> performance_summary.md
fi

cat >> performance_summary.md << 'EOF'

### 4. Scalability Analysis
EOF

echo "Processing scalability results..."
if [ -f "scalability_analysis.txt" ]; then
    echo "- **Peak Concurrency**: $(grep -E 'Concurrency_[0-9]+.*-[0-9]+' scalability_analysis.txt | sort -k3 -nr | head -1 | awk '{print $1 ": " $3 " ops/sec"}')" >> performance_summary.md
    echo "- **Scaling Efficiency**: See scalability_analysis.txt for detailed per-worker performance" >> performance_summary.md
    echo "- **Full Results**: See scalability_analysis.txt" >> performance_summary.md
else
    echo "- **Status**: No scalability data available" >> performance_summary.md
fi

cat >> performance_summary.md << 'EOF'

### 5. Pool Efficiency Analysis
EOF

echo "Processing pool efficiency results..."
if [ -f "pool_analysis.txt" ]; then
    echo "- **Pool Reuse Rate**: $(grep -E 'pool_reuse_%' pool_analysis.txt | head -1)" >> performance_summary.md
    echo "- **Concurrent Pool Performance**: $(grep -E 'ConcurrentPool' pool_analysis.txt | head -1 | awk '{print $3 " ops/sec"}')" >> performance_summary.md
    echo "- **Full Results**: See pool_analysis.txt" >> performance_summary.md
else
    echo "- **Status**: No pool efficiency data available" >> performance_summary.md
fi

cat >> performance_summary.md << 'EOF'

### 6. Throughput Analysis
EOF

echo "Processing throughput results..."
if [ -f "throughput_analysis.txt" ]; then
    echo "- **Single Thread QPS**: $(grep -E 'queries/sec.*[0-9]+' throughput_analysis.txt | head -1)" >> performance_summary.md
    echo "- **Sustained Load QPS**: $(grep -E 'sustained_queries/sec.*[0-9]+' throughput_analysis.txt | head -1)" >> performance_summary.md
    echo "- **Full Results**: See throughput_analysis.txt" >> performance_summary.md
else
    echo "- **Status**: No throughput data available" >> performance_summary.md
fi

cat >> performance_summary.md << 'EOF'

## Profile Analysis

### CPU Profiling
EOF

if [ -f "cpu.prof" ]; then
    echo "- **Profile File**: cpu.prof (use 'go tool pprof cpu.prof' for analysis)" >> performance_summary.md
    echo "- **Top Functions**: Run 'go tool pprof -top cpu.prof' to see CPU hotspots" >> performance_summary.md
else
    echo "- **Status**: No CPU profile generated" >> performance_summary.md
fi

cat >> performance_summary.md << 'EOF'

### Memory Profiling
EOF

if [ -f "mem.prof" ]; then
    echo "- **Profile File**: mem.prof (use 'go tool pprof mem.prof' for analysis)" >> performance_summary.md
    echo "- **Allocation Analysis**: Run 'go tool pprof -alloc_space mem.prof' to see allocation patterns" >> performance_summary.md
else
    echo "- **Status**: No memory profile generated" >> performance_summary.md
fi

cat >> performance_summary.md << 'EOF'

## Recommendations

Based on the analysis results:

1. **Object Pooling**: The library effectively uses object pooling to reduce allocations
2. **Concurrent Performance**: Check scalability results for optimal worker counts
3. **Memory Management**: Monitor for any memory growth in sustained usage
4. **Performance Hotspots**: Use CPU profile to identify optimization opportunities

## Files Generated

- `performance_summary.md`: This summary report
- `tokenizer_performance.txt`: Detailed tokenizer benchmarks
- `parser_performance.txt`: Detailed parser benchmarks  
- `memory_analysis.txt`: Memory management analysis
- `scalability_analysis.txt`: Concurrency and scaling tests
- `pool_analysis.txt`: Object pool efficiency analysis
- `throughput_analysis.txt`: Throughput measurements
- `comprehensive_analysis.txt`: Full benchmark suite results
- `cpu.prof`: CPU profiling data (if generated)
- `mem.prof`: Memory profiling data (if generated)

## Usage

To run interactive profile analysis:

```bash
# Analyze CPU usage
go tool pprof cpu.prof

# Analyze memory allocations  
go tool pprof mem.prof

# Generate flame graph (requires graphviz)
go tool pprof -http=:8080 cpu.prof
```

EOF

echo "✅ Performance summary report generated: reports/performance_summary.md"

echo ""
echo "🎉 Performance Analysis Complete!"
echo "================================="
echo "All benchmark results are available in the 'reports/' directory."
echo ""
echo "Key files:"
echo "  📄 performance_summary.md - Executive summary"
echo "  📊 comprehensive_analysis.txt - Full benchmark results"
echo "  🔍 cpu.prof & mem.prof - Profile data for detailed analysis"
echo ""
echo "To analyze profiles interactively:"
echo "  go tool pprof reports/cpu.prof"
echo "  go tool pprof reports/mem.prof"
echo ""
echo "Happy optimizing! 🚀"