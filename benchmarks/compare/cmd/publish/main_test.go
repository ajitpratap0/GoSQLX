package main

import "testing"

func TestParseBench(t *testing.T) {
	out := []byte(`goos: linux
goarch: amd64
cpu: AMD EPYC 7763 64-Core Processor
BenchmarkParse/simple_select/gosqlx-4         	  800000	      1450 ns/op	  17.93 MB/s	    2230 B/op	       7 allocs/op
BenchmarkParse/simple_select/gosqlx-4         	  800000	      1350.5 ns/op	  17.93 MB/s	    2230 B/op	       7 allocs/op
BenchmarkParse/simple_select/gosqlx-4         	  800000	      1500 ns/op	  17.93 MB/s	    2232 B/op	       7 allocs/op
BenchmarkParse/cte/xwb1989-4                  	--- SKIP: does not accept this query
BenchmarkParse/delete/pg_query_go             	   20000	      5705 ns/op	    1416 B/op	      30 allocs/op
PASS
`)
	cpu, data, err := parseBench(out)
	if err != nil {
		t.Fatal(err)
	}
	if cpu != "AMD EPYC 7763 64-Core Processor" {
		t.Errorf("cpu = %q", cpu)
	}
	tests := []struct {
		key               string
		n                 int
		ns, bytes, allocs float64
	}{
		{"simple_select/gosqlx", 3, 1450, 2230, 7},
		{"delete/pg_query_go", 1, 5705, 1416, 30},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			s, ok := data[tt.key]
			if !ok {
				t.Fatalf("missing %s", tt.key)
			}
			if len(s.ns) != tt.n {
				t.Fatalf("samples = %d, want %d", len(s.ns), tt.n)
			}
			if got := median(s.ns); got != tt.ns {
				t.Errorf("median ns = %v, want %v", got, tt.ns)
			}
			if got := median(s.bytes); got != tt.bytes {
				t.Errorf("median bytes = %v, want %v", got, tt.bytes)
			}
			if got := median(s.allocs); got != tt.allocs {
				t.Errorf("median allocs = %v, want %v", got, tt.allocs)
			}
		})
	}
	if _, ok := data["cte/xwb1989"]; ok {
		t.Error("skipped benchmark must not produce samples")
	}
}

func TestParseBenchEmpty(t *testing.T) {
	if _, _, err := parseBench([]byte("PASS\n")); err == nil {
		t.Fatal("expected an error when no benchmark lines are present")
	}
}

func TestMedianEven(t *testing.T) {
	if got := median([]float64{4, 1, 3, 2}); got != 2.5 {
		t.Fatalf("median = %v, want 2.5", got)
	}
}
