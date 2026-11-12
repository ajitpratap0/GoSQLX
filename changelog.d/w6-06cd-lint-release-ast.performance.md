- `LintString` and wrappers tokenize into pooled scratch storage and release the
  parsed AST after the rules run: `LintRW` B/op -40% to -45% and allocs/op -6% to
  -7% across all eight dialects, `LintParallel/lint` B/op -41%.
