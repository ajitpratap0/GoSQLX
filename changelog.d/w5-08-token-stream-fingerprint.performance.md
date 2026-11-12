- **Token-stream Normalize and Fingerprint [W5-08]**: defaults tokenize once,
  normalize into a pooled byte buffer and hash its bytes directly for
  fingerprints. On the layout-randomized amd64 CI gate (base 1f828000),
  `Normalize` is 74.31% (simple_select, 0.26x), 61.11% (join, 0.39x) and 62.49%
  (complex, 0.375x) faster; allocs/op fall from 5/21/62 to 1 and B/op by 93.7%
  to 95.9%. `simple_select` meets the PLAN threshold (<= 0.30x); `join` and
  `complex` MISS it. A CPU profile of `Normalize/complex` on arm64 splits the
  time roughly 37% tokenize, 37% `appendNormalV2` and under 5% hashing and
  pooling, so the remaining cost is the shared tokenizer plus the normal-form
  writer, not allocation. The legacy mode (`ModeLegacy`) is unchanged within
  noise (geomean -1.4% vs origin/main, local arm64, indicative).
