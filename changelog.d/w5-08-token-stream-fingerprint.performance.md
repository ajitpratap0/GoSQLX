- **Token-stream Normalize and Fingerprint [W5-08]**: defaults tokenize once,
  normalize into a pooled byte buffer and hash its bytes directly for
  fingerprints. The authoritative final-head layout-randomized amd64 CI run
  on AMD EPYC 7763 (20 layouts per arm, A/A' 0/52; base 1f828000) reports
  `Normalize` changes of -64.82% (simple_select, 0.35x of baseline), -53.62%
  (join, 0.46x) and -56.21% (complex, 0.44x). No target met the PLAN threshold
  (<= 0.30x) on that run. The earlier AMD EPYC 9V45 run reported -74.31%
  (simple_select, 0.26x), -61.11% (join, 0.39x) and -62.49% (complex, 0.375x);
  that run reduced allocs/op from 5/21/62 to 1 and B/op by 93.7% to 95.9%.
  `simple_select` met the PLAN threshold only on the 9V45 run; `join` and
  `complex` did not meet it on either run. A CPU profile of
  `Normalize/complex` on arm64 splits the time roughly 37% tokenize,
  37% `appendNormalV2` and under 5% hashing and
  pooling, so the remaining cost is the shared tokenizer plus the normal-form
  writer, not allocation. The legacy mode (`ModeLegacy`) is unchanged within
  noise (geomean -1.4% vs origin/main, local arm64, indicative).
