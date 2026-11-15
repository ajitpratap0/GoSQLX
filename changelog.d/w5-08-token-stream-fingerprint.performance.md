- **Token-stream Normalize and Fingerprint [W5-08]**: defaults tokenize once,
  normalize into a pooled byte buffer and hash its bytes directly for
  fingerprints. The authoritative final-head layout-randomized amd64 CI run
  (perf-gate run 43274969051, head 528b38c9, AMD EPYC 9V74, 20 layouts per
  arm, A/A' 0/52, base 1f828000) reports `Normalize` changes of -67.80%
  (simple_select, 0.32x of baseline), -53.85% (join, 0.46x) and -53.87%
  (complex, 0.46x); allocs/op fall from 5/21/62 to 1 and B/op by 95.92%,
  94.22% and 93.73%; the suite geomean is -5.05% (p<0.001) with no gated
  regression. No target met the PLAN threshold (<= 0.30x) on the final head.
  Earlier runs on other runners (AMD EPYC 7763: 0.35x/0.46x/0.44x; AMD EPYC
  9V45: 0.26x/0.39x/0.375x) are not comparable across CPUs; `simple_select`
  met the PLAN threshold only on the 9V45 run, and `join` and `complex` missed
  it on every run. A CPU profile of
  `Normalize/complex` on arm64 splits the time roughly 37% tokenize,
  37% `appendNormalV2` and under 5% hashing and
  pooling, so the remaining cost is the shared tokenizer plus the normal-form
  writer, not allocation. The legacy mode (`ModeLegacy`) is unchanged within
  noise (geomean -1.4% vs origin/main, local arm64, indicative).
