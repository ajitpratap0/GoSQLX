- **Perf gate**: adaptive layout counts size each benchmark to 80% estimated power
  for a lone +5% slowdown, using empirical-AUC Noether power instead of
  the MAD normal model. `-B` sets the extension budget, `-E` the deadline,
  and `-K` the per-arm cap; `-G` spends up to 600 seconds more by default.
  Raw files carry `suite-line:` labels; reports add K/power columns and
  list remaining Low power benchmarks with reasons, separate planned
  extensions from line warm-ups, show configured power targets and unknown
  estimates, and say when adaptive layouts were skipped because timings
  were not judged. Only primary time uses extra layouts; all other
  rules use stage-1 data. The perf step timeout rises from 35 to 40
  minutes; the job cap stays at 45 minutes. Library behaviour is
  unchanged. [W0-16]
