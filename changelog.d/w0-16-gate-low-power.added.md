- **Perf gate**: adaptive layout counts size each benchmark to 80% estimated power
  for a lone +5% slowdown, using empirical-AUC Noether power instead of
  the MAD normal model. `-B` sets the extension budget, `-E` the deadline,
  and `-K` the per-arm cap; `-G` spends up to 600 seconds more by default.
  Raw files carry `suite-line:` labels; reports add K/power columns and
  list remaining Low power benchmarks with reasons, separate planned
  extensions from line warm-ups, show configured power targets and unknown
  estimates, and say when adaptive layouts were skipped because timings
  were not judged. Only primary time
  uses extra layouts; all other rules use stage-1 data. Normal jobs take
  about 13.5 + 10 minutes, worst-case retry 21.7 + 10 = 31.7 minutes;
  new work stops at 35 minutes inside a 40-minute step and 45-minute job.
  Library behaviour is unchanged. [W0-16]
