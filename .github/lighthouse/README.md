# Lighthouse CI budgets

`lighthouserc.json` is enforced by `.github/workflows/lighthouse.yml` on every PR touching `website/**`.
Each URL is audited 3 times and assertions use the median run. A failed `error` assertion fails the workflow
(the treosh action exits non-zero), so there is no separate score-check step.

## Measured baseline (2026-10-14)

Production build (`npm run build` + `next start`), Lighthouse 12 default (mobile) profile, local machine, 3 runs each.
Budgets are the measured value plus roughly 20-30% headroom for CI variance.

| Route | Performance (runs) | Script | Font | Stylesheet | Total transfer |
|---|---|---|---|---|---|
| `/` | 0.63, 0.80, 0.80 | 339 KB | 114 KB | 18 KB | 2.90 MB (2.4 MB is non-script/non-font assets) |
| `/compare/` | 0.87, 0.89, 0.89 | 329 KB | 114 KB | 18 KB | 0.49 MB |

The other audited routes (`/playground/`, `/docs/`, `/docs/getting-started/`, `/benchmarks/`, `/changelog/`) share the
same layout chunks; their per-route numbers are in the uploaded Lighthouse artifacts. The local run was cut short by
a full disk, so only `/` and `/compare/` were measured locally.

## Thresholds

| Assertion | Level | Value |
|---|---|---|
| performance | error | 0.75 (target 0.90 once the performance work in 1.7-1.10 lands) |
| accessibility, seo | error | 0.95 |
| best-practices | warn | 0.85 |
| resource-summary script / font / stylesheet / total | error | 420 KB / 150 KB / 25 KB / 3.6 MB |

Re-measure and update this table whenever the budgets are changed.
