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
| `/playground/` (CI median, 2026-10-20, PR #825) | - | 420 KB | - | - | - |

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
| resource-summary script, `/playground/` only | error | 480 KB |

`/playground/` loads the CodeMirror editor and the GoSQLX highlighting bridge, so it gets its own script budget
via `assertMatrix` (the measured 420 KB plus ~15% headroom). Every other route keeps the shared 420 KB budget, and
the two matrix entries are otherwise identical: change an assertion in both when editing thresholds.

Re-measure and update this table whenever the budgets are changed.

## Field data (RUM) and p75 per route

Field data comes from Vercel Speed Insights (`<SpeedInsights />` in `website/src/app/layout.tsx`). `web-vitals`
sampling is intentionally not added, so there is one source. In the Vercel dashboard open the project Speed Insights tab,
filter to Mobile and group by Route to read p75 LCP, CLS and INP per route.

| Metric | Budget (mobile, p75) |
|---|---|
| LCP | < 2.5 s |
| CLS | < 0.1 |
| INP | < 200 ms |

## Monthly production Lighthouse

`.github/workflows/lighthouse-monthly.yml` runs on the 1st of each month (and on demand) against the production
URLs, 3 runs each, and uploads the reports as workflow artifacts. It does not assert; regressions are triaged in the
monthly review.

## Monthly review checklist

1. Download the latest `lighthouse-production-*` artifact and compare with the previous month and the baseline above.
2. Read p75 LCP, CLS and INP per route in Speed Insights against the budgets.
3. Re-grade the website scorecard and re-run the 8-route screenshot audit at 390, 768 and 1440 px in both themes.
4. Open a `fix/...` PR for each regression, naming the metric and route.
