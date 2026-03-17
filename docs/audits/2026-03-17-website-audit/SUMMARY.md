# GoSQLX Website Audit Summary — 2026-03-17

## Overall Health

| Category | Top Finding | Status |
|----------|-------------|--------|
| Performance | JS 627KB home / 985KB playground; WASM no preload | 🟡 |
| SEO | No canonical tags; broken sitemap discovery; no JSON-LD | 🔴 |
| Accessibility | No skip link; contrast failures; code blocks not keyboard accessible | 🟡 |
| Security | Missing HSTS + Permissions-Policy; unsafe-eval in CSP | 🟡 |
| Visual/Responsive | Homepage sections invisible below hero; overflow at 320px | 🔴 |
| Functional | Wrong GitHub owner links; 404 returns 200; broken .md doc links | 🔴 |
| Content | 1.28 MB unused assets; missing blog post for latest release | 🟡 |

## Fixes Applied in This PR

| # | Fix | File Changed | Impact |
|---|-----|--------------|--------|
| 1 | Fixed robots.txt sitemap URL | website/public/robots.txt | SEO: sitemap now discoverable |
| 2 | Deleted 1.28 MB unused assets | website/public/images/ | Perf: reduced repo size |
| 3 | Fixed GitHub owner links (ajitpsingh → ajitpratap0) | website/src/components/layout/Footer.tsx, Navbar.tsx | Functional: correct repo links site-wide |
| 4 | Added HSTS + Permissions-Policy security headers | website/next.config.ts | Security |
| 5 | Removed unsafe-eval from CSP; added frame-ancestors/base-uri/form-action | website/next.config.ts | Security |
| 6 | Added canonical to layout (homepage) | website/src/app/layout.tsx | SEO |
| 7 | Added JSON-LD SoftwareApplication structured data | website/src/app/layout.tsx | SEO |
| 8 | Added canonical + og:url to docs pages | website/src/app/docs/[...slug]/page.tsx | SEO |
| 9 | Added canonical + og:url + og:type to blog pages | website/src/app/blog/[slug]/page.tsx | SEO |
| 10 | Added skip-to-main-content link | website/src/app/layout.tsx | A11y |
| 11 | Wrapped page content in `<main id="main-content">` | website/src/app/layout.tsx | A11y |
| 12 | Removed broken Vercel Analytics component | website/src/app/layout.tsx | Perf: eliminates 2 console errors per page |

## GitHub Issues Created for Complex Fixes

- #396 — fix(website): homepage sections invisible below hero (IntersectionObserver)
- #397 — fix(website): 404 page returns HTTP 200 status
- #398 — fix(website): broken .md links in docs content files
- #399 — a11y(website): fix color contrast violations
- #400 — a11y(website): make code blocks keyboard accessible (tabindex=0)
- #401 — fix(website): horizontal overflow at 320px viewport
- #402 — perf(website): add rel=preload for gosqlx.wasm
- #403 — perf(website): version WASM service worker cache key
- #404 — seo(website): add JSON-LD Article to blog, BreadcrumbList to docs
- #405 — content(website): add blog post for latest release

## Audit Reports
- [Performance](performance.md)
- [SEO](seo.md)
- [Accessibility](accessibility.md)
- [Security](security.md)
- [Functional](functional.md)
- [Content](content.md)
