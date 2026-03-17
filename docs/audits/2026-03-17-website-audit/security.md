# Security Audit — 2026-03-17

Audited: https://gosqlx.dev
Auditor: Claude Code (automated)
Branch: feat/website-v2

---

## HTTP Security Headers

| Header | Status | Value |
|--------|--------|-------|
| Strict-Transport-Security | PRESENT | `max-age=63072000` (2 years) |
| Content-Security-Policy | PRESENT | see below |
| X-Frame-Options | PRESENT | `DENY` |
| X-Content-Type-Options | PRESENT | `nosniff` |
| Referrer-Policy | PRESENT | `strict-origin-when-cross-origin` |
| Permissions-Policy | **MISSING** | not set |
| Cross-Origin-Opener-Policy | **MISSING** | not set |

**Security Header Score: 5/7 headers present**

Note: HSTS is set by Vercel infrastructure (`max-age=63072000`) — it is NOT configured in `next.config.ts`. If the project ever moves off Vercel, HSTS will be lost. It should be added explicitly to `next.config.ts` with `includeSubDomains; preload`.

---

## Content-Security-Policy Analysis

```
default-src 'self';
script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval';
style-src 'self' 'unsafe-inline';
font-src 'self';
img-src 'self' https://img.shields.io https://goreportcard.com https://*.shields.io data:;
connect-src 'self' https://*.sentry.io;
worker-src 'self' blob:
```

### CSP Directive Review

| Directive | Value | Issue |
|-----------|-------|-------|
| `default-src` | `'self'` | OK — present and restrictive |
| `script-src` | `'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval'` | **HIGH** — `'unsafe-eval'` is unnecessary. `'wasm-unsafe-eval'` is sufficient for WASM. No source code uses direct eval calls. Remove `'unsafe-eval'`. |
| `style-src` | `'self' 'unsafe-inline'` | MEDIUM — required by Next.js inline styles; acceptable but noted |
| `connect-src` | `'self' https://*.sentry.io` | OK — includes Sentry wildcard |
| `img-src` | `'self' https://img.shields.io ...` | OK — covers all used sources |
| `worker-src` | `'self' blob:` | OK — needed for WASM service worker |
| `frame-ancestors` | **MISSING** | MEDIUM — add `'none'` (supersedes X-Frame-Options in modern browsers) |
| `base-uri` | **MISSING** | MEDIUM — add `'self'` to prevent base tag injection attacks |
| `form-action` | **MISSING** | LOW — add `'self'` to restrict form submissions |
| `upgrade-insecure-requests` | **MISSING** | LOW — redundant given HSTS, but good defense-in-depth |

**CSP source**: Defined in `website/next.config.ts` line 18.

**Discrepancy**: `connect-src` in `next.config.ts` includes `https://*.sentry.io` but the **live header** on the homepage does NOT include it. This suggests the deployed build is stale or the header was not rebuilt since the config was last edited. Verify with a fresh deployment.

---

## HTTPS Enforcement

- HTTP to HTTPS redirect: YES (HTTP 308 Permanent Redirect)
- HSTS present: YES (`max-age=63072000` — set by Vercel infrastructure, not app config)
- HSTS `includeSubDomains`: **MISSING** from HSTS value
- HSTS `preload`: **MISSING** from HSTS value

The HSTS header should be upgraded to `max-age=31536000; includeSubDomains; preload` for HSTS preload list eligibility and to cover subdomains.

---

## Sentry Tunnel Route (/monitoring)

- Route active: **NO** — returns HTTP 404
- GET returns: `404`
- POST returns: `404` (renders the Next.js 404 page HTML)

The `tunnelRoute: '/monitoring'` is configured in `next.config.ts` (via `withSentryConfig`), but the route is not live in the current deployment. This means Sentry error reports are sent directly to `https://o*.ingest.sentry.io`, bypassing the tunnel. This is relevant for ad-blocker bypass and data integrity.

**Action required**: Verify the Sentry tunnel route is deployed and responding. The `/monitoring` API route should return 405 on GET and 200/400 (not 404) on POST.

---

## Service Worker (wasm-sw.js)

**Cache key**: `'gosqlx-wasm-v1'` — **static string, not hash-based**

This is a stale WASM risk. The cache name never changes unless manually bumped. If `gosqlx.wasm` is updated (new Go version, new SQL features), users with the service worker already installed will continue serving the old WASM binary from cache indefinitely — even after a new deployment — until they manually clear cache or the cache name is bumped in source.

**Recommendation**: Either:
1. Inject a build hash: `'gosqlx-wasm-' + BUILD_HASH` at build time
2. Add `Cache-Control: no-cache` on the WASM file and let the service worker revalidate

---

## npm Audit

```
found 0 vulnerabilities
```

- Critical: 0
- High: 0
- Moderate: 0
- Low: 0

No dependency vulnerabilities at or above moderate severity.

---

## External Scripts / Subresource Integrity (SRI)

All scripts on the homepage are served from `/_next/static/chunks/` (same origin). No external CDN scripts were found. SRI is not applicable.

---

## Priority Fixes (ranked by severity)

### 1. Remove `'unsafe-eval'` from `script-src` — HIGH

`'wasm-unsafe-eval'` already handles WASM instantiation. No first-party code calls eval directly. The `'unsafe-eval'` permission is unnecessary and allows arbitrary JS execution if XSS is present.

File: `website/next.config.ts`, line 18

Change `script-src 'self' 'unsafe-inline' 'unsafe-eval' 'wasm-unsafe-eval'`
to `script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'`

### 2. Add `Permissions-Policy` header — HIGH

Restricts access to browser APIs (camera, microphone, geolocation, etc.) from this origin and embedded iframes.

```typescript
// Add to the headers array in website/next.config.ts
{
  key: 'Permissions-Policy',
  value: 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
},
```

### 3. Add `frame-ancestors 'none'` to CSP — MEDIUM

`X-Frame-Options: DENY` is set, but `frame-ancestors` in CSP supersedes it in modern browsers and is more granular. Including both provides defense-in-depth.

Append to CSP value in `website/next.config.ts`:
`... worker-src 'self' blob:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`

### 4. Add `base-uri 'self'` to CSP — MEDIUM

Prevents attackers from injecting a `<base>` tag to redirect all relative URLs to an attacker-controlled domain.

Append to CSP value: `... frame-ancestors 'none'; base-uri 'self'; ...`

### 5. Upgrade HSTS to include `includeSubDomains; preload` — MEDIUM

Current: `max-age=63072000` (Vercel-injected, not in app config)
Target: `max-age=31536000; includeSubDomains; preload`

Add explicitly to `next.config.ts` so it is not deployment-platform-dependent:

```typescript
{
  key: 'Strict-Transport-Security',
  value: 'max-age=31536000; includeSubDomains; preload',
},
```

### 6. Verify Sentry tunnel route `/monitoring` is deployed — MEDIUM

Currently returns 404. Confirm `withSentryConfig` with `tunnelRoute: '/monitoring'` is building and deploying the API route correctly. Test: POST to `/monitoring` should return 200 or 400, not 404.

### 7. Add `Cross-Origin-Opener-Policy` header — LOW

Isolates the browsing context to prevent cross-origin window attacks.

```typescript
{
  key: 'Cross-Origin-Opener-Policy',
  value: 'same-origin',
},
```

### 8. Fix static WASM service worker cache key — LOW

Change `'gosqlx-wasm-v1'` in `public/wasm-sw.js` to a build-time hash to prevent stale WASM serving after deployments.
