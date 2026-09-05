# ✅ Kaizo Developer PR & Code Review Security Checklist

> Every Pull Request (PR) must be verified against this checklist before merging into `develop` or `main`.

---

## 🔒 1. Secrets & Credentials (CWE-798)
- [ ] No hardcoded passwords, private API keys, connection strings, or JWT secrets in code.
- [ ] No secrets in client-side bundles (e.g. `NEXT_PUBLIC_*` or `REACT_APP_*` containing admin keys).
- [ ] Pre-commit secret scanner (`gitleaks protect --staged`) ran cleanly without bypass.
- [ ] Production source maps are disabled or restricted from public hosting.

---

## 🌐 2. Network & Infrastructure (CWE-284, CWE-319, CWE-311)
- [ ] Database ports (`5432`, `3306`, `27017`, `6379`) are **not** bound to `0.0.0.0` or exposed publicly.
- [ ] All traffic is forced to HTTPS via 301 redirects.
- [ ] HSTS header (`Strict-Transport-Security`) is present with `includeSubDomains`.

---

## 🛡️ 3. Security Headers & Clickjacking (CWE-693, CWE-1021)
- [ ] `Content-Security-Policy` (CSP) header is configured and does not use `unsafe-eval` in production.
- [ ] `X-Frame-Options: DENY` (or CSP `frame-ancestors 'none'`) is active to prevent Clickjacking.
- [ ] `X-Content-Type-Options: nosniff` is present on all responses.

---

## 🍪 4. Cookies, Session & CSRF (CWE-1275, CWE-1004, CWE-565, CWE-352, CWE-598)
- [ ] All authentication/session cookies have `HttpOnly: true`.
- [ ] All session cookies have `Secure: true`.
- [ ] All session cookies have `SameSite: 'strict'` or `'lax'`.
- [ ] Cookie `Domain` attribute is omitted (host-only) or prefixed with `__Host-`.
- [ ] Mutating state requests (`POST`, `PUT`, `DELETE`) are protected with CSRF tokens or custom headers.
- [ ] No session tokens, IDs, or sensitive PII passed in URL query strings.

---

## 📦 5. Third-Party Scripts & Assets (CWE-345, CWE-829)
- [ ] Any external `<script>` or `<link>` loaded from a CDN includes `integrity="sha384-..."` and `crossorigin="anonymous"`.
- [ ] No unvetted third-party JavaScript files included directly from unknown domains.

---

## 💾 6. Client-Side Storage & Data Exposure (CWE-359, CWE-201, CWE-525, CWE-497)
- [ ] No sensitive authentication tokens or credentials stored in `localStorage` or `sessionStorage`.
- [ ] Authenticated API responses include `Cache-Control: no-store, no-cache, must-revalidate, private`.
- [ ] HTTP Redirects (`301`/`302`) do not emit private body data (no "Big Redirect" data leaks).
- [ ] Server does not leak internal Unix timestamps or raw debug stack traces in error messages.
