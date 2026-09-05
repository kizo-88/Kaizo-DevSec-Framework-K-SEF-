# 🔍 DAST & OWASP ZAP Scanner Triage Playbook

> **Author**: Kaizo  
> **Purpose**: Standardized procedure for triaging, validating, and resolving Dynamic Application Security Testing (DAST) findings.

---

## 🧭 Triage Decision Matrix

```
[DAST Alert Received]
        │
        ▼
Is it a true vulnerability or scanner artifact?
        ├─ True Positive ──> Assign Severity & Apply K-SEF Playbook ──> Deploy Fix ──> Re-scan
        └─ Informational / False Positive ──> Document in Rule Exceptions ──> Verify baseline
```

---

## 📋 Step-by-Step Triage for Common DAST Alerts

### 1. Alert: "Content Security Policy (CSP) Header Not Set" (Medium / CWE-693)
- **Validation**: `curl -I https://staging.kaizo-app.com | grep -i content-security-policy`
- **Fix**: Apply `nextjs-security-headers.ts` or Nginx `Content-Security-Policy` directive.

### 2. Alert: "Missing Anti-clickjacking Header" (Medium / CWE-1021)
- **Validation**: Check for `X-Frame-Options` and CSP `frame-ancestors`.
- **Fix**: Add `X-Frame-Options: DENY` in reverse proxy or web application framework.

### 3. Alert: "Sub Resource Integrity Attribute Missing" (Medium / CWE-345)
- **Validation**: Inspect HTML source for CDN `<script>` or `<link>` tags without `integrity`.
- **Fix**: Run `03-implementation-code/client-security/sri-generator.sh <URL>` and paste the snippet.

### 4. Alert: "Big Redirect Detected (Potential Sensitive Information Leak)" (Low / CWE-201)
- **Validation**: Check response body of unauthenticated redirect:
  `curl -i https://staging.kaizo-app.com/dashboard`
- **Fix**: Ensure the route controller exits immediately upon redirect without compiling the view.

### 5. Alert: "Cookie No HttpOnly Flag" / "Cookie without SameSite" (Low / CWE-1004, CWE-1275)
- **Validation**: Inspect `Set-Cookie` response headers in browser DevTools:
  `Set-Cookie: name=val; Secure; HttpOnly; SameSite=Strict; Path=/`
- **Fix**: Use `session-cookie-config.ts` helper for all cookies.

### 6. Alert: "Public Exposure of Relational Database Daemon" (High / CWE-284)
- **Validation**: `nmap -p 5432,3306 -sV <PUBLIC_IP>`
- **Fix**: Bind DB to `127.0.0.1` and close public security group ports immediately.

### 7. Alert: "User Agent Fuzzer" & "Session Management Response" (Informational)
- **Validation**: Ensure application returns clean `400 Bad Request` or `404 Not Found` without stack traces or unhandled 500 errors when scanned with arbitrary user agents.
