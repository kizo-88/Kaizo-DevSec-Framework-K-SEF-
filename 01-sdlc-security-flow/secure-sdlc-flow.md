# 🔁 End-to-End Secure SDLC Flow for Kaizo

> **Goal**: Establish a seamless, developer-friendly Secure Software Development Lifecycle (SSDLC) that shifts security checks left while ensuring zero friction in velocity.

---

## 🧭 The 7-Phase DevSec Flow

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 KAIZO DEVSEC PIPELINE                                  │
└────────────────────────────────────────────────────────────────────────────────────────┘
   │
   ├── Phase 1: Requirements & Threat Modeling
   │   └── Artifact: Threat Model, STRIDE Matrix, Security Acceptance Criteria
   │
   ├── Phase 2: Architecture & Design
   │   └── Artifact: Zero-Trust Network Diagram, Auth Flow, CORS & Session Strategy
   │
   ├── Phase 3: Secure Coding & IDE Feedback
   │   └── Artifact: Pre-commit hooks (.gitleaks), Linting (eslint-plugin-security), SRI Hashes
   │
   ├── Phase 4: CI/CD Automated Security Gates
   │   └── Artifact: SAST (Semgrep/Sonar), SCA (npm audit/Snyk/Trivy), Secret Detection
   │
   ├── Phase 5: Automated Testing & DAST Gates
   │   └── Artifact: OWASP ZAP Baseline/Full Scan, Nuclei API Security Checks
   │
   ├── Phase 6: Secure Deployment & Edge Hardening
   │   └── Artifact: HSTS, CSP, X-Frame-Options, Firewall, DB Isolation (VPC / UFW)
   │
   └── Phase 7: Observability, Caching & Incident Response
       └── Artifact: Cache-Control Audit, Audit Logging, WAF Rate Limiting
```

---

## 🛠️ Phase Breakdown & Developer Responsibilities

### 1. Requirements & Threat Modeling
- **Action**: Before writing backend endpoints or data schemas, identify:
  - What sensitive data is handled? (Passwords, PII, payment info, session tokens).
  - Who interacts with the system? (Unauthenticated public, Authenticated user, Admin).
  - Apply the **STRIDE** model:
    - *Spoofing*: Is identity verified via secure tokens/passwords?
    - *Tampering*: Are inputs validated and hashes verified (e.g. SRI on CDN assets)?
    - *Repudiation*: Are state changes logged with timestamps and user IDs?
    - *Information Disclosure*: Are stack traces, internal timestamps, or DB daemons hidden?
    - *Denial of Service*: Are rate limiters active on login, search, and resource-heavy APIs?
    - *Elevation of Privilege*: Is RBAC/ABAC enforced at the controller and database level?

### 2. Secure Design & Architecture
- **Database Isolation**: Never expose DB ports (`5432`, `3306`, `27017`) to public IP `0.0.0.0`. Restrict to VPC private networks or `127.0.0.1`.
- **Session & State Management**:
  - Prefer **HttpOnly**, **Secure**, **SameSite=Strict/Lax** cookies over `localStorage`.
  - Disable URL session rewriting (`jsessionid` in query parameters).
- **CORS Architecture**: Reject `Access-Control-Allow-Origin: *` with credentials. Maintain a dynamic, strict whitelist of trusted origins.

### 3. Secure Coding & Commit Hooks (Local Dev)
- **Local Secret Scanning**: Enforce `.gitleaks.toml` via Git hooks (`husky` / `pre-commit`).
- **Input Validation**: Use schema libraries (`zod`, `joi`, `pydantic`) on all incoming request bodies, query params, and headers.
- **Frontend Asset Integrity**: Generate Subresource Integrity (SRI) hashes for all third-party CDNs.

### 4. CI/CD Security Pipeline (Automated Quality Gates)
- On every Pull Request:
  1. **Secret Scanning**: Block commits containing private keys, tokens, or Firebase admin credentials.
  2. **SAST (Static Application Security Testing)**: Run Semgrep / SonarQube. Block on High/Critical CWEs.
  3. **SCA (Software Composition Analysis)**: Scan dependencies (`npm audit --audit-level=high`, `trivy fs .`).

### 5. Build, Test & DAST Verification (Staging)
- Deploy ephemeral preview / staging environment.
- Run automated **OWASP ZAP** or **Nuclei** DAST against staging endpoints.
- Check headers:
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options: DENY` (Anti-clickjacking)
  - `X-Content-Type-Options: nosniff`
  - `Strict-Transport-Security` (HSTS)
  - `Cache-Control` on authenticated routes

### 6. Deployment & Infrastructure Hardening
- **Edge Layer (Cloudflare / Nginx / ALB)**:
  - Force HTTPS with HTTP 301 redirects.
  - Enforce HSTS with preload.
  - Strip redundant backend headers (`Server`, `X-Powered-By`).
- **Network Layer**:
  - DB Daemon bound only to internal loopback / private VPC subnet.
  - SSH access restricted to bastion host with key-based authentication.

### 7. Observability, Caching & Runtime Protection
- **Cache Directives**: Ensure responses containing user session state or PII use `Cache-Control: no-store, no-cache, must-revalidate, private`.
- **WAF & Rate Limiting**: Protect against aggressive scanners and User-Agent fuzzing.
- **Audit Logging**: Store structured JSON logs (without logging raw secrets, passwords, or full credit card numbers).
