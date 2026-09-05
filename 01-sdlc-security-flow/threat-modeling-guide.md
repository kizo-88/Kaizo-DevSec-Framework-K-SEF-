# 🧠 STRIDE Threat Modeling & Risk Scoring Guide for Developers

> **Author**: Kaizo  
> **Purpose**: A pragmatic, developer-first framework to identify vulnerabilities and design flaws before writing a single line of code.

---

## 🎯 STRIDE Model Mapped to Common Developer Flaws

| Category | Description | Developer Scenario Example | Corresponding Finding / CWE |
| :--- | :--- | :--- | :--- |
| **S - Spoofing** | Pretending to be someone or something else. | Attacker replays stolen session cookies or crafts forged requests. | `CWE-352` (Missing CSRF), `CWE-1004` (Cookie No HttpOnly), `CWE-1275` (SameSite None) |
| **T - Tampering** | Modifying data or code unauthorized. | Third-party script altered on CDN; MITM tampering with unencrypted traffic. | `CWE-345` (SRI Missing), `CWE-311` (HTTPS via HTTP), `CWE-319` (HSTS Missing) |
| **R - Repudiation** | Claiming not to have performed an action. | User performs admin operation, but server lacks user audit logging. | Audit Log Absence, Missing User-Action Nonces |
| **I - Information Disclosure** | Exposing sensitive data to unauthorized parties. | Exposing DB daemon, leaking passwords in JS bundles, URL query leaks, caching. | `CWE-798` (Hardcoded Creds), `CWE-284` (DB Exposure), `CWE-598` (Session in URL), `CWE-525` (Cache Leaks), `CWE-497` (Timestamp Leak) |
| **D - Denial of Service** | Making a system or resource unavailable. | Uncapped API endpoints, unindexed database queries, regex denial of service. | ReDoS, Unthrottled Resource Consumption |
| **E - Elevation of Privilege** | Gaining capabilities beyond authorized role. | Cross-domain iframe hijacking (Clickjacking), CORS misconfiguration. | `CWE-1021` (Clickjacking), `CWE-264` (CORS Misconfiguration), `CWE-693` (CSP Missing) |

---

## 📐 Threat Modeling Workflow for Every New Feature

```
1. Draw Data Flow Diagram (DFD)
   ├── Client (Browser/Mobile App)
   ├── Edge / Reverse Proxy (Nginx/Cloudflare)
   ├── Application Server (Node/FastAPI/Go/Java)
   └── Storage (Postgres/MySQL/Redis)

2. Identify Trust Boundaries
   ├── [Boundary A] Client <── untrusted internet ──> Edge Proxy
   ├── [Boundary B] Edge Proxy <── internal network ──> App Server
   └── [Boundary C] App Server <── private subnet ──> Database

3. Enumerate Threats using STRIDE Matrix
   ├── At Boundary A: Is HTTPS enforced? Are security headers set? Is CSRF mitigated?
   ├── At Boundary B: Are origin headers sanitized? Are internal ports exposed?
   └── At Boundary C: Is DB daemon bound strictly to 127.0.0.1 or VPC private IP?

4. Define Security Acceptance Criteria (SAC)
   └── Document in Jira/Linear issue before sprint execution.
```

---

## 🔢 DREAD Risk Scoring Calculator

To prioritize remediations and vulnerabilities, Kaizo uses the **DREAD** framework (Score: 1 - 10 per category; Risk = `(D + R + E + A + D) / 5`):

- **Damage Potential**: How severe is the harm if exploited? (1 = None, 10 = Full DB compromised).
- **Reproducibility**: How easy is it to repeat the attack? (1 = Difficult edge case, 10 = Simple web request).
- **Exploitability**: What skill level is needed? (1 = Advanced 0-day exploit, 10 = Browser URL navigation).
- **Affected Users**: How many users impacted? (1 = Edge case user, 10 = All users / entire system).
- **Discoverability**: How visible is the vulnerability? (1 = Hidden source logic, 10 = Open DB port or public JS bundle).

### Risk Classification Thresholds:
- **Score 8.0 - 10.0**: **CRITICAL** (Stop deployment immediately; fix in < 24 hrs).
- **Score 6.0 - 7.9**: **HIGH** (Fix before next release).
- **Score 4.0 - 5.9**: **MEDIUM** (Schedule in active sprint).
- **Score 1.0 - 3.9**: **LOW / INFORMATIONAL** (Harden in standard maintenance cycle).
