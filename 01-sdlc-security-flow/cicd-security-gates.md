# 🚦 CI/CD Automated Security Gates & Pipeline Architecture

> **Author**: Kaizo  
> **Goal**: Automate security enforcement in GitHub Actions, GitLab CI, or Jenkins so no vulnerable code reaches production.

---

## 🏗️ Pipeline Architecture Diagram

```
[Developer Git Push]
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 1: Fast Local/PR Gates (< 2 min)                     │
│ ├─ Gitleaks (Secret & Token Detection)                      │
│ ├─ ESLint Security & Static Type Checks                     │
│ └─ SRI Hash Verification for Client Assets                  │
└─────────────────────────────────────────────────────────────┘
         │ (Pass)
         ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 2: Deep Build Gates (< 5 min)                         │
│ ├─ Semgrep / Sonar SAST (CWE Ruleset)                       │
│ ├─ Dependency Vulnerability Scanning (npm audit / Trivy)    │
│ └─ Dockerfile / IaC Security (Hadolint / Checkov)           │
└─────────────────────────────────────────────────────────────┘
         │ (Pass)
         ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 3: Preview/Staging Environment Deployment            │
│ └─ Ephemeral deployment on isolated staging VPC             │
└─────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 4: DAST & Dynamic Verification (< 10 min)             │
│ ├─ OWASP ZAP Baseline Scan (Header & Cookie verification)   │
│ ├─ Nuclei Scan (CORS, Misconfigs, Exposed DB Ports)        │
│ └─ SSL / TLS Configuration Scan (testssl.sh)                │
└─────────────────────────────────────────────────────────────┘
         │ (Pass)
         ▼
┌─────────────────────────────────────────────────────────────┐
│ Stage 5: Production Deployment Gate                         │
│ └─ Production Edge WAF & Monitoring Activated               │
└─────────────────────────────────────────────────────────────┘
```

---

## 📋 Security Gate Policy Rules (Pass / Fail Criteria)

| Tool Category | Tool Example | Fail Conditions (Breaks Build) | Warning Conditions (Logs Alert) |
| :--- | :--- | :--- | :--- |
| **Secret Scanning** | Gitleaks / Trufflehog | Any leaked secret, private key, Firebase admin credential | Potential high-entropy string in test fixtures |
| **SAST** | Semgrep / SonarQube | Any **Critical** or **High** CWE (e.g. CWE-798, CWE-89, CWE-352) | Medium/Low findings in non-critical modules |
| **SCA (Dependencies)**| npm audit / Snyk / Trivy | Any dependency with CVSS >= 7.5 (High/Critical) without patch | Unused dev-dependencies with low CVEs |
| **DAST Scanning** | OWASP ZAP / Nuclei | Missing CSP, Missing Anti-Clickjacking, Open DB Ports, CORS `*` with credentials | Informational scanner notices, timestamp leaks |
| **IaC / Config** | Checkov / Tfsec | Database security groups exposing port 5432/3306 to `0.0.0.0/0` | Non-blocking tag warnings |

---

## 🛠️ Production-Ready GitHub Actions Workflow (`.github/workflows/security-gate.yml`)

```yaml
name: Kaizo DevSec Automated Gate

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  secret-scan:
    name: Secret & Credential Detection
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Run Gitleaks
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}

  sast-and-sca:
    name: SAST & Dependency Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'
      - name: Install Dependencies
        run: npm ci
      - name: Run Dependency Vulnerability Scan (SCA)
        run: npm audit --audit-level=high
      - name: Run Semgrep SAST
        uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/security-audit
            p/secrets
            p/owasp-top-ten

  dast-verification:
    name: OWASP ZAP DAST Baseline Scan
    needs: [secret-scan, sast-and-sca]
    runs-on: ubuntu-latest
    if: github.event_name == 'pull_request'
    steps:
      - uses: actions/checkout@v4
      - name: Run OWASP ZAP Baseline Scan against Staging
        uses: zaproxy/action-baseline@v0.12.0
        with:
          target: 'https://staging.kaizo-app.internal'
          rules_file_name: '.zap/rules.tsv'
          fail_action: true
```
