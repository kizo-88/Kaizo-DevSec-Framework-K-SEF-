#!/usr/bin/env node

/**
 * ==============================================================================
 * 🛡️ KAIZO DEVSEC FRAMEWORK (K-SEF) CLI
 * Zero-dependency, instantaneous security scaffolding, auditing & rule generator.
 * ==============================================================================
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');
const crypto = require('crypto');
const https = require('https');
const http = require('http');

const VERSION = '1.1.0';

// ANSI Terminal Colors
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgBlue: '\x1b[44m',
  bgRed: '\x1b[41m',
};

function banner() {
  console.log(`
${colors.cyan}${colors.bright}  ███████╗      ███████╗███████╗███████╗
  ██╔═══██╗     ██╔════╝██╔════╝██╔════╝
  ██║   ██║     ███████╗█████╗  █████╗  
  ██║   ██║     ╚════██║██╔══╝  ██╔══╝  
  ███████╔╝██╗  ███████║███████╗██║     
  ╚══════╝ ╚═╝  ╚══════╝╚══════╝╚═╝     ${colors.reset}
  ${colors.bright}Kaizo DevSec Framework (K-SEF) CLI v${VERSION}${colors.reset}
  ${colors.dim}Automated Security Scaffolding, Auditing & Guardrails${colors.reset}
`);
}

// ------------------------------------------------------------------------------
// TEMPLATES REPOSITORY (Embedded for zero-dependency portability)
// ------------------------------------------------------------------------------

const TEMPLATES = {
  gitleaks: `# ==============================================================================
# Kaizo DevSec Framework - Gitleaks Secret Detection Rules (CWE-798)
# ==============================================================================
title = "Kaizo DevSec Gitleaks Configuration"

[extend]
useDefault = true

[[rules]]
description = "Generic High-Entropy Admin Secret / API Key"
id = "kaizo-generic-admin-secret"
regex = '''(?i)(admin[_-]?secret|service[_-]?secret|master[_-]?key|jwt[_-]?secret)\s*[:=]\s*['"][a-zA-Z0-9_\\-\\.]{16,}['"]'''
entropy = 3.5
keywords = ["admin_secret", "service_secret", "master_key", "jwt_secret"]

[[rules]]
description = "Hardcoded Database Connection URI"
id = "kaizo-database-connection-uri"
regex = '''(?i)(postgres|postgresql|mysql|mongodb|redis):\\/\\/[a-zA-Z0-9_\\-]+:[a-zA-Z0-9_\\-\\.\\@\\$\\%\\^\\&\\*]+@[a-zA-Z0-9_\\-\\.]+:[0-9]+\\/[a-zA-Z0-9_\\-]+'''
keywords = ["postgres://", "postgresql://", "mysql://", "mongodb://", "redis://"]

[allowlist]
paths = ['''(^|/)(test|tests|spec|specs|fixtures)/''', '''package-lock\\.json''', '''pnpm-lock\\.yaml''']
`,

  gitignore: `# ==============================================================================
# Kaizo DevSec - Secure .gitignore Baseline (CWE-798 Prevention)
# ==============================================================================
node_modules/
dist/
build/
out/
.next/
*.map
.env
.env.local
.env.development.local
.env.test.local
.env.production.local
*.env
*.pem
*.key
*.crt
serviceAccountKey.json
firebase-adminsdk*.json
credentials.json
coverage/
logs/
*.log
`,

  envExample: `# ==============================================================================
# ENVIRONMENT CONFIGURATION TEMPLATE (.env.example)
# ==============================================================================
NODE_ENV=development
PORT=4000
DATABASE_URL=postgresql://app_user:strong_password@127.0.0.1:5432/app_db?sslmode=prefer
JWT_SECRET=replace_with_min_32_chars_random_secret_string_here
SESSION_SECRET=replace_with_min_32_chars_random_session_secret
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:4000
`,

  envValidator: `import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.string().default('4000').transform(Number),
  DATABASE_URL: z.string().url(),
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  SESSION_SECRET: z.string().min(32, 'SESSION_SECRET must be at least 32 characters'),
  ALLOWED_ORIGINS: z.string().transform((val) => val.split(',')),
});

const _env = envSchema.safeParse(process.env);
if (!_env.success) {
  console.error('❌ FATAL: Invalid environment variables:');
  console.error(JSON.stringify(_env.error.format(), null, 2));
  process.exit(1);
}

export const ENV = _env.data;
`,

  securityBootstrapExpress: `import express, { Express, Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';

export function initAppSecurity(app: Express, allowedOrigins: string[] = ['http://localhost:3000']) {
  app.disable('x-powered-by');
  app.use(express.json({ limit: '100kb' }));

  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:', 'https:'],
          objectSrc: ["'none'"],
          frameAncestors: ["'none'"], // Anti-Clickjacking (CWE-1021)
          upgradeInsecureRequests: [],
        },
      },
      hsts: { maxAge: 63072000, includeSubDomains: true, preload: true }, // HSTS (CWE-319)
      noSniff: true, // MIME Sniffing (CWE-693)
      frameguard: { action: 'deny' },
    })
  );

  app.use(
    cors({
      origin: (origin, cb) => {
        if (!origin || allowedOrigins.includes(origin)) cb(null, true);
        else cb(new Error('Blocked by CORS policy'));
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    })
  );

  const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    message: { error: 'Too many requests, please try again later.' },
  });
  app.use('/api/', limiter);

  app.get('/healthz', (req: Request, res: Response) => {
    res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() });
  });

  return app;
}
`,

  nextjsConfig: `import type { NextConfig } from 'next';

const isProd = process.env.NODE_ENV === 'production';

const cspHeader = \`
  default-src 'self';
  script-src 'self' \${isProd ? '' : "'unsafe-eval'"} 'unsafe-inline';
  style-src 'self' 'unsafe-inline';
  img-src 'self' blob: data: https:;
  font-src 'self';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
  upgrade-insecure-requests;
\`.replace(/\\s{2,}/g, ' ').trim();

const securityHeaders = [
  { key: 'Content-Security-Policy', value: cspHeader },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
];

const nextConfig: NextConfig = {
  poweredByHeader: false,
  productionBrowserSourceMaps: false,
  async headers() {
    return [
      { source: '/(.*)', headers: securityHeaders },
      { source: '/api/(.*)', headers: [{ key: 'Cache-Control', value: 'no-store, no-cache, must-revalidate, private' }] },
    ];
  },
};

export default nextConfig;
`,

  dockerfile: `# Production Hardened Multi-Stage Non-Root Dockerfile
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build && npm prune --production

FROM node:20-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 appuser
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
USER appuser
EXPOSE 4000
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:4000/healthz || exit 1
CMD ["node", "dist/server.js"]
`,

  githubWorkflow: `name: Kaizo DevSec Security Gate

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
          GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}

  sast-and-audit:
    name: Dependency Audit & SAST
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - name: Install & Audit
        run: |
          npm ci
          npm audit --audit-level=high
`,

  supabaseRLS: `-- Supabase Production Row-Level Security Baseline
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can read own profile" ON public.profiles FOR SELECT TO authenticated USING ((SELECT auth.uid()) = id);
CREATE POLICY "Users can update own profile" ON public.profiles FOR UPDATE TO authenticated USING ((SELECT auth.uid()) = id) WITH CHECK ((SELECT auth.uid()) = id);

CREATE POLICY "Users access own documents" ON public.documents FOR ALL TO authenticated USING (user_id = (SELECT auth.uid()));
`,

  firestoreRules: `rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} { allow read, write: if false; } // Default Deny

    match /users/{userId} {
      allow read: if request.auth != null;
      allow create: if request.auth != null && request.auth.uid == userId && request.resource.data.role == 'user';
      allow update: if request.auth != null && request.auth.uid == userId && !request.resource.data.diff(resource.data).affectedKeys().hasAny(['role', 'createdAt']);
    }
  }
}
`,

  vmHardeningScript: `#!/usr/bin/env bash
set -euo pipefail
echo "🛡️ Hardening Linux VM..."
apt-get update -y && apt-get install -y ufw fail2ban unattended-upgrades
echo 'APT::Periodic::Update-Package-Lists "1";' > /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Unattended-Upgrade "1";' >> /etc/apt/apt.conf.d/20auto-upgrades
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw --force enable
systemctl enable fail2ban && systemctl restart fail2ban
echo "✅ VM Hardened Successfully!"
`
};

// ------------------------------------------------------------------------------
// HELPER FUNCTIONS
// ------------------------------------------------------------------------------

function writeFileSafely(targetPath, content, label) {
  const dir = path.dirname(targetPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(targetPath, content, 'utf8');
  console.log(`  ${colors.green}✔ Created${colors.reset} ${label || targetPath}`);
}

function promptQuestion(rl, query) {
  return new Promise((resolve) => {
    rl.question(query, (ans) => {
      resolve(ans.trim());
    });
  });
}

// ------------------------------------------------------------------------------
// COMMAND: INIT (Interactive or Quick Generator)
// ------------------------------------------------------------------------------

async function commandInit(args) {
  banner();
  console.log(`${colors.bright}🚀 Initializing Kaizo DevSec Scaffolding into current project...${colors.reset}\n`);

  const cwd = process.cwd();
  const isYes = args.includes('-y') || args.includes('--yes');
  let framework = 'nextjs';
  let platform = 'all';

  if (!isYes) {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    console.log(`${colors.cyan}Select your primary stack:${colors.reset}`);
    console.log(`  [1] Next.js / React (App Router)`);
    console.log(`  [2] Node.js / Express / Fastify`);
    console.log(`  [3] Supabase Fullstack App`);
    console.log(`  [4] Firebase Fullstack App`);
    console.log(`  [5] Full Enterprise Guardrails (All Modules)`);

    const stackChoice = await promptQuestion(rl, `Choice [1-5] (default: 1): `);
    if (stackChoice === '2') framework = 'express';
    else if (stackChoice === '3') framework = 'supabase';
    else if (stackChoice === '4') framework = 'firebase';
    else if (stackChoice === '5') framework = 'all';

    rl.close();
  }

  console.log(`\n${colors.bright}📦 Injecting Security Guardrails...${colors.reset}\n`);

  // 1. Core Base Files
  writeFileSafely(path.join(cwd, '.gitleaks.toml'), TEMPLATES.gitleaks, '.gitleaks.toml (Secret Scanner Rules)');
  writeFileSafely(path.join(cwd, '.gitignore'), TEMPLATES.gitignore, '.gitignore (Key & Token Blocker)');
  writeFileSafely(path.join(cwd, '.env.example'), TEMPLATES.envExample, '.env.example (Environment Template)');
  writeFileSafely(path.join(cwd, '.github', 'workflows', 'security-gate.yml'), TEMPLATES.githubWorkflow, '.github/workflows/security-gate.yml (CI/CD Pipeline)');
  writeFileSafely(path.join(cwd, 'Dockerfile'), TEMPLATES.dockerfile, 'Dockerfile (Non-root Multi-Stage Container)');

  // 2. Framework Specific Files
  if (framework === 'nextjs' || framework === 'all') {
    writeFileSafely(path.join(cwd, 'src', 'config', 'security-headers.ts'), TEMPLATES.nextjsConfig, 'src/config/security-headers.ts (CSP/HSTS Next.js Config)');
  }

  if (framework === 'express' || framework === 'all') {
    writeFileSafely(path.join(cwd, 'src', 'middleware', 'security-bootstrap.ts'), TEMPLATES.securityBootstrapExpress, 'src/middleware/security-bootstrap.ts (Express Helmet/CORS/RateLimit)');
    writeFileSafely(path.join(cwd, 'src', 'config', 'env.ts'), TEMPLATES.envValidator, 'src/config/env.ts (Zod Env Validator)');
  }

  if (framework === 'supabase' || framework === 'all') {
    writeFileSafely(path.join(cwd, 'supabase', 'migrations', '00_rls_security_baseline.sql'), TEMPLATES.supabaseRLS, 'supabase/migrations/00_rls_security_baseline.sql (Supabase RLS)');
  }

  if (framework === 'firebase' || framework === 'all') {
    writeFileSafely(path.join(cwd, 'firestore.rules'), TEMPLATES.firestoreRules, 'firestore.rules (Firestore Security Rules)');
  }

  // 3. Linux VM Hardening Script
  writeFileSafely(path.join(cwd, 'scripts', 'vm-hardening.sh'), TEMPLATES.vmHardeningScript, 'scripts/vm-hardening.sh (Linux VM Hardening Script)');

  console.log(`
${colors.green}${colors.bright}🎉 K-SEF Security Scaffolding Successfully Applied!${colors.reset}

${colors.bright}Next Steps for Kaizo:${colors.reset}
  1. ${colors.cyan}npm install helmet cors express-rate-limit zod dotenv${colors.reset}
  2. Run local audit: ${colors.yellow}npx kaizo-devsec audit${colors.reset}
  3. Commit safely: ${colors.dim}git add . && git commit -m "chore: setup K-SEF security guardrails"${colors.reset}
`);
}

// ------------------------------------------------------------------------------
// COMMAND: AUDIT (Local Static Security Auditor)
// ------------------------------------------------------------------------------

function commandAudit() {
  banner();
  console.log(`${colors.bright}🔍 Running Kaizo DevSec Local Static Security Audit...${colors.reset}\n`);

  const cwd = process.cwd();
  let score = 100;
  const issues = [];
  const passes = [];

  // Check 1: Leaked .env in Git
  if (fs.existsSync(path.join(cwd, '.env'))) {
    const gitignorePath = path.join(cwd, '.gitignore');
    if (!fs.existsSync(gitignorePath) || !fs.readFileSync(gitignorePath, 'utf8').includes('.env')) {
      score -= 25;
      issues.push({ severity: 'CRITICAL', cwe: 'CWE-798', msg: '.env file exists but is NOT listed in .gitignore! Secrets risk git leak.' });
    } else {
      passes.push('.env is safely ignored in .gitignore');
    }
  }

  // Check 2: .gitleaks.toml Secret Scanner
  if (fs.existsSync(path.join(cwd, '.gitleaks.toml'))) {
    passes.push('.gitleaks.toml secret scanner rules present');
  } else {
    score -= 15;
    issues.push({ severity: 'HIGH', cwe: 'CWE-798', msg: 'Missing .gitleaks.toml secret scanning configuration.' });
  }

  // Check 3: Security Headers Config
  const hasHeaders = fs.existsSync(path.join(cwd, 'src', 'config', 'security-headers.ts')) ||
                     fs.existsSync(path.join(cwd, 'src', 'middleware', 'security-bootstrap.ts')) ||
                     fs.existsSync(path.join(cwd, 'next.config.js')) ||
                     fs.existsSync(path.join(cwd, 'next.config.ts'));

  if (hasHeaders) {
    passes.push('Security headers (CSP/HSTS/Clickjacking) configuration detected');
  } else {
    score -= 15;
    issues.push({ severity: 'MEDIUM', cwe: 'CWE-693', msg: 'No security headers (CSP/HSTS/Nosniff) middleware detected in src/ or next.config.' });
  }

  // Check 4: Dockerfile Non-Root User
  const dockerfilePath = path.join(cwd, 'Dockerfile');
  if (fs.existsSync(dockerfilePath)) {
    const dockerfileContent = fs.readFileSync(dockerfilePath, 'utf8');
    if (dockerfileContent.includes('USER appuser') || dockerfileContent.includes('USER node') || dockerfileContent.includes('USER 1001')) {
      passes.push('Dockerfile enforces non-root user execution');
    } else {
      score -= 10;
      issues.push({ severity: 'MEDIUM', cwe: 'CWE-250', msg: 'Dockerfile runs as root user. Add "USER appuser".' });
    }
  }

  // Check 5: CI/CD Security Gate
  if (fs.existsSync(path.join(cwd, '.github', 'workflows', 'security-gate.yml')) || fs.existsSync(path.join(cwd, '.github', 'workflows', 'security.yml'))) {
    passes.push('GitHub Actions automated security gate pipeline detected');
  } else {
    score -= 10;
    issues.push({ severity: 'LOW', cwe: 'CWE-16', msg: 'Missing automated CI/CD security gate in .github/workflows/.' });
  }

  // Display Passes
  passes.forEach(p => console.log(`  ${colors.green}✔ PASS:${colors.reset} ${p}`));

  // Display Issues
  if (issues.length > 0) {
    console.log(`\n${colors.yellow}${colors.bright}⚠️ Security Findings & Recommendations:${colors.reset}`);
    issues.forEach(iss => {
      const color = iss.severity === 'CRITICAL' ? colors.red : iss.severity === 'HIGH' ? colors.magenta : colors.yellow;
      console.log(`  ${color}[${iss.severity}]${colors.reset} [${iss.cwe}] ${iss.msg}`);
    });
  }

  // Score Summary
  let grade = 'A+';
  let gradeColor = colors.green;
  if (score < 60) { grade = 'F (Failing)'; gradeColor = colors.red; }
  else if (score < 75) { grade = 'C (Needs Remediation)'; gradeColor = colors.yellow; }
  else if (score < 90) { grade = 'B (Good)'; gradeColor = colors.blue; }

  console.log(`\n----------------------------------------------------------`);
  console.log(`🛡️  ${colors.bright}K-SEF Security Posture Grade:${colors.reset} ${gradeColor}${colors.bright}${grade} (${score}/100)${colors.reset}`);
  console.log(`----------------------------------------------------------\n`);
  if (score < 90) {
    console.log(`Run ${colors.cyan}npx kaizo-devsec init${colors.reset} to automatically remediate missing controls.\n`);
  }
}

// ------------------------------------------------------------------------------
// COMMAND: SRI (Subresource Integrity Generator)
// ------------------------------------------------------------------------------

async function commandSRI(target) {
  banner();
  if (!target) {
    console.error(`${colors.red}❌ Error: Please provide a URL or local file path.${colors.reset}`);
    console.log(`Usage: npx kaizo-devsec sri https://cdnjs.cloudflare.com/.../axios.min.js\n`);
    process.exit(1);
  }

  console.log(`🔐 Generating Subresource Integrity (SRI) for: ${colors.cyan}${target}${colors.reset}\n`);

  try {
    let buffer;
    if (target.startsWith('http://') || target.startsWith('https://')) {
      buffer = await new Promise((resolve, reject) => {
        const client = target.startsWith('https') ? https : http;
        client.get(target, (res) => {
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            return resolve(commandSRI(res.headers.location));
          }
          const chunks = [];
          res.on('data', chunk => chunks.push(chunk));
          res.on('end', () => resolve(Buffer.concat(chunks)));
          res.on('error', err => reject(err));
        });
      });
    } else {
      buffer = fs.readFileSync(path.resolve(target));
    }

    const hash = crypto.createHash('sha384').update(buffer).digest('base64');
    const integrity = `sha384-${hash}`;
    const isCss = target.endsWith('.css');

    console.log(`  ${colors.bright}Integrity Hash:${colors.reset} ${colors.green}${integrity}${colors.reset}\n`);
    console.log(`  ${colors.bright}Ready HTML Snippet:${colors.reset}`);
    if (isCss) {
      console.log(`  ${colors.yellow}<link rel="stylesheet" href="${target}" integrity="${integrity}" crossorigin="anonymous" referrerpolicy="no-referrer">${colors.reset}`);
    } else {
      console.log(`  ${colors.yellow}<script src="${target}" integrity="${integrity}" crossorigin="anonymous" referrerpolicy="no-referrer"></script>${colors.reset}`);
    }
    console.log('');
  } catch (err) {
    console.error(`${colors.red}❌ Failed to fetch/generate SRI: ${err.message}${colors.reset}\n`);
  }
}

// ------------------------------------------------------------------------------
// COMMAND: RULES
// ------------------------------------------------------------------------------

function commandRules(target) {
  banner();
  const cwd = process.cwd();
  if (!target || target === 'help') {
    console.log(`Available rule targets:`);
    console.log(`  ${colors.cyan}npx kaizo-devsec rules supabase${colors.reset}  -> Drops supabase RLS sql`);
    console.log(`  ${colors.cyan}npx kaizo-devsec rules firebase${colors.reset}  -> Drops firestore.rules`);
    console.log(`  ${colors.cyan}npx kaizo-devsec rules docker${colors.reset}    -> Drops hardened Dockerfile`);
    console.log(`  ${colors.cyan}npx kaizo-devsec rules vm${colors.reset}        -> Drops Linux VM hardening script`);
    console.log('');
    return;
  }

  if (target === 'supabase') {
    writeFileSafely(path.join(cwd, 'supabase-rls-baseline.sql'), TEMPLATES.supabaseRLS, 'supabase-rls-baseline.sql');
  } else if (target === 'firebase') {
    writeFileSafely(path.join(cwd, 'firestore.rules'), TEMPLATES.firestoreRules, 'firestore.rules');
  } else if (target === 'docker') {
    writeFileSafely(path.join(cwd, 'Dockerfile'), TEMPLATES.dockerfile, 'Dockerfile');
  } else if (target === 'vm') {
    writeFileSafely(path.join(cwd, 'vm-hardening.sh'), TEMPLATES.vmHardeningScript, 'vm-hardening.sh');
  } else {
    console.log(`${colors.red}Unknown rule target: ${target}${colors.reset}`);
  }
}

// ------------------------------------------------------------------------------
// MAIN CLI ROUTER
// ------------------------------------------------------------------------------

function showHelp() {
  banner();
  console.log(`${colors.bright}Usage:${colors.reset}`);
  console.log(`  ${colors.cyan}npx kaizo-devsec <command> [options]${colors.reset}`);
  console.log(`  ${colors.cyan}k-sef <command> [options]${colors.reset}\n`);
  console.log(`${colors.bright}Commands:${colors.reset}`);
  console.log(`  ${colors.green}init${colors.reset}                 Interactive wizard to scaffold security guardrails into any project`);
  console.log(`  ${colors.green}init -y, --yes${colors.reset}       Quick non-interactive scaffolding with all defaults`);
  console.log(`  ${colors.green}audit${colors.reset}                Run local static security posture audit on current repository`);
  console.log(`  ${colors.green}sri <url|file>${colors.reset}       Generate Subresource Integrity (SRI) hash and HTML tag`);
  console.log(`  ${colors.green}rules <target>${colors.reset}       Generate specific rule file (supabase | firebase | docker | vm)`);
  console.log(`  ${colors.green}--version, -v${colors.reset}        Print CLI version`);
  console.log(`  ${colors.green}--help, -h${colors.reset}           Show this help message\n`);
  console.log(`${colors.bright}Examples:${colors.reset}`);
  console.log(`  ${colors.dim}$ npx kaizo-devsec init${colors.reset}`);
  console.log(`  ${colors.dim}$ npx kaizo-devsec audit${colors.reset}`);
  console.log(`  ${colors.dim}$ npx kaizo-devsec sri https://cdnjs.cloudflare.com/ajax/libs/axios/1.6.8/axios.min.js${colors.reset}`);
  console.log(`  ${colors.dim}$ npx kaizo-devsec rules supabase${colors.reset}\n`);
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === '--help' || command === '-h') {
    showHelp();
    return;
  }

  if (command === '--version' || command === '-v') {
    console.log(`v${VERSION}`);
    return;
  }

  switch (command) {
    case 'init':
      await commandInit(args);
      break;
    case 'audit':
      commandAudit();
      break;
    case 'sri':
      await commandSRI(args[1]);
      break;
    case 'rules':
      commandRules(args[1]);
      break;
    default:
      console.error(`${colors.red}Unknown command: ${command}${colors.reset}\n`);
      showHelp();
      process.exit(1);
  }
}

main().catch((err) => {
  console.error(`\n${colors.red}❌ Error:${colors.reset}`, err.message);
  process.exit(1);
});
