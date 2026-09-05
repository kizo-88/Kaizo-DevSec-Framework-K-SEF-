# 🚀 New Project Security Starter Kit (Day-0 Setup)

> **For Kaizo**: Every time you initialize a new repository or start building a project, follow this exact Day-0 checklist and drop in these standardized boilerplate files before writing business logic.

---

## 📋 Day-0 Initialization Checklist

```
[New Repository Created]
       │
       ├── 1. Setup Safe Git & Ignore Rules (.gitignore, .env.example)
       ├── 2. Configure Local Secret Scanner (.gitleaks.toml + Husky pre-commit)
       ├── 3. Setup Strict Linting (eslint-plugin-security / TypeScript strict)
       ├── 4. Configure Secure Environment Variable Validation (Zod / Joi)
       ├── 5. Drop In Security Headers Middleware (Helmet / Nginx / Next.js)
       ├── 6. Configure Production-Hardened Container (Non-root Dockerfile)
       └── 7. Define Health & Readiness Endpoints (/healthz, /readyz)
```

---

## 📁 1. The Essential Starter Files Matrix

Every new repository should immediately contain the following baseline files:

```
my-new-project/
├── .env.example               # Template of all required keys with dummy values (NEVER real secrets)
├── .env.local                 # Local secrets (INCLUDED IN .gitignore!)
├── .gitignore                 # Blocks .env, keys, certificates, node_modules, build artifacts
├── .gitleaks.toml             # Local secret scanning configuration
├── .husky/
│   └── pre-commit             # Automated pre-commit hook running gitleaks & linter
├── src/
│   ├── config/
│   │   └── env.ts             # Runtime schema validation for environment variables
│   ├── middleware/
│   │   └── security.ts        # Security headers, CORS, rate limiting, and request sanitization
│   └── lib/
│       └── db.ts              # Connection pooling, SSL enforcement, and parameterization
├── Dockerfile                 # Multi-stage non-root container build
└── docker-compose.yml         # Isolated local dev services (Postgres, Redis on 127.0.0.1)
```

---

## ⚙️ 2. Step-by-Step Setup Commands

### Step 1: Initialize Git & Pre-commit Hooks
```bash
# 1. Initialize Git
git init

# 2. Install Husky & Lint-Staged
npm install -D husky lint-staged

# 3. Initialize Husky
npx husky init

# 4. Create Pre-commit Hook
cat << 'EOF' > .husky/pre-commit
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

echo "🔍 Running Pre-Commit Security Checks..."

# Run Gitleaks secret detection on staged files
if command -v gitleaks &> /dev/null; then
    gitleaks protect --staged --verbose
else
    echo "⚠️ Gitleaks not installed locally. Run: brew install gitleaks or choco install gitleaks"
fi

# Run Linter & Tests
npx lint-staged
EOF

chmod +x .husky/pre-commit
```

### Step 2: Install Essential Security Packages
```bash
# Core Node.js / Express security packages
npm install helmet cors express-rate-limit zod dotenv
npm install -D eslint-plugin-security @typescript-eslint/eslint-plugin
```

---

## 🔒 3. Safe Environment Variable Validator (`src/config/env.ts`)

> **Why?** Prevents server startup if critical security keys (JWT secret, DB password, API keys) are missing or too weak.

```typescript
import { z } from 'zod';
import dotenv from 'dotenv';

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.string().default('4000').transform(Number),
  
  // Database URL
  DATABASE_URL: z.string().url(),
  
  // Authentication Secrets (Enforce min length for cryptographic strength)
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters long'),
  SESSION_SECRET: z.string().min(32, 'SESSION_SECRET must be at least 32 characters long'),
  
  // CORS & Allowed Origins
  ALLOWED_ORIGINS: z.string().transform((val) => val.split(',')),
  
  // External API keys
  PAYMENT_GATEWAY_SECRET: z.string().min(1).optional(),
});

const _env = envSchema.safeParse(process.env);

if (!_env.success) {
  console.error('❌ FATAL: Invalid environment variables:');
  console.error(JSON.stringify(_env.error.format(), null, 2));
  process.exit(1); // Stop execution immediately on invalid config
}

export const ENV = _env.data;
```

---

## 📦 4. Multi-Stage Non-Root Dockerfile

> **Why?** Running containers as `root` allows container escape vulnerabilities. Multi-stage builds keep build tools, source code, and secrets out of the production image.

```dockerfile
# ------------------------------------------------------------------------------
# Stage 1: Build Dependencies & Compile
# ------------------------------------------------------------------------------
FROM node:20-alpine AS builder

WORKDIR /app

# Copy dependency definitions
COPY package*.json ./
RUN npm ci

# Copy source and build
COPY . .
RUN npm run build && npm prune --production

# ------------------------------------------------------------------------------
# Stage 2: Minimal Production Runtime
# ------------------------------------------------------------------------------
FROM node:20-alpine AS runner

WORKDIR /app

# Set production environment
ENV NODE_ENV=production

# Create non-root user and group
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 appuser

# Copy only compiled code and production modules
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist

# Assign ownership to non-root user
USER appuser

# Expose app port
EXPOSE 4000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:4000/healthz || exit 1

CMD ["node", "dist/server.js"]
```
