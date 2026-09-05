/**
 * ==============================================================================
 * Kaizo DevSec Framework - Next.js Modern Security Headers Configuration
 * Use in: next.config.ts / next.config.js or middleware.ts
 * Mitigates: CWE-693, CWE-1021, CWE-319, CWE-525, CWE-345
 * ==============================================================================
 */

import type { NextConfig } from 'next';

const isProd = process.env.NODE_ENV === 'production';

// Strict Content Security Policy definition
const cspHeader = `
  default-src 'self';
  script-src 'self' ${isProd ? '' : "'unsafe-eval'"} 'unsafe-inline';
  style-src 'self' 'unsafe-inline';
  img-src 'self' blob: data: https:;
  font-src 'self';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
  block-all-mixed-content;
  upgrade-insecure-requests;
`.replace(/\s{2,}/g, ' ').trim();

const securityHeaders = [
  // 1. Content Security Policy (CWE-693)
  {
    key: 'Content-Security-Policy',
    value: cspHeader,
  },
  // 2. Anti-Clickjacking (CWE-1021)
  {
    key: 'X-Frame-Options',
    value: 'DENY',
  },
  // 3. Prevent MIME-sniffing (CWE-693)
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff',
  },
  // 4. HSTS (CWE-319) - 2 Years with preload
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=63072000; includeSubDomains; preload',
  },
  // 5. Referrer Policy
  {
    key: 'Referrer-Policy',
    value: 'strict-origin-when-cross-origin',
  },
  // 6. Permissions Policy
  {
    key: 'Permissions-Policy',
    value: 'camera=(), microphone=(), geolocation=(), browsing-topics=()',
  },
  // 7. Cross-Origin Protections
  {
    key: 'Cross-Origin-Opener-Policy',
    value: 'same-origin',
  },
  {
    key: 'Cross-Origin-Resource-Policy',
    value: 'same-origin',
  },
];

const nextConfig: NextConfig = {
  // Disable X-Powered-By: Next.js header
  poweredByHeader: false,

  // Disallow source maps in production to prevent leaking internals (CWE-798)
  productionBrowserSourceMaps: false,

  async headers() {
    return [
      {
        // Apply security headers to all routes
        source: '/(.*)',
        headers: securityHeaders,
      },
      {
        // Enforce No-Cache on API routes (CWE-525)
        source: '/api/(.*)',
        headers: [
          {
            key: 'Cache-Control',
            value: 'no-store, no-cache, must-revalidate, private',
          },
          {
            key: 'Pragma',
            value: 'no-cache',
          },
          {
            key: 'Expires',
            value: '0',
          },
        ],
      },
    ];
  },
};

export default nextConfig;
