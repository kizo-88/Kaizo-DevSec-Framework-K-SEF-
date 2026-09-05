/**
 * ==============================================================================
 * Kaizo DevSec Framework - Node.js / Express / Fastify Security Middleware
 * Mitigates: CWE-693 (CSP, Nosniff), CWE-1021 (Clickjacking), CWE-319 (HSTS), CWE-525
 * ==============================================================================
 */

const helmet = require('helmet');
const crypto = require('crypto');

/**
 * Express Middleware Setup
 */
function applyExpressSecurity(app) {
  // 1. Generate unique per-request nonce for dynamic inline scripts/styles if needed
  app.use((req, res, next) => {
    res.locals.cspNonce = crypto.randomBytes(16).toString('base64');
    next();
  });

  // 2. Comprehensive Helmet Configuration
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.cspNonce}'`],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:', 'https:'],
          connectSrc: ["'self'", 'https://api.kaizo-app.com'],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          frameAncestors: ["'none'"], // Mitigates CWE-1021
          upgradeInsecureRequests: [],
        },
      },
      crossOriginEmbedderPolicy: false, // Set to true if SharedArrayBuffers used
      crossOriginOpenerPolicy: { policy: 'same-origin' },
      crossOriginResourcePolicy: { policy: 'same-origin' },
      dnsPrefetchControl: { allow: false },
      frameguard: { action: 'deny' }, // Mitigates CWE-1021 (X-Frame-Options: DENY)
      hidePoweredBy: true, // Hides X-Powered-By: Express
      hsts: {
        maxAge: 63072000, // 2 years (Mitigates CWE-319)
        includeSubDomains: true,
        preload: true,
      },
      ieNoOpen: true,
      noSniff: true, // Mitigates CWE-693 (X-Content-Type-Options: nosniff)
      originAgentCluster: true,
      permittedCrossDomainPolicies: { permittedPolicies: 'none' },
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
      xssFilter: true,
    })
  );

  // 3. No-Cache Middleware for Authenticated / Sensitive Routes (Mitigates CWE-525)
  const noCacheMiddleware = (req, res, next) => {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
  };

  app.use('/api', noCacheMiddleware);

  return app;
}

module.exports = {
  applyExpressSecurity,
};
