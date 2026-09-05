/**
 * ==============================================================================
 * Kaizo DevSec Framework - Drop-In Application Security Initializer
 * Usage: Call `initAppSecurity(app)` in your server entrypoint.
 * ==============================================================================
 */

import express, { Express, Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import rateLimit from 'express-rate-limit';

export interface SecurityConfig {
  allowedOrigins?: string[];
  rateLimitWindowMs?: number;
  rateLimitMax?: number;
  bodyLimit?: string;
}

export function initAppSecurity(app: Express, config: SecurityConfig = {}) {
  // 1. Enforce payload size limit to prevent Denial of Service (ReDoS / Memory exhaustion)
  app.use(express.json({ limit: config.bodyLimit || '100kb' }));
  app.use(express.urlencoded({ extended: true, limit: config.bodyLimit || '100kb' }));

  // 2. Hide Technology Stack Identifiers
  app.disable('x-powered-by');

  // 3. Security Headers (Helmet)
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:', 'https:'],
          objectSrc: ["'none'"],
          frameAncestors: ["'none'"],
          upgradeInsecureRequests: [],
        },
      },
      hsts: {
        maxAge: 63072000,
        includeSubDomains: true,
        preload: true,
      },
      frameguard: { action: 'deny' },
      noSniff: true,
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    })
  );

  // 4. Strict CORS Configuration
  const allowedOrigins = config.allowedOrigins || ['http://localhost:3000'];
  app.use(
    cors({
      origin: (origin, callback) => {
        if (!origin || allowedOrigins.includes(origin)) {
          callback(null, true);
        } else {
          callback(new Error('Blocked by CORS policy'));
        }
      },
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token', 'X-Requested-With'],
    })
  );

  // 5. Global Rate Limiting
  const limiter = rateLimit({
    windowMs: config.rateLimitWindowMs || 15 * 60 * 1000, // 15 minutes
    max: config.rateLimitMax || 100, // limit each IP to 100 requests per window
    standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
    legacyHeaders: false, // Disable `X-RateLimit-*` headers
    message: {
      status: 429,
      error: 'Too many requests, please try again later.',
    },
  });
  app.use('/api/', limiter);

  // 6. Standardized Health & Liveness Checks (Mitigates User-Agent / Scanner crash)
  app.get('/healthz', (req: Request, res: Response) => {
    res.status(200).json({ status: 'healthy', timestamp: new Date().toISOString() });
  });

  // 7. Global Error Handler (Hides raw stack traces in production - CWE-497)
  app.use((err: any, req: Request, res: Response, next: NextFunction) => {
    const isProd = process.env.NODE_ENV === 'production';
    const statusCode = err.status || err.statusCode || 500;

    res.status(statusCode).json({
      error: isProd && statusCode === 500 ? 'Internal server error' : err.message,
      ...(isProd ? {} : { stack: err.stack }),
    });
  });

  return app;
}
