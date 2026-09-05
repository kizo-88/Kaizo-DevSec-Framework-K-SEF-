/**
 * ==============================================================================
 * Kaizo DevSec Framework - Enterprise Cookie & Session Security Utility
 * Mitigates: CWE-1275 (SameSite), CWE-1004 (HttpOnly), CWE-565 (Loosely Scoped Cookie),
 *            CWE-352 (CSRF), CWE-598 (Session in URL)
 * ==============================================================================
 */

import { CookieOptions, Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

const isProduction = process.env.NODE_ENV === 'production';

export interface CookieConfigOptions {
  name?: string;
  maxAgeMs?: number;
  sameSite?: 'strict' | 'lax' | 'none';
}

/**
 * Generates enterprise-grade cookie options.
 * Adheres strictly to:
 * - HttpOnly (Prevent XSS theft - CWE-1004)
 * - Secure (HTTPS only - CWE-319/311)
 * - SameSite=Strict / Lax (Prevent CSRF - CWE-1275)
 * - Host-only scoping (Omit domain attribute - CWE-565)
 */
export function getSecureCookieOptions(custom: CookieConfigOptions = {}): CookieOptions {
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: custom.sameSite || 'strict',
    path: '/',
    maxAge: custom.maxAgeMs || 1000 * 60 * 60 * 8, // 8 hours default
    // Note: Do NOT specify `domain` attribute to prevent Loose Scoping (CWE-565)
  };
}

/**
 * Sets a session token using the recommended `__Host-` prefix
 */
export function setSecureSessionCookie(res: Response, token: string): void {
  // Use __Host- prefix in production for maximum browser isolation
  const cookieName = isProduction ? '__Host-kaizo_auth' : 'kaizo_auth';
  res.cookie(cookieName, token, getSecureCookieOptions());
}

/**
 * Clears the session cookie securely upon logout
 */
export function clearSessionCookie(res: Response): void {
  const cookieName = isProduction ? '__Host-kaizo_auth' : 'kaizo_auth';
  res.clearCookie(cookieName, {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'strict',
    path: '/',
  });
}

/**
 * CSRF Protection Middleware (Double-Submit Cookie Pattern)
 * Mitigates: CWE-352
 */
export function csrfProtectionMiddleware(req: Request, res: Response, next: NextFunction) {
  const CSRF_COOKIE_NAME = 'XSRF-TOKEN';

  // 1. On safe methods (GET, HEAD, OPTIONS), ensure CSRF cookie exists
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    if (!req.cookies || !req.cookies[CSRF_COOKIE_NAME]) {
      const csrfToken = crypto.randomBytes(32).toString('hex');
      res.cookie(CSRF_COOKIE_NAME, csrfToken, {
        httpOnly: false, // Must be readable by client JS to set in header
        secure: isProduction,
        sameSite: 'strict',
        path: '/',
      });
    }
    return next();
  }

  // 2. On mutating methods (POST, PUT, PATCH, DELETE), verify token
  const clientProvidedToken =
    req.headers['x-xsrf-token'] ||
    req.headers['x-csrf-token'] ||
    (req.body && req.body._csrf);

  const cookieToken = req.cookies ? req.cookies[CSRF_COOKIE_NAME] : null;

  if (!clientProvidedToken || !cookieToken) {
    return res.status(403).json({
      error: 'CSRF token missing. Include X-XSRF-TOKEN header.',
    });
  }

  // Constant-time string comparison to prevent timing attacks
  const isValid =
    typeof clientProvidedToken === 'string' &&
    typeof cookieToken === 'string' &&
    clientProvidedToken.length === cookieToken.length &&
    crypto.timingSafeEqual(
      Buffer.from(clientProvidedToken),
      Buffer.from(cookieToken)
    );

  if (!isValid) {
    return res.status(403).json({
      error: 'Invalid CSRF token.',
    });
  }

  next();
}
