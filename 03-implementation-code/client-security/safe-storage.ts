/**
 * ==============================================================================
 * Kaizo DevSec Framework - Safe Client-Side State & Token Management
 * Mitigates: CWE-359 (Information Exposure in Browser localStorage)
 * ==============================================================================
 */

/**
 * In-Memory Token Manager
 * 
 * WHY NOT localStorage?
 * - `localStorage` persists indefinitely across browser tabs and sessions.
 * - Any XSS flaw or third-party script can dump all keys via `localStorage.getItem()`.
 * 
 * INSTEAD:
 * 1. Primary Authentication: Handled via `HttpOnly`, `Secure`, `SameSite` cookies.
 * 2. If short-lived OAuth/JWT access tokens are required in SPA JavaScript, keep them in-memory (closure).
 * 3. Use a silent refresh mechanism (via HttpOnly refresh cookie) to fetch a new token on page reload.
 */

class SecureTokenStore {
  private accessToken: string | null = null;
  private tokenExpiry: number | null = null;

  /**
   * Sets the short-lived access token in private memory
   */
  public setAccessToken(token: string, expiresInSeconds: number): void {
    this.accessToken = token;
    this.tokenExpiry = Date.now() + expiresInSeconds * 1000;
  }

  /**
   * Retrieves the access token, returning null if expired
   */
  public getAccessToken(): string | null {
    if (!this.accessToken || !this.tokenExpiry) {
      return null;
    }
    if (Date.now() >= this.tokenExpiry) {
      this.clear();
      return null;
    }
    return this.accessToken;
  }

  /**
   * Clears the in-memory token
   */
  public clear(): void {
    this.accessToken = null;
    this.tokenExpiry = null;
  }

  /**
   * Automatic silent refresh using HttpOnly cookie endpoint
   */
  public async getOrRefreshToken(refreshEndpoint: string = '/api/auth/refresh'): Promise<string | null> {
    const existing = this.getAccessToken();
    if (existing) return existing;

    try {
      const response = await fetch(refreshEndpoint, {
        method: 'POST',
        credentials: 'include', // Sends the HttpOnly refresh token cookie
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        this.clear();
        return null;
      }

      const data = await response.json();
      this.setAccessToken(data.accessToken, data.expiresIn || 900); // 15 mins default
      return data.accessToken;
    } catch (err) {
      this.clear();
      return null;
    }
  }
}

export const tokenStore = new SecureTokenStore();
