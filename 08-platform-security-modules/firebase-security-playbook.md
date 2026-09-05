# 🔥 Firebase Production Security Playbook & Hardening Guide

> **Author**: Kaizo  
> **Target**: Firestore, Realtime Database, Firebase Storage, Auth, App Check & Admin SDK  
> **Key Mitigations**: `CWE-284` (Improper Access Control), `CWE-798` (Key Mismanagement), `CWE-359` (Data Leakage)

---

## 🔒 1. Firebase Threat Model & Public API Key Reality

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          FIREBASE DEFENSE IN DEPTH                          │
├───────────────────────────────────┬─────────────────────────────────────────┤
│ 1. Web API Key (`AIzaSy...`)      │ 2. Firebase Security Rules              │
│                                   │                                         │
│ • Public identifier by design.    │ • THE TRUE DEFENSIVE FIREWALL!          │
│ • CANNOT be hidden from clients.  │ • Denies unauthorized reads & writes.   │
│ • Restrict HTTP referrers in GCP. │ • Validates schemas, auth, & role flags.│
└───────────────────────────────────┴─────────────────────────────────────────┘
```

> [!WARNING]
> Never leave default test rules: `allow read, write: if true;` in production! Automated bots scrape GitHub for `apiKey` and `projectId` and wipe open databases within minutes.

---

## 🛡️ 2. Core Firestore Security Principles

1. **Default Deny**: Never allow wildcard access.
2. **Granular Operations**: Split `read` into `get` and `list`, and `write` into `create`, `update`, and `delete`.
3. **Schema & Field-Level Validation**: Verify incoming data types, sizes, and immutable fields.

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    
    // Global fallback: Deny all unmatched paths
    match /{document=**} {
      allow read, write: if false;
    }

    // Helper functions
    function isAuthenticated() {
      return request.auth != null;
    }
    
    function isOwner(userId) {
      return isAuthenticated() && request.auth.uid == userId;
    }
    
    function isAdmin() {
      return isAuthenticated() && request.auth.token.role == 'admin';
    }

    // 1. User Profiles Collection
    match /users/{userId} {
      // Anyone authenticated can read user profile
      allow get: if isAuthenticated();
      // Only owner can update profile; cannot tamper with role or email verification
      allow update: if isOwner(userId) 
        && !request.resource.data.diff(resource.data).affectedKeys().hasAny(['role', 'createdAt', 'isVerified']);
      // Account creation
      allow create: if isOwner(userId)
        && request.resource.data.role == 'user';
    }

    // 2. Multi-Tenant Projects Collection
    match /organizations/{orgId}/projects/{projectId} {
      allow read, write: if isAuthenticated() && (
        get(/databases/$(database)/documents/organizations/$(orgId)/members/$(request.auth.uid)).data.role in ['admin', 'editor']
      );
    }
  }
}
```

---

## 🪣 3. Firebase Storage Security Rules

1. **Strict Content-Type & File Size Validation**:
   - Prevent malicious script/executable uploads (`.exe`, `.php`, `.svg` with embedded XSS payloads).
   - Enforce size limits (e.g. 5MB max).

```javascript
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    
    // User Avatars: Max 5MB, JPG/PNG only
    match /users/{userId}/avatar.jpg {
      allow read: if true; // Publicly viewable avatar
      allow write: if request.auth != null 
        && request.auth.uid == userId
        && request.resource.size < 5 * 1024 * 1024
        && request.resource.contentType.matches('image/(jpeg|png|webp)');
    }

    // Confidential User Vault
    match /vault/{userId}/{allPaths=**} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
```

---

## 🛡️ 4. Firebase App Check (Zero-Bot & Anti-Abuse Defense)

App Check protects your Firebase backend from billing fraud, scraping, and replay attacks by verifying that incoming traffic originates strictly from your legitimate application.

### Implementation Checklist:
1. **Web (React/Next.js)**: Enable **reCAPTCHA Enterprise** or **reCAPTCHA v3**.
2. **iOS**: Enable **DeviceCheck** or **App Attest**.
3. **Android**: Enable **Play Integrity**.
4. **Cloud Functions**: Enforce App Check token verification.

```typescript
// Next.js App Check Initialization (Client)
import { initializeAppCheck, ReCaptchaV3Provider } from 'firebase/app-check';
import { app } from './firebaseConfig';

if (typeof window !== 'undefined') {
  const appCheck = initializeAppCheck(app, {
    provider: new ReCaptchaV3Provider(process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY!),
    isTokenAutoRefreshEnabled: true,
  });
}
```

---

## 🔑 5. Google Cloud Console API Key Restrictions

1. Navigate to **Google Cloud Console > APIs & Services > Credentials**.
2. Click on your `Browser key (auto created by Firebase)`.
3. Set **Application Restrictions**:
   - Select **Websites (HTTP referrers)**.
   - Add your domains: `https://kaizo-app.com/*`, `https://*.kaizo-app.com/*`.
4. Set **API Restrictions**:
   - Limit key usage strictly to: `Firebase Authentication`, `Cloud Firestore API`, `Firebase Storage`, `Firebase Installations`.
