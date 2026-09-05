# ⚡ Supabase Security Playbook & Hardening Guide

> **Author**: Kaizo  
> **Target**: Supabase Postgres, Auth, Storage, Edge Functions & Webhooks  
> **Key Mitigations**: `CWE-284` (Improper Access Control), `CWE-798` (Secret Leakage), `CWE-89` (SQL Injection)

---

## 🔒 1. Supabase Architecture: Key & Token Separation

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       SUPABASE CREDENTIAL SEPARATION                        │
├───────────────────────────────────┬─────────────────────────────────────────┤
│ 1. `NEXT_PUBLIC_SUPABASE_ANON_KEY`│ 2. `SUPABASE_SERVICE_ROLE_KEY`          │
│                                   │                                         │
│ • SAFE for browser/client-side.   │ • NEVER EXPOSE TO CLIENT / FRONTEND!    │
│ • Grants `anon` or `authenticated`│ • BYPASSES ALL ROW-LEVEL SECURITY!      │
│   roles strictly gated by RLS.    │ • Use ONLY in trusted backend/functions.│
└───────────────────────────────────┴─────────────────────────────────────────┘
```

> [!CAUTION]
> If you put `SUPABASE_SERVICE_ROLE_KEY` in `NEXT_PUBLIC_*` or ship it in client JS, **anyone can bypass all your Row Level Security and read/delete your entire database**.

---

## 🛡️ 2. Supabase Row Level Security (RLS) - Mandatory Rules

By default in Supabase, when you create a table, RLS is **disabled** unless explicitly turned on. **Rule #1: Every single table in the `public` schema MUST have RLS enabled.**

```sql
-- 1. Always enable RLS on every public table
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.documents ENABLE ROW LEVEL SECURITY;

-- 2. Prevent unauthenticated public access by default
-- (If no policies match, Supabase rejects all requests with an empty set)
```

---

## 🔐 3. Core RLS Policy Patterns

### A. User-Owned Resource (Profile / Settings)
```sql
-- Allow users to read their own profile
CREATE POLICY "Users can read own profile" 
ON public.profiles 
FOR SELECT 
TO authenticated 
USING ((SELECT auth.uid()) = id);

-- Allow users to update their own profile
CREATE POLICY "Users can update own profile" 
ON public.profiles 
FOR UPDATE 
TO authenticated 
USING ((SELECT auth.uid()) = id)
WITH CHECK ((SELECT auth.uid()) = id);
```

### B. Multi-Tenant Organization Isolation (Sub-query Optimization)
```sql
-- Optimized organization document access (using SELECT auth.uid() inside subquery to avoid per-row evaluation)
CREATE POLICY "Org members can read org documents"
ON public.documents
FOR SELECT
TO authenticated
USING (
  organization_id IN (
    SELECT org_id 
    FROM public.organization_members 
    WHERE user_id = (SELECT auth.uid())
  )
);
```

### C. Role-Based Access Control (RBAC) via Custom Claims / Metadata
```sql
-- Allow Admins to manage all organization settings
CREATE POLICY "Admins full access to org settings"
ON public.organizations
FOR ALL
TO authenticated
USING (
  (SELECT (auth.jwt() -> 'app_metadata' ->> 'role')) = 'super_admin'
);
```

---

## ⚠️ 4. Hardening PostgreSQL Functions (`SECURITY DEFINER` vs `INVOKER`)

When creating custom SQL functions in Supabase:

1. **`SECURITY DEFINER` Pitfall**: Runs with the permissions of the database owner (bypasses RLS). If not hardened, attackers can escalate privileges.
2. **Mandatory Fix**: Set `search_path = ''` to prevent schema search path injection attacks (`CWE-426`).

```sql
-- SECURE Postgres Function Template
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = '' -- CRITICAL: Prevents malicious schema hijacking
AS $$
BEGIN
  INSERT INTO public.profiles (id, full_name, email, created_at)
  VALUES (
    new.id,
    new.raw_user_meta_data->>'full_name',
    new.email,
    NOW()
  );
  RETURN new;
END;
$$;
```

---

## 🪣 5. Supabase Storage Bucket Security

1. **Private Buckets by Default**: Mark avatars, attachments, and user documents as **Private**.
2. **Apply Storage RLS Policies** on `storage.objects`:

```sql
-- Allow users to upload files ONLY into their own folder (/avatars/<user_id>/*)
CREATE POLICY "Users upload to own folder"
ON storage.objects
FOR INSERT
TO authenticated
WITH CHECK (
  bucket_id = 'user-vault' AND
  (storage.foldername(name))[1] = (SELECT auth.uid())::text
);

-- Allow users to download files ONLY from their own folder
CREATE POLICY "Users read own files"
ON storage.objects
FOR SELECT
TO authenticated
USING (
  bucket_id = 'user-vault' AND
  (storage.foldername(name))[1] = (SELECT auth.uid())::text
);
```

---

## ⚡ 6. Supabase Edge Functions & Webhooks Hardening

1. **Verify Webhook Signatures**: When Supabase calls an external endpoint or Edge Function, verify the HMAC secret:
   ```typescript
   import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
   import { createHmac } from 'https://deno.land/std@0.168.0/node/crypto.ts';

   serve(async (req) => {
     const signature = req.headers.get('x-supabase-signature');
     const rawBody = await req.text();
     
     const hmac = createHmac('sha256', Deno.env.get('WEBHOOK_SECRET')!);
     hmac.update(rawBody);
     const expectedSignature = hmac.digest('hex');

     if (signature !== expectedSignature) {
       return new Response('Unauthorized', { status: 401 });
     }

     return new Response(JSON.stringify({ status: 'success' }), {
       headers: { 'Content-Type': 'application/json' },
     });
   });
   ```
2. **Restrict CORS on Edge Functions**: Never use `Access-Control-Allow-Origin: *` for authenticated Edge Functions.
