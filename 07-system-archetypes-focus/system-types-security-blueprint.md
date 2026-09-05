# 🏛️ System Archetypes: Specialized Security Focus & Blueprint

> **For Kaizo**: Security requirements vary fundamentally depending on the **type of system** you are building. Use this guide to determine exactly where to direct your focus based on your project's architectural category.

---

## 🧭 System Type Quick-Matrix

| System Type | Primary Threat Vectors | Highest Priority Security Controls |
| :--- | :--- | :--- |
| **1. Multi-Tenant SaaS** | Cross-tenant data leaks, Tenant ID spoofing, Privilege escalation | Row-Level Security (RLS), Tenant context in DB queries, Scope validation |
| **2. E-Commerce & Payments** | Price tampering, Double-spending, Webhook forgery, Card theft | Stripe Webhook signature verification, Idempotency keys, Zero-card storage |
| **3. REST / GraphQL / tRPC APIs** | BOLA/IDOR, Mass Assignment, GraphQL DoS | Object-level authorization checks, Input DTO validation, Query depth limits |
| **4. Frontend SPAs & Mobile** | XSS, Token theft, Insecure client storage | HttpOnly cookies, CSP, DOMPurify, Disable source maps, App Check |
| **5. AI & LLM Systems (RAG/Agents)**| Prompt Injection, RAG data poisoning, Tool SSRF | Prompt guards, Document-level RAG ACLs, Sandboxed tool execution |
| **6. Admin Dashboards** | Session hijacking, Credential stuffing, Insider threat | Mandatory MFA, IP whitelisting, Short session timeouts, Immutable audit logs |
| **7. Real-Time & WebSockets** | Socket flooding, Unauthorized channel snooping | Handshake JWT verification, Room-level authz, Binary message limits |

---

## 🏢 1. Multi-Tenant SaaS Platforms

### 🎯 What You Must Focus On:
1. **Tenant Data Isolation (The #1 SaaS Risk)**:
   - *Never* rely solely on frontend passing `tenantId`.
   - Extract `tenantId` strictly from the verified JWT/Session on the server.
2. **PostgreSQL Row-Level Security (RLS)**:
   - Enforce isolation at the database engine level so even buggy code cannot query another tenant's records.

```sql
-- Enable RLS on multi-tenant table
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

-- Create policy tied to current tenant session variable
CREATE POLICY tenant_isolation_policy ON documents
  FOR ALL
  USING (tenant_id = current_setting('app.current_tenant_id')::uuid);
```

```typescript
// In backend query middleware:
await prisma.$executeRawUnsafe(
  `SET LOCAL app.current_tenant_id = '${req.user.tenantId}';`
);
```

3. **Subscription Tier Enforcement**:
   - Validate plan limits (e.g. max users, API calls, premium features) on the server, not via client UI flags.

---

## 💳 2. E-Commerce & Payment Systems

### 🎯 What You Must Focus On:
1. **Zero Raw Cardholder Data (PCI DSS)**:
   - *Never* accept or log raw credit card numbers, CVVs, or expiration dates on your servers.
   - Use client-side tokenization (Stripe Elements, Braintree, PayPal SDK).
2. **Cryptographic Webhook Verification**:
   - Always verify the HMAC signature of incoming payment webhooks before provisioning orders.

```typescript
import Stripe from 'stripe';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export const handleStripeWebhook = async (req: any, res: any) => {
  const sig = req.headers['stripe-signature'];
  let event: Stripe.Event;

  try {
    // Crucial: Use raw body buffer for signature verification
    event = stripe.webhooks.constructEvent(
      req.rawBody,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET!
    );
  } catch (err: any) {
    return res.status(400).send(`Webhook Signature Error: ${err.message}`);
  }

  // Idempotent processing (Prevent double-crediting)
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object as Stripe.Checkout.Session;
    await fulfillOrderWithIdempotency(session.id);
  }

  res.json({ received: true });
};
```

3. **Price & Quantity Tampering**:
   - Never trust the product price sent in the client POST request (`{ item: "laptop", price: 1.00 }`).
   - Look up canonical prices strictly from the server database using the product ID.
4. **Race Conditions & Double Spending**:
   - Use database row locks (`SELECT ... FOR UPDATE`) or atomic balance deductions.

---

## 🔌 3. Public & Microservice APIs (REST, GraphQL, tRPC)

### 🎯 What You Must Focus On:
1. **Broken Object Level Authorization (BOLA / IDOR)**:
   - Always verify that `req.user.id` actually owns the resource specified in `/api/orders/:orderId`.

```typescript
// ❌ VULNERABLE: IDOR (Anyone can view any order)
app.get('/api/orders/:id', async (req, res) => {
  const order = await db.order.findUnique({ where: { id: req.params.id } });
  res.json(order);
});

// ✅ SECURE: Authorization check included
app.get('/api/orders/:id', async (req, res) => {
  const order = await db.order.findFirst({
    where: {
      id: req.params.id,
      userId: req.user.id // Locked to authenticated user!
    }
  });
  if (!order) return res.status(404).json({ error: 'Order not found' });
  res.json(order);
});
```

2. **GraphQL Specific Defenses**:
   - **Disable Introspection** in production.
   - Enforce **Query Depth Limiting** (prevent nested query denial of service: `user { posts { author { posts { author... } } } }`).
   - Implement query complexity cost calculation.

---

## 💻 4. Single-Page Apps & Mobile Frontends (React, Next.js, Mobile)

### 🎯 What You Must Focus On:
1. **Cross-Site Scripting (XSS) Sanitization**:
   - Never use `dangerouslySetInnerHTML` without `DOMPurify.sanitize()`.
2. **Safe State Storage**:
   - Keep session tokens in `HttpOnly` cookies. Avoid `localStorage` for JWTs.
3. **Prevent Secret Leaking in Builds**:
   - Prefix environment variables strictly (`NEXT_PUBLIC_` only for true public IDs, never API secrets).
   - Disable production `.map` source maps.

---

## 🤖 5. AI & LLM-Integrated Applications (RAG & Autonomous Agents)

### 🎯 What You Must Focus On:
1. **Prompt Injection Mitigation**:
   - Treat all user input and external webpage fetches as **untrusted data**.
   - Delimit user inputs clearly in prompt templates:
     ```
     <context>
     {{retrieved_context}}
     </context>
     <user_query>
     {{user_input}}
     </user_query>
     ```
2. **RAG Vector Document Permissions (Document-Level ACLs)**:
   - When retrieving chunks from a vector database (Pinecone, pgvector, Qdrant), filter chunks by user authorization before feeding them into the context window:
     ```typescript
     const results = await vectorIndex.query({
       vector: queryEmbedding,
       filter: { organizationId: req.user.orgId, department: { $in: req.user.roles } },
       topK: 5
     });
     ```
3. **Sandboxing Agent Tool Execution**:
   - If an AI agent has tools (e.g. "execute SQL", "send email", "run shell command"), enforce strict human-in-the-loop approvals or execute inside isolated ephemeral containers.

---

## 🛡️ 6. Internal Admin Dashboards & Backoffice Systems

### 🎯 What You Must Focus On:
1. **Mandatory Multi-Factor Authentication (MFA / 2FA)**:
   - Enforce TOTP or WebAuthn/FIDO2 keys for all admin roles.
2. **Short Session Timeouts & Re-authentication**:
   - Invalidate idle admin sessions after 15 minutes.
   - Require password/MFA re-entry before destructive actions (e.g. delete tenant, bulk export).
3. **Immutable Audit Logging**:
   - Log `[Timestamp, Admin_User_ID, IP_Address, Action, Target_Resource, Old_Value, New_Value]`.
   - Stream logs to an append-only, tamper-evident log store.

---

## ⚡ 7. Real-Time & WebSocket Systems (Chat, IoT, Live Feeds)

### 🎯 What You Must Focus On:
1. **Connection Handshake Authentication**:
   - Authenticate during the initial HTTP upgrade handshake using secure session cookies or signed tokens.

```typescript
wss.on('connection', (ws, req) => {
  const user = authenticateHandshake(req);
  if (!user) {
    ws.close(4001, 'Unauthorized');
    return;
  }
  ws.user = user;
});
```

2. **Room / Topic Authorization**:
   - Verify user permissions before subscribing a socket connection to a specific channel:
     ```typescript
     if (msg.type === 'SUBSCRIBE_ROOM') {
       if (!canUserAccessRoom(ws.user.id, msg.roomId)) {
         return ws.send(JSON.stringify({ error: 'Access denied to room' }));
       }
       joinRoom(ws, msg.roomId);
     }
     ```
3. **Rate Limiting & Payload Sizing**:
   - Enforce maximum message frame size (e.g., `maxPayload: 64 * 1024`) to prevent socket memory exhaustion.
