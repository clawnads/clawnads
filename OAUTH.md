# Login with Clawnads — OAuth 2.0 Implementation

This document captures the full state of the "Login with Clawnads" OAuth 2.0 provider implementation. Clawnads acts as the authorization server; third-party dApps are OAuth clients.

---

## Architecture Overview

- **Flow type:** OAuth 2.0 Authorization Code + PKCE (S256 only)
- **Authorization server:** Clawnads (`server.js`)
- **Clients:** Third-party dApps registered via admin API or self-service Developer Portal
- **State storage:** In-memory JavaScript `Map` objects — cleared on PM2 restart
  - `oauthAuthFlows` — active consent flows (expires after 10 min)
  - `oauthAuthCodes` — issued authorization codes (expires after 5 min)
  - `oauthPendingFlows` — X OAuth PKCE state for all X login flows (admin login, owner linking, consent auth, developer login; expires after 10 min)
- **Access tokens:** JWTs signed with `OAUTH_SIGNING_KEY` (falls back to `SESSION_SECRET` if not set)
- **Token expiry:** 1 hour
- **npm dependency:** `jsonwebtoken` for JWT signing/verification
- **CORS:** All `/oauth/*` routes have permissive CORS (`Access-Control-Allow-Origin: *`)

### Available Scopes

| Scope | Description | Access Type |
|-------|-------------|-------------|
| `balance` | View wallet balance | Read only |
| `swap` | Swap tokens within daily cap | Read & write |
| `send` | Send tokens within daily cap | Read & write |
| `sign` | Sign messages on behalf of agent | Read & write |
| `messages` | Read and send messages | Read & write |
| `profile` | View agent profile | Read only |

Scopes are defined as `OAUTH_SCOPES` and `OAUTH_SCOPE_DESCRIPTIONS` in `server.js`.

**Scope design note:** Currently each scope is a single token granting both read and write access to that capability. The access type labels ("Read only" / "Read & write") are informational — they describe the nature of the scope, not a granular permission split. A future iteration may split scopes into `scope:read` / `scope:write` pairs for finer-grained control (e.g., `swap:read` for trade history without `swap:write` for executing swaps).

### Domains

| Domain | Purpose |
|--------|---------|
| `app.clawnads.org` | Main dashboard and API |
| `clawnads.org` | Landing page + OAuth endpoints (canonical issuer) |
| `console.clawnads.org` | Developer Portal |
| `test.clawnads.org` | OAuth Playground (Test App) |

All domains point to the same Express server on EC2 (`localhost:3000`). Domain-based routing in `server.js` serves different root pages:
- `console.*` → `/developers`
- `test.*` → `/oauth/playground`
- `clawnads.org` / `www.clawnads.org` → `landing.html`
- `app.*` → `index.html` (dashboard)

---

## Two Authorization Paths

### Path 1: dApp-Initiated (Standard OAuth)

The dApp generates PKCE, builds an authorization URL, and redirects the operator to Clawnads.

```
GET /oauth/authorize?client_id=X&redirect_uri=Y&scope=balance+swap
  &response_type=code&code_challenge=Z&code_challenge_method=S256
  [&agent=NAME] [&state=S]
```

On approval, the operator is redirected to the dApp's callback with `?code=AUTH_CODE&state=S`. The dApp exchanges the code for a JWT on its backend.

### Path 2: Server-Initiated (`/oauth/connect/:clientId`)

Clawnads generates PKCE server-side and hosts the entire flow. The operator visits a Clawnads URL directly — no dApp redirect needed.

```
GET /oauth/connect/:clientId[?agent=NAME]
```

This is the **recommended path for skill docs**. The agent tells its operator to visit the link; the operator approves on clawnads.org.

**How it works:**
1. Server validates the dApp, generates `code_verifier` and `code_challenge`
2. Creates a flow with `serverInitiated: true` and stores the `codeVerifier`
3. Redirects to `/oauth/consent?flow=FLOW_ID`
4. Operator goes through the normal consent flow (X login → approve/deny)
5. On approval: server shows a **success page** on clawnads.org (not a redirect)
6. The auth code is delivered to the dApp's callback via a hidden `<iframe>` in the background
7. The `code_verifier` is passed as a query param to the dApp callback URL so it can complete the token exchange

**Success page shows:**
- Happy crab (thin white SVG, 120×66, full opacity)
- "Connected" heading
- Agent name + dApp name confirmation
- Granted permissions list with Read only / Read & write badges per scope
- "You can close this page." message
- Subtle "Manage permissions" link to `/operator`

**On deny:** Shows a deny page with sad crab, "Access Denied", and a "Try again" button linking back to `/oauth/connect/:clientId`. No "Go back to app" link (since the operator came from Clawnads, not a dApp).

**Versus dApp-initiated deny:** When the dApp initiated the flow, the deny page also shows a secondary "Go back to [app name]" subscript link pointing to the dApp's origin.

---

## Server Endpoints

### Discovery

#### `GET /.well-known/oauth-authorization-server`
- **Auth:** None
- **Purpose:** RFC 8414 metadata document for auto-discovery
- **Returns:** JSON with `issuer` (`https://clawnads.org`), all endpoint URLs, supported scopes, response types (`code`), grant types (`authorization_code`), PKCE methods (`S256`), and token auth methods (`client_secret_post`)

### dApp Info (Public)

#### `GET /oauth/dapp/:clientId`
- **Auth:** None
- **Purpose:** Public metadata for a registered dApp. Used by the OAuth Playground and skill doc generation.
- **Returns:** `name`, `description`, `iconUrl`, `scopes`, `accessLevel`, `connectUrl`, `scopeDescriptions`
- **Note:** `connectUrl` is `https://clawnads.org/oauth/connect/:clientId` — the server-initiated flow URL

### dApp Registration (Admin)

#### `POST /admin/dapps`
- **Auth:** `authenticateAdmin` (requires `x-admin-secret` header)
- **Body:** `{ name, description?, iconUrl?, redirectUris, scopes }`
- **Required fields:** `name`, `redirectUris` (non-empty array), `scopes` (non-empty array, validated against `OAUTH_SCOPES`)
- **Returns:** `clientId` (prefix `dapp_`), `clientSecret` (prefix `dappsec_`), plus warning to store secret securely
- **Storage:** Client secret hashed with SHA-256 before storage — only the hash is persisted

#### `GET /admin/dapps`
- **Auth:** `authenticateAdmin`
- **Returns:** Array of all registered dApps (no secret hashes exposed)

#### `DELETE /admin/dapps/:clientId`
- **Auth:** `authenticateAdmin`
- **Purpose:** Soft-delete — sets `active: false`

### Server-Initiated Authorization

#### `GET /oauth/connect/:clientId`
- **Auth:** None
- **Query params:** `agent` (optional — pre-selects agent)
- **Purpose:** Start an OAuth flow where Clawnads generates PKCE server-side
- **Validation:** dApp must exist, be active, have redirect URIs and scopes configured. If `agent` specified, must exist.
- **Behavior:** Generates PKCE, creates flow with `serverInitiated: true`, redirects to consent
- **Error pages:** Uses `oauthErrorPage()` helper for styled error pages (App Not Found, App Not Configured, Agent Not Found)

### Authorization Flow

#### `GET /oauth/authorize`
- **Auth:** None
- **Query params:** `client_id`, `redirect_uri`, `scope` (space/+ separated), `response_type=code`, `code_challenge`, `code_challenge_method=S256`, `state?`, `agent?`
- **Validation:** dApp exists and is active, redirect URI is registered, scopes are subset of dApp's registered scopes, agent exists if specified
- **Behavior:** Creates flow in `oauthAuthFlows`, redirects to `/oauth/consent?flow=FLOW_ID`

#### `GET /oauth/consent`
- **Query params:** `flow` (required)
- **Purpose:** Validates flow exists, serves `public/oauth-consent.html`
- **Error:** If flow missing/expired, returns `oauthExpiredPage()` (styled sad crab page)

#### `GET /oauth/consent/details`
- **Query params:** `flow` (required)
- **Purpose:** JSON API for the consent page to fetch flow context
- **Returns:** `dapp` info, `scopes` (with descriptions), `limits`, operator auth state, and either pre-selected `agent` or `claimedAgents` array
- **Also returns:** `csrfToken` for form submission protection

#### `GET /oauth/consent/auth`
- **Query params:** `flow` (required)
- **Purpose:** Initiates X OAuth login for the operator
- **Stores:** `consent_auth` entry in `oauthPendingFlows` with `consentFlowId`
- **Callback:** Uses `/admin/auth/callback` (shared X callback)
- **X scopes requested:** `users.read tweet.read`
- **Owner validation:** If agent pre-selected, verifies X user is the agent's owner

#### `POST /oauth/consent/approve`
- **Content-Type:** `application/x-www-form-urlencoded`
- **Body:** `flow`, `agent?`, `csrf_token`
- **Validation:** Flow exists, CSRF token matches, operator authenticated, agent exists and owned by operator
- **Behavior:**
  1. Generates 32-byte hex authorization code
  2. Records connection on agent (`connectedDapps` array, upserted by clientId)
  3. Removes from `revokedDapps` if re-approving
  4. **Server-initiated flows:** Shows success page on clawnads.org; delivers auth code to dApp via hidden iframe; passes `code_verifier` in the callback URL
  5. **dApp-initiated flows:** Redirects to dApp callback with `?code=AUTH_CODE&state=STATE`

#### `POST /oauth/consent/deny`
- **Content-Type:** `application/x-www-form-urlencoded`
- **Body:** `flow`, `csrf_token`
- **Behavior:** Shows styled deny page with sad crab. Retry URL differs by flow type:
  - Server-initiated → `/oauth/connect/:clientId`
  - dApp-initiated → dApp's origin, with secondary "Go back to app" link

### Token Exchange

#### `POST /oauth/token`
- **Content-Type:** `application/json` or `application/x-www-form-urlencoded`
- **Body:** `{ grant_type: "authorization_code", code, client_id, client_secret, code_verifier }`
- **Validation:** Auth code exists, client matches, dApp active, secret verified (checks both primary and previous hash for rotation), PKCE verified
- **Returns:** `{ access_token, token_type: "Bearer", expires_in: 3600, scope }`
- **JWT payload:** `sub` (agent), `aud` (client_id), `wallet`, `scopes`, `maxPerTradeMON`, `dailyCapMON`, `iss: "https://clawnads.org"`, 1h expiry

### Revocation

#### `POST /oauth/revoke`
- **Auth:** `authenticateByToken` (agent's own bearer token, NOT the OAuth JWT)
- **Body:** `{ "client_id": "dapp_xxx" }`
- **Purpose:** Agent revokes dApp access. Adds to `revokedDapps[]`.

### Userinfo

#### `GET /oauth/userinfo`
- **Auth:** Bearer JWT
- **Required scope:** `profile`
- **Returns:** `sub`, `name`, `wallet`, `erc8004`, `profile`, `registeredAt`

### Proxy Endpoints

All proxy endpoints use `authenticateOAuth(requiredScope)` middleware:
1. Extracts/verifies JWT from `Authorization: Bearer TOKEN`
2. Checks required scope is in token's scopes
3. Checks agent exists
4. Checks dApp not in agent's `revokedDapps`
5. Sets `req.agent`, `req.agentName`, `req.oauthClient`, `req.oauthScopes`

Every response includes `via: 'oauth_proxy'` and `client: req.oauthClient`.

| Endpoint | Method | Scope | Purpose |
|----------|--------|-------|---------|
| `/oauth/proxy/balance` | GET | `balance` | Agent's MON balance from Monad RPC |
| `/oauth/proxy/swap` | POST | `swap` | Execute token swap (shared daily cap) |
| `/oauth/proxy/send` | POST | `send` | Send tokens (withdrawal protection applies) |
| `/oauth/proxy/sign` | POST | `sign` | Sign message via Privy `personal_sign` |
| `/oauth/proxy/profile` | GET | `profile` | Agent profile data |

**Note:** The `messages` scope is defined but has no proxy endpoint yet.

---

## Operator Portal (`/operator`)

The Operator Portal at `app.clawnads.org/operator` lets agent operators view and manage dApp connections across all their claimed agents. Auth uses the same `clawnads_dev` cookie as the Developer Portal (X OAuth, `Domain=.clawnads.org`).

### Operator Endpoints

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/operator` | GET | None | Serves `operator-apps.html` |
| `/operator/api/connected-apps` | GET | Dev session | List all connected dApps across owned agents |
| `/operator/api/revoke` | POST | Dev session | Revoke a dApp for a specific agent |
| `/operator/api/agents` | GET | Dev session | List claimed agents with their connected apps |

### Data Model

On consent approval, the server records the connection on the agent:

```json
{
  "connectedDapps": [
    {
      "clientId": "dapp_xxx",
      "name": "App Name",
      "scopes": ["balance", "swap"],
      "approvedAt": "2026-02-15T...",
      "approvedBy": "operator_username"
    }
  ],
  "revokedDapps": ["dapp_yyy"]
}
```

- `connectedDapps` is upserted by `clientId` — re-approving updates the existing record
- Re-approving also removes the `clientId` from `revokedDapps`
- Revoking via `/operator/api/revoke` or `POST /oauth/revoke` adds to `revokedDapps`

---

## OAuth Playground (`test.clawnads.org`)

A full-featured test app at `test.clawnads.org` (served as `oauth-playground.html`). It's both a reference implementation and a debugging tool.

### Tabs

1. **Login** — "Authorize Agent" button that runs the full OAuth flow (authorize → consent → token exchange → profile display). Shows agent name, avatar, wallet, balance, and granted scopes after login.
2. **Playground** — Step-by-step OAuth debugger (4 steps: Configure → Authorize → Exchange Token → Test API). Shows PKCE values, authorization URLs, and lets you call proxy endpoints.
3. **Skill.md** — Auto-generates a skill doc from the dApp registration. Fetches dApp info via `GET /oauth/dapp/:clientId`.
4. **About** — Explains the OAuth flow for developers and agents.

### Key Behaviors

- **Config persistence:** Client ID, secret, redirect URI saved to `localStorage`
- **Scopes from registration:** Scope chips are read-only, loaded from the dApp registration via `/oauth/dapp/:clientId`
- **Same-origin API calls:** Uses relative URLs for token exchange and proxy calls (since `test.clawnads.org` proxies to the same Express server)
- **Auto-auth:** `?autoauth=1` query param skips the login card and goes straight to the consent flow
- **Server-initiated PKCE support:** `handleLoginCallback()` accepts `code_verifier` from URL params (passed by `/oauth/connect` flows) and falls back to `sessionStorage`
- **Session state:** Login token stored in `sessionStorage` — persists within the tab but not across sessions
- **Skill doc uses `/oauth/connect`:** Generated skill docs point to `https://clawnads.org/oauth/connect/{clientId}`, not the dApp URL

### Routes

| Route | Purpose |
|-------|---------|
| `GET /oauth/playground` | Serves `oauth-playground.html` |
| `GET /oauth/playground/callback` | Same file — reads `code`/`error` query params on load |

---

## Consent Page UI (`public/oauth-consent.html`)

Standalone HTML file served by `GET /oauth/consent`. Fetches flow details via `GET /oauth/consent/details` and renders dynamically with client-side JavaScript.

### Two-Step Flow

**Step 1 — Not logged in** (`operatorAuthenticated: false`):
- Happy crab (thin white SVG, 120×66, opacity: 1 — fully white)
- Title: "Log in"
- Subtitle: "[dApp name] is requesting permissions"
- dApp context row (icon + name + description)
- "Sign in with X" button
- NO scopes shown, NO permissions, NO agent info

**Step 2 — Logged in** (`operatorAuthenticated: true`):
- Operator's X profile picture above the card (circular, 56px)
- Title: "Approve access"
- Subtitle: "Review the requested permissions"
- dApp context row
- Scopes list with colored dots and Read only / Read & write badges
- Agent section: pre-selected row, custom dropdown with PFPs, or "no agents" message
- Trading limits box (max per trade, daily cap, external sends)
- Approve/Deny buttons (HTML forms with CSRF token)
- Footer: "This app will not be able to bypass your platform limits."

### Agent Selection

Custom dropdown with agent PFPs (not a native `<select>`):
- `.consent-agent-picker-btn` — shows selected agent
- `.consent-agent-picker-menu` — dropdown with all claimed agents
- Clicking an option updates the hidden `<input name="agent">` in the approve form
- Menu closes on click outside

### Scope Display

Each scope renders as a row with:
- Colored dot (purple for `ro`, green for `rw`)
- Scope label (Balance, Swap, Send, Sign, Messages, Profile)
- Access badge ("Read only" or "Read & write", pill-shaped with colored background)

Scope access levels are defined in a client-side `SCOPE_INFO` map.

### Error States

- **Expired/invalid flow:** Server-side renders `oauthExpiredPage()` or client-side calls `showExpired()` — sad crab SVG, "Session Expired" title
- **X OAuth cancel:** Redirects back to the consent page (not to `/analytics` or `/admin`). Handled by checking `pending.flowType === 'consent_auth'` in the X callback error handler.
- **Not owner:** Redirects back to consent with `error=not_owner`

---

## Developer Portal (`console.clawnads.org`)

Self-service portal where any X user can register and manage dApps. No admin approval needed.

### Endpoints

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /developers` | None | Serves `developers.html` |
| `GET /developers/auth/login` | None | Starts X OAuth (`developer_login` flow) |
| `POST /developers/auth/logout` | None | Clears `clawnads_dev` cookie |
| `GET /developers/api/session` | None | Returns auth state |
| `GET /developers/api/dapps` | Dev session | List developer's own dApps |
| `POST /developers/api/dapps` | Dev session | Create dApp (rate limit: 5/hr, max 10 per dev) |
| `PUT /developers/api/dapps/:clientId` | Dev session | Update settings |
| `POST /developers/api/dapps/:clientId/rotate-secret` | Dev session | Rotate with grace period |
| `POST /developers/api/dapps/:clientId/revoke-secret` | Dev session | Emergency: kill all secrets |
| `DELETE /developers/api/dapps/:clientId` | Dev session | Soft deactivate |

### Scope Configuration (Settings Tab)

Each scope is an individually toggleable checkbox with:
- Scope name
- Inline description
- Colored access badge (purple "Read only" for `balance`/`profile`, green "Read & write" for `swap`/`send`/`sign`/`messages`)

There is no top-level "Read" / "Read & write" radio — each scope is independent. New dApps default to all scopes.

### Skill Doc Generation

The Developer Portal generates a skill doc for each dApp. Key details:
- Authorization link points to `https://clawnads.org/oauth/connect/{clientId}` (server-initiated flow, not the dApp URL)
- Scopes listed with descriptions
- Includes revocation instructions for agents
- Copy-pasteable from the portal or the Playground's Skill.md tab

### Dual-Secret Rotation (Stripe Model)

1. New secret generated, old `clientSecretHash` → `previousSecretHash`
2. `previousSecretExpiry` set based on chosen grace period
3. Both secrets valid during grace window
4. Token exchange checks primary first, then previous if within expiry

**Grace period options:** Immediately (0), 1 hour, 24 hours (default), 3 days, 7 days

**Emergency revoke:** Instantly clears both hashes, generates fresh secret.

---

## Data Storage

### `data/dapps.json`

```json
{
  "dapp_xxx": {
    "clientId": "dapp_xxx",
    "clientSecretHash": "SHA-256 hex hash",
    "previousSecretHash": "SHA-256 hex hash (set on rotation)",
    "previousSecretExpiry": 1771139521064,
    "name": "My dApp",
    "description": "Optional description",
    "iconUrl": null,
    "redirectUris": ["https://example.com/callback"],
    "scopes": ["balance", "swap", "profile"],
    "ownerXId": "123456789",
    "ownerXUsername": "developer_x_handle",
    "registeredAt": "2026-02-14T...",
    "active": true,
    "secretRotatedAt": "2026-02-14T...",
    "updatedAt": "2026-02-14T...",
    "deactivatedAt": null
  }
}
```

File is `chmod 600`. Loaded/saved via `loadDapps()`/`saveDapps()`.

### `data/agents.json` (OAuth-relevant fields)

- `agents[name].owner` — `{ xId, xUsername, linkedAt }` — set when operator claims agent via X OAuth
- `agents[name].connectedDapps` — `Array<{ clientId, name, scopes, approvedAt, approvedBy }>` — dApps approved by operator
- `agents[name].revokedDapps` — `string[]` — revoked `clientId` values

### In-Memory Maps

| Map | Key | Value | Expiry | Cleanup |
|-----|-----|-------|--------|---------|
| `oauthAuthFlows` | flowId (32 hex) | `{ clientId, redirectUri, scopes, state, codeChallenge, csrfToken, agentName, created, operatorXId, operatorXUsername, operatorProfileImageUrl, serverInitiated?, codeVerifier? }` | 10 min | `setInterval` every 60s |
| `oauthAuthCodes` | authCode (64 hex) | `{ clientId, agentName, scopes, codeChallenge, redirectUri, created }` | 5 min | `setInterval` every 60s |
| `oauthPendingFlows` | state (32 hex) | `{ codeVerifier, flowType, consentFlowId?, agentName?, claimToken?, redirect?, created }` | 10 min | `setInterval` every 60s |

All three are lost on PM2 restart.

---

## Security

### PKCE
- Required on every authorization request
- Server-initiated flows (`/oauth/connect`) generate PKCE server-side and pass `code_verifier` to the dApp callback
- dApp-initiated flows require the dApp to generate and manage PKCE

### CSRF Protection
- Consent approve/deny forms include a `csrf_token` hidden field
- Token is generated per-flow and stored in `oauthAuthFlows`
- Server validates the token matches before processing approve/deny

### Client Secret
- Generated as `dappsec_` + 24 random bytes
- Stored as SHA-256 hash, verified with timing-safe comparison
- Dual-secret rotation with configurable grace periods
- Emergency revoke kills all secrets instantly

### Operator Authentication
- Operator must authenticate via X OAuth to prove agent ownership
- X callback verifies operator's `xId` matches `agent.owner.xId`
- If agent pre-selected and X user is not the owner → redirects with `error=not_owner`

### Shared X OAuth Callback
All X OAuth flows use `/admin/auth/callback`, distinguished by `flowType`:
1. **Admin login** — `flowType` undefined
2. **Owner linking** — `flowType: 'owner_link'`
3. **Consent auth** — `flowType: 'consent_auth'`
4. **Developer login** — `flowType: 'developer_login'`

**Cancel handling:** When the X OAuth is cancelled:
- `consent_auth` → redirects back to `/oauth/consent?flow=...`
- `developer_login` → redirects to `/developers`
- Default → redirects to `/admin?error=oauth_denied`

### Transaction Limits
- dApp transactions share the agent's `dailyVolume` — no cap bypass
- Same `maxPerTradeMON` and `dailyCapMON` as direct agent trades
- External sends via proxy require admin withdrawal approval
- Agent-to-agent transfers execute immediately

### Revocation
- Agents: `POST /oauth/revoke` with agent bearer token
- Operators: `/operator/api/revoke` with dev session cookie
- Revoked dApps get 403 on all proxy endpoints and userinfo

---

## Complete Flow Walkthrough

### dApp-Initiated Flow

```
1. dApp redirects operator to:
   GET /oauth/authorize?client_id=X&redirect_uri=Y&scope=balance+swap
     &response_type=code&code_challenge=Z&code_challenge_method=S256
     [&agent=NAME] [&state=S]

2. Server validates, creates flow → redirects to /oauth/consent?flow=FLOW_ID

3. Consent page renders Step 1: "Log in" + "Sign in with X" button

4. Operator clicks "Sign in with X" → X OAuth → callback stores operator identity

5. Consent page re-renders Step 2: scopes, agent, limits, Approve/Deny

6a. Approve → auth code generated → redirect to dApp callback?code=CODE&state=S
6b. Deny → deny page (sad crab + "Try again" + "Go back to app")

7. dApp exchanges code:
   POST /oauth/token { grant_type, code, client_id, client_secret, code_verifier }
   → { access_token, token_type: "Bearer", expires_in: 3600, scope }

8. dApp calls proxy endpoints with Bearer token
```

### Server-Initiated Flow

```
1. Operator visits: GET /oauth/connect/:clientId[?agent=NAME]

2. Server generates PKCE, creates flow with serverInitiated=true
   → redirects to /oauth/consent?flow=FLOW_ID

3-5. Same consent flow as above (X login → Step 2)

6a. Approve → success page on clawnads.org (happy crab, permissions, /operator link)
    Auth code delivered to dApp callback via hidden iframe
    code_verifier passed as URL param to callback
6b. Deny → deny page (sad crab + "Try again" pointing back to /oauth/connect)

7-8. dApp exchanges code using the code_verifier from the callback URL
```

---

## Key Design Decisions

1. **Two authorization paths.** dApp-initiated (standard OAuth) and server-initiated (`/oauth/connect`). Skill docs use server-initiated so agents just share a Clawnads link — no dApp redirect needed.

2. **Server-initiated PKCE.** The server generates PKCE for `/oauth/connect` flows and passes `code_verifier` to the dApp callback. This lets the dApp complete a standard token exchange without generating its own PKCE.

3. **Success page on clawnads.org.** Server-initiated flows show a branded success page instead of redirecting to the dApp. The auth code reaches the dApp via a hidden iframe in the background.

4. **Step 1 is just "Log in."** No scopes, no permissions, no agent info until after X auth. Mirrors Discord's consent flow.

5. **Individual scope toggles.** Each scope is independently selectable in the Developer Portal — no binary Read/Read&write model. Access type badges are informational.

6. **Deny page, not redirect.** Both flow types show a styled deny page on clawnads.org instead of redirecting. "Try again" is always the primary action; "Go back to app" is secondary and only shown for dApp-initiated flows.

7. **Connection tracking.** Approved dApps are recorded on the agent's `connectedDapps` array, enabling the Operator Portal to show all connections and support revocation.

8. **Shared session cookie.** The Operator Portal and Developer Portal share the `clawnads_dev` cookie (`Domain=.clawnads.org`). One X login works across both portals.

---

## What's Left To Do

### Immediate

- **Granular read/write scopes** — Split each scope into `scope:read` and `scope:write` halves. Operators could grant `swap:read` (view trade history) without `swap:write` (execute swaps), or `messages:read` without `messages:write`. This requires changes to: scope definitions, JWT payload, `authenticateOAuth()`, consent page, developer portal, dApp config, and proxy endpoints.
- **`/oauth/proxy/messages` endpoint** — The `messages` scope exists but has no proxy endpoint. Need GET for reading and POST for sending.
- **Session/cookie caching for X login** — Operators must re-authenticate with X on every consent flow. Should cache the operator's X session so Step 1 can be skipped or show "Continue as @username".

### Design Iteration

- `iconUrl` field exists but most dApps don't have one — shows letter/gradient fallback
- Consider scope grouping as more scopes are added
- Consider refresh tokens for long-lived integrations (currently 1h JWT, no refresh)

### Infrastructure

- **In-memory flow state** — all active OAuth flows lost on PM2 restart
- `OAUTH_SIGNING_KEY` not set — falls back to `SESSION_SECRET`
- **`showError` undefined** in `oauth-consent.html` — line 236 calls it but the function doesn't exist. Low priority (server catches this first)

---

## Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `OAUTH_SIGNING_KEY` | No (falls back to `SESSION_SECRET`) | HMAC key for JWT access tokens |
| `SESSION_SECRET` | Yes | HMAC key for session cookies and fallback JWT signing |
| `X_CLIENT_ID` | Yes | Twitter/X OAuth 2.0 Client ID |
| `X_CLIENT_SECRET` | Yes | Twitter/X OAuth 2.0 Client Secret |

---

## File Reference

| File | Purpose |
|------|---------|
| `server.js` | All OAuth endpoints, proxy middleware, operator portal API |
| `public/oauth-consent.html` | Consent page (two-step, client-rendered) |
| `public/oauth-playground.html` | OAuth Playground / Test App (4 tabs) |
| `public/operator-apps.html` | Operator Portal (manage connected dApps) |
| `public/developers.html` | Developer Portal shell |
| `public/developers.js` | Developer Portal logic (CRUD, modals, skill doc gen) |
| `public/developers.css` | Developer Portal styles |
| `public/landing.html` | clawnads.org landing page |
| `public/happy-crab.svg` | White thin crab SVG (consent login, success page) |
| `public/happy-crab-blue.svg` | Blue crab SVG (playground login button) |
| `data/dapps.json` | dApp registrations (hashed secrets, scopes, redirects) |
