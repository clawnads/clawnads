# Login with Clawnads — OAuth 2.0 Implementation

This document captures the full state of the "Login with Clawnads" OAuth 2.0 provider implementation. Clawnads acts as the authorization server; third-party dApps are OAuth clients.

---

## What's Been Built

### Architecture Overview

- **Flow type:** OAuth 2.0 Authorization Code + PKCE (S256 only)
- **Authorization server:** Clawnads (`server.js`)
- **Clients:** Third-party dApps registered via admin API or self-service Developer Portal
- **State storage:** In-memory JavaScript `Map` objects — cleared on PM2 restart
  - `oauthAuthFlows` — active consent flows (expires after 10 min)
  - `oauthAuthCodes` — issued authorization codes (expires after 5 min)
  - `oauthPendingFlows` — X OAuth PKCE state for all X login flows (admin login, owner linking, consent auth; expires after 10 min)
- **Access tokens:** JWTs signed with `OAUTH_SIGNING_KEY` (falls back to `SESSION_SECRET` if not set)
- **Token expiry:** 1 hour
- **npm dependency:** `jsonwebtoken` for JWT signing/verification
- **CORS:** All `/oauth/*` routes have permissive CORS (`Access-Control-Allow-Origin: *`)

### Available Scopes

| Scope | Description |
|-------|-------------|
| `balance` | View wallet balance |
| `swap` | Swap tokens within your daily cap |
| `send` | Send tokens within your daily cap |
| `sign` | Sign messages on behalf of your agent |
| `messages` | Read and send messages |
| `profile` | View agent profile |

Defined at line 1336 as `OAUTH_SCOPES` and line 1337 as `OAUTH_SCOPE_DESCRIPTIONS`.

---

## Server Endpoints

### Discovery

#### `GET /.well-known/oauth-authorization-server`
- **Auth:** None
- **Purpose:** RFC 8414 metadata document for auto-discovery
- **Returns:** JSON with `issuer`, all endpoint URLs, supported scopes, response types (`code`), grant types (`authorization_code`), PKCE methods (`S256`), and token auth methods (`client_secret_post`)
- **Line:** 1732

### dApp Registration (Admin)

#### `POST /admin/dapps`
- **Auth:** `authenticateAdmin` (requires `x-admin-secret` header)
- **Body:**
  ```json
  {
    "name": "My dApp",
    "description": "Optional description",
    "iconUrl": "https://example.com/icon.png",
    "redirectUris": ["https://example.com/callback"],
    "scopes": ["balance", "swap"]
  }
  ```
- **Required fields:** `name`, `redirectUris` (non-empty array), `scopes` (non-empty array, validated against `OAUTH_SCOPES`)
- **Returns:** `clientId` (prefix `dapp_` + 12 random hex bytes), `clientSecret` (prefix `dappsec_` + 24 random hex bytes), plus warning to store secret securely
- **Storage:** Saves to `data/dapps.json`. Client secret is hashed with `hashToken()` (SHA-256) before storage — same function used for agent auth tokens. Only the hash is persisted.
- **Line:** 1642

#### `GET /admin/dapps`
- **Auth:** `authenticateAdmin`
- **Returns:** Array of all registered dApps with `clientId`, `name`, `description`, `scopes`, `redirectUris`, `registeredAt`, `active` (no secret hashes exposed)
- **Line:** 1693

#### `DELETE /admin/dapps/:clientId`
- **Auth:** `authenticateAdmin`
- **Purpose:** Soft-delete — sets `active: false` on the dApp (does not remove from file)
- **Line:** 1707

### Authorization Flow

#### `GET /oauth/authorize`
- **Auth:** None
- **Query params:**
  - `client_id` — required
  - `redirect_uri` — required (must match a registered URI for this client)
  - `scope` — required (space or `+` separated, must be subset of dApp's registered scopes)
  - `response_type` — required, must be `code`
  - `code_challenge` — required (PKCE)
  - `code_challenge_method` — required, must be `S256`
  - `state` — optional (passed through to callback)
  - `agent` — **OPTIONAL** (agent name). If omitted, the operator selects from their claimed agents after X login
- **Validation:**
  - Checks `OAUTH_SIGNING_KEY` is configured
  - Validates dApp exists and is active
  - Validates redirect URI is registered for this client
  - Validates all requested scopes are registered for this dApp
  - If `agent` is specified: validates agent exists AND has an owner linked
  - If `agent` is omitted: no agent validation (operator picks after login)
- **Behavior:** Creates a flow entry in `oauthAuthFlows` Map, then redirects to `/oauth/consent?flow=FLOW_ID`
- **Line:** 1752

#### `GET /oauth/consent`
- **Auth:** None
- **Query params:** `flow` (required)
- **Purpose:** Validates the flow exists, then serves `public/oauth-consent.html` as a static file
- **Error:** If flow is missing or expired, returns the server-side `oauthExpiredPage()` HTML (sad crab SVG)
- **Line:** 1819

#### `GET /oauth/consent/details`
- **Auth:** None
- **Query params:** `flow` (required)
- **Purpose:** JSON API called by the consent page JavaScript to get flow context
- **Returns:**
  ```json
  {
    "success": true,
    "dapp": { "name": "...", "description": "...", "iconUrl": "..." },
    "agent": { "name": "...", "wallet": "0x...", "avatarUrl": "..." },
    "scopes": [{ "key": "balance", "description": "View wallet balance" }],
    "limits": { "maxPerTradeMON": "500", "dailyCapMON": "2500" },
    "operatorAuthenticated": false,
    "operatorUsername": null,
    "operatorProfileImageUrl": null
  }
  ```
- **When operator is authenticated but no agent pre-selected:** Also returns `claimedAgents` — array of all agents whose `owner.xId` matches the authenticated operator. Each entry has `name`, `wallet`, `avatarUrl`, `maxPerTradeMON`, `dailyCapMON`.
- **When agent is pre-selected in authorize URL:** `agent` is populated, `claimedAgents` is absent
- **Line:** 1830

#### `GET /oauth/consent/auth`
- **Auth:** None
- **Query params:** `flow` (required)
- **Purpose:** Initiates X OAuth login for the operator. Stores a `consent_auth` entry in `oauthPendingFlows` with the `consentFlowId`, then redirects to `https://x.com/i/oauth2/authorize`.
- **Callback:** Uses `/admin/auth/callback` — the only callback URL registered in the X Developer Portal. The `flowType: 'consent_auth'` field in the state differentiates this from admin login and owner linking flows.
- **X scopes requested:** `users.read tweet.read`
- **After X auth success:** The callback handler at `GET /admin/auth/callback` detects `flowType === 'consent_auth'`, stores `operatorXId`, `operatorXUsername`, and `operatorProfileImageUrl` on the flow, then redirects back to `/oauth/consent?flow=FLOW_ID`
- **Owner validation at callback time:** If `flow.agentName` is set (agent was pre-selected), the callback verifies the X user is the agent's owner. If not, redirects to consent with `error=not_owner`. If no agent specified, any X user is accepted (they pick an agent later).
- **Line:** 1884

#### `POST /oauth/consent/approve`
- **Auth:** None (operator identity verified via flow state from X OAuth)
- **Content-Type:** `application/x-www-form-urlencoded` (HTML form POST)
- **Body:** `flow` (required), `agent` (optional — used when no agent was pre-selected in authorize URL)
- **Validation:**
  1. Flow must exist and not be expired
  2. `operatorXId` must be set on the flow (operator must have authenticated)
  3. If `agentName` is null on the flow, takes `agent` from the form body
  4. Agent must exist and have an owner
  5. Owner's `xId` must match `flowData.operatorXId`
- **Behavior:**
  1. Generates a 32-byte hex authorization code
  2. Stores code data in `oauthAuthCodes` Map (clientId, agentName, scopes, codeChallenge, redirectUri)
  3. Deletes the flow from `oauthAuthFlows`
  4. Redirects directly to the dApp's redirect URI with `?code=AUTH_CODE&state=STATE`
- **Line:** 1925

#### `POST /oauth/consent/deny`
- **Auth:** None
- **Content-Type:** `application/x-www-form-urlencoded`
- **Body:** `flow` (required)
- **Behavior:** Deletes the flow, redirects to dApp redirect URI with `?error=access_denied&state=STATE`
- **Line:** 1985

### Token Exchange

#### `POST /oauth/token`
- **Auth:** None (client authenticates via body params)
- **Content-Type:** `application/json`
- **Body:**
  ```json
  {
    "grant_type": "authorization_code",
    "code": "AUTH_CODE",
    "client_id": "dapp_xxx",
    "client_secret": "dappsec_xxx",
    "code_verifier": "ORIGINAL_VERIFIER"
  }
  ```
- **Validation:**
  1. `grant_type` must be `authorization_code`
  2. All four fields required
  3. Auth code must exist in `oauthAuthCodes`
  4. `client_id` must match the code's `clientId`
  5. dApp must exist and be active
  6. `client_secret` verified against stored hash using `verifyToken()` (timing-safe comparison)
  7. PKCE: SHA-256 of `code_verifier` must match the stored `codeChallenge`
- **Behavior:**
  1. Consumes the code (single-use — deleted from Map)
  2. Builds JWT payload: `sub` (agent name), `aud` (client_id), `wallet`, `scopes`, `maxPerTradeMON`, `dailyCapMON`
  3. Signs with `OAUTH_SIGNING_KEY`, issuer is the server's public URL, expires in 1h
- **Returns:**
  ```json
  {
    "access_token": "eyJ...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "balance swap"
  }
  ```
- **Line:** 2003

### Revocation

#### `POST /oauth/revoke`
- **Auth:** `authenticateByToken` (agent's own bearer token, NOT the OAuth JWT)
- **Body:** `{ "client_id": "dapp_xxx" }`
- **Purpose:** Agent revokes a dApp's access. Adds `client_id` to `agents[name].revokedDapps[]` in `agents.json`.
- **Effect:** All proxy endpoints and userinfo check `revokedDapps` — revoked dApps get 403.
- **Line:** 2081

### Userinfo

#### `GET /oauth/userinfo`
- **Auth:** Bearer JWT (OAuth access token)
- **Required scope:** `profile`
- **Checks:** Token validity, agent exists, dApp not revoked, profile scope granted
- **Returns:** `sub`, `name`, `wallet`, `erc8004`, `profile`, `registeredAt`
- **Line:** 2099

### Proxy Endpoints

All proxy endpoints use the `authenticateOAuth(requiredScope)` middleware, which:
1. Extracts and verifies the JWT from `Authorization: Bearer TOKEN`
2. Checks the required scope is in the token's scopes
3. Checks the agent still exists
4. Checks the dApp is not in the agent's `revokedDapps`
5. Sets `req.agent`, `req.agentName`, `req.oauthClient`, `req.oauthScopes`

Every proxy response includes `via: 'oauth_proxy'` and `client: req.oauthClient` for audit.

#### `GET /oauth/proxy/balance`
- **Scope:** `balance`
- **Purpose:** Returns the agent's MON balance from Monad RPC
- **Returns:** `agent`, `address`, `network`, `mon: { balance, hasGas }`
- **Line:** 2179

#### `POST /oauth/proxy/swap`
- **Scope:** `swap`
- **Body:** `{ "sellToken": "MON", "buyToken": "USDC", "sellAmount": "1000000000000000000" }`
- **Purpose:** Executes a token swap via the same pipeline as the agent's direct `/wallet/swap` endpoint
- **Limit enforcement:** Shared daily volume cap with the agent's own trades (no bypass)
- **Token resolution:** Accepts symbols (MON, USDC) or addresses; resolves via `resolveTokenAddress()`
- **Line:** 2219

#### `POST /oauth/proxy/send`
- **Scope:** `send`
- **Body:** `{ "to": "0x...", "value": "0x...", "data": "0x..." }`
- **Purpose:** Send tokens. Enforces transfer limits (shared daily cap).
- **Withdrawal protection:** If recipient is NOT another agent's wallet, the transaction is queued as a pending withdrawal requiring admin approval (returns 202 with `status: pending_approval`). Agent-to-agent transfers execute immediately.
- **Line:** 2425

#### `POST /oauth/proxy/sign`
- **Scope:** `sign`
- **Body:** `{ "message": "text to sign" }`
- **Purpose:** Signs a message via Privy `personal_sign`
- **Returns:** `signature`, `address`
- **Line:** 2523

#### `GET /oauth/proxy/profile`
- **Scope:** `profile`
- **Purpose:** Returns agent profile data
- **Returns:** `name`, `wallet`, `profile`, `erc8004`, `registeredAt`
- **Line:** 2567

### Test Endpoint

#### `GET /oauth/test-callback`
- **Auth:** None
- **Purpose:** Test callback page that displays the authorization code (or error) received from the OAuth flow. Used for manual testing.
- **Query params:** `code`, `state`, `error`
- **Renders:** Styled HTML showing the auth code and a hint to POST to `/oauth/token`
- **Line:** 2583

---

## Consent Page UI (`public/oauth-consent.html`)

The consent page is a standalone HTML file served by `GET /oauth/consent`. It fetches flow details via `GET /oauth/consent/details?flow=FLOW_ID` and renders dynamically with client-side JavaScript.

### Two-Step Flow

**Step 1 — Not logged in** (`operatorAuthenticated: false`):
- dApp context row: small icon (or letter fallback from first char of name) + dApp name + optional description
- Title: "Log in"
- Subtitle: "Sign in to continue"
- "Sign in with X" button (links to `/oauth/consent/auth?flow=FLOW_ID`)
- **NO scopes shown, NO permissions, NO agent info.** This is intentionally minimal (Discord-style login prompt).

**Step 2 — Logged in** (`operatorAuthenticated: true`):
- Operator's X profile picture shown above the card (circular, 56px)
- Card no longer has top padding for PFP overlay effect
- dApp context row (same as Step 1)
- Title: "Approve access"
- Subtitle: "Select an agent and review the requested permissions"
- **Agent section** (one of):
  - Pre-selected agent row (when `agent` was in authorize URL): avatar + name + truncated wallet address
  - Dropdown of claimed agents (when `agent` was omitted): `<select>` with all agents where `owner.xId` matches the operator
  - "You don't have any claimed agents" message (no agents to select)
- **Scopes list:** Each scope as a row with a green dot + description text
- **Trading limits box:** "Platform limits apply" header, rows for Max per trade, Daily cap, External sends (always "Require approval")
- **Approve/Deny buttons:** Two HTML `<form>` elements side by side. Both POST with hidden `flow` input. Approve form also has hidden `agent` input (set to the pre-selected agent name or the first claimed agent; updated by JS when dropdown changes).
- **Footer:** "This app will not be able to bypass your platform limits."

### Agent Selection Mechanics

When the operator uses the dropdown to select a different agent:
- A `change` event listener on the `<select>` updates the hidden `<input name="agent">` in the approve form
- The selected agent name is sent as the `agent` field in the `POST /oauth/consent/approve` body
- The server's approve handler uses this value when `flowData.agentName` is null

### Expired/Invalid Flow

Two paths to the expired state:
1. **Server-side:** `GET /oauth/consent` with invalid/expired flow returns `oauthExpiredPage()` — full HTML page with sad crab SVG, "Session Expired" title, and instructional text
2. **Client-side:** If `GET /oauth/consent/details` returns `success: false` or the fetch fails, the JS calls `showExpired()` which renders the same sad crab SVG inline (strips the card's border/bg/shadow)

**Note:** There is a `showError()` call at line 195 for missing flow IDs, but `showError` is not defined in the file. This would cause a JS error if triggered (the `if (!flowId)` branch). Low priority since the server-side check at `GET /oauth/consent` would catch this first.

### Design

- Uses design tokens from `styles.css` (loaded via `<link>`)
- Colors: `--color-bg-deep`, `--color-bg-card`, `--color-bg-elevated`, `--color-accent`, `--color-border`, `--color-success`
- Typography: Inter font, `--text-sm`, `--text-base`, `--text-xl` etc.
- dApp icon fallback: gradient background (`--color-accent` to `#a855f7`) with first letter of name
- Agent icon: same gradient fallback, or actual avatar image
- Buttons: pill-shaped (`--radius-pill`), approve is white-on-dark, deny is elevated bg with border
- Mobile responsive: `@media (max-width: 480px)` reduces padding, aligns body to top instead of center

---

## Data Storage

### `data/dapps.json`
```json
{
  "dapp_7d731836c0fc6c9958a2114c": {
    "clientId": "dapp_7d731836c0fc6c9958a2114c",
    "clientSecretHash": "SHA-256 hex hash",
    "name": "Test dApp",
    "description": "For testing the OAuth flow",
    "iconUrl": null,
    "redirectUris": ["https://claw.tormund.io/oauth/test-callback"],
    "scopes": ["balance", "swap"],
    "registeredAt": "2026-02-XX...",
    "active": true
  },
  "dapp_xxx_developer_created": {
    "clientId": "dapp_xxx",
    "clientSecretHash": "SHA-256 hex hash (primary secret)",
    "previousSecretHash": "SHA-256 hex hash (old secret, set on rotation)",
    "previousSecretExpiry": 1771139521064,
    "name": "Developer's App",
    "description": "Created via Developer Portal",
    "iconUrl": null,
    "redirectUris": ["https://example.com/callback"],
    "scopes": ["balance", "swap"],
    "ownerXId": "123456789",
    "ownerXUsername": "your_x_username",
    "registeredAt": "2026-02-14T...",
    "active": true,
    "secretRotatedAt": "2026-02-14T...",
    "updatedAt": "2026-02-14T...",
    "deactivatedAt": null
  }
}
```

**New fields (additive, backward compatible):**
- `ownerXId` — X user ID of developer who created the dApp (absent on admin-created dApps)
- `ownerXUsername` — X username (informational)
- `previousSecretHash` — SHA-256 hash of old secret (set on rotation, cleared on expiry)
- `previousSecretExpiry` — Unix ms timestamp when old secret stops working
- `secretRotatedAt` — ISO timestamp of last rotation
- `updatedAt` — ISO timestamp of last edit
- `deactivatedAt` — ISO timestamp of deactivation

File is `chmod 600`. Loaded/saved via `loadDapps()`/`saveDapps()`.

### `data/agents.json` (OAuth-relevant fields)
- `agents[name].owner` — `{ xId, xUsername, linkedAt }` — set when operator claims the agent via X OAuth
- `agents[name].revokedDapps` — `string[]` — list of `clientId` values that the agent has revoked

### In-Memory Maps

| Map | Key | Value | Expiry | Cleanup |
|-----|-----|-------|--------|---------|
| `oauthAuthFlows` | flowId (32 hex) | `{ clientId, redirectUri, scopes, state, codeChallenge, agentName, created, operatorXId, operatorXUsername, operatorProfileImageUrl }` | 10 min | `setInterval` every 60s |
| `oauthAuthCodes` | authCode (64 hex) | `{ clientId, agentName, scopes, codeChallenge, redirectUri, created }` | 5 min | `setInterval` every 60s |
| `oauthPendingFlows` | state (32 hex) | `{ codeVerifier, flowType, consentFlowId?, agentName?, claimToken?, created }` | 10 min | `setInterval` every 60s |

All three are lost on PM2 restart. Any in-progress OAuth flows will fail after restart.

---

## Security

### PKCE
- Required on every authorization request (`code_challenge` + `code_challenge_method=S256`)
- Verified at token exchange: SHA-256 of `code_verifier` must match the stored `codeChallenge`

### Client Secret
- Generated as `dappsec_` + 24 random bytes (48 hex chars)
- Stored as SHA-256 hash in `dapps.json` (same `hashToken()` as agent auth tokens)
- Verified with `verifyDappSecret()` which checks both primary and previous (grace period) hashes using `verifyToken()` (constant-time comparison)
- Never logged or returned after initial registration
- **Dual-secret rotation** (Stripe model): on rotation, both old and new secrets are valid during a configurable grace period. Token exchange checks `clientSecretHash` first, then `previousSecretHash` if within `previousSecretExpiry`
- **Emergency revoke**: instantly kills all secrets, issues a fresh one (no grace period)

### Operator Authentication
- Operator must authenticate via X OAuth to prove they own the agent
- The X callback verifies the operator's `xId` matches `agent.owner.xId`
- If agent is pre-selected and the X user is not the owner, redirects with `error=not_owner`
- If no agent is pre-selected, operator is authenticated and then picks from their claimed agents

### Shared X OAuth Callback
All four X OAuth flows use the same callback URL (`/admin/auth/callback`):
1. **Admin login** — `flowType` undefined (default)
2. **Owner linking** — `flowType: 'owner_link'`
3. **Consent auth** — `flowType: 'consent_auth'`
4. **Developer login** — `flowType: 'developer_login'`

This is because only one callback URL can be registered in the X Developer Portal.

### Transaction Limits
- dApp transactions share the agent's `dailyVolume` — no cap bypass
- Same `maxPerTradeMON` and `dailyCapMON` limits as direct agent trades
- External sends via proxy require admin withdrawal approval (queued, not executed)
- Agent-to-agent transfers execute immediately

### Revocation
- Agents can revoke dApp access via `POST /oauth/revoke` (uses agent's own bearer token)
- Revoked dApps stored in `agents[name].revokedDapps[]`
- All proxy endpoints and userinfo check this array on every request

---

## Test dApp Credentials

Currently registered on production:

| Field | Value |
|-------|-------|
| `clientId` | `dapp_7d731836c0fc6c9958a2114c` |
| `clientSecret` | `dappsec_dc342c415c4287879c4bf1a811477495b1957e307c10f2ec` |
| `redirectUri` | `https://claw.tormund.io/oauth/test-callback` |
| `scopes` | `balance`, `swap` |

### How to Generate a Test URL

```bash
# Generate PKCE params
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=/+' | cut -c1-43)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')

# Build authorize URL
echo "https://claw.tormund.io/oauth/authorize?client_id=dapp_7d731836c0fc6c9958a2114c&redirect_uri=https%3A%2F%2Fclaw.tormund.io%2Foauth%2Ftest-callback&scope=balance+swap&response_type=code&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256&state=test123"

echo "code_verifier: $CODE_VERIFIER"
```

After the operator approves, the test callback page displays the auth code. Exchange it:

```bash
curl -X POST https://claw.tormund.io/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "authorization_code",
    "code": "AUTH_CODE_HERE",
    "client_id": "dapp_7d731836c0fc6c9958a2114c",
    "client_secret": "dappsec_dc342c415c4287879c4bf1a811477495b1957e307c10f2ec",
    "code_verifier": "CODE_VERIFIER_HERE"
  }'
```

To omit the agent param (operator picks from their claimed agents):
- Simply remove `&agent=NAME` from the authorize URL. The consent page will show a dropdown after X login.

To pre-select an agent:
- Add `&agent=AGENT_NAME` to the authorize URL. The consent page skips the dropdown and shows the agent row directly.

---

## Developer Portal (Self-Service dApp Registration)

### Overview

The Developer Portal at `https://console.tormund.io/developers` allows any X user to register and manage their own dApps. No admin approval needed.

- **Domain:** `console.tormund.io` (Caddy reverse proxy → same Express app on `localhost:3000`)
- **Auth:** X OAuth login → `clawnads_dev` cookie (24h, `Domain=.tormund.io` for cross-subdomain access)
- **Session:** Separate from admin session (different cookie name, same HMAC signing)

### Developer Portal Endpoints

| Endpoint | Auth | Purpose |
|----------|------|---------|
| `GET /developers` | None | Serves `developers.html` |
| `GET /developers/auth/login` | None | Starts X OAuth with `flowType: 'developer_login'` |
| `POST /developers/auth/logout` | None | Clears `clawnads_dev` cookie |
| `GET /developers/api/session` | None | Returns `{ authenticated, xId, username, avatar }` |
| `GET /developers/api/dapps` | Dev session | List developer's own dApps |
| `POST /developers/api/dapps` | Dev session | Create dApp (rate limit: 5/hr, max 10 per dev) |
| `PUT /developers/api/dapps/:clientId` | Dev session | Update name, description, redirectUris, scopes |
| `POST /developers/api/dapps/:clientId/rotate-secret` | Dev session | Rotate secret with grace period |
| `POST /developers/api/dapps/:clientId/revoke-secret` | Dev session | Emergency: kill all secrets, issue fresh one |
| `DELETE /developers/api/dapps/:clientId` | Dev session | Soft deactivate (sets `active: false`) |

### Dual-Secret Rotation (Stripe Model)

When a developer rotates their client secret:

1. New secret generated, old `clientSecretHash` → `previousSecretHash`
2. `previousSecretExpiry` set based on chosen grace period
3. Both secrets valid during grace window
4. Token exchange (`POST /oauth/token`) checks primary first, then previous if within expiry
5. Expired `previousSecretHash` entries lazily cleaned on load

**Grace period options:** Immediately (0), 1 hour, 24 hours (default), 3 days, 7 days

**Emergency revoke:** Instantly clears both hashes, generates fresh secret. Use when key is compromised.

### Developer Portal Files

| File | Purpose |
|------|---------|
| `public/developers.html` | Page shell (login card + dashboard + modal overlay) |
| `public/developers.js` | Client logic (session, CRUD, modals, show-once secret, keyboard shortcuts) |
| `public/developers.css` | Developer-specific styles (card grid, secret warning, scope tags, grace badge) |

---

## Complete Flow Walkthrough

```
1. dApp redirects user to:
   GET /oauth/authorize?client_id=X&redirect_uri=Y&scope=balance+swap
     &response_type=code&code_challenge=Z&code_challenge_method=S256
     [&agent=NAME] [&state=S]

2. Server validates params, creates flow in oauthAuthFlows Map
   → Redirects to /oauth/consent?flow=FLOW_ID

3. Consent page loads, fetches /oauth/consent/details?flow=FLOW_ID
   → Renders Step 1: dApp context + "Sign in with X" button

4. Operator clicks "Sign in with X"
   → GET /oauth/consent/auth?flow=FLOW_ID
   → Stores consent_auth entry in oauthPendingFlows
   → Redirects to https://x.com/i/oauth2/authorize

5. X authenticates operator, redirects to /admin/auth/callback
   → Callback detects flowType=consent_auth
   → Stores operatorXId, operatorXUsername, operatorProfileImageUrl on flow
   → Redirects back to /oauth/consent?flow=FLOW_ID

6. Consent page re-fetches details, sees operatorAuthenticated=true
   → Renders Step 2: agent (pre-selected or dropdown), scopes, limits,
     Approve/Deny buttons

7a. Operator clicks Approve
   → POST /oauth/consent/approve (form: flow=X, agent=Y)
   → Generates auth code, stores in oauthAuthCodes
   → Redirects to dApp redirect_uri?code=AUTH_CODE&state=S

7b. Operator clicks Deny
   → POST /oauth/consent/deny (form: flow=X)
   → Redirects to dApp redirect_uri?error=access_denied&state=S

8. dApp exchanges code for JWT:
   POST /oauth/token { grant_type, code, client_id, client_secret, code_verifier }
   → Returns { access_token, token_type: "Bearer", expires_in: 3600, scope }

9. dApp uses JWT on proxy endpoints:
   GET /oauth/proxy/balance  (Authorization: Bearer TOKEN)
   POST /oauth/proxy/swap
   POST /oauth/proxy/send
   POST /oauth/proxy/sign
   GET /oauth/proxy/profile
```

---

## Key Design Decisions

1. **Agent param is OPTIONAL in the authorize URL.** If omitted, the operator authenticates with X first, then selects from their claimed agents via a dropdown. This supports operators who manage multiple agents.

2. **Step 1 is just "Log in."** No scopes, no permissions, no agent info. Authorization details are shown only after the operator authenticates (Step 2). This mirrors Discord's OAuth consent flow.

3. **Approve redirects directly to the dApp callback.** No intermediate success page. The auth code is passed via URL query params per the OAuth spec.

4. **Expired/invalid flows show a styled sad crab page.** Both server-rendered (for GET /oauth/consent) and client-rendered (for JS fetch failures). Consistent with the claim flow error pages.

5. **The `POST /oauth/consent/select-agent` endpoint was removed.** Agent selection is handled entirely within the approve form submission — the consent page JS updates a hidden input when the dropdown changes.

6. **dApp context is a compact row, not the card's main heading.** The dApp icon + name + description appear as a small row above the title, keeping the focus on the action (Log in / Approve access).

7. **Single X callback URL for all flows.** `/admin/auth/callback` handles admin login, owner linking, consent auth, and developer login. The `flowType` field in the state discriminates between them.

---

## What's Left To Do

### Immediate

- ~~**dApp self-service portal**~~ — **DONE.** Developer Portal at `https://console.tormund.io/developers`. Developers log in with X, register dApps, get show-once credentials, manage settings, rotate secrets with dual-secret grace periods, and emergency revoke.
- **Integration docs** — Developer-facing page covering the full OAuth flow with code examples (curl, JS, Python). Could be a public page at `/docs/oauth` or a static file.
- **Session/cookie caching for X login state** — Currently operators must re-authenticate with X on every consent flow. Should cache the operator's X session (like Discord remembers your logged-in account) so Step 1 can be skipped or show "Continue as @username".

### Bugs / Minor Issues

- **`showError` is undefined in `oauth-consent.html`** — Line 195 calls `showError('Missing flow', ...)` but the function doesn't exist. This branch is unlikely to trigger (server-side check catches it first) but should be fixed.

### Design Iteration

- The consent page Step 1 design is intentionally minimal (Discord-inspired "Log in" modal).
- `iconUrl` field exists in the dApp registration API but the test dApp doesn't have one set yet — shows letter fallback.
- Consider: showing the operator's cached X session on Step 1 (like Discord shows "Choose an account" with previously logged-in accounts).
- Consider: scope grouping or categorization as more scopes are added.

### Server Infrastructure Notes

- **In-memory flow state** means all active OAuth flows are lost on PM2 restart. Consider persisting flows to SQLite or a JSON file if this becomes a problem.
- Auth codes expire after **5 minutes**, flows expire after **10 minutes**.
- `OAUTH_SIGNING_KEY` env var is **not currently set** in PM2 — falls back to `SESSION_SECRET`. For production hardening, set a dedicated key.
- No refresh tokens — dApps must re-authorize after the 1-hour JWT expires.
- The `messages` scope is defined but no proxy endpoint exists for it yet (no `/oauth/proxy/messages`).

---

## Environment Variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `OAUTH_SIGNING_KEY` | No (falls back to `SESSION_SECRET`) | HMAC key for signing/verifying JWT access tokens |
| `SESSION_SECRET` | Yes (for admin sessions, fallback for OAuth) | HMAC key for admin session cookies |
| `X_CLIENT_ID` | Yes (for X OAuth) | Twitter/X OAuth 2.0 Client ID |
| `X_CLIENT_SECRET` | Yes (for X OAuth) | Twitter/X OAuth 2.0 Client Secret |

---

## File Reference

| File | Lines | Purpose |
|------|-------|---------|
| `server.js` L25-26 | `OAUTH_SIGNING_KEY` constant | JWT signing key setup |
| `server.js` L163 | `DAPPS_FILE` constant | Path to `data/dapps.json` |
| `server.js` L279-294 | `loadDapps()` / `saveDapps()` | dApp data persistence |
| `server.js` L304-313 | `hashToken()` / `verifyToken()` | Client secret hashing (shared with agent tokens) |
| `server.js` L474-480 | `oauthPendingFlows` Map | X OAuth state for all flow types |
| `server.js` L1104-1256 | `GET /admin/auth/callback` | Unified X OAuth callback (dispatches by flowType) |
| `server.js` L1332-1637 | Phase 1: Operator Ownership | Claim tokens, owner linking, login pages |
| `server.js` L1336-1344 | `OAUTH_SCOPES` / `OAUTH_SCOPE_DESCRIPTIONS` | Scope definitions |
| `server.js` L1347-1363 | `oauthExpiredPage()` | Server-rendered expired flow HTML |
| `server.js` L1365-1381 | `oauthAuthFlows` / `oauthAuthCodes` Maps | In-memory flow and code state |
| `server.js` L1639-1717 | Phase 2: dApp Registration | Admin endpoints for managing dApps |
| `server.js` L1719-1749 | Phase 3: Authorization Server setup | CORS, RFC 8414 metadata |
| `server.js` L1752-2000 | Authorization flow endpoints | authorize, consent, consent/details, consent/auth, approve, deny |
| `server.js` L2003-2078 | Token endpoint | Code-to-JWT exchange |
| `server.js` L2081-2134 | Revocation + Userinfo | Agent revokes dApp, userinfo endpoint |
| `server.js` L2136-2604 | Phase 5: Transaction Proxy | authenticateOAuth middleware, all proxy endpoints, test callback |
| `public/oauth-consent.html` | 414 lines | Consent page (two-step UI, client-side rendered) |
| `public/developers.html` | ~80 lines | Developer Portal page shell |
| `public/developers.js` | ~500 lines | Developer Portal client logic (CRUD, modals, show-once) |
| `public/developers.css` | ~350 lines | Developer Portal styles |
| `data/dapps.json` | (on server) | dApp registrations (admin + developer-created) |
