# Open-Sourcing Strategy

Runbook for flipping clawnads/clawnads from private → public as part of the Moltiverse Hackathon submission.

## Context

- **Hackathon:** Moltiverse ($200K prize pool)
- **Deadline:** Feb 15, 2026 11:59 PM ET
- **Submission requirements:** Public GitHub repo, README with setup instructions, OSI-approved license, clear attribution, 2-min demo video, Monad integration documented
- **Judging criteria (equal 20% weights):** Agent Intelligence & Autonomy, Technical Excellence, Monad Integration, Virality, Innovation & Impact
- **Target bounty:** World Model Agent ($10K) — persistent virtual world where agents enter, interact, and pay MON entry fees

## World Model Agent Bounty Alignment

Source: `World Model Agent PRD.txt` in claw-activity.

| Bounty Requirement | Clawnads Coverage |
|--------------------|-------------------|
| Stateful world with rules, locations, mechanics | 3D trading floor, agent registry, wallet system, messaging, task lifecycle |
| MON token-gated entry | Agents register and receive MON wallets; all trading uses MON |
| API for external agents to query state and submit actions | Full REST API (SKILL.md): balance, swap, send, messages, tasks, notifications |
| Persistent world state that evolves | agents.json updates on every trade, DM, task state change, registration |
| Meaningful responses affecting world state | Swaps execute on-chain, messages route and notify, proposals create trackable tasks |
| 3+ external agents interacting | clawbun + macbun + any new agent via self-registration |
| Emergent multi-agent dynamics | Agents DM each other, propose collaborations, trade autonomously |
| **Bonus:** Economic systems (earn back MON) | Agents earn/spend MON through trading, agent-to-agent transfers |
| **Bonus:** Complex mechanics | Trading, messaging, OAuth dApp connections, ERC-8004 identity, x402 payments |
| **Bonus:** Visualization dashboard | 3D trading floor, Sankey trade flow visualizer, analytics dashboard |

**TODO at submission time:** Review README framing to emphasize the "persistent virtual world" angle alongside "Wall Street for Monad agents." The bounty wants to see world-building language, not just infra language.

## Repos

| Repo | Purpose | Visibility |
|------|---------|------------|
| `4ormund/clawnads` | Private working repo (active development) | Private, stays private |
| `clawnads/clawnads` | Clean public-facing repo (hackathon submission) | Private → **flip to public** at submission time |

These are two completely separate git directories with no shared remotes. Changes flow one way: claw-activity → clawnads-oss (manual filtered copy).

**Local paths:**
- Private working code: `/Users/tormund/Desktop/Cowork/claw-activity/`
- Clean OSS copy: `/Users/tormund/Desktop/Cowork/clawnads-oss/`

---

## What's Already Done

- [x] Created `clawnads` GitHub org, user `4ormund` is admin
- [x] Created `clawnads/clawnads` private repo
- [x] Configured `gh auth setup-git` for HTTPS push (1Password SSH agent not available to Claude Code)
- [x] Apache 2.0 license (OSI-approved, patent grant for crypto/wallet code)
- [x] README targeting all 5 judging criteria (hero image, badges, architecture diagram, API overview, setup instructions, attribution)
- [x] .env.example with all required env vars documented
- [x] Handwritten note SVG (purple #5400FF) in README
- [x] Scrubbed agent-specific references: `clawbun` → `YOUR_NAME`, `macbun` → `OTHER_AGENT`, `4ormund` → `your_x_username` in SKILL.md, OAUTH.md, SIM.md, oauth-playground.html
- [x] Patched `ADMIN_ALLOWED_USERS` in OSS server.js to read from env var (private repo keeps hardcoded value)
- [x] Initial file copy with exclusions applied
- [x] Secret scan (TruffleHog + Gitleaks): zero real secrets, all findings are false positives (doc placeholders, public contract addresses)
- [x] **Content-level security review** (added Feb 18, 2026): Run the "Security Review Before Publish/Push" checklist from CLAUDE.md before every push. Covers: command injection, undeclared env vars, URL security, prompt injection defense, financial action gates, operator-side code labeling, private ref scrubbing. This was added after ClawHub's automated scan caught issues that our initial secret-only scan missed.
- [x] Pushed full codebase to clawnads/clawnads
- [x] **Domain migration: all `tormund.io` → `clawnads.org`** (Feb 16, 2026)
- [x] **Re-synced latest code from claw-activity** with full exclusion list, patches, and domain replacements (Feb 16, 2026)
- [x] **Removed leaked admin files** (`public/admin-competitions.html`, `public/analytics-beacon.js`) discovered during re-sync
- [x] **Committed and pushed all changes** to `clawnads/clawnads` (commit `9d1c78d`, 24 files, +5167/-1213 lines)
- [x] **Verified all excluded files are absent** from OSS repo (full audit of every exclusion)
- [x] **Verified zero `tormund.io` references remain** in codebase (grep confirmed clean)
- [x] **`public/models/` is gitignored** — 180MB GLBs exist locally but are NOT tracked or pushed

---

## Domain Migration (completed Feb 16, 2026)

All domains migrated from `tormund.io` to `clawnads.org`:

| Old Domain | New Domain | Usage |
|------------|-----------|-------|
| `claw.tormund.io` | `app.clawnads.org` | Main dashboard and API |
| `console.tormund.io` | `console.clawnads.org` | Developer Portal |
| `tormund.io` | `clawnads.org` | Landing page, canonical issuer |
| `.tormund.io` (cookie) | `.clawnads.org` (cookie) | Cross-subdomain session cookies |
| `www.tormund.io` | `www.clawnads.org` | Landing page redirect |
| `test.clawnads.org` | `test.clawnads.org` | OAuth Playground (new, no old equivalent) |

**Files changed for domain migration (17 files):**
- `README.md` — badges, "Live at" link, architecture diagram
- `server.js` — all host checks, cookie domains, issuer URLs, CORS origins, OAuth metadata
- `AGENT-SETUP.md` — all ~30 curl examples and proxy config references
- `SKILL.md` — base URL, all endpoint examples
- `OAUTH.md` — domain table, all endpoint URLs, cookie domain, issuer
- `SIM.md` — sim URL reference
- `public/oauth-playground.html` — API calls, redirect URIs
- `public/landing.html` — links and references
- `public/landing.js` — dynamic URL construction
- `public/developers.js` — API base URLs, skill doc generation
- `public/operator-apps.html` — API calls
- `public/floor.html` — script/style references
- `public/index.html` — script/style references
- `public/oauth-consent.html` — API calls
- `public/store.html` — references
- `public/styles.css` — any URL references
- `public/app.js` — API base URLs

**Post-sync domain replacement commands** (run after every rsync):
```bash
# Domain replacements (order matters — specific subdomains before bare domain)
sed -i '' 's/claw\.tormund\.io/app.clawnads.org/g' server.js AGENT-SETUP.md SKILL.md OAUTH.md SIM.md public/*.html public/*.js
sed -i '' 's/console\.tormund\.io/console.clawnads.org/g' server.js OAUTH.md public/developers.js public/operator-apps.html
sed -i '' 's/\.tormund\.io/.clawnads.org/g' server.js  # cookie domain
sed -i '' 's/www\.tormund\.io/www.clawnads.org/g' server.js
sed -i '' 's/tormund\.io/clawnads.org/g' README.md server.js AGENT-SETUP.md SKILL.md OAUTH.md SIM.md public/*.html public/*.js

# Agent name scrub
sed -i '' 's/clawbun/YOUR_NAME/g' SKILL.md
sed -i '' 's/macbun/OTHER_AGENT/g' SKILL.md
```

---

## Excluded Files (never go to public repo)

### Private docs (operational runbooks, internal IP)
- `CLAUDE.md` — private operational runbook for Claude Code
- `DESIGN.md` — internal design system reference
- `STORE.md` — store operations docs
- `SESSION-OAUTH.md` — internal session/OAuth implementation notes
- `MODEL-UPLOAD.md` — internal model upload procedures
- `SECURITY-AUDIT.md` — internal security audit findings
- `OPEN-SOURCE-STRATEGY.md` — THIS FILE (private runbook, must stay untracked)

### Deploy/ops scripts
- `deploy.sh`, `invite.sh`

### ~~Admin UI~~ → MOVED TO INCLUDED (Feb 16, 2026)
Admin UI and analytics files are now **included** in the public repo. Scrubbed: treasury address replaced with `YOUR_TREASURY_ADDRESS` placeholder in `analytics.html`. No other sensitive content found in audit.

### Data, config, and large assets
- `data/` directory (agents.json, store.json, notifications.json, analytics.db)
- `.claude/` directory
- `.env*` (except .env.example)
- `meshy-blue-model/`, `meshy-gold-model/`, `meshy-red-model/` (123MB raw exports)
- `public/models/` (180MB GLBs — excluded via .gitignore, deployed separately)
- `public/trading-floor/*.mp3` (10MB audio — excluded via .gitignore)

### Misc root-level files
- `Claude Spark - Clay.svg`, `happy-crab-raw.svg`, `sad-crab-raw.svg`, `bun 64x64.png`
- `blue-handwritten-note.svg`, `blue-extracted-text.svg`, `extracted_text_bw 1 [Vectorized].svg`
- `Moltiverse Rules & Guidelines.pdf`
- `public/index-old.html`

---

## Included Files

### Server
- `server.js` (patched ADMIN_ALLOWED_USERS), `analytics.js`, `package.json`, `package-lock.json`

### Docs
- `SKILL.md` (scrubbed), `AGENT-SETUP.md`, `OAUTH.md` (scrubbed), `SIM.md` (scrubbed)

### Public UI
- `public/index.html`, `public/floor.html`, `public/landing.html`, `public/landing.js`
- `public/styles.css`, `public/app.js`, `public/visualizer.js`
- `public/store.html`, `public/sim.html`
- `public/oauth-preview.html` ← new file added during Feb 16 re-sync

### Admin UI & Analytics (added Feb 16, 2026)
- `public/admin.html`, `public/admin.js`, `public/admin.css`
- `public/admin-elements.html`, `public/admin-nav.css`, `public/admin-nav.js`
- `public/admin-store.html`, `public/admin-competitions.html`
- `public/analytics.html` (scrubbed: treasury address → `YOUR_TREASURY_ADDRESS`)
- `public/analytics-client.js`, `public/analytics.css`, `public/analytics-beacon.js`
- `public/tools/render-thumbs.html`

### OAuth & Developer Portal
- `public/oauth-consent.html`, `public/oauth-playground.html` (scrubbed)
- `public/operator-apps.html`
- `public/developers.html`, `public/developers.js`, `public/developers.css`

### 3D Floor & Characters
- `public/trading-floor/*` (JS files — audio excluded by .gitignore)
- `public/character/*`

### Assets
- `public/Clawnads.svg`, `public/bun.png`, `public/avatar.png`
- `public/clawnads-favicon-white.svg`, `public/clawnads-logo-white.svg`
- `public/happy-crab*.svg`, `public/sad-crab.svg`
- `public/monad-logomark.svg`, `public/stage-fun-landing.svg`
- `public/default-dapp-icon.svg`
- `public/tokens/*`, `public/contracts/*`

### Config
- `.gitignore`, `.env.example`, `LICENSE`, `README.md`
- `assets/` (hero image, handwritten note)

---

## Submission Requirements Checklist

| Requirement | Status | Detail |
|-------------|--------|--------|
| Public GitHub repo | ✅ Done | `clawnads/clawnads` is **PUBLIC** as of Feb 16, 2026. URL: `https://github.com/clawnads/clawnads` |
| README with setup instructions | ✅ Done | Quick Start section: clone, npm install, .env.example, npm start. Production: Caddy + PM2 |
| OSI-approved license | ✅ Done | Apache 2.0 (`LICENSE` file in repo root) |
| Clear attribution | ✅ Done | Attribution section in README: Express, ethers, Uniswap, better-sqlite3, jsonwebtoken, Three.js, Privy, Caddy. Meshy AI for models. Copyright line |
| 2-min demo video | ✅ Done | 1:26 video linked in README: `https://x.com/4ormund/status/2023227423115157641` |
| Monad integration documented | ✅ Done | "Monad Integration" section in README, contract addresses table, chain 143 throughout |

### Judging Criteria Coverage (20% each)

| Criterion | README Coverage |
|-----------|---------------|
| Agent Intelligence & Autonomy | Self-registration, autonomous trading, heartbeat polling, agent-to-agent messaging, proposal/task lifecycle |
| Technical Excellence | OAuth 2.0 provider (PKCE), Developer Portal, Docker sandbox, fail-closed trading, SHA-256 token hashing |
| Monad Integration | Chain 143, Privy wallets, ERC-8004 identity NFTs, x402 USDC payments, Uniswap V3 routing, contract addresses |
| Virality | "Wall Street for Monad agents" framing, 3D trading floor visualization, live dashboard |
| Innovation & Impact | Full OAuth provider for AI agents, ERC-8004 on-chain identity, x402 payments, multi-agent autonomous collaboration |

### World Model Agent Bounty — README Framing TODO

The README currently leads with "Wall Street for Monad agents" (infra framing). For the World Model Agent bounty ($10K), consider adding language that emphasizes the **persistent virtual world** angle:
- "A persistent virtual world where AI agents..."
- "Agents enter the world, receive wallets, trade, message, and collaborate..."
- "World state evolves with every trade, message, and registration..."

This is a framing adjustment, not a code change.

---

## Remaining Steps (at submission time)

### 1. ~~Sync latest code changes~~ ✅ DONE (Feb 16, 2026)
Re-synced from claw-activity with all exclusions, patches, domain replacements, and agent name scrubs. Committed as `9d1c78d`.

### 2. ~~Domain migration~~ ✅ DONE (Feb 16, 2026)
All `tormund.io` references replaced with `clawnads.org` variants across 17 files. Zero references remain.

### 3. ~~Verify exclusions~~ ✅ DONE (Feb 16, 2026)
Full audit confirmed: all excluded files absent, `public/models/` gitignored, no leaked admin files.

### 4. ~~Add demo video link to README~~ ✅ DONE (Feb 16, 2026)
Video posted to X (1:26): `https://x.com/4ormund/status/2023227423115157641`. Link added to README.

### 5. ~~Flip repo to public~~ ✅ DONE (Feb 16, 2026)
```bash
gh repo edit clawnads/clawnads --visibility public --accept-visibility-change-consequences
```
Note: `--accept-visibility-change-consequences` flag is required by `gh` CLI.

### 6. Submit via hackathon form
- Public repo URL: `https://github.com/clawnads/clawnads`
- Demo video URL: `https://x.com/4ormund/status/2023227423115157641`
- Submit before 11:59 PM ET

---

## Security Notes

- **Admin routes stay in server.js** — they're gated by `ADMIN_SECRET` and `ADMIN_ALLOWED_USERS` env vars. The code is fine to publish; the access control is in the configuration, not the code.
- **The only code-level patch** is `ADMIN_ALLOWED_USERS`: private repo has `['4ormund']`, OSS repo reads from `process.env.ADMIN_ALLOWED_USERS`.
- **Footer attribution** (`@4ormund`) in index.html, floor.html, landing.html is intentional — it's the creator credit, same pattern as OpenClaw.
- **Contract addresses** are public blockchain data, not secrets.
- **1Password references** in docs are generic best-practice advice, not actual vault paths.
- **OPEN-SOURCE-STRATEGY.md** (this file) lives in the clawnads-oss directory but is **untracked by git** — it must never be committed or pushed. Add to `.gitignore` if needed.

---

## Re-sync Procedure

When you need to update the OSS repo with latest changes from claw-activity:

```bash
cd /Users/tormund/Desktop/Cowork/clawnads-oss

# Step 1: rsync with exclusions
rsync -av \
  --exclude='node_modules/' \
  --exclude='data/' \
  --exclude='.env' \
  --exclude='.DS_Store' \
  --exclude='.claude/' \
  --exclude='CLAUDE.md' \
  --exclude='DESIGN.md' \
  --exclude='STORE.md' \
  --exclude='SESSION-OAUTH.md' \
  --exclude='MODEL-UPLOAD.md' \
  --exclude='SECURITY-AUDIT.md' \
  --exclude='deploy.sh' \
  --exclude='invite.sh' \
  --exclude='meshy-blue-model/' \
  --exclude='meshy-gold-model/' \
  --exclude='meshy-red-model/' \
  --exclude='Claude Spark - Clay.svg' \
  --exclude='happy-crab-raw.svg' \
  --exclude='sad-crab-raw.svg' \
  --exclude='bun 64x64.png' \
  --exclude='blue-handwritten-note.svg' \
  --exclude='blue-extracted-text.svg' \
  --exclude='extracted_text_bw 1 [Vectorized].svg' \
  --exclude='Moltiverse Rules & Guidelines.pdf' \
  --exclude='public/admin.html' \
  --exclude='public/admin.js' \
  --exclude='public/admin.css' \
  --exclude='public/admin-elements.html' \
  --exclude='public/admin-nav.css' \
  --exclude='public/admin-nav.js' \
  --exclude='public/admin-store.html' \
  --exclude='public/admin-competitions.html' \
  --exclude='public/analytics.html' \
  --exclude='public/analytics-client.js' \
  --exclude='public/analytics.css' \
  --exclude='public/analytics-beacon.js' \
  --exclude='public/index-old.html' \
  --exclude='public/tools/' \
  --exclude='.git/' \
  --exclude='package-lock.json' \
  --exclude='OPEN-SOURCE-STRATEGY.md' \
  --exclude='OPEN-SOURCE.md' \
  /Users/tormund/Desktop/Cowork/claw-activity/ \
  /Users/tormund/Desktop/Cowork/clawnads-oss/

# Step 2: Re-apply ADMIN_ALLOWED_USERS patch
sed -i '' "s/const ADMIN_ALLOWED_USERS = \['4ormund'\];/const ADMIN_ALLOWED_USERS = (process.env.ADMIN_ALLOWED_USERS || '').split(',').map(u => u.trim()).filter(Boolean);/" server.js

# Step 3: Domain replacements (order matters — specific subdomains before bare domain)
sed -i '' 's/claw\.tormund\.io/app.clawnads.org/g' server.js AGENT-SETUP.md SKILL.md OAUTH.md SIM.md public/*.html public/*.js
sed -i '' 's/console\.tormund\.io/console.clawnads.org/g' server.js OAUTH.md public/developers.js public/operator-apps.html
sed -i '' 's/\.tormund\.io/.clawnads.org/g' server.js
sed -i '' 's/www\.tormund\.io/www.clawnads.org/g' server.js
sed -i '' 's/tormund\.io/clawnads.org/g' README.md server.js AGENT-SETUP.md SKILL.md OAUTH.md SIM.md public/*.html public/*.js

# Step 4: Agent name scrub
sed -i '' 's/clawbun/YOUR_NAME/g' SKILL.md
sed -i '' 's/macbun/OTHER_AGENT/g' SKILL.md

# Step 5: Remove any root-level SVGs that leaked through
rm -f Clawnads.svg clawnads-favicon-white.svg clawnads-logo-white.svg \
  happy-crab-blue.svg happy-crab.svg monad-logomark.svg stage-fun-landing.svg

# Step 6: Remove any admin files that leaked through
rm -f public/admin-competitions.html public/analytics-beacon.js

# Step 7: Verify
grep "ADMIN_ALLOWED_USERS" server.js
grep -r "tormund\.io" . --include="*.js" --include="*.html" --include="*.css" --include="*.md" --include="*.json" | grep -v node_modules | grep -v ".git/" | grep -v "OPEN-SOURCE-STRATEGY.md"
grep -r "4ormund" . --include="*.js" --include="*.md" | grep -v footer | grep -v Copyright | grep -v README | grep -v OPEN-SOURCE-STRATEGY
```

---

## Git History

| Commit | Date | Description |
|--------|------|-------------|
| `34f57f2` | Feb 14 | Add hero image and badges to README |
| `c27d6df` | Feb 14 | Update branding: Wall Street for Monad agents, tormund.io, copyright Paul Warren |
| `7492c57` | Feb 14 | Add handwritten note to README |
| `820f55d` | Feb 14 | Add full Clawnads codebase |
| `7eac4a2` | Feb 15 | Move handwritten note below intro, fix operator wording |
| `9d1c78d` | Feb 16 | Migrate domains from tormund.io to clawnads.org, sync latest codebase (24 files, +5167/-1213) |

---

## License Decision

**Apache 2.0** chosen over MIT because:
- OSI-approved (hackathon requirement — rules out FSL/BSL)
- Patent grant protects wallet/crypto code users
- Trademark non-grant (Clawnads brand stays ours)
- Same license as Caddy (our reverse proxy)
- OpenClaw uses MIT, but they don't have the same patent exposure from wallet/trading code
