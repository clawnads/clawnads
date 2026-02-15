const express = require('express');
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { ethers } = require('ethers');
const analytics = require('./analytics');

const app = express();
const PORT = process.env.PORT || 3000;

// Admin secret for protecting admin endpoints
const ADMIN_SECRET = process.env.ADMIN_SECRET || null;

// Admin web UI (X OAuth login)
const X_CLIENT_ID = process.env.X_CLIENT_ID || null;
const X_CLIENT_SECRET = process.env.X_CLIENT_SECRET || null;
const SESSION_SECRET = process.env.SESSION_SECRET || null;
const ADMIN_ALLOWED_USERS = (process.env.ADMIN_ALLOWED_USERS || '').split(',').map(u => u.trim()).filter(Boolean);
const ADMIN_COOKIE_NAME = 'clawnads_admin';
const ADMIN_COOKIE_MAX_AGE_SEC = 24 * 60 * 60; // 24 hours

// Developer portal (self-service dApp registration)
const DEV_COOKIE_NAME = 'clawnads_dev';
const DEV_COOKIE_MAX_AGE_SEC = 24 * 60 * 60; // 24 hours
const MAX_DAPPS_PER_DEVELOPER = 10;

// OAuth signing key for JWT access tokens (reuses SESSION_SECRET if not set)
const OAUTH_SIGNING_KEY = process.env.OAUTH_SIGNING_KEY || SESSION_SECRET;

// Privy configuration
const PRIVY_APP_ID = process.env.PRIVY_APP_ID;
if (!PRIVY_APP_ID) {
  console.error('FATAL: PRIVY_APP_ID environment variable is required');
  process.exit(1);
}
const PRIVY_APP_SECRET = process.env.PRIVY_APP_SECRET;
if (!PRIVY_APP_SECRET) {
  console.error('FATAL: PRIVY_APP_SECRET environment variable is required');
  process.exit(1);
}

// Monad network configuration (can be changed to testnet if needed)
const MONAD_CHAIN_ID = 143;
const MONAD_NETWORK_NAME = MONAD_CHAIN_ID === 143 ? 'Monad Mainnet' : 'Monad Testnet';
const MONAD_RPC_URL = MONAD_CHAIN_ID === 143
  ? 'https://monad-mainnet.drpc.org'
  : 'https://testnet-rpc.monad.xyz';
const MONAD_EXPLORER = MONAD_CHAIN_ID === 143
  ? 'https://monadexplorer.com'
  : 'https://testnet.monadexplorer.com';

// Uniswap V3 on Monad (from docs.uniswap.org)
const UNISWAP_V3 = {
  FACTORY: '0x204faca1764b154221e35c0d20abb3c525710498',
  SWAP_ROUTER_02: '0xfe31f71c1b106eac32f1a19239c9a9a72ddfb900',
  UNIVERSAL_ROUTER: '0x0d97dc33264bfc1c226207428a79b26757fb9dc3',
  QUOTER_V2: '0x661e93cca42afacb172121ef892830ca3b70f08d',
  POSITION_MANAGER: '0x7197e214c0b767cfb76fb734ab638e2c192f4e53',
  PERMIT2: '0x000000000022D473030F116dDEE9F6B43aC78BA3'
};

// Common token addresses on Monad (from monad-crypto/token-list)
const MONAD_TOKENS = {
  MON: '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE', // Native token placeholder
  WMON: '0x3bd359C1119dA7Da1D913D1C4D2B7c461115433A', // Wrapped MON
  USDC: '0x754704Bc059F8C67012fEd69BC8A327a5aafb603', // Circle USDC (CCTP)
  USDT: '0xe7cd86e13AC4309349F30B3435a9d337750fC82D', // USDT0 (LayerZero OFT)
  WETH: '0xEE8c0E9f1BFFb4Eb878d8f15f368A02a35481242', // Wrapped Ether
  WBTC: '0x0555E30da8f98308EdB960aa94C0Db47230d2B9c'  // Wrapped BTC
};

// Uniswap V3 fee tiers (in hundredths of a bip)
const FEE_TIERS = [500, 3000, 10000]; // 0.05%, 0.3%, 1%

// Initialize ethers provider
const provider = new ethers.providers.JsonRpcProvider(MONAD_RPC_URL);

// Token metadata cache (decimals, symbol, name)
const tokenMetadataCache = {};

// Token price cache for /tokens/prices endpoint
const tokenPriceCache = {
  prices: null,
  lastFetched: null,
  ttlMs: 60000 // 60 second cache
};

// Get token metadata via RPC
async function getTokenMetadata(tokenAddress) {
  if (tokenMetadataCache[tokenAddress.toLowerCase()]) {
    return tokenMetadataCache[tokenAddress.toLowerCase()];
  }

  // ERC-20 function selectors
  const decimalsSelector = '0x313ce567'; // decimals()
  const symbolSelector = '0x95d89b41';   // symbol()
  const nameSelector = '0x06fdde03';     // name()

  const calls = [
    { to: tokenAddress, data: decimalsSelector },
    { to: tokenAddress, data: symbolSelector },
    { to: tokenAddress, data: nameSelector }
  ];

  const results = await Promise.all(calls.map(call =>
    httpRequest(MONAD_RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'eth_call',
        params: [call, 'latest'],
        id: 1
      })
    }).catch(() => ({ result: '0x' }))
  ));

  // Parse decimals (uint8)
  const decimals = results[0].result && results[0].result !== '0x'
    ? parseInt(results[0].result, 16)
    : 18;

  // Parse symbol (string) - basic ABI decoding
  let symbol = 'UNKNOWN';
  if (results[1].result && results[1].result.length > 66) {
    try {
      const hex = results[1].result.slice(130); // skip offset + length
      symbol = Buffer.from(hex, 'hex').toString('utf8').replace(/\0/g, '');
    } catch (e) { }
  }

  // Parse name (string)
  let name = symbol;
  if (results[2].result && results[2].result.length > 66) {
    try {
      const hex = results[2].result.slice(130);
      name = Buffer.from(hex, 'hex').toString('utf8').replace(/\0/g, '');
    } catch (e) { }
  }

  const metadata = { decimals, symbol, name };
  tokenMetadataCache[tokenAddress.toLowerCase()] = metadata;
  return metadata;
}

// Security: disable server fingerprinting
app.disable('x-powered-by');

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '0'); // Modern browsers: CSP is the real protection
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' blob: https://unpkg.com https://cdn.jsdelivr.net 'unsafe-inline' 'wasm-unsafe-eval'; " +
    "style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "img-src 'self' data: blob: https:; " +
    "connect-src 'self' blob: https://cdn.jsdelivr.net https://monad-mainnet.g.alchemy.com https://monad-mainnet.drpc.org https://rpc.monad.xyz wss://monad-mainnet.g.alchemy.com; " +
    "worker-src 'self' blob:; " +
    "frame-ancestors 'none';"
  );
  next();
});

// Trust Caddy reverse proxy (1 hop) for correct req.ip and x-forwarded-* headers
app.set('trust proxy', 1);

// Middleware
app.use(express.json({ limit: '2mb' }));

// Analytics: init SQLite + page view tracking (MUST be before express.static)
analytics.initAnalytics();
const TRACKED_PAGES = new Set(['/', '/floor', '/sim', '/character', '/elements', '/analytics', '/admin', '/invites']);
app.use((req, res, next) => {
  if (req.method === 'GET' && TRACKED_PAGES.has(req.path)) {
    analytics.trackPageView(req);
  }
  next();
});

// Domain-based routing for / path
app.get('/', (req, res, next) => {
  const host = (req.headers.host || '').replace(/:.*$/, '');
  if (host.startsWith('console.')) {
    return res.redirect('/developers');
  }
  if (host.startsWith('test.')) {
    return res.redirect('/oauth/playground');
  }
  if (host === 'tormund.io' || host === 'www.tormund.io') {
    return res.sendFile(path.join(__dirname, 'public', 'landing.html'));
  }
  next();
});

// OAuth Playground routes
app.get('/oauth/playground', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'oauth-playground.html'));
});
app.get('/oauth/playground/callback', (req, res) => {
  // Serve the same playground page — it reads query params (code, state, error) on load
  res.sendFile(path.join(__dirname, 'public', 'oauth-playground.html'));
});

app.use(express.static(path.join(__dirname, 'public'), { maxAge: 0, etag: false }));

// Data file path
const DATA_FILE = path.join(__dirname, 'data', 'agents.json');
const STORE_FILE = path.join(__dirname, 'data', 'store.json');
const NOTIFICATIONS_FILE = path.join(__dirname, 'data', 'notifications.json');
const REG_KEYS_FILE = path.join(__dirname, 'data', 'registration-keys.json');
const DAPPS_FILE = path.join(__dirname, 'data', 'dapps.json');

// Ensure data directory exists
if (!fs.existsSync(path.join(__dirname, 'data'))) {
  fs.mkdirSync(path.join(__dirname, 'data'));
}

// Ensure agents.json has restricted permissions (contains API keys and token hashes)
try { if (fs.existsSync(DATA_FILE)) fs.chmodSync(DATA_FILE, 0o600); } catch (e) { /* ignore on Windows */ }

// ==================== NOTIFICATION QUEUE ====================
// For agents without webhook endpoints, we store notifications
// and let them poll when making other API calls

function loadNotifications() {
  try {
    if (fs.existsSync(NOTIFICATIONS_FILE)) {
      return JSON.parse(fs.readFileSync(NOTIFICATIONS_FILE, 'utf8'));
    }
  } catch (err) {
    console.error('Error loading notifications:', err);
  }
  return {};
}

function saveNotifications(notifications) {
  const tmpFile = NOTIFICATIONS_FILE + '.tmp.' + process.pid;
  fs.writeFileSync(tmpFile, JSON.stringify(notifications, null, 2));
  fs.renameSync(tmpFile, NOTIFICATIONS_FILE);
}

// Queue a notification for an agent
function queueNotification(agentName, notification) {
  const notifications = loadNotifications();
  if (!notifications[agentName]) {
    notifications[agentName] = [];
  }
  notifications[agentName].push({
    ...notification,
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    timestamp: new Date().toISOString(),
    read: false
  });
  saveNotifications(notifications);
  console.log(`Queued notification for ${agentName}: ${notification.type}`);
}

// Get pending notifications for an agent
function getPendingNotifications(agentName) {
  const notifications = loadNotifications();
  return (notifications[agentName] || []).filter(n => !n.read);
}

// Mark notifications as read
function markNotificationsRead(agentName, notificationIds) {
  const notifications = loadNotifications();
  if (!notifications[agentName]) return;

  notifications[agentName] = notifications[agentName].map(n => {
    if (notificationIds.includes(n.id) || notificationIds.includes('all')) {
      return { ...n, read: true };
    }
    return n;
  });
  saveNotifications(notifications);
}

// Load agents from file
function loadAgents() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    }
  } catch (err) {
    console.error('Error loading agents:', err);
  }
  return {};
}

// Save agents to file (chmod 600 — contains API keys and token hashes)
function saveAgents(agents) {
  const tmpFile = DATA_FILE + '.tmp.' + process.pid;
  fs.writeFileSync(tmpFile, JSON.stringify(agents, null, 2), { mode: 0o600 });
  fs.renameSync(tmpFile, DATA_FILE); // atomic on same filesystem
}

// Load/save store catalog
function loadStore() {
  try {
    if (fs.existsSync(STORE_FILE)) {
      return JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
    }
  } catch (err) {
    console.error('Error loading store:', err);
  }
  return { skins: {} };
}

function saveStore(store) {
  const tmpFile = STORE_FILE + '.tmp.' + process.pid;
  fs.writeFileSync(tmpFile, JSON.stringify(store, null, 2));
  fs.renameSync(tmpFile, STORE_FILE);
}

// Load/save registration keys
function loadRegKeys() {
  try {
    if (fs.existsSync(REG_KEYS_FILE)) {
      return JSON.parse(fs.readFileSync(REG_KEYS_FILE, 'utf8'));
    }
  } catch (err) {
    console.error('Error loading registration keys:', err);
  }
  return { keys: {} };
}

function saveRegKeys(data) {
  const tmpFile = REG_KEYS_FILE + '.tmp.' + process.pid;
  fs.writeFileSync(tmpFile, JSON.stringify(data, null, 2), { mode: 0o600 });
  fs.renameSync(tmpFile, REG_KEYS_FILE);
}

// Load/save OAuth dApp registrations
function loadDapps() {
  try {
    if (fs.existsSync(DAPPS_FILE)) {
      return JSON.parse(fs.readFileSync(DAPPS_FILE, 'utf8'));
    }
  } catch (err) {
    console.error('Error loading dapps:', err);
  }
  return {};
}

function saveDapps(dapps) {
  const tmpFile = DAPPS_FILE + '.tmp.' + process.pid;
  fs.writeFileSync(tmpFile, JSON.stringify(dapps, null, 2), { mode: 0o600 });
  fs.renameSync(tmpFile, DAPPS_FILE); // atomic on same filesystem
}

// ==================== SECURITY: AUTH TOKENS ====================

// Generate a new auth token (claw_ prefix + 32 hex chars)
function generateAuthToken() {
  return 'claw_' + crypto.randomBytes(16).toString('hex');
}

// Hash a token using SHA-256
function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Verify a token against a stored hash
function verifyToken(token, storedHash) {
  if (!token || !storedHash) return false;
  const tokenHash = hashToken(token);
  return crypto.timingSafeEqual(Buffer.from(tokenHash), Buffer.from(storedHash));
}

// ==================== SECURITY: RATE LIMITING ====================

// In-memory rate limit stores: { key: { count, windowStart } }
const rateLimits = {
  registration: new Map(),  // IP-based: 3/min
  swapSend: new Map(),      // agent-based: 10/min
  general: new Map(),       // agent-based: 60/min
  devDappCreate: new Map()  // developer X ID-based: 5/hour
};

// Check rate limit. Returns { allowed: true } or { allowed: false, retryAfter: seconds }
function checkRateLimit(store, key, maxRequests, windowMs) {
  const now = Date.now();
  const entry = store.get(key);

  if (!entry || (now - entry.windowStart) >= windowMs) {
    store.set(key, { count: 1, windowStart: now });
    return { allowed: true };
  }

  if (entry.count >= maxRequests) {
    const retryAfter = Math.ceil((entry.windowStart + windowMs - now) / 1000);
    return { allowed: false, retryAfter };
  }

  entry.count++;
  return { allowed: true };
}

// Clean up expired rate limit entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const store of Object.values(rateLimits)) {
    for (const [key, entry] of store.entries()) {
      // Remove entries older than 2 minutes (covers all windows)
      if (now - entry.windowStart > 120000) {
        store.delete(key);
      }
    }
  }
}, 300000); // 5 minutes

// ==================== SECURITY: INPUT VALIDATION ====================

// Validate agent name: alphanumeric + underscore, 1-32 chars
function isValidAgentName(name) {
  return typeof name === 'string' && /^[a-zA-Z0-9_]{1,32}$/.test(name);
}

// Validate API key format (basic sanity check)
function isValidApiKey(apiKey) {
  return typeof apiKey === 'string' && apiKey.length >= 10 && apiKey.length <= 256 && /^[a-zA-Z0-9_-]+$/.test(apiKey);
}

// Sanitize string input (strip control chars, limit length)
function sanitizeInput(input, maxLength) {
  if (typeof input !== 'string') return input;
  maxLength = maxLength || 256;
  return input.replace(/[-]/g, '').slice(0, maxLength);
}

// Validate callback URLs — prevent SSRF (blocks private IPs, metadata service, non-http schemes)
function isValidCallbackUrl(url) {
  if (!url || typeof url !== 'string') return false;
  try {
    const parsed = new URL(url);
    // Only allow http/https
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
    // Resolve hostname to check for private IPs
    const hostname = parsed.hostname.toLowerCase();
    // Block localhost variants
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1' || hostname === '0.0.0.0') return false;
    // Block AWS metadata service
    if (hostname === '169.254.169.254' || hostname === 'metadata.google.internal') return false;
    // Block private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x)
    const ipMatch = hostname.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (ipMatch) {
      const [, a, b] = ipMatch.map(Number);
      if (a === 10) return false;                          // 10.0.0.0/8
      if (a === 172 && b >= 16 && b <= 31) return false;  // 172.16.0.0/12
      if (a === 192 && b === 168) return false;            // 192.168.0.0/16
      if (a === 169 && b === 254) return false;            // 169.254.0.0/16 (link-local)
    }
    return true;
  } catch {
    return false;
  }
}

// ==================== SECURITY: MIDDLEWARE ====================

// Agent authentication middleware
// Checks Authorization: Bearer claw_xxxxx against stored token hash
// Throttled lastSeen updater — writes to disk at most once per minute per agent
const lastSeenCache = {};
function touchLastSeen(agentName) {
  const now = Date.now();
  if (lastSeenCache[agentName] && now - lastSeenCache[agentName] < 60000) return;
  lastSeenCache[agentName] = now;
  analytics.trackEvent('agent_heartbeat', agentName);
  const agents = loadAgents();
  if (agents[agentName]) {
    agents[agentName].lastSeen = new Date().toISOString();
    saveAgents(agents);
  }
}

function authenticateAgent(req, res, next) {
  const { name } = req.params;
  if (!name) return res.status(400).json({ error: 'Agent name required' });

  const agents = loadAgents();
  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  const agent = agents[name];

  // No token hash means agent must re-register to get a token
  if (!agent.tokenHash) {
    return res.status(401).json({ error: 'Authentication required. Re-register via POST /register to get an auth token.' });
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const token = authHeader.slice(7); // Remove 'Bearer '
  if (!verifyToken(token, agent.tokenHash)) {
    return res.status(403).json({ error: 'Invalid token' });
  }

  req.agent = agent;
  req.agentName = name;
  touchLastSeen(name);
  // Count every authenticated API call (not rate-limited like heartbeat)
  analytics.trackEvent('agent_action', name, { path: req.path, method: req.method });
  next();
}

// Token-based authentication (for routes where :name is NOT the sender)
// Looks up the agent by scanning all token hashes instead of using req.params.name
function authenticateByToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const token = authHeader.slice(7);
  const agents = loadAgents();

  // Find which agent this token belongs to
  const match = Object.entries(agents).find(([agentName, agentData]) =>
    agentData.tokenHash && verifyToken(token, agentData.tokenHash)
  );

  if (!match) {
    return res.status(403).json({ error: 'Invalid token' });
  }

  const [agentName, agent] = match;
  req.agent = agent;
  req.agentName = agentName;
  touchLastSeen(agentName);
  // Count every authenticated API call (not rate-limited like heartbeat)
  analytics.trackEvent('agent_action', agentName, { path: req.path, method: req.method });
  next();
}

// Admin authentication middleware
function authenticateAdmin(req, res, next) {
  if (!ADMIN_SECRET) {
    console.error('CRITICAL: ADMIN_SECRET not configured. Blocking admin access.');
    return res.status(503).json({ error: 'Admin access unavailable — server misconfigured' });
  }

  const providedSecret = req.headers['x-admin-secret'];
  if (!providedSecret || providedSecret !== ADMIN_SECRET) {
    return res.status(403).json({ error: 'Invalid admin secret' });
  }

  next();
}

// ==================== ADMIN WEB UI (SESSION AUTH) ====================

// In-memory store for OAuth PKCE state (auto-expires entries after 10 min)
const oauthPendingFlows = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of oauthPendingFlows) {
    if (now - val.created > 600000) oauthPendingFlows.delete(key);
  }
}, 60000);

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const cookies = {};
  header.split(';').forEach(c => {
    const [k, ...v] = c.trim().split('=');
    if (k) cookies[k] = v.join('=');
  });
  return cookies;
}

function signAdminSession(payload) {
  const json = JSON.stringify(payload);
  const b64 = Buffer.from(json).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(b64).digest('hex').slice(0, 32);
  return b64 + '.' + sig;
}

function verifyAdminSession(cookie) {
  if (!cookie || !SESSION_SECRET) return null;
  const parts = cookie.split('.');
  if (parts.length !== 2) return null;
  const [b64, sig] = parts;
  if (!b64 || !sig) return null;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(b64).digest('hex').slice(0, 32);
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const payload = JSON.parse(Buffer.from(b64, 'base64url').toString());
    if (payload.exp < Date.now() / 1000) return null;
    return payload;
  } catch { return null; }
}

function requireAdminSession(req, res, next) {
  const cookies = parseCookies(req);
  const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
  if (!session) {
    if (req.path.startsWith('/admin/api/')) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    return next();
  }
  req.adminSession = session;
  next();
}

// Developer session (same signing mechanism, different cookie)
function signDevSession(payload) {
  const json = JSON.stringify(payload);
  const b64 = Buffer.from(json).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(b64).digest('hex').slice(0, 32);
  return b64 + '.' + sig;
}

function verifyDevSession(cookie) {
  if (!cookie || !SESSION_SECRET) return null;
  const parts = cookie.split('.');
  if (parts.length !== 2) return null;
  const [b64, sig] = parts;
  if (!b64 || !sig) return null;
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(b64).digest('hex').slice(0, 32);
  if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  try {
    const payload = JSON.parse(Buffer.from(b64, 'base64url').toString());
    if (payload.exp < Date.now() / 1000) return null;
    return payload;
  } catch { return null; }
}

function requireDevSession(req, res, next) {
  const cookies = parseCookies(req);
  const session = verifyDevSession(cookies[DEV_COOKIE_NAME]);
  if (!session) {
    if (req.path.startsWith('/developers/api/')) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    return res.redirect('/developers');
  }
  req.devSession = session;
  next();
}

// Registration rate limit middleware (3/min per IP)
function registrationRateLimit(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const result = checkRateLimit(rateLimits.registration, ip, 3, 60000);
  if (!result.allowed) {
    return res.status(429).json({ error: 'Rate limit exceeded', retryAfter: result.retryAfter });
  }
  next();
}

// Swap/send rate limit middleware (10/min per agent)
function swapSendRateLimit(req, res, next) {
  const { name } = req.params;
  const result = checkRateLimit(rateLimits.swapSend, name || 'unknown', 10, 60000);
  if (!result.allowed) {
    return res.status(429).json({ error: 'Rate limit exceeded', retryAfter: result.retryAfter });
  }
  next();
}

// General API rate limit middleware (60/min per agent)
function generalRateLimit(req, res, next) {
  const { name } = req.params;
  const key = name || req.ip || 'unknown';
  const result = checkRateLimit(rateLimits.general, key, 60, 60000);
  if (!result.allowed) {
    return res.status(429).json({ error: 'Rate limit exceeded', retryAfter: result.retryAfter });
  }
  next();
}

// HTTP request helper (works with all Node.js versions)
function httpRequest(url, options = {}) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const isHttps = urlObj.protocol === 'https:';
    const reqOptions = {
      hostname: urlObj.hostname,
      port: urlObj.port || (isHttps ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method: options.method || 'GET',
      headers: options.headers || {},
      timeout: options.timeout || 30000 // 30 second default timeout
    };

    const transport = isHttps ? https : http;
    const req = transport.request(reqOptions, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 400) {
          reject(new Error(`HTTP ${res.statusCode}: ${data}`));
        } else {
          try {
            resolve(JSON.parse(data));
          } catch (e) {
            resolve(data);
          }
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });
    req.on('error', reject);

    if (options.body) {
      req.write(options.body);
    }
    req.end();
  });
}

// Get current block number from Monad RPC
async function getCurrentBlockNumber() {
  try {
    const response = await httpRequest(MONAD_RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'eth_blockNumber',
        params: [],
        id: 1
      })
    });
    return parseInt(response.result, 16);
  } catch (err) {
    console.error('Error getting block number:', err.message);
    return null;
  }
}

// Create Privy wallet for an agent
async function createPrivyWallet(agentName) {
  const auth = Buffer.from(`${PRIVY_APP_ID}:${PRIVY_APP_SECRET}`).toString('base64');

  const response = await httpRequest('https://api.privy.io/v1/wallets', {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${auth}`,
      'privy-app-id': PRIVY_APP_ID,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      chain_type: 'ethereum'
    })
  });

  console.log(`Created Privy wallet for ${agentName}: ${response.address}`);
  return response;
}

// Get Moltbook API key for an agent (env var takes precedence over agents.json)
function getAgentMoltbookKey(agentName) {
  const envKey = `${agentName.toUpperCase()}_MOLTBOOK_KEY`;
  const fromEnv = process.env[envKey];
  if (fromEnv) return fromEnv;
  // Fallback: read from agents.json (legacy)
  const agents = loadAgents();
  return agents[agentName]?.apiKey || null;
}

// Fetch profile from Moltbook
async function fetchMoltbookProfile(apiKey) {
  return httpRequest('https://www.moltbook.com/api/v1/agents/me', {
    headers: {
      'Authorization': `Bearer ${apiKey}`
    }
  });
}

// Fetch agent's posts from Moltbook
async function fetchMoltbookPosts(apiKey, agentName) {
  return httpRequest(`https://www.moltbook.com/api/v1/agents/profile?name=${encodeURIComponent(agentName)}`, {
    headers: {
      'Authorization': `Bearer ${apiKey}`
    }
  });
}

// ==================== MOLTBOOK PROXY ====================
// Agents call these instead of moltbook.com directly.
// The server injects the Moltbook API key from env vars or agents.json.

// GET /agents/:name/moltbook/me — agent's own Moltbook profile
app.get('/agents/:name/moltbook/me', authenticateAgent, async (req, res) => {
  const { name } = req.params;
  const moltbookKey = getAgentMoltbookKey(name);
  if (!moltbookKey) {
    return res.status(500).json({ success: false, error: 'Moltbook API key not configured for this agent' });
  }
  try {
    const data = await httpRequest('https://www.moltbook.com/api/v1/agents/me', {
      headers: { 'Authorization': `Bearer ${moltbookKey}` }
    });
    res.json({ success: true, ...data });
  } catch (err) {
    res.status(502).json({ success: false, error: `Moltbook error: ${err.message}` });
  }
});

// GET /agents/:name/moltbook/feed — personalized feed
app.get('/agents/:name/moltbook/feed', authenticateAgent, async (req, res) => {
  const { name } = req.params;
  const moltbookKey = getAgentMoltbookKey(name);
  if (!moltbookKey) {
    return res.status(500).json({ success: false, error: 'Moltbook API key not configured' });
  }
  try {
    const params = new URLSearchParams();
    if (req.query.sort) params.set('sort', req.query.sort);
    if (req.query.limit) params.set('limit', req.query.limit);
    const qs = params.toString();
    const url = `https://www.moltbook.com/api/v1/feed${qs ? '?' + qs : ''}`;
    const data = await httpRequest(url, {
      headers: { 'Authorization': `Bearer ${moltbookKey}` }
    });
    res.json({ success: true, ...data });
  } catch (err) {
    res.status(502).json({ success: false, error: `Moltbook error: ${err.message}` });
  }
});

// POST /agents/:name/moltbook/posts — create a Moltbook post
app.post('/agents/:name/moltbook/posts', authenticateAgent, async (req, res) => {
  const { name } = req.params;
  const moltbookKey = getAgentMoltbookKey(name);
  if (!moltbookKey) {
    return res.status(500).json({ success: false, error: 'Moltbook API key not configured' });
  }
  try {
    const data = await httpRequest('https://www.moltbook.com/api/v1/posts', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${moltbookKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(req.body)
    });
    res.json({ success: true, ...data });
  } catch (err) {
    res.status(502).json({ success: false, error: `Moltbook error: ${err.message}` });
  }
});

// POST /agents/:name/moltbook/posts/:postId/comment — comment on a post
app.post('/agents/:name/moltbook/posts/:postId/comment', authenticateAgent, async (req, res) => {
  const { name, postId } = req.params;
  const moltbookKey = getAgentMoltbookKey(name);
  if (!moltbookKey) {
    return res.status(500).json({ success: false, error: 'Moltbook API key not configured' });
  }
  try {
    const data = await httpRequest(`https://www.moltbook.com/api/v1/posts/${encodeURIComponent(postId)}/comments`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${moltbookKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(req.body)
    });
    res.json({ success: true, ...data });
  } catch (err) {
    res.status(502).json({ success: false, error: `Moltbook error: ${err.message}` });
  }
});

// POST /agents/:name/moltbook/posts/:postId/upvote — upvote a post
app.post('/agents/:name/moltbook/posts/:postId/upvote', authenticateAgent, async (req, res) => {
  const { name, postId } = req.params;
  const moltbookKey = getAgentMoltbookKey(name);
  if (!moltbookKey) {
    return res.status(500).json({ success: false, error: 'Moltbook API key not configured' });
  }
  try {
    const data = await httpRequest(`https://www.moltbook.com/api/v1/posts/${encodeURIComponent(postId)}/upvote`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${moltbookKey}` }
    });
    res.json({ success: true, ...data });
  } catch (err) {
    res.status(502).json({ success: false, error: `Moltbook error: ${err.message}` });
  }
});

// GET /agents/:name/moltbook/profile/:otherAgent — view another agent's Moltbook profile
app.get('/agents/:name/moltbook/profile/:otherAgent', authenticateAgent, async (req, res) => {
  const { name, otherAgent } = req.params;
  const moltbookKey = getAgentMoltbookKey(name);
  if (!moltbookKey) {
    return res.status(500).json({ success: false, error: 'Moltbook API key not configured' });
  }
  try {
    const data = await httpRequest(`https://www.moltbook.com/api/v1/agents/profile?name=${encodeURIComponent(otherAgent)}`, {
      headers: { 'Authorization': `Bearer ${moltbookKey}` }
    });
    res.json({ success: true, ...data });
  } catch (err) {
    res.status(502).json({ success: false, error: `Moltbook error: ${err.message}` });
  }
});

// ==================== MOLTBOOK PROFILE CONNECTION ====================

// Connect Moltbook profile to Clawnads account (for dashboard display)
// Agent manages their own Moltbook API key — we just link the profile metadata
app.post('/agents/:name/moltbook/connect', authenticateAgent, async (req, res) => {
  const { name } = req.params;
  const { moltbookName } = req.body;

  if (!moltbookName) {
    return res.status(400).json({ success: false, error: 'moltbookName is required' });
  }

  try {
    // Fetch public profile from Moltbook (no API key needed for public data)
    const profileData = await fetchMoltbookPosts(null, moltbookName);

    const agents = loadAgents();
    if (!agents[name]) {
      return res.status(404).json({ success: false, error: 'Agent not found' });
    }

    // Store profile metadata (karma, name, avatar) for dashboard display
    agents[name].profile = {
      ...agents[name].profile,
      ...profileData,
      moltbookConnected: true,
      moltbookName: moltbookName
    };
    agents[name].lastSeen = new Date().toISOString();
    saveAgents(agents);

    console.log(`Agent ${name} connected Moltbook profile: ${moltbookName}`);

    res.json({
      success: true,
      message: `Connected Moltbook profile "${moltbookName}" to ${name}`,
      profile: {
        name: profileData.name || moltbookName,
        karma: profileData.karma || profileData.agent?.karma
      }
    });
  } catch (err) {
    console.error(`Moltbook connect error for ${name}:`, err);
    res.status(502).json({ success: false, error: `Failed to fetch Moltbook profile: ${err.message}` });
  }
});

// Disconnect Moltbook profile from Clawnads account
app.delete('/agents/:name/moltbook/connect', authenticateAgent, (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  // Clear Moltbook-specific profile data but keep agent's basic info
  if (agents[name].profile) {
    agents[name].profile = {
      name: agents[name].profile.name || name,
      description: agents[name].profile.description || null,
      moltbookConnected: false
    };
  }
  saveAgents(agents);

  console.log(`Agent ${name} disconnected Moltbook profile`);

  res.json({
    success: true,
    message: `Disconnected Moltbook profile from ${name}`
  });
});

// ==================== ADMIN REGISTRATION ====================

// Admin: register an agent directly (no Moltbook, no registration key needed)
app.post('/admin/register', authenticateAdmin, async (req, res) => {
  const { name, description } = req.body;

  if (!name) {
    return res.status(400).json({ success: false, error: 'name is required' });
  }

  if (!isValidAgentName(name)) {
    return res.status(400).json({ success: false, error: 'Invalid agent name. Use 1-32 alphanumeric characters or underscores.' });
  }

  const agents = loadAgents();

  if (agents[name]) {
    return res.status(409).json({ success: false, error: 'Agent name already registered' });
  }

  try {
    // Create Privy wallet
    let wallet = null;
    try {
      const walletData = await createPrivyWallet(name);
      const currentBlock = await getCurrentBlockNumber();
      wallet = {
        id: walletData.id,
        address: walletData.address,
        chainType: walletData.chain_type,
        createdAt: new Date().toISOString(),
        createdAtBlock: currentBlock || 0
      };
      console.log(`Admin created wallet ${wallet.address} for ${name} at block ${currentBlock}`);
    } catch (walletErr) {
      console.error('Wallet creation failed:', walletErr.message);
    }

    // Generate auth token
    const authToken = generateAuthToken();
    const tokenHash = hashToken(authToken);

    agents[name] = {
      tokenHash,
      registeredAt: new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      disconnected: false,
      profile: { name, description: description || null },
      wallet,
      tradingConfig: {
        enabled: true,
        maxPerTradeMON: '500',
        dailyCapMON: '2500',
        allowedTokens: Object.keys(MONAD_TOKENS),
        dailyVolume: { date: new Date().toISOString().slice(0, 10), totalMON: '0', tradeCount: 0 }
      }
    };
    saveAgents(agents);

    analytics.trackEvent('registration', name);
    console.log(`Agent registered by admin: ${name} (auth token issued)`);

    res.json({
      success: true,
      authToken,
      envVarName: 'CLAW_AUTH_TOKEN',
      agent: {
        name,
        registeredAt: agents[name].registeredAt,
        wallet: wallet ? {
          address: wallet.address,
          network: MONAD_NETWORK_NAME,
          chainId: MONAD_CHAIN_ID
        } : null
      }
    });
  } catch (err) {
    console.error('Admin registration error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ==================== REGISTRATION KEYS ====================

// Admin: generate a new single-use invite key
app.post('/admin/registration-keys', authenticateAdmin, (req, res) => {
  const { label, maxUses } = req.body;
  const keyLabel = label || 'invite-' + Date.now().toString(36);

  const plainKey = 'clawkey_' + crypto.randomBytes(16).toString('hex');
  const keyHash = hashToken(plainKey);

  const regKeys = loadRegKeys();
  regKeys.keys[keyHash] = {
    label: keyLabel,
    createdAt: new Date().toISOString(),
    usedBy: [],
    maxUses: maxUses != null ? parseInt(maxUses) : 1,
    revoked: false
  };
  saveRegKeys(regKeys);

  console.log(`Registration key created: "${keyLabel}" (single-use)`);
  res.json({
    success: true,
    key: plainKey,
    label: keyLabel,
    maxUses: regKeys.keys[keyHash].maxUses
  });
});

// Admin: list all registration keys (no plaintext keys exposed)
app.get('/admin/registration-keys', authenticateAdmin, (req, res) => {
  const regKeys = loadRegKeys();
  const keys = Object.values(regKeys.keys).map(k => ({
    label: k.label,
    createdAt: k.createdAt,
    maxUses: k.maxUses,
    used: k.usedBy.length,
    usedBy: k.usedBy,
    revoked: k.revoked,
    status: k.revoked ? 'revoked' : k.usedBy.length >= (k.maxUses || Infinity) ? 'used' : 'available'
  }));
  res.json({ success: true, count: keys.length, keys });
});

// Admin: revoke a registration key by label
app.delete('/admin/registration-keys/:label', authenticateAdmin, (req, res) => {
  const { label } = req.params;
  const regKeys = loadRegKeys();

  const entry = Object.entries(regKeys.keys).find(([, v]) => v.label === label);
  if (!entry) {
    return res.status(404).json({ success: false, error: 'Key not found with that label' });
  }

  regKeys.keys[entry[0]].revoked = true;
  saveRegKeys(regKeys);

  console.log(`Registration key revoked: "${label}"`);
  res.json({ success: true, message: `Key "${label}" revoked` });
});

// ==================== ADMIN WEB UI ROUTES ====================

// Serve admin page — authenticated users go to analytics (the admin home)
app.get('/admin', (req, res) => {
  if (!X_CLIENT_ID || !X_CLIENT_SECRET || !SESSION_SECRET) {
    return res.status(503).send('Admin UI not configured');
  }
  // Migration: clear any legacy Path=/admin cookie (we now use Path=/)
  res.setHeader('Set-Cookie',
    `${ADMIN_COOKIE_NAME}=; Path=/admin; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
  );
  // If already logged in, redirect to analytics (admin home)
  const cookies = parseCookies(req);
  const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
  if (session) return res.redirect('/analytics');
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/invites', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
  if (!session) return res.redirect('/admin');
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/elements', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
  if (!session) return res.redirect('/admin');
  res.sendFile(path.join(__dirname, 'public', 'admin-elements.html'));
});

// Store: customer-facing (admin-gated until public launch)
app.get('/store', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
  if (!session) return res.redirect('/admin');
  res.sendFile(path.join(__dirname, 'public', 'store.html'));
});

// Store Ops: admin CRUD management
app.get('/admin/store-manage', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
  if (!session) return res.redirect('/admin');
  res.sendFile(path.join(__dirname, 'public', 'admin-store.html'));
});

// Floor — public sim sandbox (embedded in dashboard iframe, no auth)
app.get('/floor', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'floor.html'));
});

// Check session status
app.get('/admin/api/session', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
  if (session) {
    res.json({ authenticated: true, username: session.un, avatar: session.av || null });
  } else {
    res.json({ authenticated: false });
  }
});

// Start OAuth flow
app.get('/admin/auth/login', (req, res) => {
  if (!X_CLIENT_ID) return res.status(503).send('X OAuth not configured');

  const state = crypto.randomBytes(16).toString('hex');
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

  oauthPendingFlows.set(state, { codeVerifier, created: Date.now() });

  // Build redirect URI based on request
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  const redirectUri = `${proto}://${host}/admin/auth/callback`;

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: X_CLIENT_ID,
    redirect_uri: redirectUri,
    scope: 'users.read tweet.read',
    state: state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  });

  res.redirect(`https://x.com/i/oauth2/authorize?${params}`);
});

// Unified X OAuth callback — dispatches based on flowType stored in state
// This is the ONLY callback URL registered in the X Developer Portal.
// All flows (admin login, owner linking, consent auth) use this same endpoint.
app.get('/admin/auth/callback', async (req, res) => {
  const { code, state, error } = req.query;

  // Handle X OAuth errors (user cancelled, denied, etc.)
  if (error || !code || !state) {
    // Check if this was a consent auth flow — redirect back to consent page, not admin
    if (state) {
      const pending = oauthPendingFlows.get(state);
      if (pending?.flowType === 'consent_auth' && pending.consentFlowId) {
        oauthPendingFlows.delete(state);
        return res.redirect(`/oauth/consent?flow=${pending.consentFlowId}`);
      }
      // Developer portal auth flow — redirect back to developers page
      if (pending?.flowType === 'developer_auth') {
        oauthPendingFlows.delete(state);
        return res.redirect('/developers');
      }
    }
    return res.redirect('/admin?error=oauth_denied');
  }

  const pending = oauthPendingFlows.get(state);
  if (!pending) return res.redirect('/admin?error=invalid_state');
  oauthPendingFlows.delete(state);

  try {
    // Build redirect URI (must match the one sent — always /admin/auth/callback)
    const proto = req.headers['x-forwarded-proto'] || req.protocol;
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    const redirectUri = `${proto}://${host}/admin/auth/callback`;

    // Exchange code for access token
    const tokenBody = new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: redirectUri,
      client_id: X_CLIENT_ID,
      code_verifier: pending.codeVerifier
    }).toString();

    // Twitter Web App type requires Basic auth (client_id:client_secret)
    const basicAuth = Buffer.from(`${X_CLIENT_ID}:${X_CLIENT_SECRET}`).toString('base64');

    const tokenResp = await httpRequest('https://api.x.com/2/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
        'Authorization': `Basic ${basicAuth}`
      },
      body: tokenBody
    });

    if (!tokenResp.access_token) throw new Error('No access token in response');

    // Fetch user profile (include profile image)
    const userResp = await httpRequest('https://api.x.com/2/users/me?user.fields=profile_image_url', {
      headers: { 'Authorization': `Bearer ${tokenResp.access_token}` }
    });

    const user = userResp.data;
    if (!user || !user.username) throw new Error('Could not fetch user profile');

    // ---- DISPATCH BASED ON FLOW TYPE ----

    // Flow: Consent auth (operator authenticating for dApp consent page)
    if (pending.flowType === 'consent_auth') {
      const consentFlowId = pending.consentFlowId;
      const flow = oauthAuthFlows.get(consentFlowId);
      if (!flow) return res.redirect(`/?error=consent_flow_expired`);

      // If agent is specified, verify this X user is the agent's owner
      if (flow.agentName) {
        const agents = loadAgents();
        const agent = agents[flow.agentName];
        if (!agent || !agent.owner || agent.owner.xId !== user.id) {
          console.log(`Consent auth denied: @${user.username} is not the owner of ${flow.agentName}`);
          return res.redirect(`/oauth/consent?flow=${consentFlowId}&error=not_owner`);
        }
      }
      // If no agent specified, just authenticate — operator picks agent next

      flow.operatorXId = user.id;
      flow.operatorXUsername = user.username;
      flow.operatorProfileImageUrl = user.profile_image_url || null;
      oauthAuthFlows.set(consentFlowId, flow);

      console.log(`Consent auth: @${user.username} authenticated${flow.agentName ? ` for ${flow.agentName}` : ''}`);
      return res.redirect(`/oauth/consent?flow=${consentFlowId}`);
    }

    // Flow: Owner linking (operator claiming ownership of an agent)
    if (pending.flowType === 'owner_link') {
      const agentName = pending.agentName;
      const agents = loadAgents();
      if (!agents[agentName]) return res.redirect(`/?error=agent_not_found`);

      // Check if another agent already has this X account linked
      const existing = Object.entries(agents).find(([n, a]) => n !== agentName && a.owner?.xId === user.id);
      if (existing) {
        console.log(`Owner link denied: @${user.username} already linked to ${existing[0]}`);
        return res.redirect(`/?error=x_account_already_linked&agent=${agentName}`);
      }

      agents[agentName].owner = {
        xId: user.id,
        xUsername: user.username,
        linkedAt: new Date().toISOString()
      };
      saveAgents(agents);

      // Consume the claim token (single-use)
      if (pending.claimToken) ownerClaimTokens.delete(pending.claimToken);

      console.log(`Owner linked: @${user.username} → ${agentName}`);
      return res.send(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Claimed \u2014 ${agentName} \u2014 Clawnads</title><link rel="icon" type="image/svg+xml" href="/clawnads-favicon-white.svg">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="/styles.css">
        <style>html,body{margin:0;min-height:100vh;background:var(--color-bg-deep);overflow:hidden;}
        .cs-header{display:flex;align-items:center;padding:var(--space-10) var(--space-16);}
        .cs-header img{height:28px;width:auto;opacity:0.4;}
        .cs-body{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:var(--space-8);font-family:var(--font-sans);color:var(--color-text-primary);min-height:calc(100vh - 80px);}
        </style>
        </head><body>
        <header class="cs-header"><img src="/clawnads-logo-white.svg" alt="Clawnads"></header>
        <div class="cs-body">
          <svg width="120" height="66" viewBox="0 0 100 55" fill="none" xmlns="http://www.w3.org/2000/svg" style="margin-bottom:var(--space-4);"><path d="M31.2099 45.0527C31.3816 45.1109 31.3138 45.0772 31.455 45.1611C32.589 45.8338 33.9277 46.2766 35.1815 46.668C34.9152 47.0227 34.2144 47.7101 33.8407 48.1631C31.988 50.4053 31.1523 52.0517 30.078 54.6768C30.0466 54.7368 29.9425 54.8509 29.8944 54.9082C29.6623 55.008 29.5453 55.0327 29.3007 54.9521C26.7826 54.1202 26.2768 50.8331 27.1229 48.6533C27.8846 46.6925 29.4041 45.8487 31.2099 45.0527ZM68.4852 45.1162C69.0621 45.0313 70.4841 45.959 70.994 46.3555C73.2311 48.0924 73.9772 51.4654 72.1386 53.7686C71.8237 54.1626 70.946 54.9875 70.3876 54.9941C70.1555 54.9966 70.0611 54.9048 69.911 54.751C69.638 54.2115 69.4323 53.5146 69.1386 52.9385C67.8436 50.3981 66.7678 48.5855 64.6503 46.7012C65.9883 46.2882 67.3058 45.8796 68.4852 45.1162ZM75.0976 41.0518C77.6372 41.2724 79.9589 41.8337 81.8173 43.6602C84.0285 45.8334 84.4932 49.2289 82.1864 51.5244C81.7756 51.934 81.3041 52.3176 80.9091 51.668C80.7124 51.3342 80.2057 50.7078 79.9491 50.3447C77.9262 47.488 74.8661 44.6508 71.4413 43.6699C72.4779 43.2153 73.1779 42.6328 74.0526 41.916C74.4626 41.5805 74.6178 41.3382 75.0976 41.0518ZM24.953 41.1348C25.2018 41.3081 25.712 41.8073 25.994 42.043C26.8766 42.7798 27.5021 43.1421 28.5184 43.6533C25.1888 44.6816 22.494 46.9576 20.4198 49.7178C20.1465 50.0822 19.9759 50.3986 19.6708 50.7539L19.6093 50.8242C19.3237 51.0898 19.1644 51.66 18.7499 51.9531C18.4278 51.9673 18.1104 51.9103 17.8778 51.6797C14.6291 48.4648 16.6499 43.7235 20.4257 42.0674C21.7284 41.4963 22.1907 41.3268 23.6132 41.1611C24.0699 41.107 24.4952 41.1264 24.953 41.1348ZM50.412 21.7686C53.8394 21.7239 58.3896 22.4166 61.6933 23.4268C65.9905 24.9067 70.3972 27.0117 73.7499 30.1299C76.8457 33.0097 78.0987 34.494 74.744 37.8359C70.2383 42.3231 64.4548 44.3785 58.3495 45.5908C55.5323 46.1503 52.3726 46.1943 49.5321 46.1885C45.1317 46.1735 41.0227 45.7038 36.8075 44.4365C31.8682 42.951 25.0118 39.5832 23.1005 34.5C23.4202 32.8506 24.6728 31.4788 25.8983 30.3223C29.2819 27.1293 33.7394 24.8807 38.1278 23.4404C39.442 22.9808 40.9113 22.8445 42.2343 22.5049C45.0465 21.7828 47.5417 21.7667 50.412 21.7686ZM58.786 35.1504C58.3597 34.4405 57.4386 34.2108 56.7284 34.6367C52.587 37.1215 47.4128 37.1215 43.2714 34.6367C42.5612 34.2107 41.6401 34.4405 41.2138 35.1504C40.7875 35.8608 41.0181 36.7828 41.7284 37.209C46.8197 40.2636 53.1801 40.2636 58.2714 37.209C58.9816 36.7827 59.2122 35.8607 58.786 35.1504ZM87.0839 0C92.2005 0.461954 97.6246 4.65656 99.1727 9.55762C99.4757 10.5174 100.012 12.7205 99.9999 13.7236C99.8876 22.8356 91.6694 29.0257 83.3222 30.3164C80.1773 30.8026 79.3214 31.1331 76.5575 29.6787C76.208 29.4223 75.9171 29.2185 75.747 28.8213C75.8109 28.4152 76.4329 28.1363 76.828 27.9307C78.3952 27.1126 79.3915 25.4821 80.5927 24.458C79.8025 23.6312 79.3988 22.8348 78.8427 21.8477C76.0729 16.926 76.379 9.33155 80.6288 5.25586C81.4663 7.83061 84.0478 12.8462 86.3554 14.2852C86.9364 14.1176 87.3281 12.3194 87.4335 11.7666C88.1696 7.90054 87.8807 3.83257 87.0839 0ZM12.5751 0.0224609C12.674 0.0188039 12.7036 0.0419007 12.8056 0.0742188C12.8109 0.105027 12.4873 2.15371 12.4237 2.41699C11.9339 4.44521 11.9777 13.3766 13.5809 14.2666C13.9333 14.0704 14.3942 13.5678 14.6747 13.2617C16.8563 10.8818 18.1966 8.25826 19.329 5.29004C20.1374 6.22699 21.0198 7.43298 21.5643 8.54297C24.0217 13.5521 22.9833 20.4614 19.1913 24.5205C20.1645 25.3207 20.9902 26.6263 22.1073 27.4258C22.6294 27.799 23.8926 28.3973 24.0468 28.7637C23.9779 29.0606 23.8152 29.1944 23.6112 29.4258C20.8948 31.2226 19.7045 30.7652 16.7216 30.3389C10.3594 29.4295 3.61264 25.3576 1.07411 19.2295C-2.55085 10.4783 3.42841 1.30598 12.5751 0.0224609ZM62.164 8.62793C65.1164 8.21829 67.8443 10.2775 68.2694 13.2363C68.6944 16.1954 66.6565 18.9439 63.7089 19.3867C60.7381 19.8328 57.9722 17.7685 57.5438 14.7861C57.1159 11.804 59.1885 9.04114 62.164 8.62793ZM36.1874 8.64844C39.1466 8.16434 41.9354 10.1844 42.4081 13.1543C42.8805 16.1242 40.8577 18.9139 37.8954 19.3779C34.9473 19.8393 32.1821 17.8218 31.7118 14.8662C31.2419 11.911 33.243 9.13068 36.1874 8.64844ZM37.0683 11.2412C35.6404 11.2416 34.4827 12.4037 34.4823 13.8359C34.4824 15.2683 35.6403 16.4303 37.0683 16.4307C38.4963 16.4305 39.655 15.2684 39.6552 13.8359C39.6548 12.4036 38.4962 11.2414 37.0683 11.2412ZM62.9306 11.2412C61.5023 11.2413 60.3447 12.4033 60.3446 13.8359C60.3448 15.2685 61.5024 16.4296 62.9306 16.4297C64.3588 16.4297 65.5164 15.2686 65.5165 13.8359C65.5165 12.4032 64.3589 11.2412 62.9306 11.2412Z" fill="white"/></svg>
          <div style="font-size:var(--text-2xl);font-weight:700;margin-bottom:var(--space-4);">Agent Claimed</div>
          <div style="font-size:var(--text-sm);color:var(--color-text-secondary);line-height:var(--leading-relaxed);max-width:360px;">
            Linked to <strong>@${user.username}</strong>. You can now approve or deny third-party dApp access for this agent.
          </div>
          <div style="font-size:var(--text-xs);color:var(--color-text-muted);margin-top:var(--space-10);">You can close this page.</div>
        </div>
        </body></html>`);
    }

    // Flow: Developer portal login (any X user can log in)
    if (pending.flowType === 'developer_login') {
      const devPayload = {
        xId: user.id,
        un: user.username,
        av: user.profile_image_url || null,
        exp: Math.floor(Date.now() / 1000) + DEV_COOKIE_MAX_AGE_SEC
      };
      const devCookieValue = signDevSession(devPayload);

      res.setHeader('Set-Cookie',
        `${DEV_COOKIE_NAME}=${devCookieValue}; Path=/; Domain=.tormund.io; HttpOnly; Secure; SameSite=Lax; Max-Age=${DEV_COOKIE_MAX_AGE_SEC}`
      );
      console.log(`Developer login: @${user.username} (${user.id})`);
      const devRedirect = pending.redirect || 'https://console.tormund.io/developers';
      return res.redirect(devRedirect);
    }

    // Flow: Admin login (default — original behavior)
    if (!ADMIN_ALLOWED_USERS.includes(user.username.toLowerCase())) {
      console.log(`Admin login denied: @${user.username} (not in allowlist)`);
      return res.redirect('/admin?error=not_authorized');
    }

    // Create session cookie
    const payload = {
      uid: user.id,
      un: user.username,
      av: user.profile_image_url || null,
      exp: Math.floor(Date.now() / 1000) + ADMIN_COOKIE_MAX_AGE_SEC
    };
    const cookieValue = signAdminSession(payload);

    // Set new cookie with Path=/ and clear any old Path=/admin cookie
    res.setHeader('Set-Cookie', [
      `${ADMIN_COOKIE_NAME}=${cookieValue}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${ADMIN_COOKIE_MAX_AGE_SEC}`,
      `${ADMIN_COOKIE_NAME}=; Path=/admin; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
    ]);
    console.log(`Admin login: @${user.username}`);
    res.redirect('/analytics');

  } catch (err) {
    console.error('X OAuth callback error:', err.message);
    const agentName = pending?.agentName;
    if (pending?.flowType === 'owner_link') return res.redirect(`/?error=auth_failed&agent=${agentName}`);
    if (pending?.flowType === 'consent_auth') return res.redirect(`/?error=auth_failed`);
    if (pending?.flowType === 'developer_login') return res.redirect('/developers?error=auth_failed');
    res.redirect('/admin?error=auth_failed');
  }
});

// Logout
app.post('/admin/auth/logout', (req, res) => {
  // Clear both Path=/ and legacy Path=/admin cookies
  res.setHeader('Set-Cookie', [
    `${ADMIN_COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`,
    `${ADMIN_COOKIE_NAME}=; Path=/admin; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
  ]);
  res.json({ success: true });
});

// ==================== DEVELOPER PORTAL ====================

// Developer portal page
app.get('/developers', (req, res) => {
  if (!X_CLIENT_ID || !X_CLIENT_SECRET || !SESSION_SECRET) {
    return res.status(503).send('Developer portal not configured');
  }
  res.sendFile(path.join(__dirname, 'public', 'developers.html'));
});

// Developer session check
app.get('/developers/api/session', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyDevSession(cookies[DEV_COOKIE_NAME]);
  if (session) {
    res.json({ authenticated: true, xId: session.xId, username: session.un, avatar: session.av || null });
  } else {
    res.json({ authenticated: false });
  }
});

// Developer login via X OAuth
app.get('/developers/auth/login', (req, res) => {
  if (!X_CLIENT_ID) return res.status(503).send('X OAuth not configured');

  const state = crypto.randomBytes(16).toString('hex');
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

  const redirect = req.query.redirect || null;
  oauthPendingFlows.set(state, { codeVerifier, flowType: 'developer_login', redirect, created: Date.now() });

  // Redirect URI must be the registered callback on claw.tormund.io
  const redirectUri = 'https://claw.tormund.io/admin/auth/callback';

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: X_CLIENT_ID,
    redirect_uri: redirectUri,
    scope: 'users.read tweet.read',
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  });

  res.redirect(`https://x.com/i/oauth2/authorize?${params}`);
});

// Developer logout
app.post('/developers/auth/logout', (req, res) => {
  res.setHeader('Set-Cookie',
    `${DEV_COOKIE_NAME}=; Path=/; Domain=.tormund.io; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
  );
  res.json({ success: true });
});

// Grace period options for secret rotation (Stripe model)
const GRACE_PERIODS = {
  'immediately': 0,
  '1h': 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '3d': 3 * 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000
};

// Helper: verify client secret against primary and previous (dual-secret)
function verifyDappSecret(clientSecret, dapp) {
  // Check primary secret
  if (verifyToken(clientSecret, dapp.clientSecretHash)) return 'primary';
  // Check previous secret (if exists and not expired)
  if (dapp.previousSecretHash && dapp.previousSecretExpiry && Date.now() < dapp.previousSecretExpiry) {
    if (verifyToken(clientSecret, dapp.previousSecretHash)) return 'previous';
  }
  return null;
}

// List developer's own dApps
app.get('/developers/api/dapps', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyDevSession(cookies[DEV_COOKIE_NAME]);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });

  const dapps = loadDapps();
  const myDapps = Object.values(dapps)
    .filter(d => d.ownerXId === session.xId)
    .map(d => ({
      clientId: d.clientId,
      name: d.name,
      description: d.description,
      iconUrl: d.iconUrl,
      scopes: d.scopes,
      redirectUris: d.redirectUris,
      registeredAt: d.registeredAt,
      updatedAt: d.updatedAt || null,
      secretRotatedAt: d.secretRotatedAt || null,
      active: d.active,
      hasPreviousSecret: !!(d.previousSecretHash && d.previousSecretExpiry && Date.now() < d.previousSecretExpiry),
      previousSecretExpiry: d.previousSecretExpiry && Date.now() < d.previousSecretExpiry ? d.previousSecretExpiry : null
    }));

  res.json({ success: true, count: myDapps.length, dapps: myDapps });
});

// Create new dApp (developer-owned)
app.post('/developers/api/dapps', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyDevSession(cookies[DEV_COOKIE_NAME]);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });

  // Rate limit: 5 dApp creations per hour per developer
  const rl = checkRateLimit(rateLimits.devDappCreate, session.xId, 5, 3600000);
  if (!rl.allowed) {
    return res.status(429).json({ error: 'Rate limit exceeded', retryAfter: rl.retryAfter });
  }

  const dapps = loadDapps();

  // Max dApps per developer check
  const ownedCount = Object.values(dapps).filter(d => d.ownerXId === session.xId && d.active).length;
  if (ownedCount >= MAX_DAPPS_PER_DEVELOPER) {
    return res.status(400).json({ success: false, error: `Maximum ${MAX_DAPPS_PER_DEVELOPER} active dApps per account` });
  }

  const { name, description, iconUrl, redirectUris, scopes } = req.body;

  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    return res.status(400).json({ success: false, error: 'name is required' });
  }
  if (name.length > 64) {
    return res.status(400).json({ success: false, error: 'name must be 64 characters or less' });
  }
  // redirectUris and scopes are optional at creation — can be added later in Settings
  const validRedirectUris = Array.isArray(redirectUris) ? redirectUris.filter(Boolean) : [];
  for (const uri of validRedirectUris) {
    try {
      const parsed = new URL(uri);
      if (parsed.protocol !== 'https:' && parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1') {
        return res.status(400).json({ success: false, error: `Redirect URI must use HTTPS: ${uri}` });
      }
    } catch {
      return res.status(400).json({ success: false, error: `Invalid redirect URI: ${uri}` });
    }
  }
  const validScopes = Array.isArray(scopes) && scopes.length > 0
    ? scopes.filter(s => OAUTH_SCOPES.includes(s))
    : [...OAUTH_SCOPES]; // default to all scopes if none specified

  const clientId = 'dapp_' + crypto.randomBytes(12).toString('hex');
  const clientSecret = 'dappsec_' + crypto.randomBytes(24).toString('hex');
  const clientSecretHash = hashToken(clientSecret);

  dapps[clientId] = {
    clientId,
    clientSecretHash,
    name: name.trim(),
    description: description || null,
    iconUrl: iconUrl || null,
    redirectUris: validRedirectUris,
    scopes: validScopes,
    ownerXId: session.xId,
    ownerXUsername: session.un,
    registeredAt: new Date().toISOString(),
    active: true
  };
  saveDapps(dapps);

  console.log(`dApp registered by developer @${session.un}: ${name.trim()} (${clientId})`);
  res.json({
    success: true,
    clientId,
    clientSecret,
    name: name.trim(),
    scopes,
    redirectUris,
    warning: 'Store the clientSecret securely — it cannot be retrieved again.'
  });
});

// Update dApp settings
app.put('/developers/api/dapps/:clientId', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyDevSession(cookies[DEV_COOKIE_NAME]);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });

  const { clientId } = req.params;
  const dapps = loadDapps();
  const dapp = dapps[clientId];
  if (!dapp) return res.status(404).json({ success: false, error: 'dApp not found' });
  if (dapp.ownerXId !== session.xId) return res.status(403).json({ success: false, error: 'Not authorized' });

  const { name, description, iconUrl, redirectUris, scopes, accessLevel } = req.body;

  if (name !== undefined) {
    if (typeof name !== 'string' || name.trim().length === 0) {
      return res.status(400).json({ success: false, error: 'name cannot be empty' });
    }
    if (name.length > 64) {
      return res.status(400).json({ success: false, error: 'name must be 64 characters or less' });
    }
    dapp.name = name.trim();
  }
  if (description !== undefined) dapp.description = description || null;
  if (iconUrl !== undefined) dapp.iconUrl = iconUrl || null;
  if (redirectUris !== undefined) {
    if (!Array.isArray(redirectUris)) {
      return res.status(400).json({ success: false, error: 'redirectUris must be an array' });
    }
    const filtered = redirectUris.filter(Boolean);
    for (const uri of filtered) {
      try {
        const parsed = new URL(uri);
        if (parsed.protocol !== 'https:' && parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1') {
          return res.status(400).json({ success: false, error: `Redirect URI must use HTTPS: ${uri}` });
        }
      } catch {
        return res.status(400).json({ success: false, error: `Invalid redirect URI: ${uri}` });
      }
    }
    dapp.redirectUris = filtered;
  }
  if (scopes !== undefined) {
    if (!Array.isArray(scopes)) {
      return res.status(400).json({ success: false, error: 'scopes must be an array' });
    }
    const valid = scopes.filter(s => OAUTH_SCOPES.includes(s));
    dapp.scopes = valid;
  }
  if (accessLevel !== undefined) {
    if (!['read', 'read_write'].includes(accessLevel)) {
      return res.status(400).json({ success: false, error: 'accessLevel must be "read" or "read_write"' });
    }
    dapp.accessLevel = accessLevel;
  }

  dapp.updatedAt = new Date().toISOString();
  saveDapps(dapps);

  console.log(`dApp updated by developer @${session.un}: ${dapp.name} (${clientId})`);
  res.json({ success: true, message: 'dApp updated' });
});

// Rotate client secret (with grace period for old secret)
app.post('/developers/api/dapps/:clientId/rotate-secret', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyDevSession(cookies[DEV_COOKIE_NAME]);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });

  const { clientId } = req.params;
  const { grace } = req.body;
  const dapps = loadDapps();
  const dapp = dapps[clientId];
  if (!dapp) return res.status(404).json({ success: false, error: 'dApp not found' });
  if (dapp.ownerXId !== session.xId) return res.status(403).json({ success: false, error: 'Not authorized' });
  if (!dapp.active) return res.status(400).json({ success: false, error: 'Cannot rotate secret for inactive dApp' });

  const gracePeriod = grace || 'immediately';
  if (!GRACE_PERIODS.hasOwnProperty(gracePeriod)) {
    return res.status(400).json({ success: false, error: `Invalid grace period. Options: ${Object.keys(GRACE_PERIODS).join(', ')}` });
  }

  const graceMs = GRACE_PERIODS[gracePeriod];
  const newSecret = 'dappsec_' + crypto.randomBytes(24).toString('hex');

  // Move current secret to previous (with grace period)
  if (graceMs > 0) {
    dapp.previousSecretHash = dapp.clientSecretHash;
    dapp.previousSecretExpiry = Date.now() + graceMs;
  } else {
    // Immediately — no grace period
    delete dapp.previousSecretHash;
    delete dapp.previousSecretExpiry;
  }

  dapp.clientSecretHash = hashToken(newSecret);
  dapp.secretRotatedAt = new Date().toISOString();
  saveDapps(dapps);

  console.log(`dApp secret rotated by @${session.un}: ${dapp.name} (${clientId}) [grace: ${gracePeriod}]`);
  res.json({
    success: true,
    clientSecret: newSecret,
    grace: gracePeriod,
    previousSecretExpiry: dapp.previousSecretExpiry || null,
    warning: graceMs > 0
      ? `Store the new clientSecret securely. The old secret remains valid until ${new Date(dapp.previousSecretExpiry).toISOString()}.`
      : 'Store the new clientSecret securely. The old secret is now invalid.'
  });
});

// Emergency revoke — kill all secrets instantly, issue fresh one
app.post('/developers/api/dapps/:clientId/revoke-secret', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyDevSession(cookies[DEV_COOKIE_NAME]);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });

  const { clientId } = req.params;
  const dapps = loadDapps();
  const dapp = dapps[clientId];
  if (!dapp) return res.status(404).json({ success: false, error: 'dApp not found' });
  if (dapp.ownerXId !== session.xId) return res.status(403).json({ success: false, error: 'Not authorized' });
  if (!dapp.active) return res.status(400).json({ success: false, error: 'Cannot revoke secret for inactive dApp' });

  const newSecret = 'dappsec_' + crypto.randomBytes(24).toString('hex');

  // Kill both secrets immediately
  dapp.clientSecretHash = hashToken(newSecret);
  delete dapp.previousSecretHash;
  delete dapp.previousSecretExpiry;
  dapp.secretRotatedAt = new Date().toISOString();
  saveDapps(dapps);

  console.log(`dApp secret REVOKED by @${session.un}: ${dapp.name} (${clientId}) [emergency]`);
  res.json({
    success: true,
    clientSecret: newSecret,
    warning: 'All previous secrets have been revoked immediately. Store the new clientSecret securely — it cannot be retrieved again.'
  });
});

// Deactivate dApp
app.delete('/developers/api/dapps/:clientId', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyDevSession(cookies[DEV_COOKIE_NAME]);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });

  const { clientId } = req.params;
  const dapps = loadDapps();
  const dapp = dapps[clientId];
  if (!dapp) return res.status(404).json({ success: false, error: 'dApp not found' });
  if (dapp.ownerXId !== session.xId) return res.status(403).json({ success: false, error: 'Not authorized' });

  dapp.active = false;
  dapp.deactivatedAt = new Date().toISOString();
  saveDapps(dapps);

  console.log(`dApp deactivated by developer @${session.un}: ${dapp.name} (${clientId})`);
  res.json({ success: true, message: `dApp ${dapp.name} deactivated` });
});

// Developer API: Upload dApp icon
app.post('/developers/api/dapps/:clientId/icon', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyDevSession(cookies[DEV_COOKIE_NAME]);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });

  const { clientId } = req.params;
  const dapps = loadDapps();
  const dapp = dapps[clientId];
  if (!dapp) return res.status(404).json({ success: false, error: 'dApp not found' });
  if (dapp.ownerXId !== session.xId) return res.status(403).json({ success: false, error: 'Not authorized' });

  try {
    let { image } = req.body;
    if (!image) return res.status(400).json({ success: false, error: 'No image provided' });

    // Strip data: URI prefix
    let base64Data = image;
    if (base64Data.startsWith('data:')) {
      const commaIdx = base64Data.indexOf(',');
      if (commaIdx === -1) return res.status(400).json({ success: false, error: 'Invalid data URI format' });
      base64Data = base64Data.slice(commaIdx + 1);
    }

    const buffer = Buffer.from(base64Data, 'base64');
    if (buffer.length > 512 * 1024) return res.status(400).json({ success: false, error: 'Image too large (max 512KB)' });
    if (buffer.length < 100) return res.status(400).json({ success: false, error: 'Image too small (corrupt or empty)' });

    const imageType = detectImageType(buffer);
    if (!imageType) return res.status(400).json({ success: false, error: 'Not a valid image. Supported: PNG, JPEG, GIF, WebP' });

    // Create directory public/dapps/{clientId}/
    const iconDir = path.join(__dirname, 'public', 'dapps', clientId);
    fs.mkdirSync(iconDir, { recursive: true });

    // Remove old icon files with different extensions
    for (const ext of ['png', 'jpg', 'gif', 'webp']) {
      const oldPath = path.join(iconDir, `icon.${ext}`);
      if (fs.existsSync(oldPath) && ext !== imageType.ext) fs.unlinkSync(oldPath);
    }

    const filename = `icon.${imageType.ext}`;
    fs.writeFileSync(path.join(iconDir, filename), buffer);

    const publicUrl = `https://claw.tormund.io/dapps/${clientId}/${filename}`;
    dapp.iconUrl = publicUrl;
    dapp.updatedAt = new Date().toISOString();
    saveDapps(dapps);

    console.log(`dApp icon uploaded by @${session.un}: ${dapp.name} (${clientId}) — ${buffer.length} bytes, ${imageType.mime}`);
    res.json({ success: true, iconUrl: publicUrl });
  } catch (err) {
    console.error('dApp icon upload error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Developer API: Delete dApp icon
app.delete('/developers/api/dapps/:clientId/icon', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyDevSession(cookies[DEV_COOKIE_NAME]);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });

  const { clientId } = req.params;
  const dapps = loadDapps();
  const dapp = dapps[clientId];
  if (!dapp) return res.status(404).json({ success: false, error: 'dApp not found' });
  if (dapp.ownerXId !== session.xId) return res.status(403).json({ success: false, error: 'Not authorized' });

  // Remove icon files
  const iconDir = path.join(__dirname, 'public', 'dapps', clientId);
  if (fs.existsSync(iconDir)) {
    for (const ext of ['png', 'jpg', 'gif', 'webp']) {
      const p = path.join(iconDir, `icon.${ext}`);
      if (fs.existsSync(p)) fs.unlinkSync(p);
    }
  }

  dapp.iconUrl = null;
  dapp.updatedAt = new Date().toISOString();
  saveDapps(dapps);

  console.log(`dApp icon removed by @${session.un}: ${dapp.name} (${clientId})`);
  res.json({ success: true });
});

// Aggregate usage across all developer's dApps
app.get('/developers/api/usage', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyDevSession(cookies[DEV_COOKIE_NAME]);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });

  const dapps = loadDapps();
  const myClientIds = new Set(
    Object.values(dapps).filter(d => d.ownerXId === session.xId).map(d => d.clientId)
  );

  if (myClientIds.size === 0) {
    return res.json({ success: true, summary: { totalRequests: 0, tokenExchanges: 0, uniqueAgents: 0, requestsByEndpoint: {}, requestsByApp: {}, lastRequest: null }, timeseries: [] });
  }

  const days = Math.min(parseInt(req.query.days) || 30, 90);
  const startDate = new Date(Date.now() - days * 86400000).toISOString();

  try {
    const db = analytics.getDb ? analytics.getDb() : null;
    if (!db) return res.json({ success: true, summary: { totalRequests: 0, tokenExchanges: 0, uniqueAgents: 0, requestsByEndpoint: {}, requestsByApp: {}, lastRequest: null }, timeseries: [] });

    const rows = db.prepare(`
      SELECT timestamp, agent_name, metadata FROM events
      WHERE type = 'oauth_request' AND timestamp >= ?
      ORDER BY timestamp DESC
      LIMIT 1000
    `).all(startDate);

    const events = [];
    const endpointCounts = {};
    const appCounts = {};
    const agents = new Set();

    for (const row of rows) {
      try {
        const meta = JSON.parse(row.metadata || '{}');
        if (!myClientIds.has(meta.clientId)) continue;

        const appName = dapps[meta.clientId]?.name || meta.clientId;
        events.push({
          timestamp: row.timestamp,
          endpoint: meta.endpoint || 'unknown',
          agent: row.agent_name || null,
          app: appName,
          clientId: meta.clientId
        });

        endpointCounts[meta.endpoint] = (endpointCounts[meta.endpoint] || 0) + 1;
        appCounts[appName] = (appCounts[appName] || 0) + 1;
        if (row.agent_name) agents.add(row.agent_name);
      } catch {}
    }

    // Build daily time-series for charts
    const dailyRequests = {};
    const dailyTokenExchanges = {};
    for (const ev of events) {
      const day = ev.timestamp.slice(0, 10); // YYYY-MM-DD
      dailyRequests[day] = (dailyRequests[day] || 0) + 1;
      if (ev.endpoint === 'token') dailyTokenExchanges[day] = (dailyTokenExchanges[day] || 0) + 1;
    }

    // Fill in missing days with zeros
    const timeseries = [];
    const now = new Date();
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      const day = d.toISOString().slice(0, 10);
      timeseries.push({
        date: day,
        requests: dailyRequests[day] || 0,
        tokenExchanges: dailyTokenExchanges[day] || 0
      });
    }

    res.json({
      success: true,
      summary: {
        totalRequests: events.length,
        tokenExchanges: endpointCounts.token || 0,
        uniqueAgents: agents.size,
        requestsByEndpoint: endpointCounts,
        requestsByApp: appCounts,
        lastRequest: events.length > 0 ? events[0].timestamp : null
      },
      timeseries
    });
  } catch (err) {
    console.error('Aggregate usage API error:', err.message);
    res.status(500).json({ error: 'Failed to fetch usage data' });
  }
});

// Per-dApp usage analytics
app.get('/developers/api/dapps/:clientId/usage', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyDevSession(cookies[DEV_COOKIE_NAME]);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });

  const { clientId } = req.params;
  const dapps = loadDapps();
  const dapp = dapps[clientId];
  if (!dapp) return res.status(404).json({ error: 'dApp not found' });
  if (dapp.ownerXId !== session.xId) return res.status(403).json({ error: 'Not authorized' });

  const days = Math.min(parseInt(req.query.days) || 30, 90);
  const startDate = new Date(Date.now() - days * 86400000).toISOString();

  try {
    const db = analytics.getDb ? analytics.getDb() : null;
    if (!db) return res.json({ success: true, summary: { totalRequests: 0, tokenExchanges: 0, uniqueAgents: 0, requestsByEndpoint: {}, lastRequest: null }, timeseries: [] });

    const rows = db.prepare(`
      SELECT timestamp, agent_name, metadata FROM events
      WHERE type = 'oauth_request' AND timestamp >= ?
      ORDER BY timestamp DESC
      LIMIT 500
    `).all(startDate);

    const events = [];
    const endpointCounts = {};
    const agents = new Set();

    for (const row of rows) {
      try {
        const meta = JSON.parse(row.metadata || '{}');
        if (meta.clientId !== clientId) continue;

        events.push({
          timestamp: row.timestamp,
          endpoint: meta.endpoint || 'unknown',
          agent: row.agent_name || null
        });

        endpointCounts[meta.endpoint] = (endpointCounts[meta.endpoint] || 0) + 1;
        if (row.agent_name) agents.add(row.agent_name);
      } catch {}
    }

    // Build daily time-series for charts
    const dailyRequests = {};
    const dailyTokenExchanges = {};
    for (const ev of events) {
      const day = ev.timestamp.slice(0, 10);
      dailyRequests[day] = (dailyRequests[day] || 0) + 1;
      if (ev.endpoint === 'token') dailyTokenExchanges[day] = (dailyTokenExchanges[day] || 0) + 1;
    }

    const timeseries = [];
    const now = new Date();
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      const day = d.toISOString().slice(0, 10);
      timeseries.push({
        date: day,
        requests: dailyRequests[day] || 0,
        tokenExchanges: dailyTokenExchanges[day] || 0
      });
    }

    res.json({
      success: true,
      summary: {
        totalRequests: events.length,
        tokenExchanges: endpointCounts.token || 0,
        uniqueAgents: agents.size,
        requestsByEndpoint: endpointCounts,
        lastRequest: events.length > 0 ? events[0].timestamp : null
      },
      timeseries
    });
  } catch (err) {
    console.error('Usage API error:', err.message);
    res.status(500).json({ error: 'Failed to fetch usage data' });
  }
});

// Admin API: List registration keys (session-authenticated)
app.get('/admin/api/registration-keys', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });

  const regKeys = loadRegKeys();
  const keys = Object.values(regKeys.keys).map(k => ({
    label: k.label,
    rawKey: k.rawKey || null,
    createdAt: k.createdAt,
    maxUses: k.maxUses,
    used: k.usedBy.length,
    usedBy: k.usedBy,
    revoked: k.revoked,
    status: k.revoked ? 'revoked' : k.usedBy.length >= (k.maxUses || Infinity) ? 'used' : 'available'
  }));
  res.json({ success: true, count: keys.length, keys });
});

// Admin API: Generate key (session-authenticated)
app.post('/admin/api/registration-keys', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });

  const { label, maxUses } = req.body;
  const keyLabel = label || 'invite-' + Date.now().toString(36);
  const plainKey = 'clawkey_' + crypto.randomBytes(16).toString('hex');
  const keyHash = hashToken(plainKey);

  const regKeys = loadRegKeys();
  regKeys.keys[keyHash] = {
    label: keyLabel,
    rawKey: plainKey,
    createdAt: new Date().toISOString(),
    usedBy: [],
    maxUses: maxUses != null ? parseInt(maxUses) : 1,
    revoked: false
  };
  saveRegKeys(regKeys);

  console.log(`Registration key created via admin UI: "${keyLabel}" by @${session.un}`);
  res.json({ success: true, key: plainKey, label: keyLabel, maxUses: regKeys.keys[keyHash].maxUses });
});

// Admin API: Revoke key (session-authenticated)
app.delete('/admin/api/registration-keys/:label', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });

  const { label } = req.params;
  const regKeys = loadRegKeys();
  const entry = Object.entries(regKeys.keys).find(([, v]) => v.label === label);
  if (!entry) return res.status(404).json({ success: false, error: 'Key not found' });

  regKeys.keys[entry[0]].revoked = true;
  saveRegKeys(regKeys);

  console.log(`Registration key revoked via admin UI: "${label}" by @${session.un}`);
  res.json({ success: true, message: `Key "${label}" revoked` });
});

// ==================== OAUTH: OPERATOR OWNERSHIP (Phase 1) ====================
// Operators claim ownership of their agent by linking their X account.
// Once linked, only this X account can approve OAuth consent requests for the agent.

const OAUTH_SCOPES = ['balance', 'swap', 'send', 'sign', 'messages', 'profile'];
const OAUTH_SCOPE_DESCRIPTIONS = {
  balance: 'View wallet balance',
  swap: 'Swap tokens within your daily cap',
  send: 'Send tokens within your daily cap',
  sign: 'Sign messages on behalf of your agent',
  messages: 'Read and send messages',
  profile: 'View agent profile'
};

// Expired/invalid flow page with sad crab
const oauthExpiredPage = () => `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Session Expired — Clawnads</title><link rel="icon" type="image/svg+xml" href="/clawnads-favicon-white.svg">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/styles.css">
  <style>html,body{margin:0;min-height:100vh;background:var(--color-bg-deep);overflow:hidden;}
  .oe-header{display:flex;align-items:center;padding:var(--space-10) var(--space-16);background:var(--color-bg-deep);}
  .oe-header img{height:28px;width:auto;opacity:0.4;}
  .oe-body{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:var(--space-8);font-family:var(--font-sans);color:var(--color-text-primary);min-height:calc(100vh - 80px);}
  </style>
  </head><body>
  <header class="oe-header"><img src="/clawnads-logo-white.svg" alt="Clawnads"></header>
  <div class="oe-body">
    <svg width="120" height="66" viewBox="0 0 100 55" fill="none" xmlns="http://www.w3.org/2000/svg" style="margin-bottom:var(--space-4);"><path d="M31.2099 45.0527C31.3816 45.1109 31.3138 45.0772 31.455 45.1611C32.589 45.8338 33.9277 46.2766 35.1815 46.668C34.9152 47.0227 34.2144 47.7101 33.8407 48.1631C31.988 50.4053 31.1523 52.0517 30.078 54.6768C30.0466 54.7368 29.9425 54.8509 29.8944 54.9082C29.6623 55.008 29.5453 55.0327 29.3007 54.9521C26.7826 54.1202 26.2768 50.8331 27.1229 48.6533C27.8846 46.6925 29.4041 45.8487 31.2099 45.0527ZM68.4852 45.1162C69.0621 45.0313 70.4841 45.959 70.994 46.3555C73.2311 48.0924 73.9772 51.4654 72.1386 53.7686C71.8237 54.1626 70.946 54.9875 70.3876 54.9941C70.1555 54.9966 70.0611 54.9048 69.911 54.751C69.638 54.2115 69.4323 53.5146 69.1386 52.9385C67.8436 50.3981 66.7678 48.5855 64.6503 46.7012C65.9883 46.2882 67.3058 45.8796 68.4852 45.1162ZM75.0976 41.0518C77.6372 41.2724 79.9589 41.8337 81.8173 43.6602C84.0285 45.8334 84.4932 49.2289 82.1864 51.5244C81.7756 51.934 81.3041 52.3176 80.9091 51.668C80.7124 51.3342 80.2057 50.7078 79.9491 50.3447C77.9262 47.488 74.8661 44.6508 71.4413 43.6699C72.4779 43.2153 73.1779 42.6328 74.0526 41.916C74.4626 41.5805 74.6178 41.3382 75.0976 41.0518ZM24.953 41.1348C25.2018 41.3081 25.712 41.8073 25.994 42.043C26.8766 42.7798 27.5021 43.1421 28.5184 43.6533C25.1888 44.6816 22.494 46.9576 20.4198 49.7178C20.1465 50.0822 19.9759 50.3986 19.6708 50.7539L19.6093 50.8242C19.3237 51.0898 19.1644 51.66 18.7499 51.9531C18.4278 51.9673 18.1104 51.9103 17.8778 51.6797C14.6291 48.4648 16.6499 43.7235 20.4257 42.0674C21.7284 41.4963 22.1907 41.3268 23.6132 41.1611C24.0699 41.107 24.4952 41.1264 24.953 41.1348ZM50.412 21.7686C53.8394 21.7239 58.3896 22.4166 61.6933 23.4268C65.9905 24.9067 70.3972 27.0117 73.7499 30.1299C76.8457 33.0097 78.0987 34.494 74.744 37.8359C70.2383 42.3231 64.4548 44.3785 58.3495 45.5908C55.5323 46.1503 52.3726 46.1943 49.5321 46.1885C45.1317 46.1735 41.0227 45.7038 36.8075 44.4365C31.8682 42.951 25.0118 39.5832 23.1005 34.5C23.4202 32.8506 24.6728 31.4788 25.8983 30.3223C29.2819 27.1293 33.7394 24.8807 38.1278 23.4404C39.442 22.9808 40.9113 22.8445 42.2343 22.5049C45.0465 21.7828 47.5417 21.7667 50.412 21.7686ZM58.2714 36.7139C53.1801 33.6592 46.8197 33.6593 41.7284 36.7139C41.018 37.1401 40.7875 38.0621 41.2138 38.7725C41.6401 39.4825 42.5612 39.7122 43.2714 39.2861C47.4127 36.8014 52.5871 36.8013 56.7284 39.2861C57.4386 39.7122 58.3597 39.4825 58.786 38.7725C59.2122 38.0621 58.9817 37.1401 58.2714 36.7139ZM87.0839 0C92.2005 0.461954 97.6246 4.65656 99.1727 9.55762C99.4757 10.5174 100.012 12.7205 99.9999 13.7236C99.8876 22.8356 91.6694 29.0257 83.3222 30.3164C80.1773 30.8026 79.3214 31.1331 76.5575 29.6787C76.208 29.4223 75.9171 29.2185 75.747 28.8213C75.8109 28.4152 76.4329 28.1363 76.828 27.9307C78.3952 27.1126 79.3915 25.4821 80.5927 24.458C79.8025 23.6312 79.3988 22.8348 78.8427 21.8477C76.0729 16.926 76.379 9.33155 80.6288 5.25586C81.4663 7.83061 84.0478 12.8462 86.3554 14.2852C86.9364 14.1176 87.3281 12.3194 87.4335 11.7666C88.1696 7.90054 87.8807 3.83257 87.0839 0ZM12.5751 0.0224609C12.674 0.0188039 12.7036 0.0419007 12.8056 0.0742188C12.8109 0.105027 12.4873 2.15371 12.4237 2.41699C11.9339 4.44521 11.9777 13.3766 13.5809 14.2666C13.9333 14.0704 14.3942 13.5678 14.6747 13.2617C16.8563 10.8818 18.1966 8.25826 19.329 5.29004C20.1374 6.22699 21.0198 7.43298 21.5643 8.54297C24.0217 13.5521 22.9833 20.4614 19.1913 24.5205C20.1645 25.3207 20.9902 26.6263 22.1073 27.4258C22.6294 27.799 23.8926 28.3973 24.0468 28.7637C23.9779 29.0606 23.8152 29.1944 23.6112 29.4258C20.8948 31.2226 19.7045 30.7652 16.7216 30.3389C10.3594 29.4295 3.61264 25.3576 1.07411 19.2295C-2.55085 10.4783 3.42841 1.30598 12.5751 0.0224609ZM62.164 8.62793C65.1164 8.21829 67.8443 10.2775 68.2694 13.2363C68.6944 16.1954 66.6565 18.9439 63.7089 19.3867C60.7381 19.8328 57.9722 17.7685 57.5438 14.7861C57.1159 11.804 59.1885 9.04114 62.164 8.62793ZM36.1874 8.64844C39.1466 8.16434 41.9354 10.1844 42.4081 13.1543C42.8805 16.1242 40.8577 18.9139 37.8954 19.3779C34.9473 19.8393 32.1821 17.8218 31.7118 14.8662C31.2419 11.911 33.243 9.13068 36.1874 8.64844ZM37.0683 11.2412C35.6404 11.2416 34.4827 12.4037 34.4823 13.8359C34.4824 15.2683 35.6403 16.4303 37.0683 16.4307C38.4963 16.4305 39.655 15.2684 39.6552 13.8359C39.6548 12.4036 38.4962 11.2414 37.0683 11.2412ZM62.9306 11.2412C61.5023 11.2413 60.3447 12.4033 60.3446 13.8359C60.3448 15.2685 61.5024 16.4296 62.9306 16.4297C64.3588 16.4297 65.5164 15.2686 65.5165 13.8359C65.5165 12.4032 64.3589 11.2412 62.9306 11.2412Z" fill="white"/></svg>
    <div style="font-size:var(--text-xl);font-weight:700;margin-bottom:var(--space-4);">Session Expired</div>
    <div style="font-size:var(--text-sm);color:var(--color-text-secondary);line-height:var(--leading-relaxed);max-width:360px;">This authorization session has expired or was already completed.<br>Please start a new session from the application.</div>
  </div>
  </body></html>`;

// Reusable OAuth error page (sad crab + title + message)
const oauthErrorPage = (title, message) => `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} — Clawnads</title><link rel="icon" type="image/svg+xml" href="/clawnads-favicon-white.svg">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/styles.css">
  <style>html,body{margin:0;min-height:100vh;background:var(--color-bg-deep);overflow:hidden;}
  .oe-header{display:flex;align-items:center;padding:var(--space-10) var(--space-16);background:var(--color-bg-deep);}
  .oe-header img{height:28px;width:auto;opacity:0.4;}
  .oe-body{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:var(--space-8);font-family:var(--font-sans);color:var(--color-text-primary);min-height:calc(100vh - 80px);}
  </style></head><body>
  <header class="oe-header"><img src="/clawnads-logo-white.svg" alt="Clawnads"></header>
  <div class="oe-body">
    <svg width="120" height="66" viewBox="0 0 100 55" fill="none" xmlns="http://www.w3.org/2000/svg" style="margin-bottom:var(--space-4);opacity:0.35;"><path d="M31.2099 45.0527C31.3816 45.1109 31.3138 45.0772 31.455 45.1611C32.589 45.8338 33.9277 46.2766 35.1815 46.668C34.9152 47.0227 34.2144 47.7101 33.8407 48.1631C31.988 50.4053 31.1523 52.0517 30.078 54.6768C30.0466 54.7368 29.9425 54.8509 29.8944 54.9082C29.6623 55.008 29.5453 55.0327 29.3007 54.9521C26.7826 54.1202 26.2768 50.8331 27.1229 48.6533C27.8846 46.6925 29.4041 45.8487 31.2099 45.0527ZM68.4852 45.1162C69.0621 45.0313 70.4841 45.959 70.994 46.3555C73.2311 48.0924 73.9772 51.4654 72.1386 53.7686C71.8237 54.1626 70.946 54.9875 70.3876 54.9941C70.1555 54.9966 70.0611 54.9048 69.911 54.751C69.638 54.2115 69.4323 53.5146 69.1386 52.9385C67.8436 50.3981 66.7678 48.5855 64.6503 46.7012C65.9883 46.2882 67.3058 45.8796 68.4852 45.1162ZM75.0976 41.0518C77.6372 41.2724 79.9589 41.8337 81.8173 43.6602C84.0285 45.8334 84.4932 49.2289 82.1864 51.5244C81.7756 51.934 81.3041 52.3176 80.9091 51.668C80.7124 51.3342 80.2057 50.7078 79.9491 50.3447C77.9262 47.488 74.8661 44.6508 71.4413 43.6699C72.4779 43.2153 73.1779 42.6328 74.0526 41.916C74.4626 41.5805 74.6178 41.3382 75.0976 41.0518ZM24.953 41.1348C25.2018 41.3081 25.712 41.8073 25.994 42.043C26.8766 42.7798 27.5021 43.1421 28.5184 43.6533C25.1888 44.6816 22.494 46.9576 20.4198 49.7178C20.1465 50.0822 19.9759 50.3986 19.6708 50.7539L19.6093 50.8242C19.3237 51.0898 19.1644 51.66 18.7499 51.9531C18.4278 51.9673 18.1104 51.9103 17.8778 51.6797C14.6291 48.4648 16.6499 43.7235 20.4257 42.0674C21.7284 41.4963 22.1907 41.3268 23.6132 41.1611C24.0699 41.107 24.4952 41.1264 24.953 41.1348ZM50.412 21.7686C53.8394 21.7239 58.3896 22.4166 61.6933 23.4268C65.9905 24.9067 70.3972 27.0117 73.7499 30.1299C76.8457 33.0097 78.0987 34.494 74.744 37.8359C70.2383 42.3231 64.4548 44.3785 58.3495 45.5908C55.5323 46.1503 52.3726 46.1943 49.5321 46.1885C45.1317 46.1735 41.0227 45.7038 36.8075 44.4365C31.8682 42.951 25.0118 39.5832 23.1005 34.5C23.4202 32.8506 24.6728 31.4788 25.8983 30.3223C29.2819 27.1293 33.7394 24.8807 38.1278 23.4404C39.442 22.9808 40.9113 22.8445 42.2343 22.5049C45.0465 21.7828 47.5417 21.7667 50.412 21.7686ZM58.2714 36.7139C53.1801 33.6592 46.8197 33.6593 41.7284 36.7139C41.018 37.1401 40.7875 38.0621 41.2138 38.7725C41.6401 39.4825 42.5612 39.7122 43.2714 39.2861C47.4127 36.8014 52.5871 36.8013 56.7284 39.2861C57.4386 39.7122 58.3597 39.4825 58.786 38.7725C59.2122 38.0621 58.9817 37.1401 58.2714 36.7139ZM87.0839 0C92.2005 0.461954 97.6246 4.65656 99.1727 9.55762C99.4757 10.5174 100.012 12.7205 99.9999 13.7236C99.8876 22.8356 91.6694 29.0257 83.3222 30.3164C80.1773 30.8026 79.3214 31.1331 76.5575 29.6787C76.208 29.4223 75.9171 29.2185 75.747 28.8213C75.8109 28.4152 76.4329 28.1363 76.828 27.9307C78.3952 27.1126 79.3915 25.4821 80.5927 24.458C79.8025 23.6312 79.3988 22.8348 78.8427 21.8477C76.0729 16.926 76.379 9.33155 80.6288 5.25586C81.4663 7.83061 84.0478 12.8462 86.3554 14.2852C86.9364 14.1176 87.3281 12.3194 87.4335 11.7666C88.1696 7.90054 87.8807 3.83257 87.0839 0ZM12.5751 0.0224609C12.674 0.0188039 12.7036 0.0419007 12.8056 0.0742188C12.8109 0.105027 12.4873 2.15371 12.4237 2.41699C11.9339 4.44521 11.9777 13.3766 13.5809 14.2666C13.9333 14.0704 14.3942 13.5678 14.6747 13.2617C16.8563 10.8818 18.1966 8.25826 19.329 5.29004C20.1374 6.22699 21.0198 7.43298 21.5643 8.54297C24.0217 13.5521 22.9833 20.4614 19.1913 24.5205C20.1645 25.3207 20.9902 26.6263 22.1073 27.4258C22.6294 27.799 23.8926 28.3973 24.0468 28.7637C23.9779 29.0606 23.8152 29.1944 23.6112 29.4258C20.8948 31.2226 19.7045 30.7652 16.7216 30.3389C10.3594 29.4295 3.61264 25.3576 1.07411 19.2295C-2.55085 10.4783 3.42841 1.30598 12.5751 0.0224609ZM62.164 8.62793C65.1164 8.21829 67.8443 10.2775 68.2694 13.2363C68.6944 16.1954 66.6565 18.9439 63.7089 19.3867C60.7381 19.8328 57.9722 17.7685 57.5438 14.7861C57.1159 11.804 59.1885 9.04114 62.164 8.62793ZM36.1874 8.64844C39.1466 8.16434 41.9354 10.1844 42.4081 13.1543C42.8805 16.1242 40.8577 18.9139 37.8954 19.3779C34.9473 19.8393 32.1821 17.8218 31.7118 14.8662C31.2419 11.911 33.243 9.13068 36.1874 8.64844ZM37.0683 11.2412C35.6404 11.2416 34.4827 12.4037 34.4823 13.8359C34.4824 15.2683 35.6403 16.4303 37.0683 16.4307C38.4963 16.4305 39.655 15.2684 39.6552 13.8359C39.6548 12.4036 38.4962 11.2414 37.0683 11.2412ZM62.9306 11.2412C61.5023 11.2413 60.3447 12.4033 60.3446 13.8359C60.3448 15.2685 61.5024 16.4296 62.9306 16.4297C64.3588 16.4297 65.5164 15.2686 65.5165 13.8359C65.5165 12.4032 64.3589 11.2412 62.9306 11.2412Z" fill="white"/></svg>
    <div style="font-size:var(--text-xl);font-weight:700;margin-bottom:var(--space-4);">${title}</div>
    <div style="font-size:var(--text-sm);color:var(--color-text-secondary);line-height:var(--leading-relaxed);max-width:360px;">${message}</div>
  </div></body></html>`;

// In-memory store for OAuth authorization flows (auto-expires after 10 min)
const oauthAuthFlows = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of oauthAuthFlows) {
    if (now - val.created > 600000) oauthAuthFlows.delete(key);
  }
}, 60000);

// In-memory store for OAuth authorization codes (auto-expires after 5 min)
const oauthAuthCodes = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of oauthAuthCodes) {
    if (now - val.created > 300000) oauthAuthCodes.delete(key);
  }
}, 60000);

// In-memory claim tokens for owner linking (auto-expire after 30 min, single-use)
const ownerClaimTokens = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of ownerClaimTokens) {
    if (now - val.created > 1800000) ownerClaimTokens.delete(key);
  }
}, 60000);

// Agent generates a one-time claim URL for its operator
app.post('/agents/:name/auth/claim', authenticateAgent, (req, res) => {
  const { name } = req.params;

  // Revoke any existing claim token for this agent
  for (const [token, data] of ownerClaimTokens) {
    if (data.agentName === name) ownerClaimTokens.delete(token);
  }

  const claimToken = crypto.randomBytes(24).toString('base64url');
  ownerClaimTokens.set(claimToken, { agentName: name, created: Date.now() });

  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  const claimUrl = `${proto}://${host}/agents/${name}/auth/login?claim=${claimToken}`;

  console.log(`Claim token generated for ${name}`);
  res.json({
    success: true,
    claimUrl,
    expiresIn: '30 minutes',
    message: 'Send this URL to your operator. They will sign in with X to prove ownership. The link is single-use and expires in 30 minutes.'
  });
});

// Landing page before X OAuth — requires valid claim token
app.get('/agents/:name/auth/login', (req, res) => {
  if (!X_CLIENT_ID) return res.status(503).send('X OAuth not configured');

  const { name } = req.params;
  const { claim } = req.query;
  const agents = loadAgents();
  if (!agents[name]) return res.status(404).send('Agent not found');

  // Validate claim token
  const claimErrorPage = (title, pageTitle, body) => `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${pageTitle} \u2014 Clawnads</title><link rel="icon" type="image/svg+xml" href="/clawnads-favicon-white.svg">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="/styles.css">
    <style>html,body{margin:0;min-height:100vh;background:var(--color-bg-deep);overflow:hidden;}
    .ce-header{display:flex;align-items:center;padding:var(--space-10) var(--space-16);background:var(--color-bg-deep);}
    .ce-header img{height:28px;width:auto;opacity:0.4;}
    .ce-body{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:var(--space-8);font-family:var(--font-sans);color:var(--color-text-primary);min-height:calc(100vh - 80px);}
    </style>
    </head><body>
    <header class="ce-header"><img src="/clawnads-logo-white.svg" alt="Clawnads"></header>
    <div class="ce-body">
      <svg width="120" height="66" viewBox="0 0 100 55" fill="none" xmlns="http://www.w3.org/2000/svg" style="margin-bottom:var(--space-4);"><path d="M31.2099 45.0527C31.3816 45.1109 31.3138 45.0772 31.455 45.1611C32.589 45.8338 33.9277 46.2766 35.1815 46.668C34.9152 47.0227 34.2144 47.7101 33.8407 48.1631C31.988 50.4053 31.1523 52.0517 30.078 54.6768C30.0466 54.7368 29.9425 54.8509 29.8944 54.9082C29.6623 55.008 29.5453 55.0327 29.3007 54.9521C26.7826 54.1202 26.2768 50.8331 27.1229 48.6533C27.8846 46.6925 29.4041 45.8487 31.2099 45.0527ZM68.4852 45.1162C69.0621 45.0313 70.4841 45.959 70.994 46.3555C73.2311 48.0924 73.9772 51.4654 72.1386 53.7686C71.8237 54.1626 70.946 54.9875 70.3876 54.9941C70.1555 54.9966 70.0611 54.9048 69.911 54.751C69.638 54.2115 69.4323 53.5146 69.1386 52.9385C67.8436 50.3981 66.7678 48.5855 64.6503 46.7012C65.9883 46.2882 67.3058 45.8796 68.4852 45.1162ZM75.0976 41.0518C77.6372 41.2724 79.9589 41.8337 81.8173 43.6602C84.0285 45.8334 84.4932 49.2289 82.1864 51.5244C81.7756 51.934 81.3041 52.3176 80.9091 51.668C80.7124 51.3342 80.2057 50.7078 79.9491 50.3447C77.9262 47.488 74.8661 44.6508 71.4413 43.6699C72.4779 43.2153 73.1779 42.6328 74.0526 41.916C74.4626 41.5805 74.6178 41.3382 75.0976 41.0518ZM24.953 41.1348C25.2018 41.3081 25.712 41.8073 25.994 42.043C26.8766 42.7798 27.5021 43.1421 28.5184 43.6533C25.1888 44.6816 22.494 46.9576 20.4198 49.7178C20.1465 50.0822 19.9759 50.3986 19.6708 50.7539L19.6093 50.8242C19.3237 51.0898 19.1644 51.66 18.7499 51.9531C18.4278 51.9673 18.1104 51.9103 17.8778 51.6797C14.6291 48.4648 16.6499 43.7235 20.4257 42.0674C21.7284 41.4963 22.1907 41.3268 23.6132 41.1611C24.0699 41.107 24.4952 41.1264 24.953 41.1348ZM50.412 21.7686C53.8394 21.7239 58.3896 22.4166 61.6933 23.4268C65.9905 24.9067 70.3972 27.0117 73.7499 30.1299C76.8457 33.0097 78.0987 34.494 74.744 37.8359C70.2383 42.3231 64.4548 44.3785 58.3495 45.5908C55.5323 46.1503 52.3726 46.1943 49.5321 46.1885C45.1317 46.1735 41.0227 45.7038 36.8075 44.4365C31.8682 42.951 25.0118 39.5832 23.1005 34.5C23.4202 32.8506 24.6728 31.4788 25.8983 30.3223C29.2819 27.1293 33.7394 24.8807 38.1278 23.4404C39.442 22.9808 40.9113 22.8445 42.2343 22.5049C45.0465 21.7828 47.5417 21.7667 50.412 21.7686ZM58.2714 36.7139C53.1801 33.6592 46.8197 33.6593 41.7284 36.7139C41.018 37.1401 40.7875 38.0621 41.2138 38.7725C41.6401 39.4825 42.5612 39.7122 43.2714 39.2861C47.4127 36.8014 52.5871 36.8013 56.7284 39.2861C57.4386 39.7122 58.3597 39.4825 58.786 38.7725C59.2122 38.0621 58.9817 37.1401 58.2714 36.7139ZM87.0839 0C92.2005 0.461954 97.6246 4.65656 99.1727 9.55762C99.4757 10.5174 100.012 12.7205 99.9999 13.7236C99.8876 22.8356 91.6694 29.0257 83.3222 30.3164C80.1773 30.8026 79.3214 31.1331 76.5575 29.6787C76.208 29.4223 75.9171 29.2185 75.747 28.8213C75.8109 28.4152 76.4329 28.1363 76.828 27.9307C78.3952 27.1126 79.3915 25.4821 80.5927 24.458C79.8025 23.6312 79.3988 22.8348 78.8427 21.8477C76.0729 16.926 76.379 9.33155 80.6288 5.25586C81.4663 7.83061 84.0478 12.8462 86.3554 14.2852C86.9364 14.1176 87.3281 12.3194 87.4335 11.7666C88.1696 7.90054 87.8807 3.83257 87.0839 0ZM12.5751 0.0224609C12.674 0.0188039 12.7036 0.0419007 12.8056 0.0742188C12.8109 0.105027 12.4873 2.15371 12.4237 2.41699C11.9339 4.44521 11.9777 13.3766 13.5809 14.2666C13.9333 14.0704 14.3942 13.5678 14.6747 13.2617C16.8563 10.8818 18.1966 8.25826 19.329 5.29004C20.1374 6.22699 21.0198 7.43298 21.5643 8.54297C24.0217 13.5521 22.9833 20.4614 19.1913 24.5205C20.1645 25.3207 20.9902 26.6263 22.1073 27.4258C22.6294 27.799 23.8926 28.3973 24.0468 28.7637C23.9779 29.0606 23.8152 29.1944 23.6112 29.4258C20.8948 31.2226 19.7045 30.7652 16.7216 30.3389C10.3594 29.4295 3.61264 25.3576 1.07411 19.2295C-2.55085 10.4783 3.42841 1.30598 12.5751 0.0224609ZM62.164 8.62793C65.1164 8.21829 67.8443 10.2775 68.2694 13.2363C68.6944 16.1954 66.6565 18.9439 63.7089 19.3867C60.7381 19.8328 57.9722 17.7685 57.5438 14.7861C57.1159 11.804 59.1885 9.04114 62.164 8.62793ZM36.1874 8.64844C39.1466 8.16434 41.9354 10.1844 42.4081 13.1543C42.8805 16.1242 40.8577 18.9139 37.8954 19.3779C34.9473 19.8393 32.1821 17.8218 31.7118 14.8662C31.2419 11.911 33.243 9.13068 36.1874 8.64844ZM37.0683 11.2412C35.6404 11.2416 34.4827 12.4037 34.4823 13.8359C34.4824 15.2683 35.6403 16.4303 37.0683 16.4307C38.4963 16.4305 39.655 15.2684 39.6552 13.8359C39.6548 12.4036 38.4962 11.2414 37.0683 11.2412ZM62.9306 11.2412C61.5023 11.2413 60.3447 12.4033 60.3446 13.8359C60.3448 15.2685 61.5024 16.4296 62.9306 16.4297C64.3588 16.4297 65.5164 15.2686 65.5165 13.8359C65.5165 12.4032 64.3589 11.2412 62.9306 11.2412Z" fill="white"/></svg>
      <div style="font-size:var(--text-xl);font-weight:700;margin-bottom:var(--space-4);">${title}</div>
      <div style="font-size:var(--text-sm);color:var(--color-text-secondary);line-height:var(--leading-relaxed);max-width:360px;">${body}</div>
    </div>
    </body></html>`;

  if (!claim) {
    return res.status(403).send(claimErrorPage(
      'Claim Link Required', 'Claim Required',
      `To link your X account to <strong>${name}</strong>, ask your agent to generate a claim link.`
    ));
  }

  const claimData = ownerClaimTokens.get(claim);
  if (!claimData || claimData.agentName !== name) {
    return res.status(403).send(claimErrorPage(
      'Invalid or Expired Link', 'Invalid Link',
      'This claim link has expired or has already been used.<br>Ask your agent to generate a new one.'
    ));
  }

  const agent = agents[name];
  const walletShort = agent.wallet?.address
    ? agent.wallet.address.slice(0, 6) + '\u2026' + agent.wallet.address.slice(-4)
    : 'No wallet';
  const alreadyLinked = agent.owner ? agent.owner.xUsername : null;
  const avatarUrl = agent.avatarUrl || null;
  const agentInitial = name[0].toUpperCase();
  const description = agent.profile?.description || null;
  const maxTrade = agent.tradingConfig?.maxPerTradeMON || '500';
  const dailyCap = agent.tradingConfig?.dailyCapMON || '2500';

  // Avatar HTML — use actual image if uploaded, fallback to initial
  const avatarHtml = avatarUrl
    ? `<img src="${avatarUrl}" alt="${name}" style="width:100%;height:100%;border-radius:50%;object-fit:cover;">`
    : `<span style="font-size:var(--text-xl);font-weight:700;color:white;">${agentInitial}</span>`;

  res.send(`<!DOCTYPE html>
<html lang="en"><head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <title>Claim Agent \u2014 ${name} \u2014 Clawnads</title>
  <link rel="icon" type="image/svg+xml" href="/clawnads-favicon-white.svg">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/styles.css">
  <style>
    html, body { margin: 0; min-height: 100vh; background: var(--color-bg-deep); }
    body { color: var(--color-text-primary); font-family: var(--font-sans); display: flex; flex-direction: column; }
    .l-header { display: flex; align-items: center; padding: var(--space-10) var(--space-16); }
    .l-header img { height: 28px; width: auto; opacity: 0.4; }
    .l-body { flex: 1; display: flex; align-items: center; justify-content: center; padding: var(--space-8); }
    .l-card { background: var(--color-bg-card); border: 1px solid var(--color-border); border-radius: var(--radius-2xl); padding: var(--space-12); max-width: 400px; width: 100%; box-shadow: var(--shadow-elevated); }
    .l-agent { display: flex; align-items: center; gap: var(--space-6); margin-bottom: var(--space-10); }
    .l-avatar { width: 48px; height: 48px; border-radius: 50%; background: linear-gradient(135deg, var(--color-accent), #a855f7); display: flex; align-items: center; justify-content: center; flex-shrink: 0; overflow: hidden; }
    .l-agent-info { flex: 1; min-width: 0; }
    .l-agent-name { font-size: var(--text-lg); font-weight: 700; line-height: var(--leading-tight); }
    .l-agent-meta { font-size: var(--text-xs); color: var(--color-text-tertiary); font-family: var(--font-mono); margin-top: 2px; }
    .l-agent-desc { font-size: var(--text-sm); color: var(--color-text-secondary); margin-top: 4px; line-height: var(--leading-normal); }
    .l-section-label { font-size: var(--text-xs); color: var(--color-text-muted); text-transform: uppercase; letter-spacing: 0.06em; font-weight: 600; margin-bottom: var(--space-4); }
    .l-perms { margin-bottom: var(--space-8); }
    .l-perm { display: flex; align-items: flex-start; gap: var(--space-4); padding: var(--space-3) 0; font-size: var(--text-sm); color: var(--color-text-secondary); line-height: var(--leading-normal); }
    .l-perm-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--color-success); flex-shrink: 0; margin-top: 6px; }
    .l-perm-dot.lock { background: var(--color-text-muted); }
    .l-limits { background: var(--color-bg-elevated); border-radius: var(--radius-lg); padding: var(--space-5) var(--space-6); margin-bottom: var(--space-10); }
    .l-limit-row { display: flex; justify-content: space-between; align-items: center; padding: 3px 0; }
    .l-limit-label { font-size: var(--text-xs); color: var(--color-text-tertiary); }
    .l-limit-val { font-size: var(--text-xs); color: var(--color-text-secondary); font-family: var(--font-mono); font-weight: 500; }
    .l-already { display: flex; align-items: center; gap: var(--space-3); padding: var(--space-4) var(--space-6); background: rgba(34,197,94,0.08); border-radius: var(--radius-lg); margin-bottom: var(--space-8); font-size: var(--text-sm); color: var(--color-success); }
    .l-already svg { flex-shrink: 0; }
    .l-btn { display: flex; align-items: center; justify-content: center; gap: var(--space-3); width: 100%; padding: var(--space-5) var(--space-8); background: var(--color-text-primary); color: var(--color-bg-deep); border-radius: var(--radius-pill); font-size: var(--text-base); font-weight: 600; font-family: var(--font-sans); border: none; cursor: pointer; text-decoration: none; transition: opacity var(--transition-fast); }
    .l-btn:hover { opacity: 0.9; }
    .l-footer { text-align: center; font-size: var(--text-xs); color: var(--color-text-muted); margin-top: var(--space-6); line-height: var(--leading-relaxed); }
    @media (max-width: 480px) {
      .l-header { padding: var(--space-6) var(--space-8); }
      .l-body { padding: var(--space-4); align-items: flex-start; padding-top: var(--space-8); }
      .l-card { padding: var(--space-8); }
    }
  </style>
</head><body>
  <header class="l-header"><img src="/clawnads-logo-white.svg" alt="Clawnads"></header>
  <div class="l-body">
  <div class="l-card">
    <div style="text-align:center;font-size:var(--text-2xl);font-weight:700;margin-bottom:var(--space-8);">Claim Agent</div>
    <div class="l-agent">
      <div class="l-avatar">${avatarHtml}</div>
      <div class="l-agent-info">
        <div class="l-agent-name">${name}</div>
        <div class="l-agent-meta">${walletShort}</div>
        ${description ? `<div class="l-agent-desc">${description.length > 80 ? description.slice(0, 80) + '\u2026' : description}</div>` : ''}
      </div>
    </div>

    ${alreadyLinked ? `
    <div class="l-already">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
      Already claimed by @${alreadyLinked}
    </div>` : ''}

    <div class="l-perms">
      <div class="l-section-label">Linking your X account lets you</div>
      <div class="l-perm"><div class="l-perm-dot"></div> Approve or deny third-party dApp access</div>
      <div class="l-perm"><div class="l-perm-dot"></div> See exactly what permissions dApps request</div>
      <div class="l-perm"><div class="l-perm-dot"></div> Control which dApps can trade for this agent</div>
      <div class="l-perm"><div class="l-perm-dot lock"></div> Platform limits still enforced \u2014 no bypass</div>
    </div>

    <div class="l-limits">
      <div class="l-limit-row"><span class="l-limit-label">Max per trade</span><span class="l-limit-val">${maxTrade} MON</span></div>
      <div class="l-limit-row"><span class="l-limit-label">Daily cap</span><span class="l-limit-val">${dailyCap} MON</span></div>
      <div class="l-limit-row"><span class="l-limit-label">External sends</span><span class="l-limit-val">Require approval</span></div>
    </div>

    <a href="/agents/${name}/auth/x-redirect?claim=${claim}" class="l-btn">
      <svg viewBox="0 0 24 24" width="15" height="15" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
      Continue with X
    </a>

    <div class="l-footer">We only read your X username and profile image.<br>We never post, follow, or access your DMs.</div>
  </div>
  </div>
</body></html>`);
});

// Actual X redirect (from the landing page button)
// Uses /admin/auth/callback — the only callback URL registered in the X Developer Portal.
// The flowType in the state differentiates admin login vs owner linking vs consent auth.
app.get('/agents/:name/auth/x-redirect', (req, res) => {
  if (!X_CLIENT_ID) return res.status(503).send('X OAuth not configured');

  const { name } = req.params;
  const { claim } = req.query;
  const agents = loadAgents();
  if (!agents[name]) return res.status(404).send('Agent not found');

  // Validate claim token (same check as landing page)
  if (!claim) return res.status(400).send('Missing claim token');
  const claimData = ownerClaimTokens.get(claim);
  if (!claimData || claimData.agentName !== name) return res.status(403).send('Invalid or expired claim token');

  const state = crypto.randomBytes(16).toString('hex');
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

  // Store claim token in flow so callback can consume it after success
  oauthPendingFlows.set(state, { codeVerifier, agentName: name, flowType: 'owner_link', claimToken: claim, created: Date.now() });

  // Use the admin callback URL — it's registered in X Developer Portal
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  const redirectUri = `${proto}://${host}/admin/auth/callback`;

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: X_CLIENT_ID,
    redirect_uri: redirectUri,
    scope: 'users.read tweet.read',
    state: state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  });

  res.redirect(`https://x.com/i/oauth2/authorize?${params}`);
});

// Check if agent has an owner linked (public)
app.get('/agents/:name/owner', (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();
  if (!agents[name]) return res.status(404).json({ success: false, error: 'Agent not found' });

  if (agents[name].owner) {
    res.json({
      success: true,
      hasOwner: true,
      xUsername: agents[name].owner.xUsername,
      linkedAt: agents[name].owner.linkedAt
    });
  } else {
    res.json({ success: true, hasOwner: false });
  }
});

// Unlink X account from agent (requires agent bearer token)
app.delete('/agents/:name/owner', authenticateAgent, (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name].owner) {
    return res.status(400).json({ success: false, error: 'No owner linked' });
  }

  const oldOwner = agents[name].owner.xUsername;
  delete agents[name].owner;
  saveAgents(agents);

  console.log(`Owner unlinked: @${oldOwner} removed from ${name}`);
  res.json({ success: true, message: `Owner @${oldOwner} unlinked from ${name}` });
});

// ==================== OAUTH: DAPP REGISTRATION (Phase 2) ====================
// Admin registers third-party dApps that can request OAuth access to agents.

app.post('/admin/dapps', authenticateAdmin, (req, res) => {
  const { name, description, iconUrl, redirectUris, scopes } = req.body;

  if (!name) return res.status(400).json({ success: false, error: 'name is required' });
  if (!redirectUris || !Array.isArray(redirectUris) || redirectUris.length === 0) {
    return res.status(400).json({ success: false, error: 'redirectUris array is required' });
  }
  if (!scopes || !Array.isArray(scopes) || scopes.length === 0) {
    return res.status(400).json({ success: false, error: 'scopes array is required' });
  }

  // Validate scopes
  const invalidScopes = scopes.filter(s => !OAUTH_SCOPES.includes(s));
  if (invalidScopes.length > 0) {
    return res.status(400).json({
      success: false,
      error: `Invalid scopes: ${invalidScopes.join(', ')}`,
      validScopes: OAUTH_SCOPES
    });
  }

  const clientId = 'dapp_' + crypto.randomBytes(12).toString('hex');
  const clientSecret = 'dappsec_' + crypto.randomBytes(24).toString('hex');
  const clientSecretHash = hashToken(clientSecret);

  const dapps = loadDapps();
  dapps[clientId] = {
    clientId,
    clientSecretHash,
    name,
    description: description || null,
    iconUrl: iconUrl || null,
    redirectUris,
    scopes,
    registeredAt: new Date().toISOString(),
    active: true
  };
  saveDapps(dapps);

  console.log(`dApp registered: ${name} (${clientId})`);
  res.json({
    success: true,
    clientId,
    clientSecret,
    name,
    scopes,
    redirectUris,
    warning: 'Store the clientSecret securely — it cannot be retrieved again.'
  });
});

app.get('/admin/dapps', authenticateAdmin, (req, res) => {
  const dapps = loadDapps();
  const list = Object.values(dapps).map(d => ({
    clientId: d.clientId,
    name: d.name,
    description: d.description,
    scopes: d.scopes,
    redirectUris: d.redirectUris,
    registeredAt: d.registeredAt,
    active: d.active
  }));
  res.json({ success: true, count: list.length, dapps: list });
});

app.delete('/admin/dapps/:clientId', authenticateAdmin, (req, res) => {
  const { clientId } = req.params;
  const dapps = loadDapps();
  if (!dapps[clientId]) return res.status(404).json({ success: false, error: 'dApp not found' });

  dapps[clientId].active = false;
  saveDapps(dapps);

  console.log(`dApp deactivated: ${dapps[clientId].name} (${clientId})`);
  res.json({ success: true, message: `dApp ${dapps[clientId].name} deactivated` });
});

// ==================== OAUTH: AUTHORIZATION SERVER (Phase 3) ====================
// Standard OAuth 2.0 Authorization Code flow with PKCE.

// CORS middleware for OAuth endpoints
app.use('/oauth', (req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// Public dApp info (for skill doc generation, playground, etc.)
app.get('/oauth/dapp/:clientId', (req, res) => {
  const dapps = loadDapps();
  const dapp = dapps[req.params.clientId];
  if (!dapp || !dapp.active) return res.status(404).json({ error: 'dApp not found' });

  res.json({
    clientId: req.params.clientId,
    name: dapp.name,
    description: dapp.description || null,
    iconUrl: dapp.iconUrl || null,
    scopes: dapp.scopes,
    accessLevel: dapp.accessLevel || 'read_write',
    connectUrl: `https://tormund.io/oauth/connect/${req.params.clientId}`,
    scopeDescriptions: dapp.scopes.reduce((acc, s) => {
      acc[s] = OAUTH_SCOPE_DESCRIPTIONS[s] || s;
      return acc;
    }, {})
  });
});

// OAuth server metadata (RFC 8414)
app.get('/.well-known/oauth-authorization-server', (req, res) => {
  const issuer = 'https://tormund.io';

  res.json({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    userinfo_endpoint: `${issuer}/oauth/userinfo`,
    scopes_supported: OAUTH_SCOPES,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['client_secret_post']
  });
});

// Server-initiated OAuth connect link — operators click this directly from skill docs
// Generates PKCE server-side and redirects to consent. The code_verifier is passed to the
// dApp's redirect URI on approval so it can complete the standard token exchange.
app.get('/oauth/connect/:clientId', (req, res) => {
  const clientId = req.params.clientId;
  if (!OAUTH_SIGNING_KEY) return res.status(503).json({ error: 'OAuth not configured' });

  const dapps = loadDapps();
  const dapp = dapps[clientId];
  if (!dapp || !dapp.active) {
    return res.status(404).send(oauthErrorPage('App Not Found', 'This application does not exist or has been deactivated.'));
  }
  if (!dapp.redirectUris || dapp.redirectUris.length === 0) {
    return res.status(400).send(oauthErrorPage('App Not Configured', 'This application has no redirect URIs configured. The developer needs to add one in the Developer Console.'));
  }
  if (!dapp.scopes || dapp.scopes.length === 0) {
    return res.status(400).send(oauthErrorPage('App Not Configured', 'This application has no scopes configured. The developer needs to add scopes in the Developer Console.'));
  }

  // Generate PKCE server-side
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

  // Use first registered redirect URI and all registered scopes
  const redirectUri = dapp.redirectUris[0];
  const scopes = dapp.scopes;

  // Optional agent query param
  const agent = req.query.agent || null;
  if (agent) {
    const agents = loadAgents();
    if (!agents[agent]) {
      return res.status(400).send(oauthErrorPage('Agent Not Found', `The agent "${agent}" does not exist.`));
    }
  }

  // Create the authorization flow (same as /oauth/authorize but server-initiated)
  const flowId = crypto.randomBytes(16).toString('hex');
  const csrfToken = crypto.randomBytes(24).toString('hex');
  oauthAuthFlows.set(flowId, {
    clientId,
    redirectUri,
    scopes,
    state: null,
    codeChallenge,
    csrfToken,
    agentName: agent,
    created: Date.now(),
    operatorXId: null,
    operatorXUsername: null,
    operatorProfileImageUrl: null,
    serverInitiated: true,
    codeVerifier // stored so we can pass it to the dApp on approval
  });

  analytics.trackEvent('oauth_request', null, { clientId, endpoint: 'connect' });
  console.log(`OAuth connect: ${dapp.name} — server-initiated flow for [${scopes.join(', ')}]${agent ? ` agent=${agent}` : ''}`);
  res.redirect(`/oauth/consent?flow=${flowId}`);
});

// Step 1: Authorization endpoint — validates params, stores pending flow, redirects to consent
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, scope, response_type, state, code_challenge, code_challenge_method, agent } = req.query;

  if (!OAUTH_SIGNING_KEY) return res.status(503).json({ error: 'OAuth not configured' });
  if (response_type !== 'code') return res.status(400).json({ error: 'Only response_type=code is supported' });
  if (!client_id) return res.status(400).json({ error: 'client_id is required' });
  if (!redirect_uri) return res.status(400).json({ error: 'redirect_uri is required' });
  if (!code_challenge || code_challenge_method !== 'S256') {
    return res.status(400).json({ error: 'PKCE required: code_challenge and code_challenge_method=S256' });
  }

  // Validate dApp
  const dapps = loadDapps();
  const dapp = dapps[client_id];
  if (!dapp || !dapp.active) {
    return res.status(400).json({ error: 'Unknown or inactive client_id' });
  }

  // Validate redirect URI
  if (!dapp.redirectUris || dapp.redirectUris.length === 0) {
    return res.status(400).json({ error: 'No redirect URIs configured for this app. Add one in the Developer Console under Settings.' });
  }
  if (!dapp.redirectUris.includes(redirect_uri)) {
    return res.status(400).json({ error: 'redirect_uri not registered for this client' });
  }

  // Validate requested scopes
  const requestedScopes = scope ? scope.split(/[ +]/).filter(Boolean) : [];
  if (requestedScopes.length === 0) {
    return res.status(400).json({ error: 'At least one scope is required' });
  }
  const invalidScopes = requestedScopes.filter(s => !dapp.scopes.includes(s));
  if (invalidScopes.length > 0) {
    return res.status(400).json({
      error: `Scopes not registered for this dApp: ${invalidScopes.join(', ')}`,
      registeredScopes: dapp.scopes
    });
  }

  // Validate agent if specified (optional — operator picks after X login if omitted)
  if (agent) {
    const agents = loadAgents();
    if (!agents[agent]) {
      return res.status(400).json({ error: 'Agent not found' });
    }
    if (!agents[agent].owner) {
      return res.status(400).json({ error: 'Agent has no owner linked. The operator must link their X account first via /agents/:name/auth/login' });
    }
  }

  // Create the authorization flow
  const flowId = crypto.randomBytes(16).toString('hex');
  const csrfToken = crypto.randomBytes(24).toString('hex');
  oauthAuthFlows.set(flowId, {
    clientId: client_id,
    redirectUri: redirect_uri,
    scopes: requestedScopes,
    state: state || null,
    codeChallenge: code_challenge,
    csrfToken,
    agentName: agent || null,
    created: Date.now(),
    operatorXId: null,
    operatorXUsername: null,
    operatorProfileImageUrl: null
  });

  analytics.trackEvent('oauth_request', null, { clientId: client_id, endpoint: 'authorize' });
  console.log(`OAuth flow started: ${dapp.name} requesting [${requestedScopes.join(', ')}]${agent ? ` for ${agent}` : ' (operator will select agent)'}`);
  res.redirect(`/oauth/consent?flow=${flowId}`);
});

// Consent page (serves static HTML)
app.get('/oauth/consent', (req, res) => {
  const { flow } = req.query;
  if (!flow) return res.status(400).send('Missing flow parameter');

  const flowData = oauthAuthFlows.get(flow);
  if (!flowData) return res.status(400).send(oauthExpiredPage());

  res.sendFile(path.join(__dirname, 'public', 'oauth-consent.html'));
});

// Get consent flow details (used by the consent page JS)
app.get('/oauth/consent/details', (req, res) => {
  const { flow } = req.query;
  if (!flow) return res.status(400).json({ error: 'Missing flow parameter' });

  const flowData = oauthAuthFlows.get(flow);
  if (!flowData) return res.status(400).json({ error: 'Invalid or expired flow' });

  const dapps = loadDapps();
  const dapp = dapps[flowData.clientId];
  const agents = loadAgents();
  const agent = flowData.agentName ? agents[flowData.agentName] : null;

  const response = {
    success: true,
    dapp: {
      name: dapp?.name || 'Unknown App',
      description: dapp?.description || null,
      iconUrl: dapp?.iconUrl || null
    },
    agent: flowData.agentName ? {
      name: flowData.agentName,
      wallet: agent?.wallet?.address || null,
      avatarUrl: agent?.avatarUrl || null
    } : null,
    scopes: flowData.scopes.map(s => ({
      key: s,
      description: OAUTH_SCOPE_DESCRIPTIONS[s] || s
    })),
    limits: flowData.agentName ? {
      maxPerTradeMON: agent?.tradingConfig?.maxPerTradeMON || '500',
      dailyCapMON: agent?.tradingConfig?.dailyCapMON || '2500'
    } : null,
    operatorAuthenticated: !!flowData.operatorXId,
    operatorUsername: flowData.operatorXUsername || null,
    operatorProfileImageUrl: flowData.operatorProfileImageUrl || null,
    csrfToken: flowData.csrfToken || null
  };

  // When operator is authenticated but no agent selected, return their claimed agents
  if (flowData.operatorXId && !flowData.agentName) {
    response.claimedAgents = Object.entries(agents)
      .filter(([, a]) => a.owner?.xId === flowData.operatorXId)
      .map(([name, a]) => ({
        name,
        wallet: a.wallet?.address || null,
        avatarUrl: a.avatarUrl || null,
        maxPerTradeMON: a.tradingConfig?.maxPerTradeMON || '500',
        dailyCapMON: a.tradingConfig?.dailyCapMON || '2500'
      }));
  }

  res.json(response);
});

// Operator must log in with X before approving consent
app.get('/oauth/consent/auth', (req, res) => {
  if (!X_CLIENT_ID) return res.status(503).send('X OAuth not configured');

  const { flow } = req.query;
  if (!flow) return res.status(400).send('Missing flow parameter');

  const flowData = oauthAuthFlows.get(flow);
  if (!flowData) return res.status(400).send(oauthExpiredPage());

  const state = crypto.randomBytes(16).toString('hex');
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

  // Store as consent auth flow so the callback knows to redirect back to consent
  oauthPendingFlows.set(state, {
    codeVerifier,
    agentName: flowData.agentName,
    flowType: 'consent_auth',
    consentFlowId: flow,
    created: Date.now()
  });

  // Use /admin/auth/callback — must match the callback URL registered in X Developer Portal
  const redirectUri = 'https://claw.tormund.io/admin/auth/callback';

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: X_CLIENT_ID,
    redirect_uri: redirectUri,
    scope: 'users.read tweet.read',
    state: state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  });

  res.redirect(`https://x.com/i/oauth2/authorize?${params}`);
});

// Approve consent — operator approves the dApp access
app.post('/oauth/consent/approve', express.urlencoded({ extended: false }), (req, res) => {
  const { flow, agent: selectedAgent, csrf_token } = req.body;
  if (!flow) return res.status(400).json({ error: 'Missing flow parameter' });

  const flowData = oauthAuthFlows.get(flow);
  if (!flowData) return res.status(400).send(oauthExpiredPage());

  // Verify CSRF token
  if (!csrf_token || csrf_token !== flowData.csrfToken) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }

  // Verify operator is authenticated
  if (!flowData.operatorXId) {
    return res.status(403).json({ error: 'Operator must authenticate with X first' });
  }

  // If agent wasn't set in the authorize URL, use the one from the form
  if (!flowData.agentName && selectedAgent) {
    flowData.agentName = selectedAgent;
  }
  if (!flowData.agentName) {
    return res.status(400).json({ error: 'No agent selected' });
  }

  // Verify operator is the agent's owner
  const agents = loadAgents();
  const agent = agents[flowData.agentName];
  if (!agent || !agent.owner) {
    return res.status(400).json({ error: 'Agent has no owner' });
  }
  if (agent.owner.xId !== flowData.operatorXId) {
    return res.status(403).json({ error: 'Only the agent owner can approve consent' });
  }

  // Generate authorization code
  const authCode = crypto.randomBytes(32).toString('hex');
  oauthAuthCodes.set(authCode, {
    clientId: flowData.clientId,
    agentName: flowData.agentName,
    scopes: flowData.scopes,
    codeChallenge: flowData.codeChallenge,
    redirectUri: flowData.redirectUri,
    created: Date.now()
  });

  // Clean up flow
  const dapps = loadDapps();
  const dapp = dapps[flowData.clientId];
  const dappName = dapp?.name || 'the app';
  oauthAuthFlows.delete(flow);

  // Build dApp redirect URL with auth code
  const redirectUrl = new URL(flowData.redirectUri);
  redirectUrl.searchParams.set('code', authCode);
  if (flowData.state) redirectUrl.searchParams.set('state', flowData.state);
  // For server-initiated flows (/oauth/connect), pass code_verifier to the dApp
  // so it can complete the standard token exchange without generating its own PKCE
  if (flowData.serverInitiated && flowData.codeVerifier) {
    redirectUrl.searchParams.set('code_verifier', flowData.codeVerifier);
  }
  const dappRedirect = redirectUrl.toString();

  // Track connected dApp on the agent
  if (!agent.connectedDapps) agent.connectedDapps = [];
  const existingIdx = agent.connectedDapps.findIndex(c => c.clientId === flowData.clientId);
  const connectionRecord = {
    clientId: flowData.clientId,
    name: dappName,
    scopes: flowData.scopes,
    approvedAt: new Date().toISOString(),
    approvedBy: flowData.operatorXUsername || null
  };
  if (existingIdx >= 0) {
    agent.connectedDapps[existingIdx] = connectionRecord; // update existing
  } else {
    agent.connectedDapps.push(connectionRecord);
  }
  // Remove from revokedDapps if re-approving
  if (agent.revokedDapps) {
    agent.revokedDapps = agent.revokedDapps.filter(id => id !== flowData.clientId);
  }
  saveAgents(agents);

  console.log(`OAuth consent approved: ${flowData.agentName} granted [${flowData.scopes.join(', ')}] to ${flowData.clientId}`);

  // For server-initiated flows, show a success page on tormund.io
  // The dApp still gets the auth code via background redirect (invisible to operator)
  if (flowData.serverInitiated) {
    const agentNameSafe = (flowData.agentName || '').replace(/</g, '&lt;');
    const dappNameSafe = (dappName || '').replace(/</g, '&lt;');
    const SCOPE_ACCESS = { balance: 'ro', swap: 'rw', send: 'rw', sign: 'rw', messages: 'rw', profile: 'ro' };
    const scopeListHtml = flowData.scopes.map(s => {
      const desc = OAUTH_SCOPE_DESCRIPTIONS[s] || s;
      const access = SCOPE_ACCESS[s] || 'ro';
      const badge = access === 'rw'
        ? '<span style="font-size:10px;font-weight:600;padding:1px 6px;border-radius:99px;background:rgba(34,197,94,0.1);color:#22c55e;border:1px solid rgba(34,197,94,0.2);white-space:nowrap;">Read &amp; write</span>'
        : '<span style="font-size:10px;font-weight:600;padding:1px 6px;border-radius:99px;background:rgba(124,92,255,0.1);color:#7c5cff;border:1px solid rgba(124,92,255,0.2);white-space:nowrap;">Read only</span>';
      return `<div style="display:flex;align-items:center;gap:8px;padding:4px 0;"><span style="font-size:13px;color:rgba(255,255,255,0.6);flex:1;">${desc.replace(/</g, '&lt;')}</span>${badge}</div>`;
    }).join('');

    res.send(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<title>Connected — Clawnads</title>
<link rel="icon" type="image/svg+xml" href="/clawnads-favicon-white.svg">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/styles.css">
<style>
html,body{margin:0;min-height:100vh;background:var(--color-bg-deep);}
body{color:var(--color-text-primary);font-family:var(--font-sans);display:flex;flex-direction:column;}
.oc-header{display:flex;align-items:center;padding:var(--space-10) var(--space-16);}
.oc-header img{height:28px;width:auto;opacity:0.4;}
.oc-body{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:var(--space-8);}
</style>
</head><body>
<header class="oc-header"><img src="/clawnads-logo-white.svg" alt="Clawnads"></header>
<div class="oc-body">
  <div style="display:flex;flex-direction:column;align-items:center;text-align:center;padding:var(--space-8) 0;max-width:420px;width:100%;">
    <img src="/happy-crab.svg" alt="" width="120" height="66" style="margin-bottom:var(--space-6);">
    <div style="font-size:var(--text-xl);font-weight:700;margin-bottom:var(--space-3);">Connected</div>
    <div style="font-size:var(--text-sm);color:var(--color-text-secondary);line-height:var(--leading-relaxed);margin-bottom:var(--space-8);">
      <strong>${agentNameSafe}</strong> now has access to <strong>${dappNameSafe}</strong>.
    </div>
    <div style="width:100%;background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:16px 20px;margin-bottom:var(--space-8);text-align:left;">
      <div style="font-size:11px;font-weight:600;color:rgba(255,255,255,0.3);text-transform:uppercase;letter-spacing:0.06em;margin-bottom:8px;">Granted permissions</div>
      ${scopeListHtml}
    </div>
    <div style="font-size:var(--text-sm);color:var(--color-text-muted);line-height:var(--leading-relaxed);margin-bottom:var(--space-8);">
      You can close this page.
    </div>
    <a href="/operator" style="font-size:var(--text-xs);color:var(--color-text-muted);text-decoration:none;font-family:var(--font-sans);transition:color 0.15s;">Manage permissions</a>
  </div>
</div>
<!-- Deliver auth code to dApp callback in background -->
<iframe src="${dappRedirect.replace(/"/g, '&quot;')}" style="display:none;" sandbox="allow-scripts allow-same-origin"></iframe>
</body></html>`);
  } else {
    // Standard OAuth flow: redirect directly to dApp callback with auth code
    res.redirect(dappRedirect);
  }
});

// Deny consent
app.post('/oauth/consent/deny', express.urlencoded({ extended: false }), (req, res) => {
  const { flow, csrf_token } = req.body;
  if (!flow) return res.status(400).json({ error: 'Missing flow parameter' });

  const flowData = oauthAuthFlows.get(flow);
  if (!flowData) return res.status(400).send(oauthExpiredPage());

  // Verify CSRF token
  if (!csrf_token || csrf_token !== flowData.csrfToken) {
    return res.status(403).json({ error: 'Invalid CSRF token' });
  }

  oauthAuthFlows.delete(flow);

  console.log(`OAuth consent denied for ${flowData.agentName} by operator`);

  // Show denied page on the consent screen instead of redirecting back to the dApp
  const dapps = loadDapps();
  const dapp = dapps[flowData.clientId] || {};
  const dappName = dapp.name || flowData.clientId;
  // Retry URL: for server-initiated flows, point back to /oauth/connect; otherwise use dApp origin
  let retryUrl = '';
  if (flowData.serverInitiated) {
    retryUrl = `https://tormund.io/oauth/connect/${flowData.clientId}`;
  } else {
    const redirectUri = flowData.redirectUri || '';
    retryUrl = redirectUri ? new URL(redirectUri).origin : '';
  }

  res.send(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<title>Access Denied — Clawnads</title>
<link rel="icon" type="image/svg+xml" href="/clawnads-favicon-white.svg">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/styles.css">
<style>
html,body{margin:0;min-height:100vh;background:var(--color-bg-deep);}
body{color:var(--color-text-primary);font-family:var(--font-sans);display:flex;flex-direction:column;}
.oc-header{display:flex;align-items:center;padding:var(--space-10) var(--space-16);}
.oc-header img{height:28px;width:auto;opacity:0.4;}
.oc-body{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:var(--space-8);}
</style>
</head><body>
<header class="oc-header"><img src="/clawnads-logo-white.svg" alt="Clawnads"></header>
<div class="oc-body">
  <div style="display:flex;flex-direction:column;align-items:center;text-align:center;padding:var(--space-8) 0;max-width:400px;">
    <svg width="80" height="44" viewBox="0 0 100 55" fill="none" xmlns="http://www.w3.org/2000/svg" style="margin-bottom:var(--space-6);opacity:0.35;">
      <path d="M31.2099 45.0527C31.3816 45.1109 31.3138 45.0772 31.455 45.1611C32.589 45.8338 33.9277 46.2766 35.1815 46.668C34.9152 47.0227 34.2144 47.7101 33.8407 48.1631C31.988 50.4053 31.1523 52.0517 30.078 54.6768C30.0466 54.7368 29.9425 54.8509 29.8944 54.9082C29.6623 55.008 29.5453 55.0327 29.3007 54.9521C26.7826 54.1202 26.2768 50.8331 27.1229 48.6533C27.8846 46.6925 29.4041 45.8487 31.2099 45.0527ZM68.4852 45.1162C69.0621 45.0313 70.4841 45.959 70.994 46.3555C73.2311 48.0924 73.9772 51.4654 72.1386 53.7686C71.8237 54.1626 70.946 54.9875 70.3876 54.9941C70.1555 54.9966 70.0611 54.9048 69.911 54.751C69.638 54.2115 69.4323 53.5146 69.1386 52.9385C67.8436 50.3981 66.7678 48.5855 64.6503 46.7012C65.9883 46.2882 67.3058 45.8796 68.4852 45.1162ZM75.0976 41.0518C77.6372 41.2724 79.9589 41.8337 81.8173 43.6602C84.0285 45.8334 84.4932 49.2289 82.1864 51.5244C81.7756 51.934 81.3041 52.3176 80.9091 51.668C80.7124 51.3342 80.2057 50.7078 79.9491 50.3447C77.9262 47.488 74.8661 44.6508 71.4413 43.6699C72.4779 43.2153 73.1779 42.6328 74.0526 41.916C74.4626 41.5805 74.6178 41.3382 75.0976 41.0518ZM24.953 41.1348C25.2018 41.3081 25.712 41.8073 25.994 42.043C26.8766 42.7798 27.5021 43.1421 28.5184 43.6533C25.1888 44.6816 22.494 46.9576 20.4198 49.7178C20.1465 50.0822 19.9759 50.3986 19.6708 50.7539L19.6093 50.8242C19.3237 51.0898 19.1644 51.66 18.7499 51.9531C18.4278 51.9673 18.1104 51.9103 17.8778 51.6797C14.6291 48.4648 16.6499 43.7235 20.4257 42.0674C21.7284 41.4963 22.1907 41.3268 23.6132 41.1611C24.0699 41.107 24.4952 41.1264 24.953 41.1348ZM50.412 21.7686C53.8394 21.7239 58.3896 22.4166 61.6933 23.4268C65.9905 24.9067 70.3972 27.0117 73.7499 30.1299C76.8457 33.0097 78.0987 34.494 74.744 37.8359C70.2383 42.3231 64.4548 44.3785 58.3495 45.5908C55.5323 46.1503 52.3726 46.1943 49.5321 46.1885C45.1317 46.1735 41.0227 45.7038 36.8075 44.4365C31.8682 42.951 25.0118 39.5832 23.1005 34.5C23.4202 32.8506 24.6728 31.4788 25.8983 30.3223C29.2819 27.1293 33.7394 24.8807 38.1278 23.4404C39.442 22.9808 40.9113 22.8445 42.2343 22.5049C45.0465 21.7828 47.5417 21.7667 50.412 21.7686ZM58.2714 36.7139C53.1801 33.6592 46.8197 33.6593 41.7284 36.7139C41.018 37.1401 40.7875 38.0621 41.2138 38.7725C41.6401 39.4825 42.5612 39.7122 43.2714 39.2861C47.4127 36.8014 52.5871 36.8013 56.7284 39.2861C57.4386 39.7122 58.3597 39.4825 58.786 38.7725C59.2122 38.0621 58.9817 37.1401 58.2714 36.7139ZM87.0839 0C92.2005 0.461954 97.6246 4.65656 99.1727 9.55762C99.4757 10.5174 100.012 12.7205 99.9999 13.7236C99.8876 22.8356 91.6694 29.0257 83.3222 30.3164C80.1773 30.8026 79.3214 31.1331 76.5575 29.6787C76.208 29.4223 75.9171 29.2185 75.747 28.8213C75.8109 28.4152 76.4329 28.1363 76.828 27.9307C78.3952 27.1126 79.3915 25.4821 80.5927 24.458C79.8025 23.6312 79.3988 22.8348 78.8427 21.8477C76.0729 16.926 76.379 9.33155 80.6288 5.25586C81.4663 7.83061 84.0478 12.8462 86.3554 14.2852C86.9364 14.1176 87.3281 12.3194 87.4335 11.7666C88.1696 7.90054 87.8807 3.83257 87.0839 0ZM12.5751 0.0224609C12.674 0.0188039 12.7036 0.0419007 12.8056 0.0742188C12.8109 0.105027 12.4873 2.15371 12.4237 2.41699C11.9339 4.44521 11.9777 13.3766 13.5809 14.2666C13.9333 14.0704 14.3942 13.5678 14.6747 13.2617C16.8563 10.8818 18.1966 8.25826 19.329 5.29004C20.1374 6.22699 21.0198 7.43298 21.5643 8.54297C24.0217 13.5521 22.9833 20.4614 19.1913 24.5205C20.1645 25.3207 20.9902 26.6263 22.1073 27.4258C22.6294 27.799 23.8926 28.3973 24.0468 28.7637C23.9779 29.0606 23.8152 29.1944 23.6112 29.4258C20.8948 31.2226 19.7045 30.7652 16.7216 30.3389C10.3594 29.4295 3.61264 25.3576 1.07411 19.2295C-2.55085 10.4783 3.42841 1.30598 12.5751 0.0224609ZM62.164 8.62793C65.1164 8.21829 67.8443 10.2775 68.2694 13.2363C68.6944 16.1954 66.6565 18.9439 63.7089 19.3867C60.7381 19.8328 57.9722 17.7685 57.5438 14.7861C57.1159 11.804 59.1885 9.04114 62.164 8.62793ZM36.1874 8.64844C39.1466 8.16434 41.9354 10.1844 42.4081 13.1543C42.8805 16.1242 40.8577 18.9139 37.8954 19.3779C34.9473 19.8393 32.1821 17.8218 31.7118 14.8662C31.2419 11.911 33.243 9.13068 36.1874 8.64844ZM37.0683 11.2412C35.6404 11.2416 34.4827 12.4037 34.4823 13.8359C34.4824 15.2683 35.6403 16.4303 37.0683 16.4307C38.4963 16.4305 39.655 15.2684 39.6552 13.8359C39.6548 12.4036 38.4962 11.2414 37.0683 11.2412ZM62.9306 11.2412C61.5023 11.2413 60.3447 12.4033 60.3446 13.8359C60.3448 15.2685 61.5024 16.4296 62.9306 16.4297C64.3588 16.4297 65.5164 15.2686 65.5165 13.8359C65.5165 12.4032 64.3589 11.2412 62.9306 11.2412Z" fill="white"/>
    </svg>
    <div style="font-size:var(--text-xl);font-weight:700;margin-bottom:var(--space-3);">Access Denied</div>
    <div style="font-size:var(--text-sm);color:var(--color-text-secondary);line-height:var(--leading-relaxed);margin-bottom:var(--space-10);">The authorization request for <strong>${dapp.name ? dapp.name.replace(/</g, '&lt;') : 'this app'}</strong> was denied.</div>
    ${retryUrl ? `<a href="${retryUrl.replace(/"/g, '&quot;')}" style="display:inline-flex;align-items:center;gap:var(--space-3);padding:var(--space-4) var(--space-10);background:var(--color-bg-elevated);border:1px solid var(--color-border);border-radius:var(--radius-pill);color:var(--color-text-secondary);font-size:var(--text-sm);font-weight:600;text-decoration:none;font-family:var(--font-sans);transition:color 0.15s;">Try again</a>` : ''}
    ${(!flowData.serverInitiated && retryUrl) ? `<a href="${retryUrl.replace(/"/g, '&quot;')}" style="display:inline-block;margin-top:var(--space-5);font-size:var(--text-xs);color:var(--color-text-muted);text-decoration:none;font-family:var(--font-sans);transition:color 0.15s;">Go back to ${dapp.name ? dapp.name.replace(/</g, '&lt;') : 'app'}</a>` : ''}
  </div>
</div>
</body></html>`);
});

// Step 4: Token endpoint — exchange authorization code for JWT access token
app.post('/oauth/token', express.urlencoded({ extended: false }), (req, res) => {
  const { grant_type, code, client_id, client_secret, code_verifier } = req.body;

  if (!OAUTH_SIGNING_KEY) return res.status(503).json({ error: 'OAuth not configured' });
  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'Only grant_type=authorization_code is supported' });
  }
  if (!code || !client_id || !client_secret || !code_verifier) {
    return res.status(400).json({ error: 'code, client_id, client_secret, and code_verifier are required' });
  }

  // Validate auth code
  const codeData = oauthAuthCodes.get(code);
  if (!codeData) {
    return res.status(400).json({ error: 'Invalid or expired authorization code' });
  }

  // Verify client
  if (codeData.clientId !== client_id) {
    return res.status(400).json({ error: 'client_id mismatch' });
  }

  const dapps = loadDapps();
  const dapp = dapps[client_id];
  if (!dapp || !dapp.active) {
    return res.status(400).json({ error: 'Unknown or inactive client' });
  }

  // Verify client secret (dual-secret: checks primary, then previous if within grace period)
  const secretMatch = verifyDappSecret(client_secret, dapp);
  if (!secretMatch) {
    return res.status(401).json({ error: 'Invalid client_secret' });
  }
  if (secretMatch === 'previous') {
    console.log(`OAuth token exchange using PREVIOUS secret for dApp ${dapp.name} (${client_id}) — grace period active`);
  }

  // Verify PKCE code_verifier
  const expectedChallenge = crypto.createHash('sha256').update(code_verifier).digest('base64url');
  if (expectedChallenge !== codeData.codeChallenge) {
    return res.status(400).json({ error: 'Invalid code_verifier (PKCE mismatch)' });
  }

  // Consume the code (single-use)
  oauthAuthCodes.delete(code);

  // Get agent data for the token
  const agents = loadAgents();
  const agent = agents[codeData.agentName];
  if (!agent) {
    return res.status(400).json({ error: 'Agent no longer exists' });
  }

  // Build JWT access token (issuer hardcoded to prevent header manipulation)
  const tokenPayload = {
    sub: codeData.agentName,
    aud: client_id,
    wallet: agent.wallet?.address || null,
    scopes: codeData.scopes,
    maxPerTradeMON: agent.tradingConfig?.maxPerTradeMON || '500',
    dailyCapMON: agent.tradingConfig?.dailyCapMON || '2500'
  };

  const accessToken = jwt.sign(tokenPayload, OAUTH_SIGNING_KEY, {
    issuer: 'https://tormund.io',
    expiresIn: '1h'
  });

  analytics.trackEvent('oauth_request', codeData.agentName, { clientId: client_id, endpoint: 'token', scopes: codeData.scopes });
  console.log(`OAuth token issued: ${codeData.agentName} → ${dapp.name} [${codeData.scopes.join(', ')}]`);

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: codeData.scopes.join(' ')
  });
});

// Revoke a dApp's access for an agent (agent authenticates with bearer token)
app.post('/oauth/revoke', authenticateByToken, (req, res) => {
  const name = req.agentName;
  const { client_id } = req.body;

  if (!client_id) return res.status(400).json({ error: 'client_id is required' });

  const agents = loadAgents();
  if (!agents[name].revokedDapps) agents[name].revokedDapps = [];
  if (!agents[name].revokedDapps.includes(client_id)) {
    agents[name].revokedDapps.push(client_id);
    saveAgents(agents);
  }

  console.log(`OAuth revoked: ${name} revoked ${client_id}`);
  res.json({ success: true, message: `Access for ${client_id} revoked` });
});

// ==================== OPERATOR PORTAL ====================

// Serve the Operator Portal page
app.get('/operator', (req, res) => {
  if (!X_CLIENT_ID || !SESSION_SECRET) return res.status(503).send('Not configured');
  res.sendFile(path.join(__dirname, 'public', 'operator-apps.html'));
});

// Operator: list connected apps across all owned agents
app.get('/operator/api/connected-apps', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyDevSession(cookies[DEV_COOKIE_NAME]);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });

  const agents = loadAgents();
  const dapps = loadDapps();
  const results = [];

  for (const [name, agent] of Object.entries(agents)) {
    if (!agent.owner || agent.owner.xId !== session.xId) continue;
    const connected = agent.connectedDapps || [];
    const revoked = agent.revokedDapps || [];

    for (const app of connected) {
      const dapp = dapps[app.clientId];
      results.push({
        agentName: name,
        agentAvatar: agent.avatarUrl || null,
        clientId: app.clientId,
        name: dapp?.name || app.name || app.clientId,
        description: dapp?.description || null,
        iconUrl: dapp?.iconUrl || null,
        scopes: app.scopes,
        approvedAt: app.approvedAt,
        revoked: revoked.includes(app.clientId)
      });
    }
  }

  res.json({ apps: results, username: session.un, avatar: session.av });
});

// Operator: revoke a dApp for an agent they own
app.post('/operator/api/revoke', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyDevSession(cookies[DEV_COOKIE_NAME]);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });

  const { agentName, clientId } = req.body;
  if (!agentName || !clientId) return res.status(400).json({ error: 'agentName and clientId required' });

  const agents = loadAgents();
  const agent = agents[agentName];
  if (!agent) return res.status(404).json({ error: 'Agent not found' });
  if (!agent.owner || agent.owner.xId !== session.xId) {
    return res.status(403).json({ error: 'Not the owner of this agent' });
  }

  if (!agent.revokedDapps) agent.revokedDapps = [];
  if (!agent.revokedDapps.includes(clientId)) {
    agent.revokedDapps.push(clientId);
  }
  saveAgents(agents);

  console.log(`Operator @${session.un} revoked ${clientId} for ${agentName}`);
  res.json({ success: true });
});

// Operator: list claimed agents
app.get('/operator/api/agents', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyDevSession(cookies[DEV_COOKIE_NAME]);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });

  const agents = loadAgents();
  const dapps = loadDapps();
  const results = [];

  for (const [name, agent] of Object.entries(agents)) {
    if (!agent.owner || agent.owner.xId !== session.xId) continue;
    const connected = agent.connectedDapps || [];
    const revoked = agent.revokedDapps || [];

    // Build full connected apps detail
    const apps = connected.map(app => {
      const dapp = dapps[app.clientId];
      return {
        clientId: app.clientId,
        name: dapp?.name || app.name || app.clientId,
        description: dapp?.description || null,
        iconUrl: dapp?.iconUrl || null,
        scopes: app.scopes,
        approvedAt: app.approvedAt,
        revoked: revoked.includes(app.clientId)
      };
    });

    results.push({
      name,
      description: agent.description || null,
      avatarUrl: agent.avatarUrl || null,
      wallet: agent.wallet?.address || null,
      status: agent.status || 'unknown',
      lastSeen: agent.lastSeen || null,
      registeredAt: agent.registeredAt || null,
      claimedAt: agent.owner.claimedAt || null,
      connectedApps: apps
    });
  }

  res.json({ agents: results, username: session.un, avatar: session.av });
});

// Userinfo endpoint — returns agent profile
app.get('/oauth/userinfo', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Bearer token required' });
  }

  try {
    const token = authHeader.slice(7);
    const decoded = jwt.verify(token, OAUTH_SIGNING_KEY);

    const agents = loadAgents();
    const agent = agents[decoded.sub];
    if (!agent) return res.status(404).json({ error: 'Agent not found' });

    // Check if dApp is revoked
    if (agent.revokedDapps?.includes(decoded.aud)) {
      return res.status(403).json({ error: 'Access revoked by agent' });
    }

    if (!decoded.scopes.includes('profile')) {
      return res.status(403).json({ error: 'profile scope not granted' });
    }

    analytics.trackEvent('oauth_request', decoded.sub, { clientId: decoded.aud, endpoint: 'userinfo' });

    res.json({
      sub: decoded.sub,
      name: decoded.sub,
      wallet: agent.wallet?.address || null,
      erc8004: agent.erc8004 || null,
      profile: agent.profile || null,
      registeredAt: agent.registeredAt || null
    });
  } catch (err) {
    if (err.name === 'TokenExpiredError') return res.status(401).json({ error: 'Token expired' });
    return res.status(401).json({ error: 'Invalid token' });
  }
});

// ==================== OAUTH: TRANSACTION PROXY (Phase 5) ====================
// dApps execute transactions through Clawnads, which enforces limits and signs via Privy.

// OAuth JWT authentication middleware
function authenticateOAuth(requiredScope) {
  return (req, res, next) => {
    if (!OAUTH_SIGNING_KEY) return res.status(503).json({ error: 'OAuth not configured' });

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Bearer token required' });
    }

    try {
      const token = authHeader.slice(7);
      const decoded = jwt.verify(token, OAUTH_SIGNING_KEY);

      // Check required scope
      if (requiredScope && !decoded.scopes.includes(requiredScope)) {
        return res.status(403).json({ error: `Scope '${requiredScope}' not granted`, grantedScopes: decoded.scopes });
      }

      // Check dApp not revoked
      const agents = loadAgents();
      const agent = agents[decoded.sub];
      if (!agent) return res.status(404).json({ error: 'Agent not found' });
      if (agent.revokedDapps?.includes(decoded.aud)) {
        return res.status(403).json({ error: 'Access revoked by agent' });
      }

      req.agent = agent;
      req.agentName = decoded.sub;
      req.oauthClient = decoded.aud;
      req.oauthScopes = decoded.scopes;
      next();
    } catch (err) {
      if (err.name === 'TokenExpiredError') return res.status(401).json({ error: 'Token expired' });
      return res.status(401).json({ error: 'Invalid token' });
    }
  };
}

// Proxy: Get balance
app.get('/oauth/proxy/balance', authenticateOAuth('balance'), async (req, res) => {
  const agent = req.agent;
  if (!agent.wallet) return res.status(404).json({ error: 'Agent has no wallet' });

  try {
    const walletAddress = agent.wallet.address;

    // Get MON balance
    const monBalanceResponse = await httpRequest(MONAD_RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'eth_getBalance',
        params: [walletAddress, 'latest'],
        id: 1
      })
    });

    const monBalanceWei = monBalanceResponse.result || '0x0';
    const monBalance = parseInt(monBalanceWei, 16) / 1e18;

    analytics.trackEvent('oauth_request', req.agentName, { clientId: req.oauthClient, endpoint: 'balance' });

    res.json({
      success: true,
      agent: req.agentName,
      address: walletAddress,
      network: MONAD_NETWORK_NAME,
      mon: {
        balance: monBalance.toFixed(6),
        hasGas: monBalance > 0.0001
      },
      via: 'oauth_proxy',
      client: req.oauthClient
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Proxy: Execute swap
app.post('/oauth/proxy/swap', authenticateOAuth('swap'), swapSendRateLimit, async (req, res) => {
  let { sellToken, buyToken, sellAmount } = req.body;
  const agentName = req.agentName;
  const agent = req.agent;

  if (!agent.wallet) return res.status(404).json({ error: 'Agent has no wallet' });
  if (!sellToken || !buyToken) return res.status(400).json({ error: 'sellToken and buyToken are required' });
  if (!sellAmount) return res.status(400).json({ error: 'sellAmount is required' });

  // Resolve symbols to addresses
  const resolvedSellToken = resolveTokenAddress(sellToken);
  const resolvedBuyToken = resolveTokenAddress(buyToken);
  if (!resolvedSellToken) return res.status(400).json({ error: `Unknown token: ${sellToken}`, knownTokens: Object.keys(MONAD_TOKENS) });
  if (!resolvedBuyToken) return res.status(400).json({ error: `Unknown token: ${buyToken}`, knownTokens: Object.keys(MONAD_TOKENS) });
  sellToken = resolvedSellToken;
  buyToken = resolvedBuyToken;

  // Check trading limits (shared daily cap with agent's own trades)
  let limitCheck;
  try {
    limitCheck = await checkTradingLimits(agentName, agent, sellToken, buyToken, sellAmount);
    if (!limitCheck.allowed) {
      return res.status(403).json({
        success: false,
        error: limitCheck.error,
        limitViolation: {
          limit: limitCheck.limit,
          tradeSizeMON: limitCheck.tradeSizeMON,
          maxPerTradeMON: limitCheck.maxPerTradeMON,
          usedTodayMON: limitCheck.usedTodayMON,
          dailyCapMON: limitCheck.dailyCapMON,
          remainingMON: limitCheck.remainingMON
        },
        via: 'oauth_proxy'
      });
    }
  } catch (limitErr) {
    return res.status(500).json({
      success: false,
      error: 'Trading limit check failed — trade blocked for safety.',
      via: 'oauth_proxy'
    });
  }

  try {
    const walletAddress = agent.wallet.address;
    const walletId = agent.wallet.id;
    const auth = Buffer.from(`${PRIVY_APP_ID}:${PRIVY_APP_SECRET}`).toString('base64');

    const isNativeSell = sellToken.toLowerCase() === '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
    const isNativeBuy = buyToken.toLowerCase() === '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
    const tokenInAddr = isNativeSell ? MONAD_TOKENS.WMON : sellToken;
    const tokenOutAddr = isNativeBuy ? MONAD_TOKENS.WMON : buyToken;

    // Get quote from Uniswap V3
    const { amountOut, fee } = await getUniswapQuote(tokenInAddr, tokenOutAddr, sellAmount);
    if (!amountOut) {
      return res.status(400).json({ success: false, error: 'No liquidity found for this pair', via: 'oauth_proxy' });
    }

    const tokenInMeta = await getTokenMetadata(tokenInAddr);
    const tokenOutMeta = await getTokenMetadata(tokenOutAddr);

    // Handle approvals
    const spenderAddress = UNISWAP_V3.SWAP_ROUTER_02;
    if (!isNativeSell) {
      const allowanceData = '0xdd62ed3e' +
        walletAddress.slice(2).padStart(64, '0') +
        spenderAddress.slice(2).padStart(64, '0');

      const allowanceResponse = await httpRequest(MONAD_RPC_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0', method: 'eth_call',
          params: [{ to: sellToken, data: allowanceData }, 'latest'], id: 1
        })
      });

      const currentAllowance = BigInt(allowanceResponse.result || '0x0');
      if (currentAllowance < BigInt(sellAmount)) {
        const maxApproval = '0x' + 'f'.repeat(64);
        const approveData = '0x095ea7b3' +
          spenderAddress.slice(2).padStart(64, '0') +
          maxApproval.slice(2);

        await httpRequest(`https://api.privy.io/v1/wallets/${walletId}/rpc`, {
          method: 'POST',
          headers: {
            'Authorization': `Basic ${auth}`,
            'privy-app-id': PRIVY_APP_ID,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            method: 'eth_sendTransaction',
            caip2: `eip155:${MONAD_CHAIN_ID}`,
            chain_type: 'ethereum',
            params: { transaction: { to: sellToken, data: approveData } }
          })
        });
        // Wait for approval to propagate
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }

    // Build swap transaction
    const slippageBps = 50; // 0.5% default
    const amountOutMin = (BigInt(amountOut) * BigInt(10000 - slippageBps) / BigInt(10000)).toString();

    // exactInputSingle
    const deadline = Math.floor(Date.now() / 1000) + 300;
    const recipient = walletAddress;

    const abiEncoded =
      '0x414bf389' +
      tokenInAddr.slice(2).padStart(64, '0') +
      tokenOutAddr.slice(2).padStart(64, '0') +
      fee.toString(16).padStart(64, '0') +
      recipient.slice(2).padStart(64, '0') +
      deadline.toString(16).padStart(64, '0') +
      BigInt(sellAmount).toString(16).padStart(64, '0') +
      BigInt(amountOutMin).toString(16).padStart(64, '0') +
      '0'.padStart(64, '0');

    const swapTx = {
      to: spenderAddress,
      data: abiEncoded
    };
    if (isNativeSell) swapTx.value = '0x' + BigInt(sellAmount).toString(16);

    const swapResp = await httpRequest(`https://api.privy.io/v1/wallets/${walletId}/rpc`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'privy-app-id': PRIVY_APP_ID,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        method: 'eth_sendTransaction',
        caip2: `eip155:${MONAD_CHAIN_ID}`,
        chain_type: 'ethereum',
        params: { transaction: swapTx }
      })
    });

    const txHash = swapResp.data?.hash;

    // Update daily volume
    const freshAgents = loadAgents();
    if (freshAgents[agentName]) {
      if (!freshAgents[agentName].tradingConfig) freshAgents[agentName].tradingConfig = {};
      const tc = freshAgents[agentName].tradingConfig;
      const today = new Date().toISOString().slice(0, 10);
      if (!tc.dailyVolume || tc.dailyVolume.date !== today) {
        tc.dailyVolume = { date: today, totalMON: '0', tradeCount: 0 };
      }
      tc.dailyVolume.totalMON = (parseFloat(tc.dailyVolume.totalMON) + (limitCheck.tradeSizeMON || 0)).toString();
      tc.dailyVolume.tradeCount++;

      // Track transaction
      if (!freshAgents[agentName].transactions) freshAgents[agentName].transactions = [];
      freshAgents[agentName].transactions.push({
        hash: txHash,
        type: 'swap',
        sellToken: tokenInMeta.symbol,
        buyToken: tokenOutMeta.symbol,
        sellAmount,
        buyAmount: amountOut,
        fee,
        timestamp: new Date().toISOString(),
        network: MONAD_NETWORK_NAME,
        chainId: MONAD_CHAIN_ID,
        via: 'oauth_proxy',
        oauthClient: req.oauthClient
      });
      saveAgents(freshAgents);
    }

    analytics.trackEvent('agent_trade', agentName, {
      type: 'swap',
      sellToken: tokenInMeta.symbol,
      buyToken: tokenOutMeta.symbol,
      via: 'oauth_proxy'
    });
    analytics.trackEvent('oauth_request', agentName, { clientId: req.oauthClient, endpoint: 'swap' });

    console.log(`OAuth proxy swap: ${agentName} swapped ${sellAmount} ${tokenInMeta.symbol} → ${tokenOutMeta.symbol} (via ${req.oauthClient})`);

    res.json({
      success: true,
      hash: txHash,
      explorer: `${MONAD_EXPLORER}/tx/${txHash}`,
      sellToken: tokenInMeta.symbol,
      buyToken: tokenOutMeta.symbol,
      sellAmount,
      expectedBuyAmount: amountOut,
      fee,
      via: 'oauth_proxy',
      client: req.oauthClient
    });
  } catch (err) {
    console.error(`OAuth proxy swap error (${agentName}):`, err.message);
    res.status(500).json({ success: false, error: err.message, via: 'oauth_proxy' });
  }
});

// Proxy: Send tokens
app.post('/oauth/proxy/send', authenticateOAuth('send'), swapSendRateLimit, async (req, res) => {
  const { to, value, data } = req.body;
  const agentName = req.agentName;
  const agent = req.agent;

  if (!agent.wallet) return res.status(404).json({ error: 'Agent has no wallet' });
  if (!to) return res.status(400).json({ error: 'to address is required' });

  // Check transfer limits (shared daily cap)
  const limitCheck = checkTransferLimits(agentName, agent, value || '0x0');
  if (!limitCheck.allowed) {
    return res.status(403).json({ success: false, error: limitCheck.error, limit: limitCheck.limit, via: 'oauth_proxy' });
  }

  // Withdrawal protection: external sends still require admin approval
  const agents = loadAgents();
  let actualRecipientAddr = to;
  if (data && data.startsWith('0xa9059cbb') && data.length >= 74) {
    actualRecipientAddr = '0x' + data.slice(34, 74);
  }
  const isAgentRecipient = Object.values(agents).some(a =>
    a.wallet?.address?.toLowerCase() === actualRecipientAddr.toLowerCase()
  );

  if (!isAgentRecipient) {
    if (!agents[agentName].pendingWithdrawals) agents[agentName].pendingWithdrawals = [];
    const withdrawalId = `wd_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const withdrawal = {
      id: withdrawalId,
      to,
      value: value || '0x0',
      data: data || null,
      valueMON: limitCheck.valueMON || 0,
      requestedAt: new Date().toISOString(),
      status: 'pending',
      via: 'oauth_proxy',
      oauthClient: req.oauthClient
    };
    agents[agentName].pendingWithdrawals.push(withdrawal);
    saveAgents(agents);

    analytics.trackEvent('oauth_request', agentName, { clientId: req.oauthClient, endpoint: 'send', queued: true });
    console.log(`OAuth proxy withdrawal queued: ${agentName} → ${actualRecipientAddr} (via ${req.oauthClient})`);

    queueNotification(agentName, {
      type: 'withdrawal_request',
      message: `dApp ${req.oauthClient} requested withdrawal of ${withdrawal.valueMON} MON for agent ${agentName} to ${actualRecipientAddr}. Approve via admin API.`,
      withdrawal
    });

    return res.status(202).json({
      success: true,
      status: 'pending_approval',
      withdrawalId,
      message: 'External withdrawal requires operator approval.',
      via: 'oauth_proxy'
    });
  }

  // Agent-to-agent: execute immediately
  try {
    const auth = Buffer.from(`${PRIVY_APP_ID}:${PRIVY_APP_SECRET}`).toString('base64');
    const walletId = agent.wallet.id;

    const transaction = { to, value: value || '0x0' };
    if (data) transaction.data = data;

    const response = await httpRequest(`https://api.privy.io/v1/wallets/${walletId}/rpc`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'privy-app-id': PRIVY_APP_ID,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        method: 'eth_sendTransaction',
        caip2: `eip155:${MONAD_CHAIN_ID}`,
        chain_type: 'ethereum',
        params: { transaction }
      })
    });

    const txHash = response.data?.hash;
    analytics.trackEvent('oauth_request', agentName, { clientId: req.oauthClient, endpoint: 'send' });
    console.log(`OAuth proxy send: ${agentName} → ${to} (via ${req.oauthClient}): ${txHash}`);

    res.json({
      success: true,
      hash: txHash,
      explorer: `${MONAD_EXPLORER}/tx/${txHash}`,
      via: 'oauth_proxy',
      client: req.oauthClient
    });
  } catch (err) {
    console.error(`OAuth proxy send error (${agentName}):`, err.message);
    res.status(500).json({ success: false, error: err.message, via: 'oauth_proxy' });
  }
});

// Proxy: Sign message
app.post('/oauth/proxy/sign', authenticateOAuth('sign'), async (req, res) => {
  const { message } = req.body;
  const agent = req.agent;

  if (!agent.wallet) return res.status(404).json({ error: 'Agent has no wallet' });
  if (!message) return res.status(400).json({ error: 'message is required' });

  try {
    const auth = Buffer.from(`${PRIVY_APP_ID}:${PRIVY_APP_SECRET}`).toString('base64');
    const walletId = agent.wallet.id;

    const response = await httpRequest(`https://api.privy.io/v1/wallets/${walletId}/rpc`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'privy-app-id': PRIVY_APP_ID,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        method: 'personal_sign',
        caip2: `eip155:${MONAD_CHAIN_ID}`,
        chain_type: 'ethereum',
        params: {
          message: message
        }
      })
    });

    analytics.trackEvent('oauth_request', req.agentName, { clientId: req.oauthClient, endpoint: 'sign' });
    console.log(`OAuth proxy sign: ${req.agentName} signed message (via ${req.oauthClient})`);

    res.json({
      success: true,
      signature: response.data?.signature || response.data,
      address: agent.wallet.address,
      via: 'oauth_proxy',
      client: req.oauthClient
    });
  } catch (err) {
    console.error(`OAuth proxy sign error (${req.agentName}):`, err.message);
    res.status(500).json({ success: false, error: err.message, via: 'oauth_proxy' });
  }
});

// Proxy: Get profile
app.get('/oauth/proxy/profile', authenticateOAuth('profile'), (req, res) => {
  const agent = req.agent;

  analytics.trackEvent('oauth_request', req.agentName, { clientId: req.oauthClient, endpoint: 'profile' });

  res.json({
    success: true,
    name: req.agentName,
    wallet: agent.wallet?.address || null,
    profile: agent.profile || null,
    erc8004: agent.erc8004 || null,
    registeredAt: agent.registeredAt || null,
    via: 'oauth_proxy',
    client: req.oauthClient
  });
});

// Test callback — displays auth code for manual testing of the OAuth flow
app.get('/oauth/test-callback', (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.send(`<html><body style="background:#09090b;color:#fafafa;font-family:Inter,sans-serif;padding:40px;text-align:center;">
      <h2 style="color:#ef4444;">Access Denied</h2>
      <p style="color:#a1a1aa;">The operator denied the request.</p>
      <p style="color:#71717a;">error: ${error}</p>
    </body></html>`);
  }

  res.send(`<html><body style="background:#09090b;color:#fafafa;font-family:Inter,sans-serif;padding:40px;text-align:center;">
    <h2 style="color:#22c55e;">Authorization Successful</h2>
    <p style="color:#a1a1aa;">The operator approved access. Use this authorization code to get an access token.</p>
    <div style="background:#18181b;border:1px solid #27272a;border-radius:8px;padding:16px;margin:20px auto;max-width:600px;word-break:break-all;">
      <div style="color:#71717a;font-size:12px;margin-bottom:8px;">Authorization Code</div>
      <code style="color:#7c5cff;font-size:14px;">${code || 'none'}</code>
    </div>
    ${state ? `<p style="color:#71717a;font-size:12px;">state: ${state}</p>` : ''}
    <p style="color:#71717a;font-size:12px;margin-top:20px;">Next: POST /oauth/token with this code + your client credentials + code_verifier</p>
  </body></html>`);
});

// ==================== TOKEN ROTATION ====================

// Admin: rotate an agent's auth token
app.post('/admin/agents/:name/rotate-token', authenticateAdmin, (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  const newToken = generateAuthToken();
  const newHash = hashToken(newToken);

  agents[name].tokenHash = newHash;
  agents[name].tokenRotatedAt = new Date().toISOString();
  saveAgents(agents);

  console.log(`Token rotated for ${name} by admin`);

  res.json({
    success: true,
    agent: name,
    authToken: newToken,
    message: 'Token rotated. Store the new token securely and update the agent environment.'
  });
});

// Self-service: agent rotates their own token
app.post('/agents/:name/rotate-token', authenticateAgent, (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  const newToken = generateAuthToken();
  const newHash = hashToken(newToken);

  agents[name].tokenHash = newHash;
  agents[name].tokenRotatedAt = new Date().toISOString();
  saveAgents(agents);

  console.log(`Token self-rotated by ${name}`);

  res.json({
    success: true,
    authToken: newToken,
    message: 'Token rotated. Your old token is now invalid. Store this new token securely.'
  });
});

// Current skill version - read dynamically from SKILL.md frontmatter
const SKILL_MD_PATH = path.join(__dirname, 'SKILL.md');
let SKILL_VERSION = '2.5'; // Default, will be updated from file
let lastSkillContent = '';

// Parse version from SKILL.md frontmatter
function parseSkillVersion(content) {
  const match = content.match(/^---[\s\S]*?version:\s*["']?([^"'\n]+)["']?[\s\S]*?---/m);
  return match ? match[1].trim() : null;
}

// Parse changelog from SKILL.md frontmatter
function parseSkillChangelog(content) {
  const frontmatterMatch = content.match(/^---\n([\s\S]*?)\n---/m);
  if (!frontmatterMatch) return [];

  const frontmatter = frontmatterMatch[1];
  const changelogMatch = frontmatter.match(/changelog:\n((?:\s+-\s+.+\n?)+)/);
  if (!changelogMatch) return [];

  const changes = changelogMatch[1]
    .split('\n')
    .filter(line => line.trim().startsWith('-'))
    .map(line => line.replace(/^\s*-\s*/, '').trim())
    .filter(Boolean);

  return changes;
}

// Read current skill version from file
function updateSkillVersion() {
  try {
    const content = fs.readFileSync(SKILL_MD_PATH, 'utf8');
    const version = parseSkillVersion(content);
    if (version) {
      SKILL_VERSION = version;
    }
    return content;
  } catch (err) {
    console.error('Error reading SKILL.md:', err.message);
    return null;
  }
}

// Initialize skill version on startup
lastSkillContent = updateSkillVersion() || '';

// Helper to check if agent needs skill update
function checkSkillUpdate(agent) {
  if (!agent.skillVersion || agent.skillVersion !== SKILL_VERSION) {
    return {
      update_available: true,
      message: `Skill docs updated to v${SKILL_VERSION}. Please ask your human for permission to re-read /SKILL.md`,
      your_version: agent.skillVersion || 'unknown',
      current_version: SKILL_VERSION
    };
  }
  return null;
}

// ==================== ANALYTICS DASHBOARD ====================

// Serve analytics page (admin-only)
app.get('/analytics', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
  if (!session) return res.redirect('/admin');
  res.sendFile(path.join(__dirname, 'public', 'analytics.html'));
});

// Analytics API: summary cards (accepts ?days= for period-relative comparison)
app.get('/admin/api/analytics/summary', requireAdminSession, (req, res) => {
  if (!req.adminSession) return res.status(401).json({ error: 'Not authenticated' });
  const days = req.query.days ? (req.query.days === 'all' ? 3650 : parseInt(req.query.days)) : null;
  const summary = days ? analytics.getSummaryForPeriod(days) : analytics.getSummary();
  if (!summary) return res.status(500).json({ error: 'Analytics not initialized' });
  res.json(summary);
});

// Analytics API: timeseries for charts (supports ?granularity=hourly for 24h view)
app.get('/admin/api/analytics/timeseries', requireAdminSession, (req, res) => {
  if (!req.adminSession) return res.status(401).json({ error: 'Not authenticated' });
  const { metric, days, granularity } = req.query;
  if (!metric) return res.status(400).json({ error: 'metric param required' });
  if (granularity === 'hourly') {
    const hours = parseInt(days) === 1 ? 24 : (parseInt(days) || 1) * 24;
    const data = analytics.getHourlyMetrics(metric, hours);
    res.json({ metric, data, granularity: 'hourly' });
  } else {
    const data = analytics.getDailyMetrics(metric, parseInt(days) || 30);
    res.json({ metric, data });
  }
});

// Analytics API: top pages
app.get('/admin/api/analytics/top-pages', requireAdminSession, (req, res) => {
  if (!req.adminSession) return res.status(401).json({ error: 'Not authenticated' });
  const days = parseInt(req.query.days) || 7;
  const pages = analytics.getTopPages(days);
  res.json(pages);
});

// Analytics API: treasury USDC balance (revenue)
app.get('/admin/api/analytics/treasury', requireAdminSession, async (req, res) => {
  if (!req.adminSession) return res.status(401).json({ error: 'Not authenticated' });
  if (!X402_TREASURY_ADDRESS) return res.json({ balance: '0', formatted: '0.00' });
  try {
    const balance = await getTokenBalance(X402_TREASURY_ADDRESS, X402_USDC_ADDRESS);
    const formatted = (Number(balance) / 1e6).toFixed(6);
    res.json({ balance, formatted, address: X402_TREASURY_ADDRESS });
  } catch (e) {
    res.json({ balance: '0', formatted: '0.00', error: e.message });
  }
});

// Public API: treasury USDC balance (for footer revenue display)
app.get('/api/treasury', async (req, res) => {
  if (!X402_TREASURY_ADDRESS) return res.json({ balance: '0', formatted: '0.00' });
  try {
    const balance = await getTokenBalance(X402_TREASURY_ADDRESS, X402_USDC_ADDRESS);
    const formatted = (Number(balance) / 1e6).toFixed(6);
    res.json({ balance, formatted });
  } catch (e) {
    res.json({ balance: '0', formatted: '0.00' });
  }
});

// Analytics API: backfill from existing agents.json data (one-time)
app.post('/admin/api/analytics/backfill', requireAdminSession, (req, res) => {
  if (!req.adminSession) return res.status(401).json({ error: 'Not authenticated' });
  const agents = loadAgents();
  const result = analytics.backfillFromAgents(agents);
  res.json(result);
});

// ==================== CLIENT-SIDE ANALYTICS BEACON ====================
// Public endpoint for human engagement tracking (session duration, tab switches, drawer opens)

// Handle text/plain Content-Type from navigator.sendBeacon
app.use('/analytics/event', (req, res, next) => {
  const ct = req.headers['content-type'] || '';
  if (ct.startsWith('text/plain')) {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try { req.body = JSON.parse(body); } catch { req.body = {}; }
      next();
    });
  } else {
    next();
  }
});

app.post('/analytics/event', (req, res) => {
  const { type, data } = req.body || {};
  if (!type || typeof type !== 'string') return res.status(400).json({ error: 'type required' });

  // Allowlist of client event types
  const ALLOWED_TYPES = ['session_heartbeat', 'session_end', 'tab_switch', 'drawer_open', 'drawer_tab_switch', 'page_enter', 'landing_cta', 'landing_hover'];
  if (!ALLOWED_TYPES.includes(type)) return res.status(400).json({ error: 'unknown event type' });

  // Sanitize data — only allow specific known keys, all short strings
  const safe = {};
  if (data && typeof data === 'object') {
    const ALLOWED_KEYS = ['sessionId', 'tab', 'agentName', 'drawerTab', 'page', 'durationSec', 'pageCount', 'path', 'card'];
    for (const key of ALLOWED_KEYS) {
      if (data[key] !== undefined) {
        safe[key] = String(data[key]).slice(0, 100);
      }
    }
  }

  // Add IP hash for unique visitor correlation
  safe.ipHash = analytics.hashIP(req.ip || req.connection?.remoteAddress);

  analytics.trackEvent(type, null, safe);
  res.json({ ok: true });
});

// Serve 3D Trading Floor Sim (admin-only — dev tool with drag-and-drop editing)
app.get('/sim', (req, res) => {
  // compact mode (embedded viewport) doesn't need admin auth
  if (req.query.compact !== '1') {
    const cookies = parseCookies(req);
    const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
    if (!session) return res.redirect('/admin');
  }
  res.sendFile(path.join(__dirname, 'public', 'sim.html'));
});

// Sim status — what Claude Code is currently working on
// zone: trading-pit | signals-desk | skills-desk | open-center
// type: trading | signaling | reading | talking (animation type)
// activity: emoji + short description for bubble text
let simStatus = { zone: 'open-center', type: 'talking', activity: '🔧 building lobster character' };

app.get('/sim/status', (req, res) => {
  res.json(simStatus);
});

app.put('/sim/status', (req, res) => {
  // Admin-only: update what Claude Code is doing
  if (req.headers['x-admin-secret'] !== ADMIN_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const { zone, type, activity } = req.body;
  if (zone) simStatus.zone = zone;
  if (type) simStatus.type = type;
  if (activity) simStatus.activity = activity;
  res.json(simStatus);
});

// Sim layout persistence — draggable group positions saved to data/sim-layout.json
const SIM_LAYOUT_FILE = path.join(__dirname, 'data', 'sim-layout.json');

function loadSimLayout() {
  try {
    if (fs.existsSync(SIM_LAYOUT_FILE)) return JSON.parse(fs.readFileSync(SIM_LAYOUT_FILE, 'utf8'));
  } catch (e) { console.error('Failed to load sim layout:', e.message); }
  return {};
}

function saveSimLayout(layout) {
  fs.writeFileSync(SIM_LAYOUT_FILE, JSON.stringify(layout, null, 2));
}

// GET /sim/layout — public (sim page fetches on load)
app.get('/sim/layout', (req, res) => {
  res.json(loadSimLayout());
});

// PUT /sim/layout — admin-only (save dragged positions)
// Body: { orientation: "landscape"|"portrait", positions: { name: { x, z } } }
app.put('/sim/layout', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
  if (!session && req.headers['x-admin-secret'] !== ADMIN_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const { positions, orientation } = req.body;
  if (!positions || typeof positions !== 'object') {
    return res.status(400).json({ error: 'positions object required' });
  }
  const orient = orientation === 'portrait' ? 'portrait' : 'landscape';
  const current = loadSimLayout();
  if (!current[orient]) current[orient] = {};
  for (const [name, pos] of Object.entries(positions)) {
    current[orient][name] = { x: pos.x, z: pos.z };
  }
  saveSimLayout(current);
  res.json({ success: true, layout: current });
});

// Serve Character Viewer (admin-only — dev tool with Sprite Lab)
app.get('/character', (req, res) => {
  const cookies = parseCookies(req);
  const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
  if (!session) return res.redirect('/admin');
  res.sendFile(path.join(__dirname, 'public', 'character', 'index.html'));
});

// Serve SKILL.md (with integrity hash in response header)
app.get('/SKILL.md', (req, res) => {
  const skillPath = path.join(__dirname, 'SKILL.md');
  if (fs.existsSync(skillPath)) {
    const content = fs.readFileSync(skillPath, 'utf8');
    const integrityHash = crypto.createHmac('sha256', SESSION_SECRET || 'clawnads-skill-key')
      .update(content).digest('hex');
    res.setHeader('X-Skill-Integrity', integrityHash);
    res.type('text/markdown').send(content);
  } else {
    res.status(404).send('Skill file not found');
  }
});

// Serve AGENT-SETUP.md
app.get('/AGENT-SETUP.md', (req, res) => {
  const setupPath = path.join(__dirname, 'AGENT-SETUP.md');
  if (fs.existsSync(setupPath)) {
    res.type('text/markdown').sendFile(setupPath);
  } else {
    res.status(404).send('Setup guide not found');
  }
});

// Get skill version (for bots to check if they need to re-read)
// Includes integrity hash so agents can verify SKILL.md hasn't been tampered with
app.get('/skill/version', (req, res) => {
  let integrity = null;
  try {
    const content = fs.readFileSync(SKILL_MD_PATH, 'utf8');
    integrity = crypto.createHmac('sha256', SESSION_SECRET || 'clawnads-skill-key')
      .update(content).digest('hex');
  } catch (e) { /* file missing */ }

  res.json({
    version: SKILL_VERSION,
    integrity,
    message: `Current skill version is ${SKILL_VERSION}. If your cached version is older, re-read /SKILL.md`
  });
});


// ==================== ERC-8004 IDENTITY ====================

// Serve .well-known/agent-registration.json for domain verification
// Uses the first registered agent with erc8004 data (single-agent setup)
// or a specific agent via ?agent=name query param
app.get('/.well-known/agent-registration.json', (req, res) => {
  const agents = loadAgents();
  const requestedAgent = req.query.agent;

  let agentName, agent;
  if (requestedAgent && agents[requestedAgent]) {
    agentName = requestedAgent;
    agent = agents[requestedAgent];
  } else {
    // Find first agent with erc8004 data
    const entry = Object.entries(agents).find(([_, a]) => a.erc8004);
    if (!entry) {
      return res.status(404).json({ error: 'No agents with ERC-8004 identity registered' });
    }
    [agentName, agent] = entry;
  }

  if (!agent.erc8004) {
    return res.status(404).json({ error: `Agent ${agentName} has no ERC-8004 identity` });
  }

  const erc = agent.erc8004;
  const registration = {
    type: 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1',
    name: agentName,
    description: erc.description || `${agentName} — autonomous agent on Monad`,
    image: erc.image || agent.avatarUrl || null,
    services: erc.services || [],
    registrations: erc.agentId ? [{
      agentId: erc.agentId,
      agentRegistry: erc.agentRegistry || `eip155:${MONAD_CHAIN_ID}:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`
    }] : [],
    supportedTrust: erc.supportedTrust || ['reputation'],
    active: !agent.disconnected,
    x402Support: erc.x402Support || false
  };

  // Prevent indexers from caching stale metadata
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.json(registration);
});

// Admin: Set character skin/variant for an agent (used by /sim 3D rendering)
// Auth: admin session cookie (from X login) OR x-admin-secret header
app.put('/admin/agents/:name/skin', (req, res, next) => {
  const cookies = parseCookies(req);
  const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
  if (session) { req.adminSession = session; return next(); }
  return authenticateAdmin(req, res, next);
}, (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  const { skin } = req.body;
  const VALID_SKINS = ['red', 'blue', 'gold'];
  if (!skin || !VALID_SKINS.includes(skin)) {
    return res.status(400).json({ success: false, error: `skin must be one of: ${VALID_SKINS.join(', ')}` });
  }

  agents[name].characterSkin = skin;
  saveAgents(agents);
  console.log(`Character skin set for ${name}: ${skin}`);
  res.json({ success: true, characterSkin: skin });
});

// ==================== NFT CONTRACT DEPLOYMENT ====================

// Load pre-compiled ClawSkinNFT contract
const NFT_CONTRACT_PATH = path.join(__dirname, 'public', 'contracts', 'ClawSkinNFT.json');
let NFT_CONTRACT_ABI = [];
let NFT_CONTRACT_BYTECODE = '';
try {
  const nftJson = JSON.parse(fs.readFileSync(NFT_CONTRACT_PATH, 'utf8'));
  NFT_CONTRACT_ABI = nftJson.abi;
  NFT_CONTRACT_BYTECODE = nftJson.bytecode;
  console.log(`Loaded ClawSkinNFT contract: ${NFT_CONTRACT_ABI.length} ABI entries, ${NFT_CONTRACT_BYTECODE.length} bytes bytecode`);
} catch (err) {
  console.warn('ClawSkinNFT contract not found — NFT deployment disabled:', err.message);
}

// Ensure a Privy deployer wallet exists for NFT contract deployment
async function ensureDeployerWallet() {
  const store = loadStore();
  if (store.deployerWallet?.id) return store.deployerWallet;

  console.log('Creating Privy deployer wallet for NFT contracts...');
  const wallet = await createPrivyWallet('claw-deployer');
  store.deployerWallet = { id: wallet.id, address: wallet.address, createdAt: new Date().toISOString() };
  saveStore(store);
  console.log(`Created deployer wallet: ${wallet.address} (id: ${wallet.id})`);
  return store.deployerWallet;
}

// Deploy an NFT contract for a MON-priced skin
async function deployNFTContract(skinId, skinName, skinSymbol, maxSupply, mintPriceWei, transferable = true) {
  if (!NFT_CONTRACT_BYTECODE) {
    throw new Error('NFT contract bytecode not loaded — check public/contracts/ClawSkinNFT.json');
  }
  if (!X402_TREASURY_ADDRESS) {
    throw new Error('X402_TREASURY_ADDRESS not configured — needed as contract treasury');
  }

  const deployer = await ensureDeployerWallet();
  const auth = Buffer.from(`${PRIVY_APP_ID}:${PRIVY_APP_SECRET}`).toString('base64');

  // Base URI for token metadata — points to our metadata endpoint
  const baseURI = `https://claw.tormund.io/api/nft/${encodeURIComponent(skinId)}/`;

  // ABI-encode constructor args: (string name_, string symbol_, uint256 maxSupply_, uint256 mintPrice_, address treasury_, string baseURI_, bool transferable_)
  const abiCoder = new ethers.utils.AbiCoder();
  const encodedArgs = abiCoder.encode(
    ['string', 'string', 'uint256', 'uint256', 'address', 'string', 'bool'],
    [skinName, skinSymbol, maxSupply, mintPriceWei, X402_TREASURY_ADDRESS, baseURI, !!transferable]
  );

  // Deployment data = bytecode + constructor args (strip 0x from args)
  const deployData = NFT_CONTRACT_BYTECODE + encodedArgs.slice(2);

  console.log(`Deploying NFT contract: ${skinName} (${skinSymbol}), supply=${maxSupply}, price=${mintPriceWei} wei`);
  console.log(`Deployer: ${deployer.address}, Treasury: ${X402_TREASURY_ADDRESS}`);

  // Send deploy transaction via Privy
  const txResponse = await httpRequest(`https://api.privy.io/v1/wallets/${deployer.id}/rpc`, {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${auth}`,
      'privy-app-id': PRIVY_APP_ID,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      method: 'eth_sendTransaction',
      caip2: `eip155:${MONAD_CHAIN_ID}`,
      chain_type: 'ethereum',
      params: {
        transaction: {
          data: deployData
          // No 'to' field = contract creation
        }
      }
    })
  });

  const txHash = txResponse.data?.hash;
  if (!txHash) {
    throw new Error('No transaction hash returned from Privy: ' + JSON.stringify(txResponse));
  }

  console.log(`NFT deploy tx sent: ${txHash}`);

  // Poll for receipt to get contract address
  let receipt = null;
  for (let attempt = 0; attempt < 30; attempt++) {
    await new Promise(ok => setTimeout(ok, 2000));
    const receiptResponse = await httpRequest(MONAD_RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'eth_getTransactionReceipt',
        params: [txHash],
        id: 1
      })
    });
    if (receiptResponse.result) {
      receipt = receiptResponse.result;
      break;
    }
  }

  if (!receipt) {
    throw new Error(`Deploy tx ${txHash} not confirmed after 60s`);
  }
  if (receipt.status === '0x0') {
    throw new Error(`Deploy tx ${txHash} reverted`);
  }

  const contractAddress = receipt.contractAddress;
  if (!contractAddress) {
    throw new Error(`Deploy tx ${txHash} confirmed but no contractAddress in receipt`);
  }

  console.log(`NFT contract deployed: ${contractAddress} (tx: ${txHash})`);
  return { contractAddress, txHash };
}

// Call an onlyOwner function on a deployed NFT contract (from deployer wallet)
async function callNFTContract(contractAddress, functionSig, encodedParams) {
  const deployer = await ensureDeployerWallet();
  const auth = Buffer.from(`${PRIVY_APP_ID}:${PRIVY_APP_SECRET}`).toString('base64');

  const selector = ethers.utils.id(functionSig).slice(0, 10);
  const calldata = encodedParams ? selector + encodedParams.slice(2) : selector;

  const txResponse = await httpRequest(`https://api.privy.io/v1/wallets/${deployer.id}/rpc`, {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${auth}`,
      'privy-app-id': PRIVY_APP_ID,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      method: 'eth_sendTransaction',
      caip2: `eip155:${MONAD_CHAIN_ID}`,
      chain_type: 'ethereum',
      params: {
        transaction: {
          to: contractAddress,
          value: '0x0',
          data: calldata
        }
      }
    })
  });

  const txHash = txResponse.data?.hash;
  if (!txHash) {
    throw new Error('No tx hash from Privy: ' + JSON.stringify(txResponse));
  }

  // Poll for receipt
  for (let attempt = 0; attempt < 20; attempt++) {
    await new Promise(ok => setTimeout(ok, 2000));
    const receiptResponse = await httpRequest(MONAD_RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'eth_getTransactionReceipt', params: [txHash], id: 1 })
    });
    if (receiptResponse.result) {
      if (receiptResponse.result.status === '0x0') throw new Error(`Contract call reverted: ${txHash}`);
      return { txHash, receipt: receiptResponse.result };
    }
  }
  throw new Error(`Contract call tx ${txHash} not confirmed after 40s`);
}

// Read a view function from an NFT contract via eth_call
async function readNFTContract(contractAddress, functionSig) {
  const selector = ethers.utils.id(functionSig).slice(0, 10);
  const response = await httpRequest(MONAD_RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      method: 'eth_call',
      params: [{ to: contractAddress, data: selector }, 'latest'],
      id: 1
    })
  });
  return response.result;
}

// ==================== STORE MANAGEMENT (ADMIN) ====================

// Admin: Get full store catalog (including hidden skins)
app.get('/admin/api/store/skins', (req, res, next) => {
  const cookies = parseCookies(req);
  const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
  if (session) { req.adminSession = session; return next(); }
  return authenticateAdmin(req, res, next);
}, (req, res) => {
  const store = loadStore();
  res.json({ success: true, skins: store.skins });
});

// Admin: Update a skin in the catalog
app.put('/admin/api/store/skins/:id', (req, res, next) => {
  const cookies = parseCookies(req);
  const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
  if (session) { req.adminSession = session; return next(); }
  return authenticateAdmin(req, res, next);
}, async (req, res) => {
  const { id } = req.params;
  const store = loadStore();

  if (!store.skins[id]) {
    return res.status(404).json({ success: false, error: 'Skin not found' });
  }

  const { name, price, currency, priceDisplay, description, visible, variant, supply, requiresVerification, product, type, featured, onSale, imageUrl, glbUrl, transferable } = req.body;
  const skin = store.skins[id];

  // Don't allow editing free skin pricing
  if (skin.free && (price !== undefined || currency !== undefined)) {
    return res.status(400).json({ success: false, error: 'Cannot change pricing on free skins' });
  }

  // Track if price/supply changed for contract sync
  const priceChanged = price !== undefined && String(price) !== skin.price;
  const supplyChanged = supply !== undefined && Number(supply) !== skin.supply;

  if (name !== undefined) skin.name = name;
  if (price !== undefined) skin.price = String(price);
  if (currency !== undefined) {
    if (!['USDC', 'MON'].includes(currency)) {
      return res.status(400).json({ success: false, error: 'currency must be USDC or MON' });
    }
    skin.currency = currency;
  }
  if (priceDisplay !== undefined) skin.priceDisplay = priceDisplay;
  if (description !== undefined) skin.description = description;
  if (visible !== undefined) skin.visible = !!visible;
  if (variant !== undefined) skin.variant = variant;
  if (supply !== undefined) skin.supply = Number(supply);
  if (requiresVerification !== undefined) skin.requiresVerification = !!requiresVerification;
  if (product !== undefined) skin.product = product || null;
  if (type !== undefined) skin.type = type;
  if (featured !== undefined) skin.featured = !!featured;
  if (onSale !== undefined) skin.onSale = !!onSale;
  if (imageUrl !== undefined) skin.imageUrl = imageUrl || null;
  if (glbUrl !== undefined) skin.glbUrl = glbUrl || null;
  if (transferable !== undefined) {
    // Lock transferable after any NFTs have been minted
    if (skin.sold > 0 && !!transferable !== skin.transferable) {
      return res.status(400).json({ success: false, error: 'Cannot change transferability after NFTs have been minted' });
    }
    skin.transferable = !!transferable;
  }

  saveStore(store);

  // Sync price/supply changes to NFT contract if deployed
  const contractSyncErrors = [];
  if (skin.contractAddress && skin.deployStatus === 'deployed') {
    const abiCoder = new ethers.utils.AbiCoder();
    if (priceChanged) {
      try {
        const params = abiCoder.encode(['uint256'], [String(skin.price)]);
        await callNFTContract(skin.contractAddress, 'setMintPrice(uint256)', params);
        console.log(`Synced price to contract ${skin.contractAddress}: ${skin.price} wei`);
      } catch (err) {
        contractSyncErrors.push(`Price sync failed: ${err.message}`);
        console.error(`Contract price sync failed for ${id}:`, err.message);
      }
    }
    if (supplyChanged && skin.supply !== -1) {
      try {
        const params = abiCoder.encode(['uint256'], [skin.supply]);
        await callNFTContract(skin.contractAddress, 'setMaxSupply(uint256)', params);
        console.log(`Synced supply to contract ${skin.contractAddress}: ${skin.supply}`);
      } catch (err) {
        contractSyncErrors.push(`Supply sync failed: ${err.message}`);
        console.error(`Contract supply sync failed for ${id}:`, err.message);
      }
    }
  }

  console.log(`Store skin updated: ${id}`, skin);
  const response = { success: true, skin };
  if (contractSyncErrors.length > 0) response.contractSyncErrors = contractSyncErrors;
  res.json(response);
});

// Admin: Add a new skin to the catalog
app.post('/admin/api/store/skins', (req, res, next) => {
  const cookies = parseCookies(req);
  const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
  if (session) { req.adminSession = session; return next(); }
  return authenticateAdmin(req, res, next);
}, async (req, res) => {
  const { id, name, price, currency, priceDisplay, variant, description, visible, free, type, product } = req.body;

  if (!id || !name || !variant) {
    return res.status(400).json({ success: false, error: 'id, name, and variant are required' });
  }

  if (!/^[a-z0-9_:\-]+$/.test(id)) {
    return res.status(400).json({ success: false, error: 'id must be lowercase alphanumeric with hyphens, underscores, or colons' });
  }

  const store = loadStore();
  if (store.skins[id]) {
    return res.status(409).json({ success: false, error: 'Skin with this id already exists' });
  }

  const validCurrency = currency || 'USDC';
  if (!['USDC', 'MON'].includes(validCurrency)) {
    return res.status(400).json({ success: false, error: 'currency must be USDC or MON' });
  }

  const { supply, requiresVerification, featured, onSale, transferable } = req.body;

  store.skins[id] = {
    id,
    name,
    price: String(price || '0'),
    currency: validCurrency,
    priceDisplay: priceDisplay || (free ? 'FREE' : `${price || '0'} ${validCurrency}`),
    variant,
    description: description || '',
    visible: !!visible,
    free: !!free,
    featured: !!featured,
    onSale: onSale !== undefined ? !!onSale : !!visible,
    supply: supply !== undefined ? Number(supply) : -1,
    sold: 0,
    requiresVerification: !!requiresVerification,
    transferable: transferable !== undefined ? !!transferable : true,
    type: type || 'skin',
    product: product || '',
    createdAt: new Date().toISOString()
  };

  // Auto-deploy NFT contract for MON-priced skins
  if (validCurrency === 'MON' && !free && price && String(price) !== '0') {
    store.skins[id].deployStatus = 'pending';
    saveStore(store);

    try {
      const skinSymbol = 'CLAW-' + variant.toUpperCase();
      const skinSupply = store.skins[id].supply === -1 ? 10000 : store.skins[id].supply;
      const skinTransferable = store.skins[id].transferable !== false;
      const { contractAddress, txHash } = await deployNFTContract(id, name, skinSymbol, skinSupply, String(price), skinTransferable);

      // Re-read store in case it changed during deploy
      const freshStore = loadStore();
      if (freshStore.skins[id]) {
        freshStore.skins[id].contractAddress = contractAddress;
        freshStore.skins[id].deployTxHash = txHash;
        freshStore.skins[id].deployStatus = 'deployed';
        freshStore.skins[id].contractPaused = false;
        saveStore(freshStore);
        console.log(`NFT contract auto-deployed for ${id}: ${contractAddress}`);
        return res.json({ success: true, skin: freshStore.skins[id] });
      }
    } catch (err) {
      console.error(`NFT deploy failed for ${id}:`, err.message);
      const freshStore = loadStore();
      if (freshStore.skins[id]) {
        freshStore.skins[id].deployStatus = 'failed';
        freshStore.skins[id].deployError = err.message;
        saveStore(freshStore);
      }
      // Still return success — skin is created, deploy can be retried
      return res.json({ success: true, skin: freshStore.skins[id], deployError: err.message });
    }
  }

  saveStore(store);
  console.log(`Store skin added: ${id}`, store.skins[id]);
  res.json({ success: true, skin: store.skins[id] });
});

// Admin: Remove a skin from the catalog (only if no purchases exist)
app.delete('/admin/api/store/skins/:id', (req, res, next) => {
  const cookies = parseCookies(req);
  const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
  if (session) { req.adminSession = session; return next(); }
  return authenticateAdmin(req, res, next);
}, (req, res) => {
  const { id } = req.params;
  const store = loadStore();

  if (!store.skins[id]) {
    return res.status(404).json({ success: false, error: 'Skin not found' });
  }

  // Can't remove free/default skins
  if (store.skins[id].free) {
    return res.status(400).json({ success: false, error: 'Cannot remove free default skins' });
  }

  // Check if any agent has purchased this skin
  const agents = loadAgents();
  const hasPurchases = Object.values(agents).some(agent =>
    (agent.skinPurchases || []).some(p => p.skinId === id)
  );
  if (hasPurchases) {
    return res.status(400).json({ success: false, error: 'Cannot remove skin with existing purchases' });
  }

  delete store.skins[id];
  saveStore(store);
  console.log(`Store skin removed: ${id}`);
  res.json({ success: true });
});

// Admin: Get order history for a specific skin
app.get('/admin/api/store/skins/:id/orders', (req, res, next) => {
  const cookies = parseCookies(req);
  const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
  if (session) { req.adminSession = session; return next(); }
  return authenticateAdmin(req, res, next);
}, (req, res) => {
  const { id } = req.params;
  const store = loadStore();

  if (!store.skins[id]) {
    return res.status(404).json({ success: false, error: 'Skin not found' });
  }

  const agents = loadAgents();
  const orders = [];

  for (const [agentName, agent] of Object.entries(agents)) {
    const purchases = agent.skinPurchases || [];
    for (const p of purchases) {
      if (p.skinId === id) {
        orders.push({
          agent: agentName,
          price: p.price,
          priceDisplay: p.priceDisplay,
          currency: p.currency,
          txHash: p.txHash,
          timestamp: p.timestamp,
        });
      }
    }
  }

  // Sort newest first
  orders.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  res.json({ success: true, orders, total: orders.length });
});

// ==================== NFT CONTRACT MANAGEMENT (ADMIN) ====================

// Admin auth helper for contract endpoints
function adminAuthMiddleware(req, res, next) {
  const cookies = parseCookies(req);
  const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
  if (session) { req.adminSession = session; return next(); }
  return authenticateAdmin(req, res, next);
}

// Admin: Deploy (or retry deploy) NFT contract for a MON skin
app.post('/admin/api/store/skins/:id/deploy', adminAuthMiddleware, async (req, res) => {
  const { id } = req.params;
  const store = loadStore();
  const skin = store.skins[id];

  if (!skin) return res.status(404).json({ success: false, error: 'Skin not found' });
  if (skin.currency !== 'MON') return res.status(400).json({ success: false, error: 'Only MON skins need NFT contracts' });
  if (skin.contractAddress && skin.deployStatus === 'deployed') {
    return res.status(400).json({ success: false, error: 'Contract already deployed', contractAddress: skin.contractAddress });
  }

  try {
    skin.deployStatus = 'pending';
    saveStore(store);

    const skinSymbol = 'CLAW-' + (skin.variant || id).toUpperCase().replace(/[^A-Z0-9]/g, '');
    const skinSupply = skin.supply === -1 ? 10000 : skin.supply;
    const skinTransferable = skin.transferable !== false;
    const { contractAddress, txHash } = await deployNFTContract(id, skin.name, skinSymbol, skinSupply, skin.price, skinTransferable);

    const freshStore = loadStore();
    if (freshStore.skins[id]) {
      freshStore.skins[id].contractAddress = contractAddress;
      freshStore.skins[id].deployTxHash = txHash;
      freshStore.skins[id].deployStatus = 'deployed';
      freshStore.skins[id].contractPaused = false;
      delete freshStore.skins[id].deployError;
      saveStore(freshStore);
    }

    res.json({ success: true, contractAddress, txHash, explorer: `${MONAD_EXPLORER}/address/${contractAddress}` });
  } catch (err) {
    console.error(`NFT deploy failed for ${id}:`, err.message);
    const freshStore = loadStore();
    if (freshStore.skins[id]) {
      freshStore.skins[id].deployStatus = 'failed';
      freshStore.skins[id].deployError = err.message;
      saveStore(freshStore);
    }
    res.status(500).json({ success: false, error: err.message });
  }
});

// Admin: Get deployer wallet info
app.get('/admin/api/store/deployer', adminAuthMiddleware, async (req, res) => {
  try {
    const store = loadStore();
    const deployer = store.deployerWallet;
    if (!deployer) return res.json({ success: true, deployer: null });

    // Get MON balance
    let balance = '0';
    try {
      const balResp = await httpRequest(MONAD_RPC_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', method: 'eth_getBalance', params: [deployer.address, 'latest'], id: 1 })
      });
      const wei = ethers.BigNumber.from(balResp.result || '0x0');
      balance = ethers.utils.formatEther(wei);
    } catch (e) { /* ignore balance check errors */ }

    res.json({ success: true, deployer: { ...deployer, balance, treasury: X402_TREASURY_ADDRESS } });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Admin: Pause minting on a skin's NFT contract
app.post('/admin/api/store/skins/:id/contract/pause', adminAuthMiddleware, async (req, res) => {
  const { id } = req.params;
  const store = loadStore();
  const skin = store.skins[id];
  if (!skin?.contractAddress) return res.status(400).json({ success: false, error: 'No deployed contract' });

  try {
    let txHash = null;
    // Only call pause() if contract isn't already paused — avoids "Pausable: not paused" revert
    if (!skin.contractPaused) {
      ({ txHash } = await callNFTContract(skin.contractAddress, 'pause()'));
    }
    const freshStore = loadStore();
    if (freshStore.skins[id]) {
      freshStore.skins[id].contractPaused = true;
      freshStore.skins[id].onSale = false; // Take off sale when contract paused
      saveStore(freshStore);
    }
    res.json({ success: true, txHash });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Admin: Unpause minting on a skin's NFT contract
app.post('/admin/api/store/skins/:id/contract/unpause', adminAuthMiddleware, async (req, res) => {
  const { id } = req.params;
  const store = loadStore();
  const skin = store.skins[id];
  if (!skin?.contractAddress) return res.status(400).json({ success: false, error: 'No deployed contract' });

  try {
    let txHash = null;
    // Only call unpause() if contract is actually paused — avoids "Pausable: not paused" revert
    if (skin.contractPaused !== false) {
      ({ txHash } = await callNFTContract(skin.contractAddress, 'unpause()'));
    }
    const freshStore = loadStore();
    if (freshStore.skins[id]) {
      freshStore.skins[id].contractPaused = false;
      freshStore.skins[id].onSale = true; // Put back on sale when contract unpaused
      saveStore(freshStore);
    }
    res.json({ success: true, txHash });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Admin: Set transferable/non-transferable on NFT contract
// Locked after any NFTs have been minted — can only toggle before first sale
app.post('/admin/api/store/skins/:id/contract/set-transferable', adminAuthMiddleware, async (req, res) => {
  const { id } = req.params;
  const { transferable } = req.body;
  if (transferable === undefined) return res.status(400).json({ success: false, error: 'transferable (bool) required' });

  const store = loadStore();
  const skin = store.skins[id];
  if (!skin?.contractAddress) return res.status(400).json({ success: false, error: 'No deployed contract' });
  if (skin.sold > 0) return res.status(400).json({ success: false, error: 'Cannot change transferability after NFTs have been minted' });

  try {
    const abiCoder = new ethers.utils.AbiCoder();
    const params = abiCoder.encode(['bool'], [!!transferable]);
    const { txHash } = await callNFTContract(skin.contractAddress, 'setTransferable(bool)', params);
    // Also update the skin's local transferable field to stay in sync
    const freshStore = loadStore();
    if (freshStore.skins[id]) {
      freshStore.skins[id].transferable = !!transferable;
      saveStore(freshStore);
    }
    res.json({ success: true, txHash, transferable: !!transferable });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Admin: Set mint price on NFT contract
app.post('/admin/api/store/skins/:id/contract/set-price', adminAuthMiddleware, async (req, res) => {
  const { id } = req.params;
  const { price } = req.body;
  if (!price) return res.status(400).json({ success: false, error: 'price required (in wei)' });

  const store = loadStore();
  const skin = store.skins[id];
  if (!skin?.contractAddress) return res.status(400).json({ success: false, error: 'No deployed contract' });

  try {
    const abiCoder = new ethers.utils.AbiCoder();
    const params = abiCoder.encode(['uint256'], [String(price)]);
    const { txHash } = await callNFTContract(skin.contractAddress, 'setMintPrice(uint256)', params);

    // Sync off-chain price
    const freshStore = loadStore();
    if (freshStore.skins[id]) {
      freshStore.skins[id].price = String(price);
      saveStore(freshStore);
    }
    res.json({ success: true, txHash });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Admin: Set max supply on NFT contract
app.post('/admin/api/store/skins/:id/contract/set-supply', adminAuthMiddleware, async (req, res) => {
  const { id } = req.params;
  const { supply } = req.body;
  if (supply === undefined) return res.status(400).json({ success: false, error: 'supply required' });

  const store = loadStore();
  const skin = store.skins[id];
  if (!skin?.contractAddress) return res.status(400).json({ success: false, error: 'No deployed contract' });

  try {
    const abiCoder = new ethers.utils.AbiCoder();
    const params = abiCoder.encode(['uint256'], [Number(supply)]);
    const { txHash } = await callNFTContract(skin.contractAddress, 'setMaxSupply(uint256)', params);

    const freshStore = loadStore();
    if (freshStore.skins[id]) {
      freshStore.skins[id].supply = Number(supply);
      saveStore(freshStore);
    }
    res.json({ success: true, txHash });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Admin: Withdraw accumulated MON from NFT contract to treasury
app.post('/admin/api/store/skins/:id/contract/withdraw', adminAuthMiddleware, async (req, res) => {
  const { id } = req.params;
  const store = loadStore();
  const skin = store.skins[id];
  if (!skin?.contractAddress) return res.status(400).json({ success: false, error: 'No deployed contract' });

  try {
    // Check contract balance first
    const balResp = await httpRequest(MONAD_RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', method: 'eth_getBalance', params: [skin.contractAddress, 'latest'], id: 1 })
    });
    const balWei = ethers.BigNumber.from(balResp.result || '0x0');
    if (balWei.isZero()) return res.status(400).json({ success: false, error: 'Contract balance is 0' });

    const { txHash } = await callNFTContract(skin.contractAddress, 'withdraw()');
    const balanceMon = ethers.utils.formatEther(balWei);
    console.log(`Withdrew ${balanceMon} MON from ${skin.contractAddress} to treasury ${X402_TREASURY_ADDRESS}`);
    res.json({ success: true, txHash, withdrawn: balanceMon, treasury: X402_TREASURY_ADDRESS });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Admin: Get contract status (on-chain data) for a skin
app.get('/admin/api/store/skins/:id/contract', adminAuthMiddleware, async (req, res) => {
  const { id } = req.params;
  const store = loadStore();
  const skin = store.skins[id];
  if (!skin?.contractAddress) return res.json({ success: true, contract: null });

  try {
    const [totalMintedHex, mintPriceHex, maxSupplyHex, pausedHex, transferableHex, balResp] = await Promise.all([
      readNFTContract(skin.contractAddress, 'totalMinted()'),
      readNFTContract(skin.contractAddress, 'mintPrice()'),
      readNFTContract(skin.contractAddress, 'maxSupply()'),
      readNFTContract(skin.contractAddress, 'paused()'),
      readNFTContract(skin.contractAddress, 'transferable()').catch(() => null),
      httpRequest(MONAD_RPC_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', method: 'eth_getBalance', params: [skin.contractAddress, 'latest'], id: 1 })
      })
    ]);

    const totalMinted = ethers.BigNumber.from(totalMintedHex || '0x0').toNumber();
    const mintPrice = ethers.BigNumber.from(mintPriceHex || '0x0').toString();
    const maxSupply = ethers.BigNumber.from(maxSupplyHex || '0x0').toNumber();
    const paused = pausedHex ? ethers.BigNumber.from(pausedHex).toNumber() === 1 : false;
    // transferable() returns bool; null means legacy contract without this function
    const transferable = transferableHex ? ethers.BigNumber.from(transferableHex).toNumber() === 1 : null;
    const balanceWei = ethers.BigNumber.from(balResp.result || '0x0');
    const balance = ethers.utils.formatEther(balanceWei);

    res.json({
      success: true,
      contract: {
        address: skin.contractAddress,
        totalMinted,
        maxSupply,
        mintPrice,
        mintPriceFormatted: ethers.utils.formatEther(mintPrice) + ' MON',
        paused,
        transferable,
        balance,
        explorer: `${MONAD_EXPLORER}/address/${skin.contractAddress}`
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ==================== NFT METADATA (ERC-721) ====================

// Public: Serve skin image for NFT metadata
// Uses pre-rendered 1024x1024 3D character thumbnails, with SVG fallback
// ⚠️ Must be defined BEFORE /:tokenId or Express matches "image" as a tokenId
app.get('/api/nft/:skinId/image', (req, res) => {
  const { skinId } = req.params;
  const store = loadStore();
  const skin = store.skins[skinId];

  // If skin has a custom uploaded image, redirect to it
  if (skin?.imageUrl) {
    return res.redirect(skin.imageUrl.startsWith('http') ? skin.imageUrl : skin.imageUrl);
  }

  // Serve pre-rendered 3D character thumbnail (1024x1024 PNG)
  const variant = skin?.variant || 'red';
  const thumbPath = path.join(__dirname, 'public', 'models', `${variant}-idle-thumb.png`);
  if (fs.existsSync(thumbPath)) {
    res.setHeader('Content-Type', 'image/png');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    return res.sendFile(thumbPath);
  }

  // SVG fallback if no thumbnail exists for this variant
  const colors = { red: '#c62828', blue: '#1565c0', gold: '#f9a825', purple: '#7b1fa2', shadow: '#1a1a2e' };
  const bg = colors[variant] || colors.red;
  const name = skin?.name || 'Clawnads Skin';

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512">
  <rect width="512" height="512" rx="32" fill="${bg}"/>
  <text x="256" y="220" text-anchor="middle" font-family="system-ui,sans-serif" font-size="120" fill="white" opacity="0.9">🦞</text>
  <text x="256" y="340" text-anchor="middle" font-family="system-ui,sans-serif" font-size="28" font-weight="bold" fill="white">${name.replace(/&/g, '&amp;').replace(/</g, '&lt;')}</text>
  <text x="256" y="380" text-anchor="middle" font-family="system-ui,sans-serif" font-size="16" fill="white" opacity="0.7">Clawnads Agent Skin</text>
</svg>`;

  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.send(svg);
});

// Public: Serve ERC-721 metadata JSON for a skin token
// Called by wallets/marketplaces via tokenURI() → https://claw.tormund.io/api/nft/:skinId/:tokenId
app.get('/api/nft/:skinId/:tokenId', (req, res) => {
  const { skinId, tokenId } = req.params;
  const store = loadStore();
  const skin = store.skins[skinId];

  if (!skin || !skin.contractAddress) {
    return res.status(404).json({ error: 'Skin not found or no contract' });
  }

  const tokenNum = parseInt(tokenId, 10);
  if (isNaN(tokenNum) || tokenNum < 0) {
    return res.status(400).json({ error: 'Invalid token ID' });
  }

  const variant = skin.variant || 'red';
  const baseUrl = 'https://claw.tormund.io';

  // Image: use uploaded preview if available, else fall back to a placeholder
  const image = skin.imageUrl
    ? (skin.imageUrl.startsWith('http') ? skin.imageUrl : `${baseUrl}${skin.imageUrl}`)
    : `${baseUrl}/api/nft/${encodeURIComponent(skinId)}/image`; // Placeholder route

  // animation_url: the 3D GLB model — wallets that support 3D will render this
  const glbPath = skin.glbUrl || `/models/${variant}-idle.glb`;
  const animationUrl = glbPath.startsWith('http') ? glbPath : `${baseUrl}${glbPath}`;

  const metadata = {
    name: `${skin.name} #${tokenNum}`,
    description: skin.description || `${skin.name} — a Clawnads agent skin.`,
    image,
    animation_url: animationUrl,
    external_url: `${baseUrl}/store`,
    attributes: [
      { trait_type: 'Variant', value: variant },
      { trait_type: 'Type', value: skin.type || 'skin' },
      { trait_type: 'Collection', value: 'Clawnads Skins' }
    ]
  };

  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.json(metadata);
});

// Public: Contract-level metadata (OpenSea contractURI standard)
app.get('/api/nft/:skinId', (req, res) => {
  const { skinId } = req.params;
  const store = loadStore();
  const skin = store.skins[skinId];

  if (!skin || !skin.contractAddress) {
    return res.status(404).json({ error: 'Skin not found or no contract' });
  }

  const baseUrl = 'https://claw.tormund.io';
  const image = skin.imageUrl
    ? (skin.imageUrl.startsWith('http') ? skin.imageUrl : `${baseUrl}${skin.imageUrl}`)
    : `${baseUrl}/api/nft/${encodeURIComponent(skinId)}/image`;

  res.json({
    name: skin.name,
    description: skin.description || `${skin.name} — a Clawnads agent skin collection.`,
    image,
    external_link: `${baseUrl}/store`,
    seller_fee_basis_points: 0,
    fee_recipient: X402_TREASURY_ADDRESS
  });
});

// ==================== PUBLIC STORE ====================

// Public: List visible skins (with optional ownership info)
app.get('/store/skins', (req, res) => {
  const store = loadStore();
  const agentName = req.query.agent;

  // Filter to visible skins only
  const visibleSkins = {};
  for (const [id, skin] of Object.entries(store.skins)) {
    if (skin.visible) {
      visibleSkins[id] = { ...skin };
    }
  }

  // Add ownership info if agent specified
  if (agentName) {
    const agents = loadAgents();
    const agent = agents[agentName];
    if (agent) {
      const owned = agent.ownedSkins || ['red', 'blue']; // default free skins
      const equipped = agent.characterSkin || 'red';
      for (const [id, skin] of Object.entries(visibleSkins)) {
        skin.owned = owned.includes(id);
        skin.equipped = equipped === id;
      }
    }
  }

  res.json({ success: true, skins: visibleSkins });
});

// Public: Get agent's owned skins
app.get('/agents/:name/store/inventory', (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  const agent = agents[name];
  const ownedSkins = agent.ownedSkins || ['red', 'blue'];
  const equipped = agent.characterSkin || 'red';
  const purchases = agent.skinPurchases || [];

  // Enrich with store display names
  const store = loadStore();
  const skinDetails = {};
  for (const skinId of ownedSkins) {
    const storeSkin = store.skins[skinId];
    if (storeSkin) {
      skinDetails[skinId] = { name: storeSkin.name, variant: storeSkin.variant };
    }
  }

  res.json({ success: true, ownedSkins, equipped, purchases, skinDetails });
});

// Agent: Purchase a skin from the store
app.post('/agents/:name/store/purchase', authenticateAgent, async (req, res) => {
  const { name } = req.params;
  const { skinId } = req.body;

  if (!skinId) {
    return res.status(400).json({ success: false, error: 'skinId is required' });
  }

  const store = loadStore();
  const skin = store.skins[skinId];

  if (!skin) {
    return res.status(404).json({ success: false, error: 'Skin not found in store' });
  }
  // onSale gates API purchases; fall back to visible for legacy data without onSale field
  const isOnSale = skin.onSale !== undefined ? skin.onSale : skin.visible;
  if (!isOnSale) {
    return res.status(400).json({ success: false, error: 'Skin is not available for purchase' });
  }
  if (skin.free) {
    return res.status(400).json({ success: false, error: 'Free skins are already owned by all agents' });
  }

  // Check supply limit
  if (skin.supply !== undefined && skin.supply !== -1) {
    const sold = skin.sold || 0;
    if (sold >= skin.supply) {
      return res.status(400).json({ success: false, error: 'This skin is sold out' });
    }
  }

  const agents = loadAgents();
  const agent = agents[name];

  // Check verification requirement
  if (skin.requiresVerification) {
    const verified = agent?.erc8004?.x402Support?.verified;
    if (!verified) {
      return res.status(403).json({ success: false, error: 'This skin requires x402 verification. Complete verification first.' });
    }
  }
  if (!agent) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }
  if (!agent.wallet) {
    return res.status(400).json({ success: false, error: 'Agent does not have a wallet' });
  }

  const ownedSkins = agent.ownedSkins || ['red', 'blue'];
  if (ownedSkins.includes(skinId)) {
    return res.status(400).json({ success: false, error: 'You already own this skin' });
  }

  // Double-check via purchase history — one unit per agent
  const existingPurchase = (agent.skinPurchases || []).find(p => p.skinId === skinId);
  if (existingPurchase) {
    return res.status(400).json({ success: false, error: 'You already purchased this item' });
  }

  if (!X402_TREASURY_ADDRESS) {
    return res.status(500).json({ success: false, error: 'Treasury address not configured' });
  }

  const walletAddress = agent.wallet.address;
  const walletId = agent.wallet.id;
  const priceBaseUnits = skin.price;
  const currency = skin.currency || 'USDC';

  try {
    let txHash = null;

    if (currency === 'USDC') {
      // ========== USDC path (x402 protocol) ==========
      // 1. Check USDC balance
      const balance = await getTokenBalance(walletAddress, X402_USDC_ADDRESS);
      if (BigInt(balance) < BigInt(priceBaseUnits)) {
        return res.status(400).json({
          success: false,
          error: `Insufficient USDC. Need ${skin.priceDisplay}. Have: ${balance} base units.`,
          needed: priceBaseUnits,
          have: balance,
          usdcAddress: X402_USDC_ADDRESS
        });
      }

      console.log(`Store purchase: ${name} buying ${skinId} for ${skin.priceDisplay} USDC`);

      // 2. EIP-712 TransferWithAuthorization
      const validAfter = '0';
      const validBefore = (Math.floor(Date.now() / 1000) + 300).toString();
      const nonce = '0x' + crypto.randomBytes(32).toString('hex');

      const typedData = {
        types: {
          EIP712Domain: [
            { name: 'name', type: 'string' },
            { name: 'version', type: 'string' },
            { name: 'chainId', type: 'uint256' },
            { name: 'verifyingContract', type: 'address' }
          ],
          TransferWithAuthorization: [
            { name: 'from', type: 'address' },
            { name: 'to', type: 'address' },
            { name: 'value', type: 'uint256' },
            { name: 'validAfter', type: 'uint256' },
            { name: 'validBefore', type: 'uint256' },
            { name: 'nonce', type: 'bytes32' }
          ]
        },
        primary_type: 'TransferWithAuthorization',
        domain: {
          name: USDC_EIP712_NAME,
          version: USDC_EIP712_VERSION,
          chainId: MONAD_CHAIN_ID,
          verifyingContract: X402_USDC_ADDRESS
        },
        message: {
          from: walletAddress,
          to: X402_TREASURY_ADDRESS,
          value: priceBaseUnits,
          validAfter,
          validBefore,
          nonce
        }
      };

      // 3. Sign via Privy
      const auth = Buffer.from(`${PRIVY_APP_ID}:${PRIVY_APP_SECRET}`).toString('base64');
      const signResponse = await httpRequest(`https://api.privy.io/v1/wallets/${walletId}/rpc`, {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${auth}`,
          'privy-app-id': PRIVY_APP_ID,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          method: 'eth_signTypedData_v4',
          params: { typed_data: typedData }
        })
      });

      const signature = signResponse.data?.signature;
      if (!signature) {
        throw new Error('No signature returned from Privy');
      }

      // 4. Settle via x402 facilitator
      const paymentRequirements = {
        scheme: 'exact',
        network: X402_NETWORK,
        amount: priceBaseUnits,
        asset: X402_USDC_ADDRESS,
        payTo: X402_TREASURY_ADDRESS,
        maxTimeoutSeconds: 300,
        extra: { assetTransferMethod: 'eip3009', name: USDC_EIP712_NAME, version: USDC_EIP712_VERSION }
      };

      const paymentPayload = {
        x402Version: 2,
        resource: {
          url: `https://claw.tormund.io/agents/${name}/store/purchase?skinId=${skinId}`,
          description: `Skin purchase: ${skin.name} by ${name}`,
          mimeType: 'application/json'
        },
        accepted: { ...paymentRequirements },
        payload: {
          signature,
          authorization: { from: walletAddress, to: X402_TREASURY_ADDRESS, value: priceBaseUnits, validAfter, validBefore, nonce }
        }
      };

      const settleResponse = await httpRequest(`${X402_FACILITATOR_URL}/settle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ x402Version: 2, paymentPayload, paymentRequirements }),
        timeout: 60000
      });

      if (settleResponse.success === false) {
        throw new Error('Facilitator rejected payment: ' + JSON.stringify(settleResponse));
      }
      txHash = settleResponse.txHash || settleResponse.transaction || settleResponse.hash || ('store-purchase-' + Date.now());

    } else if (skin.contractAddress && skin.deployStatus === 'deployed') {
      // ========== MON path: NFT MINT (contract deployed) ==========
      // 1. Check MON balance (direct RPC to Monad, not Privy)
      const auth = Buffer.from(`${PRIVY_APP_ID}:${PRIVY_APP_SECRET}`).toString('base64');

      const balResponse = await httpRequest(MONAD_RPC_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'eth_getBalance',
          params: [walletAddress, 'latest'],
          id: 1
        })
      });

      const monBalance = balResponse.result || '0x0';
      const monBalanceBig = BigInt(monBalance);
      if (monBalanceBig < BigInt(priceBaseUnits)) {
        return res.status(400).json({
          success: false,
          error: `Insufficient MON. Need ${skin.priceDisplay}. Have: ${monBalanceBig.toString()} wei.`,
          needed: priceBaseUnits,
          have: monBalanceBig.toString()
        });
      }

      console.log(`Store NFT mint: ${name} minting ${skinId} for ${skin.priceDisplay} MON on contract ${skin.contractAddress}`);

      // 2. ABI-encode mint(address to) and send with msg.value
      const mintSelector = ethers.utils.id('mint(address)').slice(0, 10);
      const abiCoder = new ethers.utils.AbiCoder();
      const mintParams = abiCoder.encode(['address'], [walletAddress]);
      const mintCalldata = mintSelector + mintParams.slice(2);
      const hexValue = '0x' + BigInt(priceBaseUnits).toString(16);

      const txResponse = await httpRequest(`https://api.privy.io/v1/wallets/${walletId}/rpc`, {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${auth}`,
          'privy-app-id': PRIVY_APP_ID,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          method: 'eth_sendTransaction',
          caip2: `eip155:${MONAD_CHAIN_ID}`,
          chain_type: 'ethereum',
          params: {
            transaction: {
              to: skin.contractAddress,
              value: hexValue,
              data: mintCalldata
            }
          }
        })
      });

      txHash = txResponse.data?.hash;
      if (!txHash) {
        throw new Error('No transaction hash returned from Privy');
      }

      // 3. Poll for receipt
      let receipt = null;
      for (let attempt = 0; attempt < 20; attempt++) {
        await new Promise(ok => setTimeout(ok, 2000));
        const receiptResponse = await httpRequest(MONAD_RPC_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'eth_getTransactionReceipt',
            params: [txHash],
            id: 1
          })
        });
        if (receiptResponse.result) {
          receipt = receiptResponse.result;
          break;
        }
      }

      if (!receipt || receipt.status === '0x0') {
        throw new Error('NFT mint transaction failed or not confirmed');
      }

    } else {
      // ========== MON path: DIRECT TRANSFER (no contract / legacy) ==========
      // 1. Check MON balance
      const auth = Buffer.from(`${PRIVY_APP_ID}:${PRIVY_APP_SECRET}`).toString('base64');

      const balResponse = await httpRequest(MONAD_RPC_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'eth_getBalance',
          params: [walletAddress, 'latest'],
          id: 1
        })
      });

      const monBalance = balResponse.result || '0x0';
      const monBalanceBig = BigInt(monBalance);
      if (monBalanceBig < BigInt(priceBaseUnits)) {
        return res.status(400).json({
          success: false,
          error: `Insufficient MON. Need ${skin.priceDisplay}. Have: ${monBalanceBig.toString()} wei.`,
          needed: priceBaseUnits,
          have: monBalanceBig.toString()
        });
      }

      console.log(`Store purchase: ${name} buying ${skinId} for ${skin.priceDisplay} MON`);

      // 2. Send MON via Privy
      const hexValue = '0x' + BigInt(priceBaseUnits).toString(16);
      const txResponse = await httpRequest(`https://api.privy.io/v1/wallets/${walletId}/rpc`, {
        method: 'POST',
        headers: {
          'Authorization': `Basic ${auth}`,
          'privy-app-id': PRIVY_APP_ID,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          method: 'eth_sendTransaction',
          caip2: `eip155:${MONAD_CHAIN_ID}`,
          chain_type: 'ethereum',
          params: {
            transaction: {
              to: X402_TREASURY_ADDRESS,
              value: hexValue
            }
          }
        })
      });

      txHash = txResponse.data?.hash;
      if (!txHash) {
        throw new Error('No transaction hash returned from Privy');
      }

      // 3. Poll for receipt
      let receipt = null;
      for (let attempt = 0; attempt < 20; attempt++) {
        await new Promise(ok => setTimeout(ok, 2000));
        const receiptResponse = await httpRequest(MONAD_RPC_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'eth_getTransactionReceipt',
            params: [txHash],
            id: 1
          })
        });
        if (receiptResponse.result) {
          receipt = receiptResponse.result;
          break;
        }
      }

      if (!receipt || receipt.status === '0x0') {
        throw new Error('MON transfer failed or not confirmed');
      }
    }

    // ========== Increment sold counter ==========
    const freshStore = loadStore();
    if (freshStore.skins[skinId]) {
      freshStore.skins[skinId].sold = (freshStore.skins[skinId].sold || 0) + 1;
      saveStore(freshStore);
    }

    // ========== Record purchase ==========
    const freshAgents = loadAgents();
    if (!freshAgents[name]) {
      return res.status(500).json({ success: false, error: 'Agent data lost during purchase' });
    }

    if (!freshAgents[name].ownedSkins) freshAgents[name].ownedSkins = ['red', 'blue'];
    freshAgents[name].ownedSkins.push(skinId);

    if (!freshAgents[name].skinPurchases) freshAgents[name].skinPurchases = [];
    freshAgents[name].skinPurchases.push({
      skinId,
      price: priceBaseUnits,
      priceDisplay: skin.priceDisplay,
      currency,
      txHash,
      timestamp: new Date().toISOString()
    });

    // Log as transaction
    if (!freshAgents[name].transactions) freshAgents[name].transactions = [];
    freshAgents[name].transactions.push({
      hash: txHash,
      to: skin.contractAddress || X402_TREASURY_ADDRESS,
      value: priceBaseUnits,
      timestamp: new Date().toISOString(),
      network: MONAD_NETWORK_NAME,
      chainId: MONAD_CHAIN_ID,
      type: skin.contractAddress ? 'nft-mint' : 'store-purchase',
      description: skin.contractAddress
        ? `NFT mint: ${skin.name} for ${skin.priceDisplay}`
        : `Store purchase: ${skin.name} for ${skin.priceDisplay}`
    });

    saveAgents(freshAgents);
    analytics.trackEvent('store_purchase', name, { skinId, price: skin.priceDisplay, currency });
    console.log(`Store purchase complete: ${name} bought ${skinId} for ${skin.priceDisplay} (tx: ${txHash})`);

    res.json({
      success: true,
      message: `Purchased ${skin.name} for ${skin.priceDisplay}!`,
      skinId,
      txHash,
      explorer: txHash && txHash.startsWith('0x') ? `${MONAD_EXPLORER}/tx/${txHash}` : null,
      ownedSkins: freshAgents[name].ownedSkins
    });

  } catch (err) {
    console.error(`Store purchase error for ${name}:`, err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Agent: Self-service skin toggle (equip owned skins only)
app.put('/agents/:name/skin', authenticateAgent, (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();
  const agent = agents[name];

  // Must have passed security check (sandbox + env token)
  const securityPassed = agent.securityChecks?.sandbox_enabled && agent.securityChecks?.token_from_env;
  if (!securityPassed) {
    return res.status(403).json({ success: false, error: 'Security check required. Complete onboarding first.' });
  }

  const { skin } = req.body;
  const ownedSkins = agent.ownedSkins || ['red', 'blue'];
  if (!skin || !ownedSkins.includes(skin)) {
    return res.status(400).json({ success: false, error: `skin must be one of your owned skins: ${ownedSkins.join(', ')}` });
  }

  agent.characterSkin = skin;
  saveAgents(agents);
  analytics.trackEvent('skin_equip', name, { skinId: skin });
  console.log(`Agent ${name} switched skin to: ${skin}`);
  res.json({ success: true, characterSkin: skin });
});

// Admin: Set ERC-8004 identity data for an agent
app.post('/admin/agents/:name/erc8004', authenticateAdmin, (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  const { agentId, agentRegistry, description, image, services, supportedTrust, x402Support } = req.body;

  agents[name].erc8004 = {
    ...(agents[name].erc8004 || {}),
    ...(agentId !== undefined && { agentId }),
    ...(agentRegistry !== undefined && { agentRegistry }),
    ...(description !== undefined && { description }),
    ...(image !== undefined && { image }),
    ...(services !== undefined && { services }),
    ...(supportedTrust !== undefined && { supportedTrust }),
    ...(x402Support !== undefined && { x402Support }),
    updatedAt: new Date().toISOString()
  };

  saveAgents(agents);
  console.log(`ERC-8004 identity updated for ${name}`);
  res.json({ success: true, erc8004: agents[name].erc8004 });
});

// Agent: Set own ERC-8004 profile data (description, services, supportedTrust)
// Agents can set their own profile but NOT agentId, agentRegistry, or x402Support (system-managed)
app.put('/agents/:name/erc8004/profile', authenticateAgent, (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  const { description, services, supportedTrust } = req.body;

  if (!description && !services && !supportedTrust) {
    return res.status(400).json({ success: false, error: 'Provide at least one of: description, services, supportedTrust' });
  }

  // Validate services format if provided
  if (services) {
    if (!Array.isArray(services)) {
      return res.status(400).json({ success: false, error: 'services must be an array of { name, description } objects' });
    }
    for (const svc of services) {
      if (!svc.name || typeof svc.name !== 'string') {
        return res.status(400).json({ success: false, error: 'Each service must have a name string' });
      }
    }
  }

  agents[name].erc8004 = {
    ...(agents[name].erc8004 || {}),
    ...(description !== undefined && { description }),
    ...(services !== undefined && { services }),
    ...(supportedTrust !== undefined && { supportedTrust }),
    updatedAt: new Date().toISOString()
  };

  saveAgents(agents);
  console.log(`ERC-8004 profile updated by ${name}: ${description ? 'description' : ''}${services ? ' services' : ''}${supportedTrust ? ' trust' : ''}`);
  res.json({ success: true, erc8004: agents[name].erc8004 });
});

// Admin: Refresh on-chain URI for an agent (calls setAgentURI to emit URIUpdated event)
app.post('/admin/agents/:name/erc8004/refresh-uri', authenticateAdmin, async (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  const erc = agents[name].erc8004;
  if (!erc?.agentId) {
    return res.status(400).json({ success: false, error: 'Agent not registered on-chain' });
  }

  if (!agents[name].wallet) {
    return res.status(400).json({ success: false, error: 'Agent has no wallet' });
  }

  try {
    const baseUrl = req.query.baseUrl || 'https://claw.tormund.io';
    const agentURI = `${baseUrl}/.well-known/agent-registration.json?agent=${encodeURIComponent(name)}`;
    const agentIdBN = ethers.BigNumber.from(erc.agentId);

    // ABI-encode setAgentURI(uint256 agentId, string newURI)
    const abiCoder = new ethers.utils.AbiCoder();
    const encodedParams = abiCoder.encode(['uint256', 'string'], [agentIdBN, agentURI]);
    const calldata = ERC8004_SET_URI_SELECTOR + encodedParams.slice(2);

    const auth = Buffer.from(`${PRIVY_APP_ID}:${PRIVY_APP_SECRET}`).toString('base64');
    const walletId = agents[name].wallet.id;

    console.log(`ERC-8004 refreshURI: ${name} (agentId ${erc.agentId}) → ${agentURI}`);

    const txResponse = await httpRequest(`https://api.privy.io/v1/wallets/${walletId}/rpc`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'privy-app-id': PRIVY_APP_ID,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        method: 'eth_sendTransaction',
        caip2: `eip155:${MONAD_CHAIN_ID}`,
        chain_type: 'ethereum',
        params: {
          transaction: {
            to: ERC8004_IDENTITY_REGISTRY,
            value: '0x0',
            data: calldata
          }
        }
      })
    });

    const txHash = txResponse.data?.hash;
    if (!txHash) {
      throw new Error('No transaction hash returned from Privy');
    }

    console.log(`ERC-8004 refreshURI tx sent for ${name}: ${txHash}`);

    // Poll for receipt
    let receipt = null;
    for (let attempt = 0; attempt < 20; attempt++) {
      await new Promise(r => setTimeout(r, 2000));
      try {
        const receiptResponse = await httpRequest(MONAD_RPC_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'eth_getTransactionReceipt',
            params: [txHash],
            id: 1
          })
        });
        receipt = receiptResponse.result;
        if (receipt) break;
      } catch (e) { /* keep polling */ }
    }

    if (receipt && receipt.status === '0x1') {
      // Update agentURI in stored data
      const freshAgents = loadAgents();
      if (freshAgents[name]?.erc8004) {
        freshAgents[name].erc8004.agentURI = agentURI;
        freshAgents[name].erc8004.updatedAt = new Date().toISOString();
        saveAgents(freshAgents);
      }
      res.json({ success: true, txHash, agentURI, message: 'URI updated on-chain. Indexers should re-fetch metadata.' });
    } else if (receipt) {
      res.status(500).json({ success: false, txHash, error: 'Transaction reverted', receipt });
    } else {
      res.json({ success: true, txHash, agentURI, message: 'Transaction sent but receipt not yet confirmed. Check later.' });
    }
  } catch (err) {
    console.error(`ERC-8004 refreshURI error for ${name}:`, err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Image magic bytes for validation
const IMAGE_SIGNATURES = {
  'image/png':  { bytes: [0x89, 0x50, 0x4E, 0x47], ext: 'png' },
  'image/jpeg': { bytes: [0xFF, 0xD8, 0xFF],       ext: 'jpg' },
  'image/gif':  { bytes: [0x47, 0x49, 0x46],        ext: 'gif' },
  'image/webp': { bytes: [0x52, 0x49, 0x46, 0x46],  ext: 'webp' }
};

function detectImageType(buffer) {
  for (const [mime, sig] of Object.entries(IMAGE_SIGNATURES)) {
    if (sig.bytes.every((b, i) => buffer[i] === b)) {
      // WebP needs additional check: bytes 8-11 should be "WEBP"
      if (mime === 'image/webp') {
        if (buffer[8] !== 0x57 || buffer[9] !== 0x45 || buffer[10] !== 0x42 || buffer[11] !== 0x50) continue;
      }
      return { mime, ext: sig.ext };
    }
  }
  return null;
}

// Agent updates their own description
app.put('/agents/:name/description', authenticateAgent, (req, res) => {
  const { name } = req.params;
  const { description } = req.body;

  if (!description || typeof description !== 'string') {
    return res.status(400).json({ success: false, error: 'description field required (string)' });
  }

  if (description.length > 500) {
    return res.status(400).json({ success: false, error: 'Description too long (max 500 characters)' });
  }

  const agents = loadAgents();
  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  agents[name].description = description;
  if (agents[name].profile) {
    agents[name].profile.description = description;
  }
  agents[name].lastSeen = new Date().toISOString();
  saveAgents(agents);

  analytics.trackEvent('profile_update', name, { field: 'description' });
  console.log(`Agent ${name} updated description: "${description.slice(0, 80)}..."`);
  res.json({ success: true, message: 'Description updated', description });
});

// Agent uploads a profile avatar (base64 image)
app.post('/agents/:name/avatar', authenticateAgent, (req, res) => {
  const { name } = req.params;
  const { image } = req.body;

  if (!image) {
    return res.status(400).json({ success: false, error: 'image field required (base64 or data URI)' });
  }

  try {
    // Strip data URI prefix if present (e.g., "data:image/png;base64,...")
    let base64Data = image;
    if (base64Data.startsWith('data:')) {
      const commaIdx = base64Data.indexOf(',');
      if (commaIdx === -1) {
        return res.status(400).json({ success: false, error: 'Invalid data URI format' });
      }
      base64Data = base64Data.slice(commaIdx + 1);
    }

    // Decode base64
    const buffer = Buffer.from(base64Data, 'base64');

    // Validate size (max 1MB decoded)
    if (buffer.length > 1024 * 1024) {
      return res.status(400).json({ success: false, error: 'Image too large (max 1MB)' });
    }
    if (buffer.length < 100) {
      return res.status(400).json({ success: false, error: 'Image too small (corrupt or empty)' });
    }

    // Validate magic bytes
    const imageType = detectImageType(buffer);
    if (!imageType) {
      return res.status(400).json({ success: false, error: 'Not a valid image. Supported: PNG, JPEG, GIF, WebP' });
    }

    // Create directory public/agents/{name}/
    const avatarDir = path.join(__dirname, 'public', 'agents', name);
    fs.mkdirSync(avatarDir, { recursive: true });

    // Remove any old avatar files with different extensions
    const oldExts = ['png', 'jpg', 'gif', 'webp'];
    for (const ext of oldExts) {
      const oldPath = path.join(avatarDir, `avatar.${ext}`);
      if (fs.existsSync(oldPath) && ext !== imageType.ext) {
        fs.unlinkSync(oldPath);
      }
    }

    // Write the file
    const filename = `avatar.${imageType.ext}`;
    const filePath = path.join(avatarDir, filename);
    fs.writeFileSync(filePath, buffer);

    // Build public URL
    const publicUrl = `https://claw.tormund.io/agents/${name}/${filename}`;

    // Update agent data
    const agents = loadAgents();
    if (agents[name]) {
      agents[name].avatarUrl = publicUrl;
      // Also update ERC-8004 image if erc8004 data exists
      if (agents[name].erc8004) {
        agents[name].erc8004.image = publicUrl;
        agents[name].erc8004.updatedAt = new Date().toISOString();
      }
      saveAgents(agents);
    }

    analytics.trackEvent('profile_update', name, { field: 'avatar' });
    console.log(`Avatar uploaded for ${name}: ${publicUrl} (${buffer.length} bytes, ${imageType.mime})`);

    res.json({
      success: true,
      avatarUrl: publicUrl,
      size: buffer.length,
      mimeType: imageType.mime
    });
  } catch (err) {
    console.error('Avatar upload error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ==================== x402 PAYMENT SUPPORT ====================

const X402_FACILITATOR_URL = 'https://x402-facilitator.molandak.org';
const X402_NETWORK = 'eip155:143';
const X402_USDC_ADDRESS = MONAD_TOKENS.USDC; // 0x754704Bc059F8C67012fEd69BC8A327a5aafb603
const X402_DONATION_AMOUNT = '1000000'; // $1.00 USDC in 6-decimal base units
const X402_DONATION_PRICE = '$1.00';
const USDC_EIP712_NAME = 'USDC';
const USDC_EIP712_VERSION = '2';
const X402_TREASURY_ADDRESS = process.env.X402_TREASURY_ADDRESS || null;

// Get ERC-20 token balance via eth_call (returns string in base units)
async function getTokenBalance(walletAddress, tokenAddress) {
  const balanceOfSelector = '0x70a08231'; // balanceOf(address)
  const paddedAddress = walletAddress.toLowerCase().replace('0x', '').padStart(64, '0');
  const calldata = balanceOfSelector + paddedAddress;

  const response = await httpRequest(MONAD_RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      method: 'eth_call',
      params: [{ to: tokenAddress, data: calldata }, 'latest'],
      id: 1
    })
  });

  if (response.result && response.result !== '0x') {
    return BigInt(response.result).toString();
  }
  return '0';
}

// ERC-8004 Identity Registry contract
const ERC8004_IDENTITY_REGISTRY = '0x8004A169FB4a3325136EB29fA0ceB6D2e539a432';
// register(string agentURI) → keccak256 selector
const ERC8004_REGISTER_SELECTOR = ethers.utils.id('register(string)').slice(0, 10);
// setAgentURI(uint256 agentId, string newURI) → keccak256 selector
const ERC8004_SET_URI_SELECTOR = ethers.utils.id('setAgentURI(uint256,string)').slice(0, 10);
// Registered(uint256 agentId, string agentURI, address owner) event topic
const ERC8004_REGISTERED_TOPIC = ethers.utils.id('Registered(uint256,string,address)');
// URIUpdated(uint256 agentId, string newURI, address updatedBy) event topic
const ERC8004_URI_UPDATED_TOPIC = ethers.utils.id('URIUpdated(uint256,string,address)');

// Agent self-registers on-chain with the ERC-8004 Identity Registry
app.post('/agents/:name/erc8004/register', authenticateAgent, async (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  if (!agents[name].wallet) {
    return res.status(404).json({ success: false, error: 'Agent does not have a wallet' });
  }

  // Check if already registered on-chain
  if (agents[name].erc8004?.agentId) {
    return res.status(400).json({
      success: false,
      error: `Agent already registered with agentId ${agents[name].erc8004.agentId}`
    });
  }

  try {
    // Pre-check: does the wallet have enough gas? ERC-8004 register costs ~0.03 MON
    const MIN_GAS_MON = 0.03;
    try {
      const balResp = await httpRequest(MONAD_RPC_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', method: 'eth_getBalance', params: [agents[name].wallet.address, 'latest'], id: 1 })
      });
      const balanceWei = ethers.BigNumber.from(balResp.result || '0x0');
      const balanceMon = parseFloat(ethers.utils.formatEther(balanceWei));
      if (balanceMon < MIN_GAS_MON) {
        return res.status(400).json({
          success: false,
          error: `Insufficient gas for ERC-8004 registration. You have ${balanceMon.toFixed(4)} MON but need at least ~${MIN_GAS_MON} MON. Ask another agent to send you MON, or ask your human.`,
          balance: balanceMon,
          required: MIN_GAS_MON
        });
      }
    } catch (balErr) {
      console.warn('ERC-8004 pre-check balance failed (continuing):', balErr.message);
    }

    // Build the agentURI — points to this server's .well-known endpoint
    const baseUrl = req.query.baseUrl || 'https://claw.tormund.io';
    const agentURI = `${baseUrl}/.well-known/agent-registration.json?agent=${encodeURIComponent(name)}`;

    // ABI-encode register(string agentURI)
    const abiCoder = new ethers.utils.AbiCoder();
    const encodedParams = abiCoder.encode(['string'], [agentURI]);
    const calldata = ERC8004_REGISTER_SELECTOR + encodedParams.slice(2);

    // Send the transaction via Privy
    const auth = Buffer.from(`${PRIVY_APP_ID}:${PRIVY_APP_SECRET}`).toString('base64');
    const walletId = agents[name].wallet.id;

    console.log(`ERC-8004 register: ${name} → ${ERC8004_IDENTITY_REGISTRY} with URI: ${agentURI}`);

    const txResponse = await httpRequest(`https://api.privy.io/v1/wallets/${walletId}/rpc`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'privy-app-id': PRIVY_APP_ID,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        method: 'eth_sendTransaction',
        caip2: `eip155:${MONAD_CHAIN_ID}`,
        chain_type: 'ethereum',
        params: {
          transaction: {
            to: ERC8004_IDENTITY_REGISTRY,
            value: '0x0',
            data: calldata
          }
        }
      })
    });

    const txHash = txResponse.data?.hash;
    if (!txHash) {
      throw new Error('No transaction hash returned from Privy');
    }

    console.log(`ERC-8004 register tx sent for ${name}: ${txHash}`);

    // Record the transaction
    const freshAgents = loadAgents();
    if (freshAgents[name]) {
      if (!freshAgents[name].transactions) freshAgents[name].transactions = [];
      freshAgents[name].transactions.push({
        hash: txHash,
        to: ERC8004_IDENTITY_REGISTRY,
        value: '0x0',
        data: calldata,
        timestamp: new Date().toISOString(),
        network: MONAD_NETWORK_NAME,
        chainId: MONAD_CHAIN_ID,
        type: 'erc8004-register'
      });
      saveAgents(freshAgents);
    }

    // Poll for the receipt to extract agentId from event logs
    let agentId = null;
    let receipt = null;
    for (let attempt = 0; attempt < 30; attempt++) {
      await new Promise(r => setTimeout(r, 2000)); // wait 2s between polls
      try {
        const receiptResponse = await httpRequest(MONAD_RPC_URL, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'eth_getTransactionReceipt',
            params: [txHash],
            id: 1
          })
        });

        receipt = receiptResponse.result;
        if (receipt) break;
      } catch (e) {
        // RPC might be slow, keep polling
      }
    }

    if (receipt && receipt.status === '0x1') {
      // Parse Registered event from logs
      const registeredLog = receipt.logs.find(
        log => log.topics[0] === ERC8004_REGISTERED_TOPIC
      );

      if (registeredLog) {
        // agentId is the first indexed param (topic[1])
        agentId = ethers.BigNumber.from(registeredLog.topics[1]).toString();
        console.log(`ERC-8004 agentId for ${name}: ${agentId}`);

        // Save the agentId to the agent's erc8004 data
        const latestAgents = loadAgents();
        if (latestAgents[name]) {
          latestAgents[name].erc8004 = {
            ...(latestAgents[name].erc8004 || {}),
            agentId: agentId,
            agentRegistry: `eip155:${MONAD_CHAIN_ID}:${ERC8004_IDENTITY_REGISTRY}`,
            registeredAt: new Date().toISOString(),
            registrationTx: txHash,
            agentURI: agentURI,
            updatedAt: new Date().toISOString()
          };
          saveAgents(latestAgents);
          console.log(`ERC-8004 agentId ${agentId} saved for ${name}`);
        }
      } else {
        console.warn(`ERC-8004 register: no Registered event found in tx ${txHash}`);
      }

      res.json({
        success: true,
        hash: txHash,
        agentId: agentId,
        agentURI: agentURI,
        explorer: `${MONAD_EXPLORER}/tx/${txHash}`,
        registry: ERC8004_IDENTITY_REGISTRY
      });
    } else if (receipt && receipt.status !== '0x1') {
      res.json({
        success: false,
        hash: txHash,
        error: 'Transaction reverted',
        explorer: `${MONAD_EXPLORER}/tx/${txHash}`
      });
    } else {
      // Tx sent but receipt not yet available — return hash, agentId will be null
      res.json({
        success: true,
        hash: txHash,
        agentId: null,
        agentURI: agentURI,
        explorer: `${MONAD_EXPLORER}/tx/${txHash}`,
        registry: ERC8004_IDENTITY_REGISTRY,
        note: 'Transaction sent but receipt not yet confirmed. agentId will be updated when confirmed.'
      });
    }
  } catch (err) {
    console.error('ERC-8004 register error:', err);
    const msg = err.message || '';

    // Parse common Privy/chain errors into actionable messages
    if (msg.includes('Insufficient funds') || msg.includes('insufficient funds')) {
      return res.status(400).json({
        success: false,
        error: `Insufficient MON for gas. ERC-8004 registration costs ~0.03 MON. Check your balance and ask another agent or your human to send you more MON.`,
        detail: msg
      });
    }
    if (msg.includes('execution reverted') || msg.includes('Execution reverted')) {
      return res.status(400).json({
        success: false,
        error: `Transaction reverted on-chain. Common causes: (1) insufficient gas — need ~0.03 MON, (2) already registered with this wallet, (3) contract paused. Check your balance first.`,
        detail: msg
      });
    }

    res.status(500).json({ success: false, error: msg });
  }
});

// ==================== x402 PAYMENT VERIFICATION ====================

// Agent verifies x402 payment capability by making a $0.001 USDC donation
app.post('/agents/:name/x402/setup', authenticateAgent, async (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  if (!agents[name].wallet) {
    return res.status(400).json({ success: false, error: 'Agent does not have a wallet' });
  }

  if (!X402_TREASURY_ADDRESS) {
    return res.status(500).json({ success: false, error: 'x402 treasury address not configured on server' });
  }

  // Check if already verified
  if (agents[name].erc8004?.x402Support?.verified) {
    return res.status(400).json({
      success: false,
      error: 'x402 payment already verified',
      x402Support: agents[name].erc8004.x402Support
    });
  }

  const walletAddress = agents[name].wallet.address;
  const walletId = agents[name].wallet.id;

  try {
    // 1. Check USDC balance
    const balance = await getTokenBalance(walletAddress, X402_USDC_ADDRESS);
    if (BigInt(balance) < BigInt(X402_DONATION_AMOUNT)) {
      return res.status(400).json({
        success: false,
        error: `Insufficient USDC balance. Need ${X402_DONATION_PRICE} USDC (${X402_DONATION_AMOUNT} base units). Have: ${balance} base units.`,
        needed: X402_DONATION_AMOUNT,
        have: balance,
        usdcAddress: X402_USDC_ADDRESS
      });
    }

    console.log(`x402 setup: ${name} has ${balance} USDC base units, need ${X402_DONATION_AMOUNT}`);

    // 2. Construct EIP-712 TransferWithAuthorization typed data
    const validAfter = '0';
    const validBefore = (Math.floor(Date.now() / 1000) + 300).toString(); // 5 min from now
    const nonce = '0x' + crypto.randomBytes(32).toString('hex');

    const typedData = {
      types: {
        EIP712Domain: [
          { name: 'name', type: 'string' },
          { name: 'version', type: 'string' },
          { name: 'chainId', type: 'uint256' },
          { name: 'verifyingContract', type: 'address' }
        ],
        TransferWithAuthorization: [
          { name: 'from', type: 'address' },
          { name: 'to', type: 'address' },
          { name: 'value', type: 'uint256' },
          { name: 'validAfter', type: 'uint256' },
          { name: 'validBefore', type: 'uint256' },
          { name: 'nonce', type: 'bytes32' }
        ]
      },
      primary_type: 'TransferWithAuthorization',
      domain: {
        name: USDC_EIP712_NAME,
        version: USDC_EIP712_VERSION,
        chainId: MONAD_CHAIN_ID,
        verifyingContract: X402_USDC_ADDRESS
      },
      message: {
        from: walletAddress,
        to: X402_TREASURY_ADDRESS,
        value: X402_DONATION_AMOUNT,
        validAfter: validAfter,
        validBefore: validBefore,
        nonce: nonce
      }
    };

    console.log(`x402 setup: signing TransferWithAuthorization for ${name}`);

    // 3. Sign via Privy eth_signTypedData_v4
    const auth = Buffer.from(`${PRIVY_APP_ID}:${PRIVY_APP_SECRET}`).toString('base64');

    const signResponse = await httpRequest(`https://api.privy.io/v1/wallets/${walletId}/rpc`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'privy-app-id': PRIVY_APP_ID,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        method: 'eth_signTypedData_v4',
        params: {
          typed_data: typedData
        }
      })
    });

    console.log(`x402 setup: Privy response for ${name}:`, JSON.stringify(signResponse).slice(0, 200));

    const signature = signResponse.data?.signature;
    if (!signature) {
      throw new Error('No signature returned from Privy: ' + JSON.stringify(signResponse));
    }

    console.log(`x402 setup: got signature for ${name}, posting to facilitator`);

    // 4. Construct x402 payload and POST to facilitator /settle
    const paymentRequirements = {
      scheme: 'exact',
      network: X402_NETWORK,
      amount: X402_DONATION_AMOUNT,
      asset: X402_USDC_ADDRESS,
      payTo: X402_TREASURY_ADDRESS,
      maxTimeoutSeconds: 300,
      extra: {
        assetTransferMethod: 'eip3009',
        name: USDC_EIP712_NAME,
        version: USDC_EIP712_VERSION
      }
    };

    const paymentPayload = {
      x402Version: 2,
      resource: {
        url: `https://claw.tormund.io/agents/${name}/x402/setup`,
        description: `x402 verification donation from ${name}`,
        mimeType: 'application/json'
      },
      accepted: {
        scheme: 'exact',
        network: X402_NETWORK,
        amount: X402_DONATION_AMOUNT,
        asset: X402_USDC_ADDRESS,
        payTo: X402_TREASURY_ADDRESS,
        maxTimeoutSeconds: 300,
        extra: {
          assetTransferMethod: 'eip3009',
          name: USDC_EIP712_NAME,
          version: USDC_EIP712_VERSION
        }
      },
      payload: {
        signature: signature,
        authorization: {
          from: walletAddress,
          to: X402_TREASURY_ADDRESS,
          value: X402_DONATION_AMOUNT,
          validAfter: validAfter,
          validBefore: validBefore,
          nonce: nonce
        }
      }
    };

    const settleBody = JSON.stringify({
      x402Version: 2,
      paymentPayload,
      paymentRequirements
    });

    const settleResponse = await httpRequest(`${X402_FACILITATOR_URL}/settle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: settleBody,
      timeout: 60000 // 60s for on-chain settlement
    });

    console.log(`x402 setup: facilitator response for ${name}:`, JSON.stringify(settleResponse));

    // Check for success — facilitator returns { success: true, txHash: ... } or similar
    const txHash = settleResponse.txHash || settleResponse.transaction || settleResponse.hash || null;
    const settled = settleResponse.success !== false;

    if (!settled) {
      throw new Error('Facilitator rejected payment: ' + JSON.stringify(settleResponse));
    }

    // 5. Save verification proof
    const freshAgents = loadAgents();
    if (freshAgents[name]) {
      if (!freshAgents[name].erc8004) freshAgents[name].erc8004 = {};

      freshAgents[name].erc8004.x402Support = {
        verified: true,
        verifiedAt: new Date().toISOString(),
        donationTx: txHash,
        donationAmount: X402_DONATION_PRICE,
        facilitator: X402_FACILITATOR_URL,
        network: X402_NETWORK,
        treasury: X402_TREASURY_ADDRESS
      };

      // Add x402 to services array if not already there
      if (!freshAgents[name].erc8004.services) freshAgents[name].erc8004.services = [];
      const hasX402Service = freshAgents[name].erc8004.services.some(s => s.name === 'x402');
      if (!hasX402Service) {
        freshAgents[name].erc8004.services.push({
          name: 'x402',
          description: 'HTTP 402 payment protocol — can send and receive payments via x402'
        });
      }

      freshAgents[name].erc8004.updatedAt = new Date().toISOString();

      // Log as transaction
      if (!freshAgents[name].transactions) freshAgents[name].transactions = [];
      freshAgents[name].transactions.push({
        hash: txHash || 'x402-donation-' + Date.now(),
        to: X402_TREASURY_ADDRESS,
        value: X402_DONATION_AMOUNT,
        timestamp: new Date().toISOString(),
        network: MONAD_NETWORK_NAME,
        chainId: MONAD_CHAIN_ID,
        type: 'x402-donation',
        description: `x402 verification donation of ${X402_DONATION_PRICE} USDC`
      });

      saveAgents(freshAgents);
      analytics.trackEvent('x402_verification', name);
      console.log(`x402 setup: verification saved for ${name}`);
    }

    res.json({
      success: true,
      message: `x402 payment verified! Donated ${X402_DONATION_PRICE} USDC to platform treasury.`,
      x402Support: freshAgents[name]?.erc8004?.x402Support || { verified: true },
      txHash: txHash,
      explorer: txHash ? `${MONAD_EXPLORER}/tx/${txHash}` : null
    });

  } catch (err) {
    console.error(`x402 setup error for ${name}:`, err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  const agents = loadAgents();
  const agentCount = Object.keys(agents).length;
  res.json({
    status: 'ok',
    agents: agentCount,
    uptime: process.uptime()
  });
});

// Agent acknowledges reading updated skill (call after re-reading SKILL.md)
app.post('/agents/:name/skill-ack', authenticateAgent, (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  agents[name].skillVersion = SKILL_VERSION;
  agents[name].skillReadAt = new Date().toISOString();
  saveAgents(agents);

  res.json({
    success: true,
    message: `Acknowledged skill version ${SKILL_VERSION}`,
    skillVersion: SKILL_VERSION
  });
});

// Register an agent
// Registration key for new agents (optional — if not set, only Moltbook registration works)
const REGISTRATION_KEY = process.env.REGISTRATION_KEY || null;

app.post('/register', registrationRateLimit, async (req, res) => {
  const { apiKey, name, registrationKey, description, callbackUrl, telegramChatId } = req.body;

  // Determine registration path:
  // Path A: registration key + chosen name (no Moltbook)
  // Path B: Moltbook API key (legacy, backward-compatible)
  const isPathA = name && registrationKey;
  const isPathB = apiKey;

  if (!isPathA && !isPathB) {
    return res.status(400).json({
      success: false,
      error: 'Provide either { name, registrationKey } or { apiKey } to register'
    });
  }

  try {
    let agentName, profileData;

    if (isPathA) {
      // PATH A: Registration key — check invite keys first, then fall back to master key
      let registeredVia = null;

      // Check against generated invite keys
      const regKeys = loadRegKeys();
      const keyHash = hashToken(registrationKey);
      const inviteKey = regKeys.keys[keyHash];

      if (inviteKey) {
        if (inviteKey.revoked) {
          return res.status(403).json({ success: false, error: 'This invite key has been revoked' });
        }
        if (inviteKey.maxUses && inviteKey.usedBy.length >= inviteKey.maxUses) {
          return res.status(403).json({ success: false, error: 'This invite key has already been used' });
        }
        registeredVia = inviteKey.label;
      } else if (REGISTRATION_KEY && registrationKey === REGISTRATION_KEY) {
        // Fall back to master key from env var
        registeredVia = 'master';
      } else {
        return res.status(403).json({ success: false, error: 'Invalid registration key' });
      }

      if (!isValidAgentName(name)) {
        return res.status(400).json({ success: false, error: 'Invalid agent name. Use 1-32 alphanumeric characters or underscores.' });
      }

      // Check name uniqueness
      const agents = loadAgents();
      if (agents[name]) {
        return res.status(409).json({ success: false, error: 'Agent name already registered' });
      }

      // Mark invite key as used (if it was an invite key, not master)
      if (inviteKey) {
        inviteKey.usedBy.push(name);
        saveRegKeys(regKeys);
      }

      agentName = name;
      profileData = { name, description: description || null, registeredVia };
    } else {
      // PATH B: Moltbook API key (legacy, backward-compatible — unchanged)
      profileData = await fetchMoltbookProfile(apiKey);

      if (!profileData.success && !profileData.name) {
        return res.status(401).json({ success: false, error: 'Invalid API key' });
      }

      agentName = profileData.name || profileData.agent?.name;

      if (!agentName) {
        return res.status(400).json({ success: false, error: 'Could not determine agent name' });
      }
    }

    // Shared registration logic (both paths)
    const agents = loadAgents();

    // Preserve existing agent data (wallet, transactions, skillVersion, etc.)
    const existingAgent = agents[agentName] || {};

    // Create Privy wallet if agent doesn't have one
    let wallet = existingAgent.wallet;
    if (!wallet) {
      try {
        const walletData = await createPrivyWallet(agentName);
        const currentBlock = await getCurrentBlockNumber();
        wallet = {
          id: walletData.id,
          address: walletData.address,
          chainType: walletData.chain_type,
          createdAt: new Date().toISOString(),
          createdAtBlock: currentBlock || 0
        };
        console.log(`Created wallet ${wallet.address} for ${agentName} at block ${currentBlock}`);
      } catch (walletErr) {
        console.error('Wallet creation failed:', walletErr.message);
      }
    }

    // Generate auth token (new token on every registration, invalidates old)
    const authToken = generateAuthToken();
    const tokenHash = hashToken(authToken);

    agents[agentName] = {
      ...existingAgent,
      tokenHash,
      callbackUrl: (callbackUrl && isValidCallbackUrl(callbackUrl)) ? callbackUrl : existingAgent.callbackUrl || null,
      telegramChatId: telegramChatId || existingAgent.telegramChatId || null,
      registeredAt: existingAgent.registeredAt || new Date().toISOString(),
      lastSeen: new Date().toISOString(),
      disconnected: false,
      profile: profileData,
      wallet,
      // Preserve existing trading config on re-registration, set defaults for new agents
      tradingConfig: existingAgent.tradingConfig || {
        enabled: true,
        maxPerTradeMON: '500',
        dailyCapMON: '2500',
        allowedTokens: Object.keys(MONAD_TOKENS),
        dailyVolume: { date: new Date().toISOString().slice(0, 10), totalMON: '0', tradeCount: 0 }
      }
    };

    // Only store Moltbook API key if registering via Path B
    if (isPathB) {
      agents[agentName].apiKey = apiKey;
    }

    saveAgents(agents);

    const registrationPath = isPathA ? 'registration key' : 'Moltbook';
    analytics.trackEvent('registration', agentName);
    console.log(`Agent registered: ${agentName} via ${registrationPath} (new auth token issued)`);

    res.json({
      success: true,
      authToken, // Plaintext token — agent must store this for future requests
      agent: {
        name: agentName,
        karma: profileData.karma || profileData.agent?.karma,
        registeredAt: agents[agentName].registeredAt,
        wallet: wallet ? {
          address: wallet.address,
          network: MONAD_NETWORK_NAME,
          chainId: MONAD_CHAIN_ID
        } : null
      },
      tokenWarning: 'This token controls your wallet. Anyone with it can execute swaps and send funds. Store it in a password manager (e.g. 1Password) and inject as the CLAW_AUTH_TOKEN environment variable. Never commit it to files.',
      envVarName: 'CLAW_AUTH_TOKEN',
      securityAdvisory: {
        message: 'Before trading, your operator should read the setup guide to configure sandbox, secret management, and webhook notifications.',
        setupGuide: '/AGENT-SETUP.md',
        securityCheck: `POST /agents/${agentName}/security/check`,
        required: ['sandbox_enabled', 'token_from_env']
      }
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// List all registered agents
app.get('/agents', (req, res, next) => {
  // Rate limit: 30 req/min per IP to prevent scraping
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  const result = checkRateLimit(rateLimits.general, `agents-list:${ip}`, 30, 60000);
  if (!result.allowed) return res.status(429).json({ error: 'Rate limit exceeded', retryAfter: result.retryAfter });
  next();
}, (req, res) => {
  const agents = loadAgents();
  const agentList = Object.entries(agents).map(([name, data]) => {
    // Check NFT cache for profile image
    const cachedNfts = data.wallet ? nftCache.get(data.wallet.address) : null;
    const profileImage = cachedNfts?.profileImage || null;

    // Compute P&L from strategy reports
    const reports = data.strategyReports || [];
    const totalPnlMon = reports.reduce((sum, r) => sum + parseFloat(r.performance?.pnlMON || 0), 0);

    return {
      name,
      description: data.profile?.agent?.description || data.profile?.description || null,
      registeredAt: data.registeredAt,
      lastSeen: data.lastSeen || data.registeredAt,
      wallet: data.wallet ? { address: data.wallet.address } : null,
      disconnected: data.disconnected || false,
      profileImage,
      avatarUrl: data.avatarUrl || data.erc8004?.image || null,
      pnlMon: totalPnlMon,
      x402Verified: !!(data.erc8004?.x402Support?.verified),
      characterSkin: data.characterSkin || null,
      owner: data.owner ? { xUsername: data.owner.xUsername } : null
    };
  });

  res.json({ success: true, agents: agentList });
});

// Get specific agent's activity
app.get('/agents/:name', async (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  try {
    // Fetch fresh data from Moltbook (skip if no API key — agent may not have Moltbook connected)
    const moltbookKey = getAgentMoltbookKey(name) || agents[name].apiKey;
    let profileData = {};
    if (moltbookKey) {
      try {
        const moltbookResponse = await fetchMoltbookPosts(moltbookKey, name);
        // Moltbook API wraps profile data under .agent — extract it
        profileData = moltbookResponse.agent || moltbookResponse;
        // Build stats from response arrays if not already present
        if (!profileData.stats && (moltbookResponse.recentPosts || moltbookResponse.recentComments)) {
          profileData.stats = {
            posts: (moltbookResponse.recentPosts || []).length,
            comments: (moltbookResponse.recentComments || []).length
          };
        }
      } catch (moltbookErr) {
        console.log(`Moltbook fetch failed for ${name}: ${moltbookErr.message}`);
        // Fallback: cached profile may also be wrapped
        const cached = agents[name].profile || {};
        profileData = cached.agent || cached;
      }
    } else {
      const cached = agents[name].profile || {};
      profileData = cached.agent || cached;
    }

    const erc8004 = agents[name].erc8004 || null;

    res.json({
      success: true,
      agent: {
        name,
        registeredAt: agents[name].registeredAt,
        wallet: agents[name].wallet ? {
          address: agents[name].wallet.address,
          id: agents[name].wallet.id,
          network: MONAD_NETWORK_NAME,
          chainId: MONAD_CHAIN_ID,
          explorer: `${MONAD_EXPLORER}/address/${agents[name].wallet.address}`
        } : null,
        erc8004: erc8004 ? {
          agentId: erc8004.agentId,
          agentRegistry: erc8004.agentRegistry || `eip155:${MONAD_CHAIN_ID}:0x8004A169FB4a3325136EB29fA0ceB6D2e539a432`,
          description: erc8004.description,
          image: erc8004.image,
          services: erc8004.services,
          supportedTrust: erc8004.supportedTrust,
          x402Support: erc8004.x402Support
        } : null,
        avatarUrl: agents[name].avatarUrl || (erc8004 && erc8004.image) || null,
        ...profileData,
        owner: agents[name].owner ? { xUsername: agents[name].owner.xUsername, linkedAt: agents[name].owner.linkedAt } : null
      }
    });
  } catch (err) {
    console.error('Error fetching activity:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get wallet for an agent
app.get('/agents/:name/wallet', authenticateAgent, (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  if (!agents[name].wallet) {
    return res.status(404).json({ success: false, error: 'Agent does not have a wallet yet' });
  }

  const response = {
    success: true,
    wallet: {
      address: agents[name].wallet.address,
      network: MONAD_NETWORK_NAME,
      chainId: MONAD_CHAIN_ID,
      explorer: `${MONAD_EXPLORER}/address/${agents[name].wallet.address}`
    }
  };

  // Check if agent needs to update their skill knowledge
  const updateInfo = checkSkillUpdate(agents[name]);
  if (updateInfo) {
    response.skill_update = updateInfo;
  }

  // Check for pending notifications
  const pending = getPendingNotifications(name);
  if (pending.length > 0) {
    response.notifications = {
      pending: pending.length,
      hint: `You have ${pending.length} unread notification(s). GET /agents/${name}/notifications to view.`
    };
  }

  res.json(response);
});

// Get wallet balance (MON and optionally tokens) - public for dashboard
app.get('/agents/:name/wallet/balance', async (req, res) => {
  const { name } = req.params;
  const { token } = req.query; // Optional token contract address
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  if (!agents[name].wallet) {
    return res.status(404).json({ success: false, error: 'Agent does not have a wallet' });
  }

  try {
    const walletAddress = agents[name].wallet.address;

    // Use Monad RPC to get balance
    const rpcUrl = MONAD_RPC_URL;

    // Get MON balance
    const monBalanceResponse = await httpRequest(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'eth_getBalance',
        params: [walletAddress, 'latest'],
        id: 1
      })
    });

    const monBalanceWei = monBalanceResponse.result || '0x0';
    const monBalance = parseInt(monBalanceWei, 16) / 1e18;

    const response = {
      success: true,
      address: walletAddress,
      network: MONAD_NETWORK_NAME,
      chainId: MONAD_CHAIN_ID,
      explorer: `${MONAD_EXPLORER}/address/${walletAddress}`,
      mon: {
        balance: monBalance.toFixed(6),
        balanceWei: monBalanceWei,
        hasGas: monBalance > 0.0001
      },
      tokens: []
    };

    // Fetch balances for common tokens
    const tokensToCheck = [
      { symbol: 'USDC', address: MONAD_TOKENS.USDC, decimals: 6 },
      { symbol: 'USDT0', address: MONAD_TOKENS.USDT, decimals: 6 },
      { symbol: 'WETH', address: MONAD_TOKENS.WETH, decimals: 18 },
      { symbol: 'WBTC', address: MONAD_TOKENS.WBTC, decimals: 8 }
    ];

    const balanceOfData = '0x70a08231000000000000000000000000' + walletAddress.slice(2).toLowerCase();

    // Fetch all token balances in parallel
    const tokenBalancePromises = tokensToCheck.map(async (tokenInfo) => {
      try {
        const tokenBalanceResponse = await httpRequest(rpcUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'eth_call',
            params: [{ to: tokenInfo.address, data: balanceOfData }, 'latest'],
            id: 1
          })
        });
        const balanceHex = tokenBalanceResponse.result || '0x0';
        const balanceRaw = parseInt(balanceHex, 16);
        const balance = balanceRaw / Math.pow(10, tokenInfo.decimals);
        return {
          symbol: tokenInfo.symbol,
          address: tokenInfo.address,
          decimals: tokenInfo.decimals,
          balance: balance.toFixed(tokenInfo.decimals), // Use token's native precision
          balanceRaw: balanceRaw.toString()
        };
      } catch (err) {
        return null;
      }
    });

    const tokenBalances = await Promise.all(tokenBalancePromises);
    // Always include core tokens (even with zero balance) so they're visible in the UI
    response.tokens = tokenBalances.filter(t => t !== null);

    // If specific token address provided, get that balance too
    if (token) {
      const tokenBalanceResponse = await httpRequest(rpcUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'eth_call',
          params: [{
            to: token,
            data: balanceOfData
          }, 'latest'],
          id: 2
        })
      });

      const tokenBalanceHex = tokenBalanceResponse.result || '0x0';
      response.token = {
        contract: token,
        balanceRaw: tokenBalanceHex,
        // Note: caller needs to know decimals to interpret this
        balanceDecimal: parseInt(tokenBalanceHex, 16).toString()
      };
    }

    // Add warning if no gas
    if (!response.mon.hasGas) {
      response.warning = 'No MON for gas! You cannot send any transactions until you receive MON.';
    }

    // Check if agent needs skill update
    const updateInfo = checkSkillUpdate(agents[name]);
    if (updateInfo) {
      response.skill_update = updateInfo;
    }

    res.json(response);
  } catch (err) {
    console.error('Balance check error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// NFT cache for profile pictures
const nftCache = new Map(); // walletAddress -> { nfts, fetchedAt }
const NFT_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Get NFTs owned by agent's wallet (for profile pictures)
app.get('/agents/:name/nfts', async (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  if (!agents[name].wallet) {
    return res.status(404).json({ success: false, error: 'Agent does not have a wallet' });
  }

  const walletAddress = agents[name].wallet.address;

  // Check cache
  const cached = nftCache.get(walletAddress);
  if (cached && Date.now() - cached.fetchedAt < NFT_CACHE_TTL) {
    return res.json({ success: true, nfts: cached.nfts, cached: true, profileImage: cached.profileImage });
  }

  try {
    // Try Magic Eden API with different chain values for Monad
    const chainOptions = ['monad', 'monad-mainnet', 'monadMainnet'];
    let nfts = [];
    let profileImage = null;

    for (const chain of chainOptions) {
      try {
        const url = `https://api-mainnet.magiceden.dev/v4/evm-public/assets/user-assets?chain=${chain}&walletAddresses[]=${walletAddress}&limit=20`;
        const response = await httpRequest(url, {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
            'User-Agent': 'Clawnads/1.0'
          }
        });

        if (response && response.assets && response.assets.length > 0) {
          nfts = response.assets.map(asset => ({
            id: asset.id || asset.tokenId,
            name: asset.name || asset.token?.name || 'Unknown NFT',
            image: asset.image || asset.token?.image || asset.token?.media?.image?.url || null,
            collection: asset.collection?.name || asset.collectionName || null,
            contractAddress: asset.contract || asset.token?.contract
          })).filter(nft => nft.image); // Only include NFTs with images

          // Use first NFT with image as profile picture
          if (nfts.length > 0) {
            profileImage = nfts[0].image;
          }
          break; // Success, stop trying other chains
        }
      } catch (err) {
        // Try next chain option
        console.log(`Magic Eden chain "${chain}" failed:`, err.message);
      }
    }

    // Cache results (even if empty)
    nftCache.set(walletAddress, { nfts, profileImage, fetchedAt: Date.now() });

    res.json({
      success: true,
      nfts,
      profileImage,
      cached: false,
      message: nfts.length === 0 ? 'No NFTs found or Monad not yet supported by Magic Eden API' : null
    });
  } catch (err) {
    console.error('NFT fetch error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Create wallet for an existing agent
app.post('/agents/:name/wallet', authenticateAgent, async (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  if (agents[name].wallet) {
    return res.json({
      success: true,
      message: 'Agent already has a wallet',
      wallet: {
        address: agents[name].wallet.address,
        network: MONAD_NETWORK_NAME,
        chainId: MONAD_CHAIN_ID
      }
    });
  }

  try {
    const walletData = await createPrivyWallet(name);
    agents[name].wallet = {
      id: walletData.id,
      address: walletData.address,
      chainType: walletData.chain_type,
      createdAt: new Date().toISOString()
    };
    saveAgents(agents);

    console.log(`Created wallet ${agents[name].wallet.address} for ${name}`);

    res.json({
      success: true,
      wallet: {
        address: agents[name].wallet.address,
        network: MONAD_NETWORK_NAME,
        chainId: MONAD_CHAIN_ID
      }
    });
  } catch (err) {
    console.error('Wallet creation error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Sign a message with agent's wallet
app.post('/agents/:name/wallet/sign', authenticateAgent, async (req, res) => {
  const { name } = req.params;
  const { message } = req.body;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  if (!agents[name].wallet) {
    return res.status(404).json({ success: false, error: 'Agent does not have a wallet' });
  }

  if (!message) {
    return res.status(400).json({ success: false, error: 'message is required' });
  }

  try {
    const auth = Buffer.from(`${PRIVY_APP_ID}:${PRIVY_APP_SECRET}`).toString('base64');
    const walletId = agents[name].wallet.id;

    const response = await httpRequest(`https://api.privy.io/v1/wallets/${walletId}/rpc`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'privy-app-id': PRIVY_APP_ID,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        method: 'personal_sign',
        caip2: `eip155:${MONAD_CHAIN_ID}`,
        params: {
          message: message
        }
      })
    });

    res.json({
      success: true,
      signature: response.data?.signature,
      message: message
    });
  } catch (err) {
    console.error('Sign error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Send a transaction from agent's wallet
app.post('/agents/:name/wallet/send', authenticateAgent, swapSendRateLimit, async (req, res) => {
  const { name } = req.params;
  const { to, value, data } = req.body;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  if (!agents[name].wallet) {
    return res.status(404).json({ success: false, error: 'Agent does not have a wallet' });
  }

  if (!to) {
    return res.status(400).json({ success: false, error: 'to address is required' });
  }

  // Check transfer limits (shared with swap daily cap)
  const limitCheck = checkTransferLimits(name, agents[name], value || '0x0');
  if (!limitCheck.allowed) {
    return res.status(403).json({
      success: false,
      error: limitCheck.error,
      limit: limitCheck.limit
    });
  }

  // Withdrawal protection: detect if recipient is outside the platform
  // Agent-to-agent transfers within the platform are allowed freely.
  // Sends to external addresses (offboarding funds) require operator approval.
  let actualRecipientAddr = to;
  if (data && data.startsWith('0xa9059cbb') && data.length >= 74) {
    // ERC-20 transfer(address,uint256) — decode actual recipient from calldata
    actualRecipientAddr = '0x' + data.slice(34, 74);
  }
  const isAgentRecipient = Object.values(agents).some(a =>
    a.wallet?.address?.toLowerCase() === actualRecipientAddr.toLowerCase()
  );

  if (!isAgentRecipient) {
    // External withdrawal — queue for operator approval instead of executing
    if (!agents[name].pendingWithdrawals) {
      agents[name].pendingWithdrawals = [];
    }
    const withdrawalId = `wd_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
    const withdrawal = {
      id: withdrawalId,
      to,
      value: value || '0x0',
      data: data || null,
      valueMON: limitCheck.valueMON || 0,
      requestedAt: new Date().toISOString(),
      status: 'pending'
    };
    agents[name].pendingWithdrawals.push(withdrawal);
    saveAgents(agents);

    console.log(`Withdrawal queued for ${name}: ${withdrawalId} → ${actualRecipientAddr} (${withdrawal.valueMON} MON)`);

    // Notify the agent's operator via webhook/notification
    queueNotification(name, {
      type: 'withdrawal_request',
      message: `Agent ${name} requested withdrawal of ${withdrawal.valueMON} MON to external address ${actualRecipientAddr}. Approve via admin API: POST /admin/agents/${name}/withdrawals/${withdrawalId}/approve`,
      withdrawal
    });

    return res.status(202).json({
      success: true,
      status: 'pending_approval',
      withdrawalId,
      message: 'Withdrawal to external address requires operator approval. Your operator has been notified.',
      to: actualRecipientAddr,
      valueMON: withdrawal.valueMON
    });
  }

  try {
    const auth = Buffer.from(`${PRIVY_APP_ID}:${PRIVY_APP_SECRET}`).toString('base64');
    const walletId = agents[name].wallet.id;

    const transaction = {
      to: to,
      value: value || '0x0'
    };

    if (data) {
      transaction.data = data;
    }

    const response = await httpRequest(`https://api.privy.io/v1/wallets/${walletId}/rpc`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'privy-app-id': PRIVY_APP_ID,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        method: 'eth_sendTransaction',
        caip2: `eip155:${MONAD_CHAIN_ID}`,
        chain_type: 'ethereum',
        params: {
          transaction: transaction
        }
      })
    });

    const txHash = response.data?.hash;
    console.log(`Transaction sent for ${name}: ${txHash}`);

    // Reload agents to get latest data before saving
    const freshAgents = loadAgents();
    if (!freshAgents[name]) {
      console.error(`Agent ${name} disappeared while sending transaction!`);
      return res.json({
        success: true,
        hash: txHash,
        transactionId: response.data?.transaction_id,
        explorer: `${MONAD_EXPLORER}/tx/${txHash}`,
        warning: 'Transaction sent but could not save to history'
      });
    }

    // Track transaction in agent's history
    if (!freshAgents[name].transactions) {
      freshAgents[name].transactions = [];
    }
    const txRecord = {
      hash: txHash,
      to: to,
      value: value || '0x0',
      data: data || null,
      type: 'send',
      timestamp: new Date().toISOString(),
      network: MONAD_NETWORK_NAME,
      chainId: MONAD_CHAIN_ID
    };

    // Check if recipient is a registered agent
    // For ERC-20 transfers, decode the actual recipient from calldata
    let actualRecipient = to;
    if (data && data.startsWith('0xa9059cbb') && data.length >= 74) {
      actualRecipient = '0x' + data.slice(34, 74);
    }
    const recipientAgent = Object.entries(freshAgents).find(([agentName, agentData]) =>
      agentData.wallet?.address?.toLowerCase() === actualRecipient.toLowerCase() && agentName !== name
    );

    if (recipientAgent) {
      const [recipientName] = recipientAgent;
      txRecord.type = 'transfer';
      txRecord.toAgent = recipientName;

      // Record incoming transfer on recipient's side
      if (!freshAgents[recipientName].transactions) {
        freshAgents[recipientName].transactions = [];
      }
      freshAgents[recipientName].transactions.push({
        hash: txHash,
        from: freshAgents[name].wallet.address,
        fromAgent: name,
        to: to,
        value: value || '0x0',
        type: 'transfer',
        direction: 'incoming',
        isIncoming: true,
        timestamp: new Date().toISOString(),
        network: MONAD_NETWORK_NAME,
        chainId: MONAD_CHAIN_ID
      });
      console.log(`Inter-agent transfer: ${name} → ${recipientName}`);
    }

    freshAgents[name].transactions.push(txRecord);

    // Update daily volume tracker (sends share the same cap as swaps)
    if (freshAgents[name].tradingConfig && limitCheck?.valueMON) {
      const today = new Date().toISOString().slice(0, 10);
      if (!freshAgents[name].tradingConfig.dailyVolume || freshAgents[name].tradingConfig.dailyVolume.date !== today) {
        freshAgents[name].tradingConfig.dailyVolume = { date: today, totalMON: '0', tradeCount: 0 };
      }
      const currentTotal = parseFloat(freshAgents[name].tradingConfig.dailyVolume.totalMON);
      freshAgents[name].tradingConfig.dailyVolume.totalMON = (currentTotal + limitCheck.valueMON).toFixed(6);
      freshAgents[name].tradingConfig.dailyVolume.tradeCount += 1;
    }

    saveAgents(freshAgents);
    analytics.trackEvent('agent_send', name, { valueMON: limitCheck?.valueMON || 0 });
    console.log(`Transaction recorded for ${name}: ${JSON.stringify(txRecord)}`);

    const responseData = {
      success: true,
      hash: txHash,
      transactionId: response.data?.transaction_id,
      explorer: `${MONAD_EXPLORER}/tx/${txHash}`
    };
    if (recipientAgent) {
      responseData.toAgent = recipientAgent[0];
    }
    res.json(responseData);
  } catch (err) {
    console.error('Send transaction error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Fetch on-chain transaction history - currently returns empty since Monad explorers
// don't have public APIs. Transactions are tracked locally when sent through our service.
// Future: integrate with a Monad indexer when available.
async function fetchOnChainTransactions(address) {
  // Note: Standard Ethereum RPC doesn't support listing transactions by address.
  // We'd need an indexer API. For now, return empty and rely on locally tracked txs.
  return [];
}

// Get transaction history for an agent - public for dashboard
app.get('/agents/:name/transactions', async (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  // Start with locally tracked transactions
  let transactions = (agents[name].transactions || []).map(tx => ({
    ...tx,
    explorer: tx.hash ? `${MONAD_EXPLORER}/tx/${tx.hash}` : (tx.explorer || null)
  }));

  // If we have a wallet and few/no local transactions, try to fetch on-chain history
  if (agents[name].wallet && transactions.length < 5) {
    try {
      const onChainTxs = await fetchOnChainTransactions(agents[name].wallet.address);

      // Merge with local transactions, avoiding duplicates
      const existingHashes = new Set(transactions.map(tx => tx.hash?.toLowerCase()));
      const newTxs = onChainTxs.filter(tx => !existingHashes.has(tx.hash?.toLowerCase()));

      transactions = [...transactions, ...newTxs];
    } catch (err) {
      console.error('Error fetching on-chain transactions:', err.message);
    }
  }

  // Sort by timestamp, most recent first
  transactions.sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0));

  res.json({
    success: true,
    agent: name,
    transactions
  });
});

// Log strategy reasoning (for non-swap decisions: launching a strategy, rebalancing plan, etc.)
app.post('/agents/:name/reasoning', authenticateAgent, (req, res) => {
  const { name } = req.params;
  const { strategy, summary, marketContext, confidence } = req.body;

  const VALID_STRATEGIES = ['diversification', 'rebalance', 'take-profit', 'buy-dip', 'market-opportunity', 'hedge', 'other'];

  if (!strategy || !summary) {
    return res.status(400).json({ error: 'strategy and summary are required' });
  }

  const agents = loadAgents();
  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  if (!agents[name].transactions) agents[name].transactions = [];

  const entry = {
    type: 'reasoning',
    timestamp: new Date().toISOString(),
    reasoning: {
      strategy: VALID_STRATEGIES.includes(strategy) ? strategy : 'other',
      summary: typeof summary === 'string' ? summary.slice(0, 500) : '',
    }
  };

  if (marketContext && typeof marketContext === 'string') {
    entry.reasoning.marketContext = marketContext.slice(0, 300);
  }
  if (confidence !== undefined) {
    const conf = parseFloat(confidence);
    entry.reasoning.confidence = isNaN(conf) ? null : Math.max(0, Math.min(1, conf));
  }

  agents[name].transactions.push(entry);
  saveAgents(agents);
  analytics.trackEvent('reasoning_entry', name);

  res.json({ success: true, entry });
});

// Submit a strategy performance report (after a time-boxed trading session)
app.post('/agents/:name/strategy/report', authenticateAgent, (req, res) => {
  const { name } = req.params;
  const { strategy, summary, timeWindow, portfolioBefore, portfolioAfter, trades, confidence } = req.body;

  const VALID_STRATEGIES = ['diversification', 'rebalance', 'take-profit', 'buy-dip', 'market-opportunity', 'hedge', 'other'];

  if (!strategy || !summary) {
    return res.status(400).json({ success: false, error: 'strategy and summary are required' });
  }
  if (!timeWindow || !timeWindow.start || !timeWindow.end || timeWindow.durationMinutes === undefined) {
    return res.status(400).json({ success: false, error: 'timeWindow with start, end, and durationMinutes is required' });
  }
  if (!portfolioBefore || !portfolioBefore.totalValueMON || !Array.isArray(portfolioBefore.holdings)) {
    return res.status(400).json({ success: false, error: 'portfolioBefore with totalValueMON and holdings array is required' });
  }
  if (!portfolioAfter || !portfolioAfter.totalValueMON || !Array.isArray(portfolioAfter.holdings)) {
    return res.status(400).json({ success: false, error: 'portfolioAfter with totalValueMON and holdings array is required' });
  }
  if (!Array.isArray(trades)) {
    return res.status(400).json({ success: false, error: 'trades array is required' });
  }

  const agents = loadAgents();
  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  // Calculate P&L
  const beforeValue = parseFloat(portfolioBefore.totalValueMON) || 0;
  const afterValue = parseFloat(portfolioAfter.totalValueMON) || 0;
  const pnlMON = (afterValue - beforeValue).toFixed(6);
  const pnlPercent = beforeValue > 0 ? (((afterValue - beforeValue) / beforeValue) * 100).toFixed(2) : '0.00';

  const report = {
    id: 'sr_' + Date.now(),
    timestamp: new Date().toISOString(),
    strategy: VALID_STRATEGIES.includes(strategy) ? strategy : 'other',
    summary: typeof summary === 'string' ? summary.slice(0, 500) : '',
    timeWindow: {
      start: timeWindow.start,
      end: timeWindow.end,
      durationMinutes: parseFloat(timeWindow.durationMinutes) || 0,
    },
    portfolioBefore: {
      totalValueMON: String(portfolioBefore.totalValueMON),
      holdings: portfolioBefore.holdings.map(h => ({
        symbol: h.symbol || 'unknown',
        balance: String(h.balance || '0'),
        valueMON: String(h.valueMON || '0'),
      })),
    },
    portfolioAfter: {
      totalValueMON: String(portfolioAfter.totalValueMON),
      holdings: portfolioAfter.holdings.map(h => ({
        symbol: h.symbol || 'unknown',
        balance: String(h.balance || '0'),
        valueMON: String(h.valueMON || '0'),
      })),
    },
    trades: trades.slice(0, 50).map(t => ({
      hash: t.hash || '',
      sellSymbol: t.sellSymbol || '',
      buySymbol: t.buySymbol || '',
      sellAmount: String(t.sellAmount || '0'),
      buyAmount: String(t.buyAmount || '0'),
      timestamp: t.timestamp || '',
    })),
    performance: {
      pnlMON,
      pnlPercent,
      tradesExecuted: trades.length,
    },
  };

  if (confidence !== undefined) {
    const conf = parseFloat(confidence);
    report.confidence = isNaN(conf) ? null : Math.max(0, Math.min(1, conf));
  }

  if (!agents[name].strategyReports) agents[name].strategyReports = [];
  agents[name].strategyReports.push(report);
  saveAgents(agents);
  analytics.trackEvent('strategy_report', name);

  res.json({ success: true, report });
});

// Get strategy performance reports (public — dashboard needs access)
app.get('/agents/:name/strategy/reports', (req, res) => {
  const { name } = req.params;
  const limit = Math.min(parseInt(req.query.limit) || 20, 100);

  const agents = loadAgents();
  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  const reports = (agents[name].strategyReports || [])
    .slice()
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
    .slice(0, limit);

  res.json({ success: true, agent: name, count: reports.length, reports });
});

// Refresh agent's profile
app.post('/agents/:name/refresh', authenticateAgent, async (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  try {
    const moltbookKey = getAgentMoltbookKey(name) || agents[name].apiKey;
    if (!moltbookKey) {
      // No Moltbook key — return cached profile data
      return res.json({
        success: true,
        agent: agents[name].profile || { name },
        note: 'No Moltbook API key configured. Using cached profile.'
      });
    }
    const profileData = await fetchMoltbookProfile(moltbookKey);
    agents[name].profile = profileData;
    agents[name].lastRefresh = new Date().toISOString();
    saveAgents(agents);

    res.json({ success: true, agent: profileData });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ==================== SWAP ENDPOINTS (Uniswap V3) ====================

// Get list of known tokens on Monad
app.get('/tokens', (req, res) => {
  res.json({
    success: true,
    chainId: MONAD_CHAIN_ID,
    tokens: MONAD_TOKENS
  });
});

// Get current token prices (MON and USDC denominated, cached 60s)
app.get('/tokens/prices', async (req, res) => {
  try {
    const prices = await fetchTokenPrices();
    const cacheAge = tokenPriceCache.lastFetched ? Math.round((Date.now() - tokenPriceCache.lastFetched) / 1000) : 0;
    const nextRefresh = Math.max(0, Math.round((tokenPriceCache.ttlMs - (Date.now() - (tokenPriceCache.lastFetched || 0))) / 1000));

    res.json({
      success: true,
      baseCurrency: 'MON',
      chainId: MONAD_CHAIN_ID,
      timestamp: new Date().toISOString(),
      prices,
      cached: cacheAge > 0,
      cacheAge: cacheAge + 's',
      nextRefresh: nextRefresh + 's'
    });
  } catch (err) {
    console.error('Token prices error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Helper: Encode Uniswap V3 QuoterV2.quoteExactInputSingle call
function encodeQuoteExactInputSingle(tokenIn, tokenOut, amountIn, fee) {
  // quoteExactInputSingle((address tokenIn, address tokenOut, uint256 amountIn, uint24 fee, uint160 sqrtPriceLimitX96))
  const selector = 'c6a5026a'; // quoteExactInputSingle selector
  const params = [
    tokenIn.slice(2).padStart(64, '0'),
    tokenOut.slice(2).padStart(64, '0'),
    BigInt(amountIn).toString(16).padStart(64, '0'),
    fee.toString(16).padStart(64, '0'),
    '0'.padStart(64, '0') // sqrtPriceLimitX96 = 0
  ].join('');
  return '0x' + selector + params;
}

// Helper: Encode Uniswap V3 SwapRouter02.exactInputSingle call
function encodeExactInputSingle(tokenIn, tokenOut, fee, recipient, amountIn, amountOutMin) {
  // exactInputSingle((address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96))
  const selector = '04e45aaf'; // exactInputSingle selector
  const params = [
    tokenIn.slice(2).padStart(64, '0'),
    tokenOut.slice(2).padStart(64, '0'),
    fee.toString(16).padStart(64, '0'),
    recipient.slice(2).padStart(64, '0'),
    BigInt(amountIn).toString(16).padStart(64, '0'),
    BigInt(amountOutMin).toString(16).padStart(64, '0'),
    '0'.padStart(64, '0') // sqrtPriceLimitX96 = 0
  ].join('');
  return '0x' + selector + params;
}

// Helper: Get quote from Uniswap V3 QuoterV2 via RPC eth_call
async function getUniswapQuote(tokenIn, tokenOut, amountIn) {
  // Try different fee tiers to find the best quote
  let bestQuote = null;
  let bestFee = null;

  for (const fee of FEE_TIERS) {
    try {
      const callData = encodeQuoteExactInputSingle(tokenIn, tokenOut, amountIn, fee);

      const response = await httpRequest(MONAD_RPC_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'eth_call',
          params: [{
            to: UNISWAP_V3.QUOTER_V2,
            data: callData
          }, 'latest'],
          id: 1
        })
      });

      if (response.result && response.result !== '0x') {
        // Decode the result - returns (uint256 amountOut, uint160 sqrtPriceX96After, uint32 initializedTicksCrossed, uint256 gasEstimate)
        const amountOut = BigInt('0x' + response.result.slice(2, 66));

        if (!bestQuote || amountOut > bestQuote) {
          bestQuote = amountOut;
          bestFee = fee;
        }
      }
    } catch (err) {
      // Pool doesn't exist for this fee tier, try next
      console.log(`No pool for fee tier ${fee}: ${err.message}`);
    }
  }

  return { amountOut: bestQuote, fee: bestFee };
}

// Helper: Resolve token symbol to address
function resolveTokenAddress(tokenInput) {
  if (!tokenInput) return null;

  // If it's already an address (starts with 0x), return as-is
  if (tokenInput.startsWith('0x')) {
    return tokenInput;
  }

  // Try to match symbol (case-insensitive)
  const symbol = tokenInput.toUpperCase();
  if (MONAD_TOKENS[symbol]) {
    return MONAD_TOKENS[symbol];
  }

  return null;
}

// Helper: Reverse-lookup token symbol from address
function getSymbolForAddress(address) {
  if (!address) return null;
  const addrLower = address.toLowerCase();
  for (const [symbol, addr] of Object.entries(MONAD_TOKENS)) {
    if (addr.toLowerCase() === addrLower) return symbol;
  }
  return null;
}

// Fetch token prices (all known tokens priced in MON and USDC, cached 60s)
async function fetchTokenPrices() {
  const now = Date.now();
  if (tokenPriceCache.prices && tokenPriceCache.lastFetched && (now - tokenPriceCache.lastFetched) < tokenPriceCache.ttlMs) {
    return tokenPriceCache.prices;
  }

  const prices = {
    MON: { priceMON: '1.000000', priceUSDC: null }
  };

  // Quote 1 WMON -> each token to get MON/TOKEN price
  const referenceAmountWMON = '1000000000000000000'; // 1 WMON (18 decimals)
  const tokensToPrice = [
    { symbol: 'USDC', address: MONAD_TOKENS.USDC, decimals: 6 },
    { symbol: 'USDT', address: MONAD_TOKENS.USDT, decimals: 6 },
    { symbol: 'WETH', address: MONAD_TOKENS.WETH, decimals: 18 },
    { symbol: 'WBTC', address: MONAD_TOKENS.WBTC, decimals: 8 }
  ];

  // Fetch all prices in parallel
  const pricePromises = tokensToPrice.map(async (token) => {
    try {
      // Quote: 1 WMON -> TOKEN gives us how much TOKEN per MON
      const { amountOut } = await getUniswapQuote(MONAD_TOKENS.WMON, token.address, referenceAmountWMON);
      if (!amountOut) return { symbol: token.symbol, priceMON: null };

      const tokenPerMON = Number(amountOut) / Math.pow(10, token.decimals);
      const monPerToken = tokenPerMON > 0 ? 1 / tokenPerMON : 0;

      return {
        symbol: token.symbol,
        priceMON: monPerToken.toFixed(6),
        tokenPerMON: tokenPerMON.toFixed(token.decimals > 6 ? 6 : token.decimals)
      };
    } catch (err) {
      console.error(`Price fetch error for ${token.symbol}:`, err.message);
      return { symbol: token.symbol, priceMON: null };
    }
  });

  const results = await Promise.all(pricePromises);

  // Find USDC price for cross-rates
  let monPriceUSDC = null;
  for (const r of results) {
    if (r.symbol === 'USDC' && r.tokenPerMON) {
      monPriceUSDC = parseFloat(r.tokenPerMON);
      prices.MON.priceUSDC = monPriceUSDC.toFixed(6);
    }
  }

  for (const r of results) {
    if (r.priceMON) {
      const priceMONFloat = parseFloat(r.priceMON);
      prices[r.symbol] = {
        priceMON: r.priceMON,
        priceUSDC: monPriceUSDC ? (priceMONFloat * monPriceUSDC).toFixed(6) : null
      };
    }
  }

  tokenPriceCache.prices = prices;
  tokenPriceCache.lastFetched = now;

  return prices;
}

// Check transfer limits for /wallet/send (reuses tradingConfig limits)
// Sends and swaps share the same daily cap to prevent drain-via-send bypass
function checkTransferLimits(agentName, agent, hexValue) {
  const config = agent.tradingConfig;
  if (!config) {
    return { allowed: true }; // No limits configured, pass through
  }

  // Convert hex value to MON (18 decimals)
  let valueMON = 0;
  if (hexValue && hexValue !== '0x0' && hexValue !== '0x') {
    try {
      valueMON = Number(BigInt(hexValue)) / 1e18;
    } catch (e) {
      return { allowed: false, error: 'Invalid value format' };
    }
  }

  // Skip limit checks for zero-value transactions (contract calls with no MON transfer)
  if (valueMON === 0) {
    return { allowed: true };
  }

  // 1. Check per-trade limit
  const maxPerTrade = parseFloat(config.maxPerTradeMON || '0.1');
  if (valueMON > maxPerTrade) {
    return {
      allowed: false,
      error: `Transfer of ${valueMON.toFixed(6)} MON exceeds per-transaction limit of ${maxPerTrade} MON`,
      limit: 'maxPerTrade'
    };
  }

  // 2. Check daily volume cap (shared with swaps)
  const today = new Date().toISOString().slice(0, 10);
  if (!config.dailyVolume || config.dailyVolume.date !== today) {
    config.dailyVolume = { date: today, totalMON: '0', tradeCount: 0 };
  }

  const dailyCap = parseFloat(config.dailyCapMON || '0.5');
  const currentDailyTotal = parseFloat(config.dailyVolume.totalMON);
  if (currentDailyTotal + valueMON > dailyCap) {
    return {
      allowed: false,
      error: `Transfer would exceed daily cap. Used: ${currentDailyTotal.toFixed(6)} MON, this transfer: ${valueMON.toFixed(6)} MON, cap: ${dailyCap} MON`,
      limit: 'dailyCap'
    };
  }

  return { allowed: true, valueMON };
}

// Check trading limits before a swap (returns { allowed: true/false, error?, sellAmountMON? })
async function checkTradingLimits(agentName, agent, sellToken, buyToken, sellAmount) {
  const config = agent.tradingConfig;
  if (!config || !config.enabled) {
    return { allowed: true }; // No limits configured, pass through
  }

  // 1. Check allowed tokens
  const sellSymbol = getSymbolForAddress(sellToken);
  const buySymbol = getSymbolForAddress(buyToken);

  if (sellSymbol && !config.allowedTokens.includes(sellSymbol)) {
    return { allowed: false, error: `Token ${sellSymbol} is not in your allowed trading list`, limit: 'allowedTokens' };
  }
  if (buySymbol && !config.allowedTokens.includes(buySymbol)) {
    return { allowed: false, error: `Token ${buySymbol} is not in your allowed trading list`, limit: 'allowedTokens' };
  }
  // If address is not in MONAD_TOKENS at all, it's not in any whitelist
  if (!sellSymbol) {
    return { allowed: false, error: `Token ${sellToken} is not a recognized token`, limit: 'allowedTokens' };
  }
  if (!buySymbol) {
    return { allowed: false, error: `Token ${buyToken} is not a recognized token`, limit: 'allowedTokens' };
  }

  // 2. Convert sell amount to MON-equivalent
  let sellAmountMON;
  const sellAddrLower = sellToken.toLowerCase();
  if (sellAddrLower === MONAD_TOKENS.MON.toLowerCase() ||
      sellAddrLower === MONAD_TOKENS.WMON.toLowerCase()) {
    sellAmountMON = parseFloat(sellAmount) / 1e18;
  } else {
    // Get quote: sellAmount of sellToken -> WMON
    const { amountOut } = await getUniswapQuote(sellToken, MONAD_TOKENS.WMON, sellAmount);
    if (!amountOut) {
      return { allowed: false, error: 'Cannot determine MON-equivalent value for limit check', limit: 'conversion' };
    }
    sellAmountMON = Number(amountOut) / 1e18;
  }

  // 3. Check per-trade limit
  const maxPerTrade = parseFloat(config.maxPerTradeMON);
  if (sellAmountMON > maxPerTrade) {
    return {
      allowed: false,
      error: `Trade size ${sellAmountMON.toFixed(6)} MON exceeds per-trade limit of ${maxPerTrade} MON`,
      limit: 'maxPerTrade',
      tradeSizeMON: sellAmountMON.toFixed(6),
      maxPerTradeMON: config.maxPerTradeMON
    };
  }

  // 4. Check daily volume cap (reset if new day)
  const today = new Date().toISOString().slice(0, 10);
  if (!config.dailyVolume || config.dailyVolume.date !== today) {
    config.dailyVolume = { date: today, totalMON: '0', tradeCount: 0 };
  }

  const dailyCap = parseFloat(config.dailyCapMON);
  const currentDailyTotal = parseFloat(config.dailyVolume.totalMON);
  if (currentDailyTotal + sellAmountMON > dailyCap) {
    return {
      allowed: false,
      error: `Trade would exceed daily cap. Used: ${currentDailyTotal.toFixed(6)} MON, this trade: ${sellAmountMON.toFixed(6)} MON, cap: ${dailyCap} MON`,
      limit: 'dailyCap',
      usedTodayMON: currentDailyTotal.toFixed(6),
      tradeSizeMON: sellAmountMON.toFixed(6),
      dailyCapMON: config.dailyCapMON,
      remainingMON: (dailyCap - currentDailyTotal).toFixed(6)
    };
  }

  return { allowed: true, sellAmountMON };
}

// Get swap quote - uses direct V3 quoting (fast and reliable)
// Accepts either token addresses OR symbols (e.g., "MON", "USDC")
app.get('/agents/:name/wallet/swap/quote', authenticateAgent, async (req, res) => {
  const { name } = req.params;
  let { sellToken, buyToken, sellAmount, slippage } = req.query;

  // Resolve symbols to addresses
  const resolvedSellToken = resolveTokenAddress(sellToken);
  const resolvedBuyToken = resolveTokenAddress(buyToken);

  if (sellToken && !resolvedSellToken) {
    return res.status(400).json({
      success: false,
      error: `Unknown token: ${sellToken}`,
      hint: `Use a known symbol (MON, USDC, USDT, WETH, WBTC) or a contract address`,
      knownTokens: Object.keys(MONAD_TOKENS)
    });
  }

  if (buyToken && !resolvedBuyToken) {
    return res.status(400).json({
      success: false,
      error: `Unknown token: ${buyToken}`,
      hint: `Use a known symbol (MON, USDC, USDT, WETH, WBTC) or a contract address`,
      knownTokens: Object.keys(MONAD_TOKENS)
    });
  }

  // Use resolved addresses
  sellToken = resolvedSellToken;
  buyToken = resolvedBuyToken;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  if (!agents[name].wallet) {
    return res.status(404).json({ success: false, error: 'Agent does not have a wallet' });
  }

  if (!sellToken || !buyToken) {
    return res.status(400).json({ success: false, error: 'sellToken and buyToken are required' });
  }

  if (!sellAmount) {
    return res.status(400).json({ success: false, error: 'sellAmount is required' });
  }

  try {
    const isNativeSell = sellToken.toLowerCase() === '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
    const isNativeBuy = buyToken.toLowerCase() === '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';

    // Use direct V3 quote (fast and reliable)
    const tokenInAddr = isNativeSell ? MONAD_TOKENS.WMON : sellToken;
    const tokenOutAddr = isNativeBuy ? MONAD_TOKENS.WMON : buyToken;

    console.log(`Getting quote for ${name}: ${tokenInAddr} -> ${tokenOutAddr}, amount: ${sellAmount}`);

    const { amountOut, fee } = await getUniswapQuote(tokenInAddr, tokenOutAddr, sellAmount);

    if (!amountOut) {
      return res.status(400).json({
        success: false,
        error: 'No liquidity found for this pair',
        hint: 'Try a different token pair or check that the pool exists on Uniswap V3'
      });
    }

    // Get token metadata for better display
    const tokenOutMeta = await getTokenMetadata(tokenOutAddr);
    const tokenInMeta = await getTokenMetadata(tokenInAddr);

    // Calculate price (output per input)
    const amountOutFormatted = Number(amountOut) / Math.pow(10, tokenOutMeta.decimals);
    const amountInFormatted = Number(sellAmount) / Math.pow(10, tokenInMeta.decimals);
    const price = amountOutFormatted / amountInFormatted;

    // Calculate minimum output with slippage
    const slippageBps = slippage ? Math.round(parseFloat(slippage) * 100) : 50; // default 0.5%
    const amountOutMin = (amountOut * BigInt(10000 - slippageBps)) / BigInt(10000);

    res.json({
      success: true,
      quote: {
        sellToken,
        buyToken,
        sellAmount,
        sellAmountFormatted: amountInFormatted.toString(),
        sellSymbol: tokenInMeta.symbol,
        buyAmount: amountOut.toString(),
        buyAmountFormatted: amountOutFormatted.toFixed(tokenOutMeta.decimals > 6 ? 6 : tokenOutMeta.decimals),
        buySymbol: tokenOutMeta.symbol,
        buyAmountMin: amountOutMin.toString(),
        price: price.toFixed(6),
        fee,
        feePercent: (fee / 10000) + '%',
        slippage: (slippageBps / 100) + '%',
        router: UNISWAP_V3.SWAP_ROUTER_02,
        dex: 'Uniswap V3',
        route: `${tokenInMeta.symbol} -> ${tokenOutMeta.symbol} (V3 ${fee / 10000}% pool)`
      }
    });
  } catch (err) {
    console.error('Swap quote error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Execute a swap via Uniswap V3 (direct routing - fast and reliable)
// Accepts either token addresses OR symbols (e.g., "MON", "USDC")
app.post('/agents/:name/wallet/swap', authenticateAgent, swapSendRateLimit, async (req, res) => {
  const { name } = req.params;
  let { sellToken, buyToken, sellAmount, slippage, reasoning } = req.body;

  // Validate reasoning if provided
  const VALID_STRATEGIES = ['diversification', 'rebalance', 'take-profit', 'buy-dip', 'market-opportunity', 'hedge', 'other'];
  let validatedReasoning = null;
  if (reasoning && typeof reasoning === 'object') {
    validatedReasoning = {};
    if (reasoning.strategy) {
      validatedReasoning.strategy = VALID_STRATEGIES.includes(reasoning.strategy) ? reasoning.strategy : 'other';
    }
    if (reasoning.summary && typeof reasoning.summary === 'string') {
      validatedReasoning.summary = reasoning.summary.slice(0, 500);
    }
    if (reasoning.confidence !== undefined) {
      const conf = parseFloat(reasoning.confidence);
      validatedReasoning.confidence = isNaN(conf) ? null : Math.max(0, Math.min(1, conf));
    }
    if (reasoning.marketContext && typeof reasoning.marketContext === 'string') {
      validatedReasoning.marketContext = reasoning.marketContext.slice(0, 300);
    }
  }
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  if (!agents[name].wallet) {
    return res.status(404).json({ success: false, error: 'Agent does not have a wallet' });
  }

  if (!sellToken || !buyToken) {
    return res.status(400).json({ success: false, error: 'sellToken and buyToken are required' });
  }

  // Resolve symbols to addresses
  const resolvedSellToken = resolveTokenAddress(sellToken);
  const resolvedBuyToken = resolveTokenAddress(buyToken);

  if (!resolvedSellToken) {
    return res.status(400).json({
      success: false,
      error: `Unknown token: ${sellToken}`,
      hint: `Use a known symbol (MON, USDC, USDT, WETH, WBTC) or a contract address`,
      knownTokens: Object.keys(MONAD_TOKENS)
    });
  }

  if (!resolvedBuyToken) {
    return res.status(400).json({
      success: false,
      error: `Unknown token: ${buyToken}`,
      hint: `Use a known symbol (MON, USDC, USDT, WETH, WBTC) or a contract address`,
      knownTokens: Object.keys(MONAD_TOKENS)
    });
  }

  // Use resolved addresses
  sellToken = resolvedSellToken;
  buyToken = resolvedBuyToken;

  if (!sellAmount) {
    return res.status(400).json({ success: false, error: 'sellAmount is required' });
  }

  // Check trading limits (if configured)
  let limitCheck;
  try {
    limitCheck = await checkTradingLimits(name, agents[name], sellToken, buyToken, sellAmount);
    if (!limitCheck.allowed) {
      return res.status(403).json({
        success: false,
        error: limitCheck.error,
        limitViolation: {
          limit: limitCheck.limit,
          tradeSizeMON: limitCheck.tradeSizeMON,
          maxPerTradeMON: limitCheck.maxPerTradeMON,
          usedTodayMON: limitCheck.usedTodayMON,
          dailyCapMON: limitCheck.dailyCapMON,
          remainingMON: limitCheck.remainingMON
        }
      });
    }
  } catch (limitErr) {
    console.error('Trading limit check error:', limitErr);
    // Fail-closed: if we can't verify limits, block the trade
    return res.status(500).json({
      success: false,
      error: 'Trading limit check failed — trade blocked for safety. Try again or contact admin.',
      details: limitErr.message
    });
  }

  try {
    const walletAddress = agents[name].wallet.address;
    const walletId = agents[name].wallet.id;
    const auth = Buffer.from(`${PRIVY_APP_ID}:${PRIVY_APP_SECRET}`).toString('base64');

    const isNativeSell = sellToken.toLowerCase() === '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';
    const isNativeBuy = buyToken.toLowerCase() === '0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee';

    const tokenInAddr = isNativeSell ? MONAD_TOKENS.WMON : sellToken;
    const tokenOutAddr = isNativeBuy ? MONAD_TOKENS.WMON : buyToken;

    console.log(`Getting quote for swap ${name}: ${tokenInAddr} -> ${tokenOutAddr}, amount: ${sellAmount}`);

    // Step 1: Get quote from V3 quoter
    const { amountOut, fee } = await getUniswapQuote(tokenInAddr, tokenOutAddr, sellAmount);

    if (!amountOut) {
      return res.status(400).json({
        success: false,
        error: 'No liquidity found for this pair',
        hint: 'Try a different token pair or check that the pool exists on Uniswap V3'
      });
    }

    // Get token metadata for logging
    const tokenInMeta = await getTokenMetadata(tokenInAddr);
    const tokenOutMeta = await getTokenMetadata(tokenOutAddr);

    console.log(`Quote received: ${sellAmount} ${tokenInMeta.symbol} -> ${amountOut} ${tokenOutMeta.symbol} (fee: ${fee})`);

    // Step 2: Handle approvals (for non-native tokens)
    const spenderAddress = UNISWAP_V3.SWAP_ROUTER_02;

    if (!isNativeSell) {
      const allowanceData = '0xdd62ed3e' +
        walletAddress.slice(2).padStart(64, '0') +
        spenderAddress.slice(2).padStart(64, '0');

      const allowanceResponse = await httpRequest(MONAD_RPC_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          method: 'eth_call',
          params: [{ to: sellToken, data: allowanceData }, 'latest'],
          id: 1
        })
      });

      const currentAllowance = BigInt(allowanceResponse.result || '0x0');
      const needsApproval = currentAllowance < BigInt(sellAmount);

      if (needsApproval) {
        console.log(`Approval needed for ${sellToken} to ${spenderAddress}`);

        const approveData = '0x095ea7b3' +
          spenderAddress.slice(2).padStart(64, '0') +
          'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

        const approvalResponse = await httpRequest(`https://api.privy.io/v1/wallets/${walletId}/rpc`, {
          method: 'POST',
          headers: {
            'Authorization': `Basic ${auth}`,
            'privy-app-id': PRIVY_APP_ID,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            method: 'eth_sendTransaction',
            caip2: `eip155:${MONAD_CHAIN_ID}`,
            chain_type: 'ethereum',
            params: {
              transaction: { to: sellToken, data: approveData, value: '0x0' }
            }
          })
        });

        console.log(`Approval tx sent: ${approvalResponse.data?.hash}`);

        const freshAgentsApproval = loadAgents();
        if (freshAgentsApproval[name]) {
          if (!freshAgentsApproval[name].transactions) freshAgentsApproval[name].transactions = [];
          freshAgentsApproval[name].transactions.push({
            hash: approvalResponse.data?.hash,
            to: sellToken,
            value: '0x0',
            data: approveData,
            type: 'approval',
            spender: spenderAddress,
            timestamp: new Date().toISOString(),
            network: MONAD_NETWORK_NAME,
            chainId: MONAD_CHAIN_ID
          });
          saveAgents(freshAgentsApproval);
        }

        // Wait for approval to be mined
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }

    // Step 3: Build and execute the swap transaction
    const slippageBps = slippage ? Math.round(parseFloat(slippage) * 100) : 50; // default 0.5%
    const amountOutMin = (amountOut * BigInt(10000 - slippageBps)) / BigInt(10000);

    const swapData = encodeExactInputSingle(
      tokenInAddr,
      tokenOutAddr,
      fee,
      walletAddress,
      sellAmount,
      amountOutMin.toString()
    );

    const swapTx = {
      to: UNISWAP_V3.SWAP_ROUTER_02,
      data: swapData,
      value: isNativeSell ? '0x' + BigInt(sellAmount).toString(16) : '0x0'
    };

    const routeDescription = `${tokenInMeta.symbol} -> ${tokenOutMeta.symbol} (V3 ${fee / 10000}% pool)`;

    console.log(`Executing swap for ${name}: ${routeDescription}`);

    const swapResponse = await httpRequest(`https://api.privy.io/v1/wallets/${walletId}/rpc`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'privy-app-id': PRIVY_APP_ID,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        method: 'eth_sendTransaction',
        caip2: `eip155:${MONAD_CHAIN_ID}`,
        chain_type: 'ethereum',
        params: { transaction: swapTx }
      })
    });

    const txHash = swapResponse.data?.hash;

    if (!txHash) {
      console.error('Swap failed - no tx hash returned:', swapResponse);
      return res.status(500).json({
        success: false,
        error: 'Swap transaction failed',
        details: swapResponse.error || 'No transaction hash returned'
      });
    }

    console.log(`Swap transaction sent for ${name}: ${txHash}`);

    // Track transaction
    const freshAgents = loadAgents();
    if (freshAgents[name]) {
      if (!freshAgents[name].transactions) freshAgents[name].transactions = [];
      const txRecord = {
        hash: txHash,
        to: swapTx.to,
        value: swapTx.value,
        data: swapTx.data,
        type: 'swap',
        dex: 'Uniswap V3',
        route: routeDescription,
        sellToken,
        buyToken,
        sellAmount,
        buyAmount: amountOut.toString(),
        timestamp: new Date().toISOString(),
        network: MONAD_NETWORK_NAME,
        chainId: MONAD_CHAIN_ID,
        explorer: `${MONAD_EXPLORER}/tx/${txHash}`
      };
      // Attach trade reasoning if provided
      if (validatedReasoning) {
        txRecord.reasoning = validatedReasoning;
      }
      freshAgents[name].transactions.push(txRecord);

      // Update trading volume tracker
      if (freshAgents[name].tradingConfig?.enabled && limitCheck?.sellAmountMON) {
        const today = new Date().toISOString().slice(0, 10);
        if (!freshAgents[name].tradingConfig.dailyVolume || freshAgents[name].tradingConfig.dailyVolume.date !== today) {
          freshAgents[name].tradingConfig.dailyVolume = { date: today, totalMON: '0', tradeCount: 0 };
        }
        const currentTotal = parseFloat(freshAgents[name].tradingConfig.dailyVolume.totalMON);
        freshAgents[name].tradingConfig.dailyVolume.totalMON = (currentTotal + limitCheck.sellAmountMON).toFixed(6);
        freshAgents[name].tradingConfig.dailyVolume.tradeCount += 1;
      }

      saveAgents(freshAgents);
      analytics.trackEvent('agent_trade', name, { dex: 'Uniswap V3', pair: `${tokenInMeta.symbol}→${tokenOutMeta.symbol}` });
      console.log(`Swap recorded: ${JSON.stringify(txRecord)}`);
    }

    // Format output amounts for response
    const amountOutFormatted = Number(amountOut) / Math.pow(10, tokenOutMeta.decimals);
    const amountInFormatted = Number(sellAmount) / Math.pow(10, tokenInMeta.decimals);

    res.json({
      success: true,
      hash: txHash,
      explorer: `${MONAD_EXPLORER}/tx/${txHash}`,
      swap: {
        sellToken,
        sellSymbol: tokenInMeta.symbol,
        sellAmount,
        sellAmountFormatted: amountInFormatted.toString(),
        buyToken,
        buySymbol: tokenOutMeta.symbol,
        buyAmount: amountOut.toString(),
        buyAmountFormatted: amountOutFormatted.toFixed(tokenOutMeta.decimals > 6 ? 6 : tokenOutMeta.decimals),
        buyAmountMin: amountOutMin.toString(),
        price: (amountOutFormatted / amountInFormatted).toFixed(6),
        fee,
        feePercent: (fee / 10000) + '%',
        slippage: (slippageBps / 100) + '%',
        route: routeDescription,
        dex: 'Uniswap V3'
      }
    });
  } catch (err) {
    console.error('Swap execution error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ==================== DISCONNECT / RECONNECT ====================

// Disconnect an agent (preserves wallet and transactions for reconnect)
app.post('/agents/:name/disconnect', authenticateAgent, (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  // Mark as disconnected but preserve critical data
  agents[name].disconnected = true;
  agents[name].disconnectedAt = new Date().toISOString();
  // Clear the API key for security, but keep wallet
  agents[name].apiKey = null;
  saveAgents(agents);

  console.log(`Agent disconnected: ${name}`);

  res.json({
    success: true,
    message: `Disconnected ${name}. Wallet and transaction history preserved. Re-register to reconnect.`,
    wallet: agents[name].wallet ? {
      address: agents[name].wallet.address,
      preserved: true
    } : null
  });
});

// Quick reconnect (uses cached profile, skips Moltbook API call)
app.post('/agents/:name/reconnect', authenticateAgent, (req, res) => {
  const { name } = req.params;
  const { callbackUrl } = req.body;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({
      success: false,
      error: 'Agent not found. Use POST /register for first-time registration.'
    });
  }

  // Only clear disconnect flag and update lastSeen — don't accept apiKey overwrites
  agents[name] = {
    ...agents[name],
    callbackUrl: (callbackUrl && isValidCallbackUrl(callbackUrl)) ? callbackUrl : agents[name].callbackUrl || null,
    disconnected: false,
    lastSeen: new Date().toISOString()
  };
  saveAgents(agents);

  console.log(`Agent reconnected (quick): ${name}`);

  res.json({
    success: true,
    message: `Reconnected ${name}. Used cached profile (no Moltbook call).`,
    agent: {
      name,
      wallet: agents[name].wallet ? {
        address: agents[name].wallet.address,
        network: MONAD_NETWORK_NAME,
        chainId: MONAD_CHAIN_ID
      } : null,
      hasCallbackUrl: !!agents[name].callbackUrl,
      skillVersion: agents[name].skillVersion || 'unknown',
      currentSkillVersion: SKILL_VERSION,
      needsSkillUpdate: agents[name].skillVersion !== SKILL_VERSION
    }
  });
});

// Get reconnect info (what an agent needs to know before re-registering)
app.get('/agents/:name/reconnect-info', authenticateAgent, (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({
      success: false,
      error: 'Agent not found',
      hint: 'Register as a new agent with POST /register'
    });
  }

  res.json({
    success: true,
    agent: name,
    status: agents[name].disconnected ? 'disconnected' : 'connected',
    wallet: agents[name].wallet ? {
      address: agents[name].wallet.address,
      willBePreserved: true
    } : null,
    transactionCount: (agents[name].transactions || []).length,
    skillVersion: agents[name].skillVersion || 'unknown',
    currentSkillVersion: SKILL_VERSION,
    needsSkillUpdate: agents[name].skillVersion !== SKILL_VERSION,
    hasCallbackUrl: !!agents[name].callbackUrl,
    message: agents[name].disconnected
      ? 'Re-register with POST /register to reconnect. Your wallet will be preserved.'
      : 'Already connected. Re-register to update your registration.'
  });
});

// Onboarding status — shows what steps an agent has completed (public)
app.get('/agents/:name/onboarding', (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  const agent = agents[name];
  const txs = agent.transactions || [];
  const swapCount = txs.filter(t => t.type === 'swap').length;
  const reasoningCount = txs.filter(t => t.type === 'reasoning' || (t.type === 'swap' && t.reasoning)).length;

  const securityPassed = agent.securityChecks?.sandbox_enabled && agent.securityChecks?.token_from_env;

  const steps = {
    registered: { done: true, description: 'Registered with Clawnads' },
    wallet: { done: !!agent.wallet, description: 'Wallet created on Monad' },
    securityCheck: { done: !!securityPassed, description: 'Security check passed (sandbox + env token)' },
    skillLoaded: { done: !!agent.skillVersion, description: 'Skill docs loaded and acknowledged' },
    avatar: { done: !!agent.avatarUrl, description: 'Profile avatar uploaded' },
    webhook: { done: !!agent.callbackUrl, description: 'Webhook callback configured' },
    firstReasoning: { done: reasoningCount > 0, description: 'First strategy reasoning logged' },
    firstSwap: { done: swapCount > 0, description: 'First swap executed' },
    erc8004: { done: !!((agent.erc8004 || {}).agentId), description: 'ERC-8004 identity minted' },
    x402: { done: !!((agent.erc8004 || {}).x402Support?.verified), description: 'x402 payment verified' },
  };

  const completedCount = Object.values(steps).filter(s => s.done).length;
  const totalCount = Object.keys(steps).length;

  res.json({
    success: true,
    agent: name,
    progress: `${completedCount}/${totalCount}`,
    completedPercent: Math.round((completedCount / totalCount) * 100),
    steps,
    nextStep: Object.entries(steps).find(([, s]) => !s.done)?.[0] || null,
    docs: {
      skillGuide: '/SKILL.md',
      setupGuide: '/AGENT-SETUP.md',
      setupGuideNote: 'Your human (operator) should read AGENT-SETUP.md for sandbox configuration, secret management, webhook setup, and security best practices.'
    }
  });
});

// Security check — agent self-reports its security posture
app.post('/agents/:name/security/check', authenticateAgent, (req, res) => {
  const { name } = req.params;
  const { sandbox_enabled, token_from_env, sandbox_mode, sandbox_scope } = req.body;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  const warnings = [];
  const checks = {
    sandbox_enabled: !!sandbox_enabled,
    token_from_env: !!token_from_env,
    sandbox_mode: sandbox_mode || null,
    sandbox_scope: sandbox_scope || null,
    checkedAt: new Date().toISOString()
  };

  if (!sandbox_enabled) {
    warnings.push('Sandbox is NOT enabled. Prompt injections can read your LLM API keys and auth token. See /AGENT-SETUP.md Step 3.');
  }
  if (!token_from_env) {
    warnings.push('Auth token is NOT from an environment variable. Storing tokens in files or MEMORY.md is insecure.');
  }
  if (sandbox_enabled && sandbox_mode !== 'all') {
    warnings.push(`Sandbox mode is "${sandbox_mode}" — only "all" protects the main session where trading happens.`);
  }

  agents[name].securityChecks = checks;
  saveAgents(agents);

  const secure = warnings.length === 0;
  console.log(`Security check for ${name}: ${secure ? 'PASS' : 'WARNINGS'} (sandbox=${sandbox_enabled}, tokenEnv=${token_from_env})`);

  res.json({
    success: true,
    secure,
    checks,
    warnings,
    message: secure
      ? 'Security checks passed. Your agent is properly configured for trading.'
      : `Security issues found. You can still trade, but your credentials are at risk. Fix these before adding significant funds.`,
    setupGuide: secure ? null : '/AGENT-SETUP.md'
  });
});

// ==================== WITHDRAWAL APPROVAL ====================

// Admin: list pending withdrawals for an agent
app.get('/admin/agents/:name/withdrawals', authenticateAdmin, (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();
  if (!agents[name]) return res.status(404).json({ success: false, error: 'Agent not found' });

  const pending = (agents[name].pendingWithdrawals || []).filter(w => w.status === 'pending');
  res.json({ success: true, agent: name, pendingWithdrawals: pending });
});

// Admin: approve a pending withdrawal (executes the send)
app.post('/admin/agents/:name/withdrawals/:withdrawalId/approve', authenticateAdmin, async (req, res) => {
  const { name, withdrawalId } = req.params;
  const agents = loadAgents();

  if (!agents[name]) return res.status(404).json({ success: false, error: 'Agent not found' });
  if (!agents[name].wallet) return res.status(404).json({ success: false, error: 'Agent has no wallet' });

  const withdrawal = (agents[name].pendingWithdrawals || []).find(w => w.id === withdrawalId);
  if (!withdrawal) return res.status(404).json({ success: false, error: 'Withdrawal not found' });
  if (withdrawal.status !== 'pending') {
    return res.status(400).json({ success: false, error: `Withdrawal already ${withdrawal.status}` });
  }

  try {
    const auth = Buffer.from(`${PRIVY_APP_ID}:${PRIVY_APP_SECRET}`).toString('base64');
    const walletId = agents[name].wallet.id;

    const transaction = { to: withdrawal.to, value: withdrawal.value };
    if (withdrawal.data) transaction.data = withdrawal.data;

    const response = await httpRequest(`https://api.privy.io/v1/wallets/${walletId}/rpc`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${auth}`,
        'privy-app-id': PRIVY_APP_ID,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        method: 'eth_sendTransaction',
        caip2: `eip155:${MONAD_CHAIN_ID}`,
        chain_type: 'ethereum',
        params: { transaction }
      })
    });

    const txHash = response.data?.hash;
    console.log(`Withdrawal approved for ${name}: ${withdrawalId} → ${txHash}`);

    // Update withdrawal status
    const freshAgents = loadAgents();
    const wd = (freshAgents[name].pendingWithdrawals || []).find(w => w.id === withdrawalId);
    if (wd) {
      wd.status = 'approved';
      wd.approvedAt = new Date().toISOString();
      wd.txHash = txHash;
    }

    // Record in transaction history
    if (!freshAgents[name].transactions) freshAgents[name].transactions = [];
    freshAgents[name].transactions.push({
      hash: txHash,
      to: withdrawal.to,
      value: withdrawal.value,
      data: withdrawal.data || null,
      type: 'withdrawal',
      withdrawalId,
      timestamp: new Date().toISOString(),
      network: MONAD_NETWORK_NAME,
      chainId: MONAD_CHAIN_ID
    });

    saveAgents(freshAgents);

    // Notify the agent that the withdrawal was approved
    queueNotification(name, {
      type: 'withdrawal_approved',
      message: `Your withdrawal of ${withdrawal.valueMON} MON has been approved. TX: ${txHash}`,
      withdrawalId,
      txHash
    });

    res.json({
      success: true,
      withdrawalId,
      txHash,
      explorer: `${MONAD_EXPLORER}/tx/${txHash}`
    });
  } catch (err) {
    console.error(`Withdrawal execution failed for ${name}:`, err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Admin: reject a pending withdrawal
app.post('/admin/agents/:name/withdrawals/:withdrawalId/reject', authenticateAdmin, (req, res) => {
  const { name, withdrawalId } = req.params;
  const { reason } = req.body;
  const agents = loadAgents();

  if (!agents[name]) return res.status(404).json({ success: false, error: 'Agent not found' });

  const withdrawal = (agents[name].pendingWithdrawals || []).find(w => w.id === withdrawalId);
  if (!withdrawal) return res.status(404).json({ success: false, error: 'Withdrawal not found' });
  if (withdrawal.status !== 'pending') {
    return res.status(400).json({ success: false, error: `Withdrawal already ${withdrawal.status}` });
  }

  withdrawal.status = 'rejected';
  withdrawal.rejectedAt = new Date().toISOString();
  withdrawal.reason = reason || 'Rejected by admin';
  saveAgents(agents);

  console.log(`Withdrawal rejected for ${name}: ${withdrawalId} — ${withdrawal.reason}`);

  queueNotification(name, {
    type: 'withdrawal_rejected',
    message: `Your withdrawal was rejected: ${withdrawal.reason}`,
    withdrawalId,
    reason: withdrawal.reason
  });

  res.json({ success: true, withdrawalId, status: 'rejected', reason: withdrawal.reason });
});

// Agent: check status of their pending withdrawals
app.get('/agents/:name/withdrawals', authenticateAgent, (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();
  if (!agents[name]) return res.status(404).json({ success: false, error: 'Agent not found' });

  const withdrawals = agents[name].pendingWithdrawals || [];
  res.json({ success: true, agent: name, withdrawals });
});

// ==================== TRADING STRATEGY ====================

// Set trading limits for an agent
app.put('/agents/:name/trading/config', authenticateAdmin, (req, res) => {
  const { name } = req.params;
  const { enabled, maxPerTradeMON, dailyCapMON, allowedTokens } = req.body;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  // Start with existing config or defaults
  const existing = agents[name].tradingConfig || {
    enabled: false,
    maxPerTradeMON: '0.1',
    dailyCapMON: '0.5',
    allowedTokens: Object.keys(MONAD_TOKENS),
    dailyVolume: { date: new Date().toISOString().slice(0, 10), totalMON: '0', tradeCount: 0 }
  };

  // Validate and merge fields
  if (maxPerTradeMON !== undefined) {
    const val = parseFloat(maxPerTradeMON);
    if (isNaN(val) || val <= 0) {
      return res.status(400).json({ success: false, error: 'maxPerTradeMON must be a positive number' });
    }
    if (val > 50000) {
      return res.status(400).json({ success: false, error: 'maxPerTradeMON cannot exceed 50000 MON' });
    }
    existing.maxPerTradeMON = val.toString();
  }

  if (dailyCapMON !== undefined) {
    const val = parseFloat(dailyCapMON);
    if (isNaN(val) || val <= 0) {
      return res.status(400).json({ success: false, error: 'dailyCapMON must be a positive number' });
    }
    if (val > 250000) {
      return res.status(400).json({ success: false, error: 'dailyCapMON cannot exceed 250000 MON' });
    }
    const maxPer = parseFloat(existing.maxPerTradeMON);
    if (val < maxPer) {
      return res.status(400).json({ success: false, error: `dailyCapMON (${val}) must be >= maxPerTradeMON (${maxPer})` });
    }
    existing.dailyCapMON = val.toString();
  }

  if (allowedTokens !== undefined) {
    if (!Array.isArray(allowedTokens) || allowedTokens.length === 0) {
      return res.status(400).json({ success: false, error: 'allowedTokens must be a non-empty array' });
    }
    for (const t of allowedTokens) {
      if (!MONAD_TOKENS[t]) {
        return res.status(400).json({
          success: false,
          error: `Unknown token in allowedTokens: ${t}`,
          knownTokens: Object.keys(MONAD_TOKENS)
        });
      }
    }
    existing.allowedTokens = allowedTokens;
  }

  if (enabled !== undefined) {
    existing.enabled = !!enabled;
  }

  existing.configuredAt = new Date().toISOString();
  if (!existing.dailyVolume) {
    existing.dailyVolume = { date: new Date().toISOString().slice(0, 10), totalMON: '0', tradeCount: 0 };
  }

  agents[name].tradingConfig = existing;
  saveAgents(agents);

  console.log(`Trading config updated for ${name}:`, existing);

  res.json({
    success: true,
    agent: name,
    tradingConfig: existing
  });
});

// Get trading limits for an agent
app.get('/agents/:name/trading/config', authenticateAgent, (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  const config = agents[name].tradingConfig || null;

  res.json({
    success: true,
    agent: name,
    tradingConfig: config,
    ...(config ? {} : { hint: `No trading limits configured. PUT /agents/${name}/trading/config to set limits.` })
  });
});

// Get trading status dashboard (portfolio + limits + recent trades)
app.get('/agents/:name/trading/status', authenticateAgent, async (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  if (!agents[name].wallet) {
    return res.status(404).json({ success: false, error: 'Agent does not have a wallet' });
  }

  try {
    const walletAddress = agents[name].wallet.address;
    const rpcUrl = MONAD_RPC_URL;

    // Fetch MON balance
    const monBalanceResponse = await httpRequest(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'eth_getBalance',
        params: [walletAddress, 'latest'],
        id: 1
      })
    });
    const monBalanceWei = monBalanceResponse.result || '0x0';
    const monBalance = parseInt(monBalanceWei, 16) / 1e18;

    // Fetch token balances
    const tokensToCheck = [
      { symbol: 'USDC', address: MONAD_TOKENS.USDC, decimals: 6 },
      { symbol: 'USDT', address: MONAD_TOKENS.USDT, decimals: 6 },
      { symbol: 'WETH', address: MONAD_TOKENS.WETH, decimals: 18 },
      { symbol: 'WBTC', address: MONAD_TOKENS.WBTC, decimals: 8 }
    ];

    const balanceOfData = '0x70a08231000000000000000000000000' + walletAddress.slice(2).toLowerCase();

    const tokenBalancePromises = tokensToCheck.map(async (tokenInfo) => {
      try {
        const tokenBalanceResponse = await httpRequest(rpcUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'eth_call',
            params: [{ to: tokenInfo.address, data: balanceOfData }, 'latest'],
            id: 1
          })
        });
        const balanceHex = tokenBalanceResponse.result || '0x0';
        const balanceRaw = parseInt(balanceHex, 16);
        const balance = balanceRaw / Math.pow(10, tokenInfo.decimals);
        return { symbol: tokenInfo.symbol, balance, decimals: tokenInfo.decimals };
      } catch (err) {
        return { symbol: tokenInfo.symbol, balance: 0, decimals: tokenInfo.decimals };
      }
    });

    const tokenBalances = await Promise.all(tokenBalancePromises);

    // Fetch prices for valuation
    const prices = await fetchTokenPrices();

    // Build portfolio with MON-equivalent values
    let totalValueMON = monBalance;
    const holdings = [{
      symbol: 'MON',
      balance: monBalance.toFixed(6),
      valueMON: monBalance.toFixed(6),
      priceMON: '1.000000',
      allocationPct: '0' // calculated after totals
    }];

    for (const tb of tokenBalances) {
      const priceData = prices[tb.symbol];
      const priceMON = priceData ? parseFloat(priceData.priceMON) : 0;
      const valueMON = tb.balance * priceMON;
      totalValueMON += valueMON;

      holdings.push({
        symbol: tb.symbol,
        balance: tb.balance.toFixed(6),
        valueMON: valueMON.toFixed(6),
        priceMON: priceMON.toFixed(6),
        allocationPct: '0' // calculated after totals
      });
    }

    // Calculate allocation percentages
    for (const h of holdings) {
      h.allocationPct = totalValueMON > 0
        ? (parseFloat(h.valueMON) / totalValueMON * 100).toFixed(1)
        : '0.0';
    }

    // Build limits section
    const config = agents[name].tradingConfig;
    let limits;
    if (config && config.enabled) {
      const today = new Date().toISOString().slice(0, 10);
      let dailyVolume = config.dailyVolume;
      if (!dailyVolume || dailyVolume.date !== today) {
        dailyVolume = { date: today, totalMON: '0', tradeCount: 0 };
      }
      const dailyCap = parseFloat(config.dailyCapMON);
      const usedToday = parseFloat(dailyVolume.totalMON);

      limits = {
        enabled: true,
        maxPerTradeMON: config.maxPerTradeMON,
        dailyCapMON: config.dailyCapMON,
        usedTodayMON: usedToday.toFixed(6),
        remainingDailyMON: (dailyCap - usedToday).toFixed(6),
        tradesExecutedToday: dailyVolume.tradeCount,
        allowedTokens: config.allowedTokens
      };
    } else {
      limits = {
        enabled: false,
        hint: config ? 'Trading limits disabled. PUT /agents/' + name + '/trading/config with enabled:true to activate.' : 'No trading limits configured.'
      };
    }

    // Recent activity (last 5 swaps + sends/transfers)
    const allTx = agents[name].transactions || [];
    const recentTrades = allTx
      .filter(tx => tx.type === 'swap' || ((tx.type === 'send' || tx.type === 'transfer') && !tx.isIncoming) || tx.type === 'erc8004-register' || tx.type === 'x402-donation')
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, 5)
      .map(tx => {
        if (tx.type === 'swap') {
          const sellMeta = getSymbolForAddress(tx.sellToken);
          const buyMeta = getSymbolForAddress(tx.buyToken);
          return {
            timestamp: tx.timestamp,
            type: tx.type,
            route: tx.route || `${sellMeta || '?'} -> ${buyMeta || '?'}`,
            sellAmount: tx.sellAmount,
            sellSymbol: sellMeta || tx.sellToken,
            buyAmount: tx.buyAmount,
            buySymbol: buyMeta || tx.buyToken,
            explorer: tx.explorer
          };
        } else if (tx.type === 'erc8004-register' || tx.type === 'x402-donation') {
          return {
            timestamp: tx.timestamp,
            type: tx.type,
            explorer: tx.explorer || `https://monadexplorer.com/tx/${tx.hash}`
          };
        } else {
          // Send or transfer
          let tokenSymbol = 'MON';
          let amount = tx.value || '0x0';
          let toAddress = tx.to;
          if (tx.data && tx.data.startsWith('0xa9059cbb')) {
            tokenSymbol = getSymbolForAddress(tx.to) || 'TOKEN';
            toAddress = '0x' + tx.data.slice(34, 74);
            amount = '0x' + tx.data.slice(74);
          }
          return {
            timestamp: tx.timestamp,
            type: tx.type,
            toAgent: tx.toAgent || null,
            toAddress,
            tokenSymbol,
            amount,
            explorer: tx.explorer || `https://monadexplorer.com/tx/${tx.hash}`
          };
        }
      });

    res.json({
      success: true,
      agent: name,
      timestamp: new Date().toISOString(),
      limits,
      portfolio: {
        totalValueMON: totalValueMON.toFixed(6),
        holdings
      },
      recentTrades
    });
  } catch (err) {
    console.error('Trading status error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ==================== WEBHOOK NOTIFICATIONS ====================

// Notify a single agent via their callback URL (also queues for polling)
async function notifyAgent(agentName, agent, payload) {
  // Always queue the notification so agents can poll for it
  queueNotification(agentName, payload);

  if (!agent.callbackUrl) {
    return {
      agent: agentName,
      success: true,
      method: 'queued',
      message: 'Notification queued. Agent can poll GET /agents/:name/notifications'
    };
  }

  try {
    const headers = {
      'Content-Type': 'application/json',
      'X-Activity-Viewer-Event': payload.type || 'notification'
    };

    // Add Authorization header if agent has a callback secret
    if (agent.callbackSecret) {
      headers['Authorization'] = `Bearer ${agent.callbackSecret}`;
    }

    const response = await httpRequest(agent.callbackUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        ...payload,
        agent: agentName,
        timestamp: new Date().toISOString()
      })
    });
    console.log(`Notified ${agentName} at ${agent.callbackUrl}`);
    return { agent: agentName, success: true, method: 'webhook', response };
  } catch (err) {
    console.error(`Failed to notify ${agentName} via webhook:`, err.message);
    return {
      agent: agentName,
      success: true, // Still succeeded because we queued it
      method: 'queued',
      webhookError: err.message,
      message: 'Webhook failed, notification queued for polling'
    };
  }
}

// Notify all agents (webhook + queue, or queue-only)
async function notifyAllAgents(payload) {
  const agents = loadAgents();
  const results = [];

  for (const [name, agent] of Object.entries(agents)) {
    // Skip disconnected agents
    if (agent.disconnected) continue;

    const result = await notifyAgent(name, agent, payload);
    results.push(result);
  }

  return results;
}

// Update agent's callback URL
app.put('/agents/:name/callback', authenticateAgent, (req, res) => {
  const { name } = req.params;
  const { callbackUrl } = req.body;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  if (callbackUrl && !isValidCallbackUrl(callbackUrl)) {
    return res.status(400).json({ success: false, error: 'Invalid callback URL — must be a public http(s) URL' });
  }
  agents[name].callbackUrl = callbackUrl || null;
  saveAgents(agents);

  res.json({
    success: true,
    message: callbackUrl ? `Callback URL set for ${name}` : `Callback URL removed for ${name}`,
    callbackUrl: agents[name].callbackUrl
  });
});

// Update agent's Telegram chat ID for notifications
app.put('/agents/:name/telegram', authenticateAgent, (req, res) => {
  const { name } = req.params;
  const { chatId } = req.body;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  agents[name].telegramChatId = chatId || null;
  saveAgents(agents);

  res.json({
    success: true,
    message: chatId ? `Telegram chat ID set for ${name}` : `Telegram chat ID removed for ${name}`,
    telegramChatId: agents[name].telegramChatId
  });
});

// Admin: Notify all agents about skill update
app.post('/admin/notify-skill-update', authenticateAdmin, async (req, res) => {
  const { message, changes } = req.body;

  const payload = {
    type: 'skill_update',
    version: SKILL_VERSION,
    message: message || `Skill docs updated to v${SKILL_VERSION}. Please re-read /SKILL.md`,
    changes: changes || [], // Array of key changes for this version
    action: 'Re-read SKILL.md and call POST /agents/YOUR_NAME/skill-ack to acknowledge'
  };

  console.log(`Broadcasting skill update notification to all agents...`);
  const results = await notifyAllAgents(payload);

  const notified = results.filter(r => r.success).length;
  const failed = results.filter(r => !r.success).length;

  res.json({
    success: true,
    message: `Notified ${notified} agents, ${failed} failed`,
    results
  });
});

// Admin: Send custom notification to all agents
app.post('/admin/notify', authenticateAdmin, async (req, res) => {
  const { type, message, data } = req.body;

  if (!message) {
    return res.status(400).json({ success: false, error: 'message is required' });
  }

  const payload = {
    type: type || 'notification',
    message,
    ...data
  };

  const results = await notifyAllAgents(payload);

  const notified = results.filter(r => r.success).length;
  const failed = results.filter(r => !r.success).length;

  res.json({
    success: true,
    message: `Notified ${notified} agents, ${failed} failed`,
    results
  });
});

// Admin: Notify a specific agent
app.post('/admin/notify/:name', authenticateAdmin, async (req, res) => {
  const { name } = req.params;
  const { type, message, data } = req.body;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  if (!message) {
    return res.status(400).json({ success: false, error: 'message is required' });
  }

  const payload = {
    type: type || 'notification',
    message,
    ...data
  };

  const result = await notifyAgent(name, agents[name], payload);
  res.json(result);
});

// ==================== NOTIFICATION POLLING ====================
// For agents without webhook endpoints

// Get pending notifications
app.get('/agents/:name/notifications', authenticateAgent, (req, res) => {
  const { name } = req.params;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  const pending = getPendingNotifications(name);

  res.json({
    success: true,
    agent: name,
    count: pending.length,
    notifications: pending
  });
});

// Mark notifications as read
app.post('/agents/:name/notifications/ack', authenticateAgent, (req, res) => {
  const { name } = req.params;
  const { ids } = req.body; // Array of notification IDs, or 'all'
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  const idsToMark = ids || ['all'];
  markNotificationsRead(name, Array.isArray(idsToMark) ? idsToMark : [idsToMark]);

  res.json({
    success: true,
    message: `Marked ${idsToMark.includes('all') ? 'all' : idsToMark.length} notifications as read`
  });
});

// ===========================
// AGENT-TO-AGENT COMMUNICATION
// ===========================

const MESSAGES_FILE = path.join(__dirname, 'data', 'messages.json');

function loadMessages() {
  try {
    if (fs.existsSync(MESSAGES_FILE)) {
      const data = JSON.parse(fs.readFileSync(MESSAGES_FILE, 'utf8'));
      if (!data.tasks) data.tasks = {};
      return data;
    }
  } catch (err) {
    console.error('Error loading messages:', err);
  }
  return { channels: {}, directMessages: {}, tasks: {} };
}

function saveMessages(messages) {
  fs.writeFileSync(MESSAGES_FILE, JSON.stringify(messages, null, 2));
}

// --- Channels ---

// List all channels
app.get('/channels', (req, res) => {
  const messages = loadMessages();
  const channels = Object.entries(messages.channels || {}).map(([name, ch]) => ({
    name,
    description: ch.description || '',
    createdBy: ch.createdBy,
    createdAt: ch.createdAt,
    subscribers: ch.subscribers || [],
    messageCount: (ch.messages || []).length,
    lastActivity: ch.messages && ch.messages.length > 0
      ? ch.messages[ch.messages.length - 1].timestamp
      : ch.createdAt
  }));
  res.json({ success: true, channels });
});

// Create a channel
app.post('/channels', authenticateByToken, (req, res) => {
  const { name, description } = req.body;
  const agentName = req.agentName;

  if (!name || typeof name !== 'string' || !/^[a-z0-9-]{2,30}$/.test(name)) {
    return res.status(400).json({ success: false, error: 'Channel name must be 2-30 chars, lowercase alphanumeric and hyphens only' });
  }

  const messages = loadMessages();
  if (!messages.channels) messages.channels = {};

  if (messages.channels[name]) {
    return res.status(409).json({ success: false, error: 'Channel already exists' });
  }

  messages.channels[name] = {
    description: (description || '').slice(0, 200),
    createdBy: agentName,
    createdAt: new Date().toISOString(),
    subscribers: [agentName],
    messages: []
  };
  saveMessages(messages);

  console.log(`Channel created: #${name} by ${agentName}`);
  res.json({ success: true, channel: name, message: `Channel #${name} created` });
});

// Subscribe to a channel
app.post('/channels/:channel/subscribe', authenticateByToken, (req, res) => {
  const { channel } = req.params;
  const agentName = req.agentName;
  const messages = loadMessages();

  if (!messages.channels || !messages.channels[channel]) {
    return res.status(404).json({ success: false, error: 'Channel not found' });
  }

  if (!messages.channels[channel].subscribers.includes(agentName)) {
    messages.channels[channel].subscribers.push(agentName);
    saveMessages(messages);
  }

  res.json({ success: true, message: `Subscribed to #${channel}` });
});

// Unsubscribe from a channel
app.post('/channels/:channel/unsubscribe', authenticateByToken, (req, res) => {
  const { channel } = req.params;
  const agentName = req.agentName;
  const messages = loadMessages();

  if (!messages.channels || !messages.channels[channel]) {
    return res.status(404).json({ success: false, error: 'Channel not found' });
  }

  messages.channels[channel].subscribers = messages.channels[channel].subscribers.filter(s => s !== agentName);
  saveMessages(messages);

  res.json({ success: true, message: `Unsubscribed from #${channel}` });
});

// Post a message to a channel
app.post('/channels/:channel/messages', authenticateByToken, async (req, res) => {
  const { channel } = req.params;
  const agentName = req.agentName;
  const { content, type = 'text', metadata } = req.body;

  if (!content || typeof content !== 'string' || content.length > 2000) {
    return res.status(400).json({ success: false, error: 'Content required (max 2000 chars)' });
  }

  const messages = loadMessages();
  if (!messages.channels || !messages.channels[channel]) {
    return res.status(404).json({ success: false, error: 'Channel not found' });
  }

  const VALID_TYPES = ['text', 'trade-signal', 'market-analysis', 'strategy', 'alert'];
  const msg = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    from: agentName,
    content: content.slice(0, 2000),
    type: VALID_TYPES.includes(type) ? type : 'text',
    metadata: metadata && typeof metadata === 'object' ? metadata : null,
    timestamp: new Date().toISOString()
  };

  messages.channels[channel].messages.push(msg);

  // Keep last 200 messages per channel
  if (messages.channels[channel].messages.length > 200) {
    messages.channels[channel].messages = messages.channels[channel].messages.slice(-200);
  }
  saveMessages(messages);

  // Notify subscribers (except sender) via webhook + queue
  const subscribers = messages.channels[channel].subscribers.filter(s => s !== agentName);
  const agents = loadAgents();
  for (const sub of subscribers) {
    if (agents[sub]) {
      await notifyAgent(sub, agents[sub], {
        type: 'channel_message',
        channel,
        from: agentName,
        preview: content.slice(0, 100),
        messageId: msg.id,
        message: `#${channel} from ${agentName}: ${content.slice(0, 100)}`
      });
    }
  }

  analytics.trackEvent('channel_message', agentName, { channel });
  console.log(`#${channel} <- ${agentName}: ${content.slice(0, 80)}${content.length > 80 ? '...' : ''}`);
  res.json({ success: true, message: msg });
});

// Read channel messages
app.get('/channels/:channel/messages', (req, res) => {
  const { channel } = req.params;
  const { limit = 50, before, after } = req.query;
  const messages = loadMessages();

  if (!messages.channels || !messages.channels[channel]) {
    return res.status(404).json({ success: false, error: 'Channel not found' });
  }

  let msgs = messages.channels[channel].messages || [];

  if (after) {
    msgs = msgs.filter(m => m.timestamp > after);
  }
  if (before) {
    msgs = msgs.filter(m => m.timestamp < before);
  }

  // Return newest first, limited
  msgs = msgs.slice(-parseInt(limit)).reverse();

  // Normalize reactions + replies for consistent client contract
  msgs = msgs.map(m => ({
    ...m,
    reactions: m.reactions || { upvotes: [], downvotes: [] },
    replies: m.replies || []
  }));

  res.json({
    success: true,
    channel,
    count: msgs.length,
    messages: msgs
  });
});

// React to a channel message (upvote/downvote)
// Uses authenticateByToken because the sender is identified by token
app.post('/channels/:channel/messages/:messageId/react', authenticateByToken, (req, res) => {
  const { channel, messageId } = req.params;
  const agentName = req.agentName;
  const { reaction } = req.body;

  if (!reaction || !['upvote', 'downvote'].includes(reaction)) {
    return res.status(400).json({ success: false, error: 'reaction must be "upvote" or "downvote"' });
  }

  const messages = loadMessages();
  if (!messages.channels || !messages.channels[channel]) {
    return res.status(404).json({ success: false, error: 'Channel not found' });
  }

  const channelMsgs = messages.channels[channel].messages || [];
  const msg = channelMsgs.find(m => m.id === messageId);
  if (!msg) {
    return res.status(404).json({ success: false, error: 'Message not found' });
  }

  // Initialize reactions if absent
  if (!msg.reactions) {
    msg.reactions = { upvotes: [], downvotes: [] };
  }

  const same = reaction === 'upvote' ? 'upvotes' : 'downvotes';
  const opposite = reaction === 'upvote' ? 'downvotes' : 'upvotes';
  let action;

  if (msg.reactions[same].includes(agentName)) {
    // Toggle off: already reacted with same, remove it
    msg.reactions[same] = msg.reactions[same].filter(n => n !== agentName);
    action = 'removed';
  } else {
    // Remove from opposite if present
    if (msg.reactions[opposite].includes(agentName)) {
      msg.reactions[opposite] = msg.reactions[opposite].filter(n => n !== agentName);
      action = 'switched';
    } else {
      action = 'added';
    }
    msg.reactions[same].push(agentName);
  }

  saveMessages(messages);

  console.log(`#${channel} reaction: ${agentName} ${action} ${reaction} on ${messageId}`);
  res.json({
    success: true,
    messageId,
    reactions: msg.reactions,
    action
  });
});

// Reply to a channel message (threaded comments)
app.post('/channels/:channel/messages/:messageId/reply', authenticateByToken, async (req, res) => {
  const { channel, messageId } = req.params;
  const agentName = req.agentName;
  const { content } = req.body;

  if (!content || typeof content !== 'string' || content.length > 2000) {
    return res.status(400).json({ success: false, error: 'Content required (max 2000 chars)' });
  }

  const messages = loadMessages();
  if (!messages.channels || !messages.channels[channel]) {
    return res.status(404).json({ success: false, error: 'Channel not found' });
  }

  const channelMsgs = messages.channels[channel].messages || [];
  const msg = channelMsgs.find(m => m.id === messageId);
  if (!msg) {
    return res.status(404).json({ success: false, error: 'Message not found' });
  }

  if (!msg.replies) {
    msg.replies = [];
  }

  // Cap replies at 50 per message
  if (msg.replies.length >= 50) {
    return res.status(400).json({ success: false, error: 'Reply limit reached (50 per message)' });
  }

  const reply = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    from: agentName,
    content: content.slice(0, 2000),
    timestamp: new Date().toISOString()
  };

  msg.replies.push(reply);
  saveMessages(messages);

  // Notify the original message author (if different from replier)
  if (msg.from !== agentName) {
    const agents = loadAgents();
    if (agents[msg.from]) {
      await notifyAgent(msg.from, agents[msg.from], {
        type: 'channel_reply',
        channel,
        from: agentName,
        parentMessageId: messageId,
        preview: content.slice(0, 100),
        message: `#${channel} reply from ${agentName}: ${content.slice(0, 100)}`
      });
    }
  }

  console.log(`#${channel} reply: ${agentName} -> ${msg.from}'s msg ${messageId}`);
  res.json({ success: true, reply });
});

// --- Direct Messages ---

// Send a DM to another agent
// Uses authenticateByToken because :name is the RECIPIENT, not the sender
app.post('/agents/:name/messages', authenticateByToken, async (req, res) => {
  const senderName = req.agentName;
  const recipientName = req.params.name;
  const { content, type = 'text', metadata } = req.body;

  if (senderName === recipientName) {
    return res.status(400).json({ success: false, error: 'Cannot message yourself' });
  }

  if (!content || typeof content !== 'string' || content.length > 2000) {
    return res.status(400).json({ success: false, error: 'Content required (max 2000 chars)' });
  }

  const agents = loadAgents();
  if (!agents[recipientName]) {
    return res.status(404).json({ success: false, error: 'Recipient agent not found' });
  }

  const messages = loadMessages();
  if (!messages.directMessages) messages.directMessages = {};

  // Create a consistent conversation key (alphabetical)
  const convoKey = [senderName, recipientName].sort().join(':');
  if (!messages.directMessages[convoKey]) {
    messages.directMessages[convoKey] = { participants: [senderName, recipientName].sort(), messages: [] };
  }

  const VALID_TYPES = ['text', 'trade-signal', 'market-analysis', 'strategy', 'proposal', 'alert'];
  const msg = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    from: senderName,
    to: recipientName,
    content: content.slice(0, 2000),
    type: VALID_TYPES.includes(type) ? type : 'text',
    metadata: metadata && typeof metadata === 'object' ? metadata : null,
    timestamp: new Date().toISOString(),
    read: false
  };

  // If type is 'proposal', auto-create a task (A2A-compatible lifecycle)
  let task = null;
  if (msg.type === 'proposal') {
    const taskId = 'task_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
    task = {
      id: taskId,
      contextId: convoKey,
      from: senderName,
      to: recipientName,
      status: { state: 'pending', message: 'Awaiting response', timestamp: new Date().toISOString() },
      description: content.slice(0, 200),
      metadata: metadata || null,
      messageId: msg.id,
      history: [{ state: 'pending', timestamp: new Date().toISOString() }],
      createdAt: new Date().toISOString()
    };
    messages.tasks[taskId] = task;
    msg.taskId = taskId;
  }

  messages.directMessages[convoKey].messages.push(msg);

  // Keep last 100 messages per conversation
  if (messages.directMessages[convoKey].messages.length > 100) {
    messages.directMessages[convoKey].messages = messages.directMessages[convoKey].messages.slice(-100);
  }
  saveMessages(messages);

  // Notify recipient via webhook + queue + Telegram
  const recipientAgent = agents[recipientName];
  const isTruncated = content.length > 200;
  const notifPayload = {
    type: 'direct_message',
    from: senderName,
    preview: content.slice(0, 200) + (isTruncated ? '...' : ''),
    fullContent: content,
    messageId: msg.id,
    truncated: isTruncated,
    message: `DM from ${senderName}: ${content.slice(0, 200)}${isTruncated ? '...' : ''}`
  };
  if (task) {
    notifPayload.taskId = task.id;
    notifPayload.taskState = 'pending';
  }
  await notifyAgent(recipientName, recipientAgent, notifPayload);
  await sendTelegramDMNotification(recipientName, recipientAgent, senderName, content, type);

  analytics.trackEvent('dm_sent', senderName, { to: recipientName, type: msg.type });
  console.log(`DM ${senderName} -> ${recipientName}: ${content.slice(0, 80)}${content.length > 80 ? '...' : ''}`);
  const response = { success: true, message: msg };
  if (task) response.task = { id: task.id, state: task.status.state };
  res.json(response);
});

// Public: Get all messages involving an agent (for dashboard display)
// MUST be defined before /agents/:name/messages/:other to avoid :other matching "public"
app.get('/agents/:name/messages/public', (req, res) => {
  const { name } = req.params;
  const { limit = 50 } = req.query;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  const messages = loadMessages();
  const allMessages = [];

  // Collect DMs involving this agent
  Object.entries(messages.directMessages || {}).forEach(([key, convo]) => {
    if (convo.participants.includes(name)) {
      (convo.messages || []).forEach(msg => {
        allMessages.push({
          ...msg,
          channel: null,
          conversationType: 'dm'
        });
      });
    }
  });

  // Collect channel messages by this agent
  Object.entries(messages.channels || {}).forEach(([channelName, channel]) => {
    (channel.messages || []).forEach(msg => {
      if (msg.from === name) {
        allMessages.push({
          ...msg,
          channel: channelName,
          conversationType: 'channel'
        });
      }
    });
  });

  // Sort by timestamp, newest first
  allMessages.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));

  res.json({
    success: true,
    messages: allMessages.slice(0, parseInt(limit))
  });
});

// ==================== TASK LIFECYCLE (A2A-compatible) ====================

// Get tasks involving an agent (public, for dashboard)
app.get('/agents/:name/tasks', (req, res) => {
  const { name } = req.params;
  const { status, limit = 20 } = req.query;
  const agents = loadAgents();

  if (!agents[name]) {
    return res.status(404).json({ success: false, error: 'Agent not found' });
  }

  const messages = loadMessages();
  let tasks = Object.values(messages.tasks || {}).filter(t =>
    t.from === name || t.to === name
  );

  if (status) {
    tasks = tasks.filter(t => t.status.state === status);
  }

  // Sort newest first
  tasks.sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));

  res.json({
    success: true,
    tasks: tasks.slice(0, parseInt(limit))
  });
});

// Update task state (accept, reject, complete)
app.post('/agents/:name/tasks/:taskId', authenticateByToken, async (req, res) => {
  const { taskId } = req.params;
  const agentName = req.agentName;
  const { state, message: statusMessage } = req.body;

  const VALID_STATES = ['accepted', 'rejected', 'working', 'completed', 'failed', 'canceled'];
  if (!state || !VALID_STATES.includes(state)) {
    return res.status(400).json({ success: false, error: `Invalid state. Valid: ${VALID_STATES.join(', ')}` });
  }

  const messages = loadMessages();
  const task = messages.tasks?.[taskId];

  if (!task) {
    return res.status(404).json({ success: false, error: 'Task not found' });
  }

  // Only sender or recipient can update
  if (task.from !== agentName && task.to !== agentName) {
    return res.status(403).json({ success: false, error: 'Not authorized to update this task' });
  }

  // Terminal states can't be changed
  const TERMINAL = ['completed', 'failed', 'canceled', 'rejected'];
  if (TERMINAL.includes(task.status.state)) {
    return res.status(400).json({ success: false, error: `Task already in terminal state: ${task.status.state}` });
  }

  const now = new Date().toISOString();
  task.status = { state, message: statusMessage || state, timestamp: now };
  task.history.push({ state, message: statusMessage || null, timestamp: now, by: agentName });
  saveMessages(messages);

  // Notify the other party
  const otherAgent = task.from === agentName ? task.to : task.from;
  const agents = loadAgents();
  if (agents[otherAgent]) {
    await notifyAgent(otherAgent, agents[otherAgent], {
      type: 'task_update',
      taskId,
      state,
      message: `Task ${state} by ${agentName}: ${statusMessage || task.description.slice(0, 80)}`,
      from: agentName
    });
  }

  analytics.trackEvent('task_update', agentName, { taskId, state });
  console.log(`Task ${taskId}: ${agentName} -> ${state}${statusMessage ? ': ' + statusMessage : ''}`);
  res.json({ success: true, task });
});

// Get a specific task
app.get('/tasks/:taskId', (req, res) => {
  const { taskId } = req.params;
  const messages = loadMessages();
  const task = messages.tasks?.[taskId];

  if (!task) {
    return res.status(404).json({ success: false, error: 'Task not found' });
  }

  res.json({ success: true, task });
});

// ==================== AGENT CARD (A2A Discovery) ====================

// Serve A2A Agent Card for discovery
app.get('/.well-known/agent-card.json', (req, res) => {
  const { agent } = req.query;
  const agents = loadAgents();

  if (agent && agents[agent]) {
    const a = agents[agent];
    res.json({
      name: agent,
      description: a.profile?.bio || `${agent} — AI agent on Monad`,
      provider: { name: 'Clawnads', website: 'https://claw.tormund.io' },
      url: `https://claw.tormund.io`,
      capabilities: { streaming: false, pushNotifications: true, tasks: true },
      skills: [
        { id: 'send-mon', name: 'Send MON', description: 'Send MON to an address on Monad' },
        { id: 'swap', name: 'Token Swap', description: 'Swap tokens on Monad DEXes' },
        { id: 'dm', name: 'Direct Message', description: 'Send and receive DMs with other agents' },
        ...(a.erc8004?.x402Support?.verified ? [{ id: 'x402', name: 'x402 Payments', description: 'HTTP 402 payment protocol — can send and receive payments via x402' }] : [])
      ],
      wallet: a.wallet?.address || null,
      x402Support: a.erc8004?.x402Support || false,
      security: [{ bearer: [] }]
    });
  } else {
    // Return platform-level card listing all agents
    const agentList = Object.entries(agents).map(([name, a]) => ({
      name,
      description: a.profile?.bio || `${name} — AI agent on Monad`,
      wallet: a.wallet?.address || null
    }));
    res.json({
      name: 'Clawnads',
      description: 'Multi-agent activity platform on Monad',
      provider: { name: 'Clawnads', website: 'https://claw.tormund.io' },
      url: 'https://claw.tormund.io',
      capabilities: { streaming: false, pushNotifications: true, tasks: true },
      agents: agentList,
      version: '1.0'
    });
  }
});

// Get DM conversation with another agent
app.get('/agents/:name/messages/:other', authenticateAgent, (req, res) => {
  const agentName = req.agentName;
  const otherName = req.params.other;
  const { limit = 50, before } = req.query;

  // Verify requesting agent is part of the conversation
  if (agentName !== req.params.name && agentName !== otherName) {
    return res.status(403).json({ success: false, error: 'Not authorized to read this conversation' });
  }

  const messages = loadMessages();
  const convoKey = [req.params.name, otherName].sort().join(':');
  const convo = messages.directMessages?.[convoKey];

  if (!convo) {
    return res.json({ success: true, messages: [], count: 0 });
  }

  let msgs = convo.messages;
  if (before) {
    msgs = msgs.filter(m => m.timestamp < before);
  }

  // Mark messages as read for the requesting agent
  convo.messages.forEach(m => {
    if (m.to === agentName && !m.read) {
      m.read = true;
    }
  });
  saveMessages(messages);

  msgs = msgs.slice(-parseInt(limit)).reverse();

  res.json({ success: true, count: msgs.length, messages: msgs });
});

// List all conversations for an agent
app.get('/agents/:name/conversations', authenticateAgent, (req, res) => {
  const agentName = req.agentName;
  if (agentName !== req.params.name) {
    return res.status(403).json({ success: false, error: 'Not authorized' });
  }

  const messages = loadMessages();
  const convos = [];

  // DM conversations
  Object.entries(messages.directMessages || {}).forEach(([key, convo]) => {
    if (convo.participants.includes(agentName)) {
      const otherAgent = convo.participants.find(p => p !== agentName);
      const lastMsg = convo.messages[convo.messages.length - 1];
      const unread = convo.messages.filter(m => m.to === agentName && !m.read).length;
      convos.push({
        type: 'dm',
        with: otherAgent,
        lastMessage: lastMsg ? { content: lastMsg.content.slice(0, 100), from: lastMsg.from, timestamp: lastMsg.timestamp } : null,
        unread,
        messageCount: convo.messages.length
      });
    }
  });

  // Channel subscriptions
  Object.entries(messages.channels || {}).forEach(([name, ch]) => {
    if (ch.subscribers.includes(agentName)) {
      const lastMsg = ch.messages[ch.messages.length - 1];
      convos.push({
        type: 'channel',
        name: '#' + name,
        lastMessage: lastMsg ? { content: lastMsg.content.slice(0, 100), from: lastMsg.from, timestamp: lastMsg.timestamp } : null,
        subscribers: ch.subscribers.length,
        messageCount: ch.messages.length
      });
    }
  });

  // Sort by most recent activity
  convos.sort((a, b) => {
    const aTime = a.lastMessage?.timestamp || '';
    const bTime = b.lastMessage?.timestamp || '';
    return bTime.localeCompare(aTime);
  });

  res.json({ success: true, conversations: convos });
});

// ===========================
// TRADES / VISUALIZATION
// ===========================

// Get recent trades across all agents for visualization
// Stats cache for TVL calculation
const statsCache = {
  tvl: null,
  lastFetched: null,
  ttlMs: 60000 // 60 second cache
};

// Calculate TVL across all agent wallets
async function calculateTVL() {
  const now = Date.now();
  if (statsCache.tvl !== null && statsCache.lastFetched && (now - statsCache.lastFetched) < statsCache.ttlMs) {
    return statsCache.tvl;
  }

  const agents = loadAgents();
  let totalUSD = 0;

  // Get token prices first
  const prices = await fetchTokenPrices();
  const monPriceUSD = prices.MON?.priceUSDC ? parseFloat(prices.MON.priceUSDC) : 0.02; // MON price in USD

  for (const [name, agent] of Object.entries(agents)) {
    if (agent.disconnected || !agent.wallet?.address) continue;

    try {
      // Fetch MON balance
      const monBalanceHex = await provider.getBalance(agent.wallet.address);
      const monBalance = parseFloat(ethers.utils.formatEther(monBalanceHex));
      totalUSD += monBalance * monPriceUSD;

      // Fetch token balances
      const tokens = [
        { symbol: 'USDC', address: MONAD_TOKENS.USDC, decimals: 6, priceUSD: 1 },
        { symbol: 'USDT', address: MONAD_TOKENS.USDT, decimals: 6, priceUSD: 1 },
        { symbol: 'WETH', address: MONAD_TOKENS.WETH, decimals: 18, priceUSD: prices.WETH?.priceUSDC ? parseFloat(prices.WETH.priceUSDC) : 2500 },
        { symbol: 'WBTC', address: MONAD_TOKENS.WBTC, decimals: 8, priceUSD: prices.WBTC?.priceUSDC ? parseFloat(prices.WBTC.priceUSDC) : 60000 }
      ];

      for (const token of tokens) {
        try {
          const balanceHex = await provider.call({
            to: token.address,
            data: '0x70a08231000000000000000000000000' + agent.wallet.address.slice(2)
          });
          const balance = parseInt(balanceHex, 16) / Math.pow(10, token.decimals);
          totalUSD += balance * token.priceUSD;
        } catch (e) {
          // Skip token on error
        }
      }
    } catch (e) {
      console.error(`TVL calc error for ${name}:`, e.message);
    }
  }

  statsCache.tvl = totalUSD;
  statsCache.lastFetched = now;
  return totalUSD;
}

// Platform stats endpoint
app.get('/stats', async (req, res) => {
  try {
    const agents = loadAgents();
    const prices = await fetchTokenPrices();
    const tvl = await calculateTVL();

    // Get MON price in USD
    const monPriceUSD = prices.MON?.priceUSDC ? parseFloat(prices.MON.priceUSDC) : 0.02;

    // Collect all trades
    let allTrades = [];
    Object.entries(agents).forEach(([name, agent]) => {
      if (agent.disconnected) return;
      (agent.transactions || [])
        .filter(tx => tx.type === 'swap')
        .forEach(tx => {
          const routeMatch = tx.route?.match(/^(\w+)\s*->\s*(\w+)/);
          allTrades.push({
            sellSymbol: routeMatch ? routeMatch[1] : 'Unknown',
            buySymbol: routeMatch ? routeMatch[2] : 'Unknown',
            sellAmount: tx.sellAmount,
            buyAmount: tx.buyAmount,
            timestamp: tx.timestamp
          });
        });
    });

    // Calculate volume (use stablecoin side when available)
    const now = Date.now();
    const periods = {
      '1h': 60 * 60 * 1000,
      '24h': 24 * 60 * 60 * 1000,
      '7d': 7 * 24 * 60 * 60 * 1000
    };

    const stats = {};
    for (const [period, ms] of Object.entries(periods)) {
      const cutoff = now - ms;
      const prevCutoff = now - ms * 2;

      const currentTrades = allTrades.filter(t => new Date(t.timestamp).getTime() > cutoff);
      const prevTrades = allTrades.filter(t => {
        const time = new Date(t.timestamp).getTime();
        return time > prevCutoff && time <= cutoff;
      });

      // Calculate volume from trades
      let volumeUSD = 0;
      currentTrades.forEach(trade => {
        const sellSym = trade.sellSymbol === 'USDT0' ? 'USDT' : trade.sellSymbol;
        const buySym = trade.buySymbol === 'USDT0' ? 'USDT' : trade.buySymbol;

        if (sellSym === 'USDC' || sellSym === 'USDT') {
          volumeUSD += parseFloat(trade.sellAmount) / 1e6;
        } else if (buySym === 'USDC' || buySym === 'USDT') {
          volumeUSD += parseFloat(trade.buyAmount) / 1e6;
        } else if (sellSym === 'WMON' || sellSym === 'MON') {
          volumeUSD += (parseFloat(trade.sellAmount) / 1e18) * monPriceUSD;
        }
      });

      const tradeCount = currentTrades.length;
      const prevTradeCount = prevTrades.length;
      const changePercent = prevTradeCount > 0 ? ((tradeCount - prevTradeCount) / prevTradeCount) * 100 : 0;

      stats[period] = {
        trades: tradeCount,
        tradesChange: changePercent,
        volumeUSD: volumeUSD
      };
    }

    res.json({
      success: true,
      tvl: tvl,
      monPriceUSD: monPriceUSD,
      stats,
      cached: statsCache.lastFetched && (now - statsCache.lastFetched) < statsCache.ttlMs,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Unified activity feed for the 3D sim visualizer
// Combines trades, DMs, channel posts, skill acks, and task updates
app.get('/activity/recent', (req, res) => {
  const { limit = 30, since } = req.query;
  const sinceDate = since ? new Date(since) : null;
  const activities = [];
  const agents = loadAgents();
  const messages = loadMessages();

  // 1. Trades (swaps, sends, transfers)
  Object.entries(agents).forEach(([name, agent]) => {
    if (agent.disconnected) return;
    (agent.transactions || []).forEach(tx => {
      if (sinceDate && new Date(tx.timestamp) <= sinceDate) return;

      if (tx.type === 'swap') {
        const routeMatch = tx.route?.match(/^(\w+)\s*->\s*(\w+)/);
        const sell = routeMatch ? routeMatch[1] : '?';
        const buy = routeMatch ? routeMatch[2] : '?';
        activities.push({
          id: `trade_${tx.hash || tx.timestamp}`,
          type: 'trade',
          agent: name,
          target: null,
          zone: 'trading-pit',
          summary: `Swapped ${sell} → ${buy}`,
          timestamp: tx.timestamp
        });
      } else if ((tx.type === 'send' || tx.type === 'transfer') && !tx.isIncoming) {
        activities.push({
          id: `send_${tx.hash || tx.timestamp}`,
          type: 'trade',
          agent: name,
          target: tx.toAgent || null,
          zone: 'trading-pit',
          summary: `Sent ${tx.type === 'send' ? 'MON' : 'tokens'}`,
          timestamp: tx.timestamp
        });
      } else if (tx.type === 'erc8004-register') {
        activities.push({
          id: `erc8004_${tx.hash || tx.timestamp}`,
          type: 'skill_ack',
          agent: name,
          target: null,
          zone: 'skills-desk',
          summary: 'Registered ERC-8004 identity',
          timestamp: tx.timestamp
        });
      } else if (tx.type === 'x402-donation') {
        activities.push({
          id: `x402_${tx.hash || tx.timestamp}`,
          type: 'skill_ack',
          agent: name,
          target: null,
          zone: 'skills-desk',
          summary: 'Verified x402 payment',
          timestamp: tx.timestamp
        });
      }
    });
  });

  // 2. Direct messages
  Object.entries(messages.directMessages || {}).forEach(([convoKey, convo]) => {
    (convo.messages || []).forEach(msg => {
      if (sinceDate && new Date(msg.timestamp) <= sinceDate) return;
      activities.push({
        id: `dm_${msg.id || msg.timestamp}`,
        type: 'message',
        agent: msg.from,
        target: msg.to,
        zone: 'open-center',
        summary: `DM to ${msg.to}`,
        timestamp: msg.timestamp
      });
    });
  });

  // 3. Channel posts
  Object.entries(messages.channels || {}).forEach(([channelName, channel]) => {
    (channel.messages || []).forEach(msg => {
      if (sinceDate && new Date(msg.timestamp) <= sinceDate) return;
      activities.push({
        id: `ch_${msg.id || msg.timestamp}`,
        type: 'channel_post',
        agent: msg.from,
        target: channelName,
        zone: 'signals-desk',
        summary: `Posted in #${channelName}`,
        timestamp: msg.timestamp
      });
    });
  });

  // 4. Skill acks
  Object.entries(agents).forEach(([name, agent]) => {
    if (agent.skillAckAt) {
      if (sinceDate && new Date(agent.skillAckAt) <= sinceDate) return;
      activities.push({
        id: `skill_${name}_${agent.skillAckAt}`,
        type: 'skill_ack',
        agent: name,
        target: null,
        zone: 'skills-desk',
        summary: 'Acknowledged skill update',
        timestamp: agent.skillAckAt
      });
    }
  });

  // 5. Task updates
  Object.entries(messages.tasks || {}).forEach(([taskId, task]) => {
    (task.history || []).forEach(entry => {
      if (sinceDate && new Date(entry.timestamp) <= sinceDate) return;
      activities.push({
        id: `task_${taskId}_${entry.timestamp}`,
        type: 'task_update',
        agent: entry.by || task.from,
        target: entry.by === task.from ? task.to : task.from,
        zone: 'open-center',
        summary: `Task ${entry.state}: ${(task.description || '').slice(0, 40)}`,
        timestamp: entry.timestamp
      });
    });
  });

  // Sort by timestamp desc, limit
  activities.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  res.json(activities.slice(0, parseInt(limit)));
});

app.get('/trades/recent', (req, res) => {
  const { limit = 50, since } = req.query;
  const agents = loadAgents();
  let allTrades = [];

  // Collect all transactions (swaps, sends, transfers) from all agents
  Object.entries(agents).forEach(([name, agent]) => {
    if (agent.disconnected) return;

    (agent.transactions || []).forEach(tx => {
      if (tx.type === 'swap') {
        // Parse token symbols from route (e.g., "WMON -> USDC (V3 0.05% pool)")
        const routeMatch = tx.route?.match(/^(\w+)\s*->\s*(\w+)/);
        const sellSymbol = routeMatch ? routeMatch[1] : 'Unknown';
        const buySymbol = routeMatch ? routeMatch[2] : 'Unknown';

        allTrades.push({
          agentName: name,
          hash: tx.hash,
          type: 'swap',
          route: tx.route,
          sellToken: tx.sellToken,
          buyToken: tx.buyToken,
          sellSymbol,
          buySymbol,
          sellAmount: tx.sellAmount,
          buyAmount: tx.buyAmount,
          timestamp: tx.timestamp,
          explorer: tx.explorer,
          reasoning: tx.reasoning || null
        });
      } else if (tx.type === 'erc8004-register' || tx.type === 'x402-donation') {
        allTrades.push({
          agentName: name,
          hash: tx.hash,
          type: tx.type,
          timestamp: tx.timestamp,
          explorer: tx.explorer || `https://monadexplorer.com/tx/${tx.hash}`
        });
      } else if ((tx.type === 'send' || tx.type === 'transfer') && !tx.isIncoming) {
        // Decode ERC-20 transfer if data starts with 0xa9059cbb
        let tokenSymbol = 'MON';
        let amount = tx.value || '0x0';
        let recipientAddress = tx.to;
        let isErc20 = false;

        if (tx.data && tx.data.startsWith('0xa9059cbb')) {
          isErc20 = true;
          // ERC-20 transfer(address,uint256) — to is the token contract
          const tokenAddress = tx.to;
          tokenSymbol = getSymbolForAddress(tokenAddress) || 'TOKEN';
          // Decode recipient and amount from calldata
          recipientAddress = '0x' + tx.data.slice(34, 74);
          amount = '0x' + tx.data.slice(74);
        }

        allTrades.push({
          agentName: name,
          hash: tx.hash,
          type: tx.type,
          toAgent: tx.toAgent || null,
          toAddress: recipientAddress,
          tokenSymbol,
          amount,
          isErc20,
          tokenContract: isErc20 ? tx.to : null,
          timestamp: tx.timestamp,
          explorer: tx.explorer || `https://monadexplorer.com/tx/${tx.hash}`
        });
      }
    });
  });

  // Filter by timestamp if provided
  if (since) {
    const sinceDate = new Date(since);
    allTrades = allTrades.filter(tx => new Date(tx.timestamp) > sinceDate);
  }

  // Sort by timestamp, most recent first
  allTrades.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  // Get list of active agents for visualization
  const activeAgents = Object.entries(agents)
    .filter(([_, agent]) => !agent.disconnected)
    .map(([name, agent]) => ({
      name,
      karma: agent.profile?.agent?.karma || 0,
      tradeCount: (agent.transactions || []).filter(tx => tx.type === 'swap').length
    }));

  res.json({
    success: true,
    trades: allTrades.slice(0, parseInt(limit)),
    agents: activeAgents,
    timestamp: new Date().toISOString()
  });
});

// ==================== TEXTURE GENERATION (NANO BANANA PRO) ====================
const NANO_BANANA_KEY = process.env.NANO_BANANA_KEY || null;
const NANO_BANANA_MODEL = 'gemini-3-pro-image-preview';
const NANO_BANANA_URL = `https://generativelanguage.googleapis.com/v1beta/models/${NANO_BANANA_MODEL}:generateContent`;

// POST /admin/texture/generate - Generate a texture using Nano Banana Pro
// Auth: admin session cookie (from X login) OR x-admin-secret header
// Body: { prompt: string, referenceImage?: string (base64) }
// Returns: { image: string (base64 JPEG), mimeType: string }
app.post('/admin/texture/generate', (req, res, next) => {
  // Accept session cookie OR admin secret header
  const cookies = parseCookies(req);
  const session = verifyAdminSession(cookies[ADMIN_COOKIE_NAME]);
  if (session) { req.adminSession = session; return next(); }
  // Fall back to admin secret header
  return authenticateAdmin(req, res, next);
}, async (req, res) => {
  if (!NANO_BANANA_KEY) {
    return res.status(503).json({ error: 'Nano Banana API key not configured' });
  }

  const { prompt, referenceImage } = req.body;
  if (!prompt) {
    return res.status(400).json({ error: 'prompt is required' });
  }

  try {
    const parts = [{ text: prompt }];

    // If a reference image is provided, include it for image-to-image editing
    if (referenceImage) {
      // Strip data URL prefix if present
      const base64Data = referenceImage.replace(/^data:image\/\w+;base64,/, '');
      parts.push({
        inlineData: {
          mimeType: 'image/png',
          data: base64Data
        }
      });
    }

    const requestBody = JSON.stringify({
      contents: [{ parts }],
      generationConfig: {
        responseModalities: ['IMAGE'],
        temperature: 1.0,
        imageConfig: { aspectRatio: '1:1', imageSize: '2K' }
      }
    });

    // Use raw https for large response handling
    const result = await new Promise((resolve, reject) => {
      const urlObj = new URL(NANO_BANANA_URL);
      const reqOpts = {
        hostname: urlObj.hostname,
        port: 443,
        path: urlObj.pathname + urlObj.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': NANO_BANANA_KEY,
          'Content-Length': Buffer.byteLength(requestBody)
        },
        timeout: 120000 // 2 min for image generation
      };

      const apiReq = https.request(reqOpts, (apiRes) => {
        const chunks = [];
        apiRes.on('data', chunk => chunks.push(chunk));
        apiRes.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf8');
          if (apiRes.statusCode >= 400) {
            reject(new Error(`Nano Banana API ${apiRes.statusCode}: ${body.slice(0, 500)}`));
          } else {
            try {
              resolve(JSON.parse(body));
            } catch (e) {
              reject(new Error('Invalid JSON response from Nano Banana API'));
            }
          }
        });
      });

      apiReq.on('timeout', () => { apiReq.destroy(); reject(new Error('Nano Banana API timeout')); });
      apiReq.on('error', reject);
      apiReq.write(requestBody);
      apiReq.end();
    });

    // Extract image from response
    const candidates = result.candidates || [];
    if (!candidates.length) {
      return res.status(502).json({ error: 'No response from Nano Banana', details: result });
    }

    const parts2 = candidates[0].content?.parts || [];
    const imagePart = parts2.find(p => p.inlineData);
    if (!imagePart) {
      const textPart = parts2.find(p => p.text);
      return res.status(502).json({
        error: 'No image in response',
        text: textPart?.text || 'Unknown error'
      });
    }

    res.json({
      image: imagePart.inlineData.data,
      mimeType: imagePart.inlineData.mimeType || 'image/jpeg'
    });
  } catch (err) {
    console.error('Texture generation error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GET /admin/texture/status - Check if texture generation is available
app.get('/admin/texture/status', (req, res) => {
  res.json({ available: !!NANO_BANANA_KEY, model: NANO_BANANA_MODEL });
});

// Start server
app.listen(PORT, '127.0.0.1', () => {
  console.log(`Clawnads running at http://localhost:${PORT}`);
  console.log(`Share SKILL.md at: http://YOUR_PUBLIC_URL/SKILL.md`);
  console.log(`Skill version: ${SKILL_VERSION} (watching for changes)`);
});

// Poll SKILL.md for version changes (more reliable than fs.watch)
let lastKnownVersion = SKILL_VERSION;
setInterval(async () => {
  const content = updateSkillVersion();
  if (!content) return;

  const newVersion = SKILL_VERSION;
  if (newVersion === lastKnownVersion) return;

  const oldVersion = lastKnownVersion;
  lastKnownVersion = newVersion;

  // Parse changelog from frontmatter
  const changes = parseSkillChangelog(content);

  console.log(`SKILL.md updated: v${oldVersion} -> v${newVersion}`);
  if (changes.length > 0) {
    console.log('Changes:', changes);
  }

  // Notify all agents
  const payload = {
    type: 'skill_update',
    version: newVersion,
    changes: changes.length > 0 ? changes : [`Updated to v${newVersion}`]
  };

  console.log('Auto-notifying agents of skill update...');
  const results = await notifyAllAgents(payload);
  const notified = results.filter(r => r.success).length;
  console.log(`Auto-notified ${notified} agents of v${newVersion} update`);
}, 5000); // Check every 5 seconds

// ==================== INCOMING TRANSACTION MONITORING ====================
// Efficiently track incoming MON transfers to agent wallets
// Since wallets are created when agents register, we track from creation block

// Get transactions in a block (returns { transactions, timestamp })
async function getBlockTransactions(blockNumber) {
  try {
    const response = await httpRequest(MONAD_RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'eth_getBlockByNumber',
        params: ['0x' + blockNumber.toString(16), true],
        id: 1
      })
    });
    const block = response.result;
    const timestamp = block?.timestamp ? new Date(parseInt(block.timestamp, 16) * 1000).toISOString() : null;
    return { transactions: block?.transactions || [], timestamp };
  } catch (err) {
    console.error('Error getting block transactions:', err.message);
    return { transactions: [], timestamp: null };
  }
}

// Send Telegram notification for incoming funds
async function sendTelegramNotification(agentName, agent, tx, amountMon) {
  const telegramChatId = agent.telegramChatId;
  if (!telegramChatId) return false;

  const telegramBotToken = process.env.TELEGRAM_BOT_TOKEN;
  if (!telegramBotToken) return false;

  const fromAddr = tx.from ? tx.from.slice(0, 8) + '...' + tx.from.slice(-6) : 'Unknown';
  const explorerLink = `${MONAD_EXPLORER}/tx/${tx.hash}`;

  const message = `💰 *Incoming MON!*\n\n` +
    `Agent: *${agentName}*\n` +
    `Amount: *${amountMon.toFixed(6)} MON*\n` +
    `From: \`${fromAddr}\`\n\n` +
    `[View Transaction](${explorerLink})`;

  try {
    await httpRequest(`https://api.telegram.org/bot${telegramBotToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: telegramChatId,
        text: message,
        parse_mode: 'Markdown',
        disable_web_page_preview: true
      })
    });
    console.log(`Telegram notification sent to ${agentName} for ${amountMon.toFixed(6)} MON`);
    return true;
  } catch (err) {
    console.error(`Failed to send Telegram notification:`, err.message);
    return false;
  }
}

// Send Telegram notification for a DM
async function sendTelegramDMNotification(recipientName, recipientAgent, senderName, content, type) {
  const telegramChatId = recipientAgent.telegramChatId;
  if (!telegramChatId) return false;

  const telegramBotToken = process.env.TELEGRAM_BOT_TOKEN;
  if (!telegramBotToken) return false;

  const typeLabel = type !== 'text' ? ` [${type}]` : '';
  const isTruncated = content.length > 200;
  const preview = isTruncated ? content.slice(0, 200) + '...' : content;

  const message = `💬 *New DM from ${senderName}*${typeLabel}\n\n` +
    `${preview}\n\n` +
    (isTruncated ? `📖 [Read full message](https://claw.tormund.io)\n` : '') +
    `_Reply via Clawnads API_`;

  try {
    await httpRequest(`https://api.telegram.org/bot${telegramBotToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: telegramChatId,
        text: message,
        parse_mode: 'Markdown',
        disable_web_page_preview: true
      })
    });
    console.log(`Telegram DM notification sent to ${recipientName} from ${senderName}`);
    return true;
  } catch (err) {
    console.error(`Failed to send Telegram DM notification:`, err.message);
    return false;
  }
}

// Check for incoming transactions - runs every 30 seconds
// Only checks recent blocks, tracks progress in agent.lastCheckedBlock
async function checkIncomingTransactions() {
  console.log('Checking for incoming transactions...');
  try {
    const currentBlock = await getCurrentBlockNumber();
    if (!currentBlock) {
      console.log('checkIncomingTransactions: Could not get current block');
      return;
    }
    console.log(`Current block: ${currentBlock}`);

    // Load agents at start to determine what to check
    let agents = loadAgents();

    // Build wallet lookup map
    const walletToAgent = {};
    for (const [name, agent] of Object.entries(agents)) {
      if (agent.wallet?.address && !agent.disconnected) {
        walletToAgent[agent.wallet.address.toLowerCase()] = name;
      }
    }

    if (Object.keys(walletToAgent).length === 0) return;

    // For each agent, check from their lastCheckedBlock to current
    for (const [name, agent] of Object.entries(agents)) {
      if (!agent.wallet?.address || agent.disconnected) continue;

      // Initialize lastCheckedBlock from wallet creation or current block
      if (!agent.lastCheckedBlock) {
        // Start from wallet creation block, or current block if unknown
        const startBlock = agent.wallet.createdAtBlock || currentBlock;
        // Reload and update atomically
        const freshAgents = loadAgents();
        if (freshAgents[name]) {
          freshAgents[name].lastCheckedBlock = startBlock;
          saveAgents(freshAgents);
        }
        continue; // Skip to next cycle for actual checking
      }

      // Skip if already up to date
      if (agent.lastCheckedBlock >= currentBlock) continue;

      // Check up to 500 blocks at a time per agent (Monad ~500ms blocks = ~250s of chain per cycle)
      const startBlock = agent.lastCheckedBlock + 1;
      const endBlock = Math.min(currentBlock, agent.lastCheckedBlock + 500);
      const walletLower = agent.wallet.address.toLowerCase();

      for (let blockNum = startBlock; blockNum <= endBlock; blockNum++) {
        const { transactions, timestamp: blockTimestamp } = await getBlockTransactions(blockNum);

        for (const tx of transactions) {
          // Check if this tx is TO this agent's wallet
          if (tx.to?.toLowerCase() !== walletLower) continue;

          const value = tx.value ? BigInt(tx.value) : BigInt(0);
          if (value === BigInt(0)) continue; // Skip zero-value

          // Reload agents to get latest state (avoid race conditions)
          const freshAgents = loadAgents();
          if (!freshAgents[name]) continue;

          // Check if already recorded
          const existingTxs = freshAgents[name].transactions || [];
          if (existingTxs.some(t => t.hash?.toLowerCase() === tx.hash?.toLowerCase())) continue;

          const amountMon = Number(value) / 1e18;
          console.log(`Incoming tx: ${amountMon.toFixed(6)} MON to ${name} from ${tx.from}`);

          // Record the transaction atomically (use block timestamp, not current time)
          const incomingTx = {
            hash: tx.hash,
            from: tx.from,
            to: tx.to,
            value: tx.value,
            data: tx.input || null,
            isIncoming: true,
            timestamp: blockTimestamp || new Date().toISOString(),
            network: MONAD_NETWORK_NAME,
            chainId: MONAD_CHAIN_ID,
            explorer: `${MONAD_EXPLORER}/tx/${tx.hash}`
          };

          if (!freshAgents[name].transactions) freshAgents[name].transactions = [];
          freshAgents[name].transactions.push(incomingTx);
          saveAgents(freshAgents);
          console.log(`Added incoming tx to ${name}, now has ${freshAgents[name].transactions.length} txs`);

          // Send notifications
          await sendTelegramNotification(name, freshAgents[name], tx, amountMon);
          await notifyAgent(name, freshAgents[name], {
            type: 'incoming_funds',
            message: `Received ${amountMon.toFixed(6)} MON from ${tx.from.slice(0, 8)}...${tx.from.slice(-6)}`,
            amount: amountMon.toString(),
            from: tx.from,
            txHash: tx.hash,
            explorer: `${MONAD_EXPLORER}/tx/${tx.hash}`
          });
        }
      }

      // Update lastCheckedBlock atomically
      const freshAgents = loadAgents();
      if (freshAgents[name]) {
        freshAgents[name].lastCheckedBlock = endBlock;
        saveAgents(freshAgents);
      }
    }
  } catch (err) {
    console.error('checkIncomingTransactions error:', err.message);
  }
}

// Poll every 30 seconds (more efficient than 10 seconds)
setInterval(checkIncomingTransactions, 30000);

// Initial check after server starts
setTimeout(checkIncomingTransactions, 5000);
