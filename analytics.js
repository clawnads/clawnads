// ==================== ANALYTICS MODULE ====================
// SQLite-backed analytics for Clawnads
// Tracks: human page views, session engagement, agent actions, heartbeats, trades, messages, verifications

const path = require('path');
const crypto = require('crypto');
const Database = require('better-sqlite3');

const DB_PATH = path.join(__dirname, 'data', 'analytics.db');
let db;

// Bot detection patterns
const BOT_PATTERNS = /bot|crawl|spider|slurp|curl|wget|python-requests|httpx|go-http|java\/|node-fetch|axios|undici|postman|insomnia|scrapy|facebookexternalhit|twitterbot|linkedinbot|googlebot|bingbot|yandexbot|baiduspider|duckduckbot|semrush|ahrefs|mj12bot|dotbot|petalbot|bytespider/i;

function isBot(userAgent) {
  if (!userAgent) return true;
  return BOT_PATTERNS.test(userAgent);
}

function hashIP(ip) {
  if (!ip) return null;
  return crypto.createHash('sha256').update(ip + 'clawnads-salt').digest('hex').slice(0, 16);
}

function initAnalytics() {
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('busy_timeout = 5000');

  db.exec(`
    CREATE TABLE IF NOT EXISTS page_views (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      path TEXT NOT NULL,
      ip_hash TEXT,
      user_agent TEXT,
      referrer TEXT,
      is_bot INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      type TEXT NOT NULL,
      agent_name TEXT,
      metadata TEXT
    );

    CREATE TABLE IF NOT EXISTS daily_metrics (
      date TEXT NOT NULL,
      metric TEXT NOT NULL,
      value INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (date, metric)
    );

    CREATE INDEX IF NOT EXISTS idx_page_views_timestamp ON page_views(timestamp);
    CREATE INDEX IF NOT EXISTS idx_page_views_path ON page_views(path);
    CREATE INDEX IF NOT EXISTS idx_page_views_is_bot ON page_views(is_bot);
    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
    CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_name);
    CREATE INDEX IF NOT EXISTS idx_daily_metrics_date ON daily_metrics(date);
  `);

  return db;
}

// Track a page view from an HTTP request
function trackPageView(req) {
  if (!db) return;
  try {
    const ua = req.headers['user-agent'] || '';
    const stmt = db.prepare(`
      INSERT INTO page_views (timestamp, path, ip_hash, user_agent, referrer, is_bot)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      new Date().toISOString(),
      req.path,
      hashIP(req.ip || req.connection?.remoteAddress),
      ua.slice(0, 500),
      (req.headers.referer || '').slice(0, 500),
      isBot(ua) ? 1 : 0
    );
  } catch (e) {
    console.error('Analytics trackPageView error:', e.message);
  }
}

// Track a discrete event
function trackEvent(type, agentName, metadata) {
  if (!db) return;
  try {
    const stmt = db.prepare(`
      INSERT INTO events (timestamp, type, agent_name, metadata)
      VALUES (?, ?, ?, ?)
    `);
    stmt.run(
      new Date().toISOString(),
      type,
      agentName || null,
      metadata ? JSON.stringify(metadata) : null
    );
  } catch (e) {
    console.error('Analytics trackEvent error:', e.message);
  }
}

// Insert a historical event (for backfill)
function trackEventAt(timestamp, type, agentName, metadata) {
  if (!db) return;
  try {
    const stmt = db.prepare(`
      INSERT INTO events (timestamp, type, agent_name, metadata)
      VALUES (?, ?, ?, ?)
    `);
    stmt.run(
      timestamp,
      type,
      agentName || null,
      metadata ? JSON.stringify(metadata) : null
    );
  } catch (e) {
    console.error('Analytics trackEventAt error:', e.message);
  }
}

// Aggregate daily metrics for a given date (YYYY-MM-DD)
function aggregateDaily(date) {
  if (!db) return;
  const dayStart = `${date}T00:00:00`;
  const dayEnd = `${date}T23:59:59.999`;

  const metrics = {};

  // Human visits (non-bot)
  const visits = db.prepare(`
    SELECT COUNT(*) as c FROM page_views
    WHERE timestamp >= ? AND timestamp <= ? AND is_bot = 0
  `).get(dayStart, dayEnd);
  metrics.human_visits = visits.c;

  // Unique humans (distinct ip_hash, non-bot)
  const unique = db.prepare(`
    SELECT COUNT(DISTINCT ip_hash) as c FROM page_views
    WHERE timestamp >= ? AND timestamp <= ? AND is_bot = 0 AND ip_hash IS NOT NULL
  `).get(dayStart, dayEnd);
  metrics.unique_humans = unique.c;

  // Active agents (distinct agents with heartbeats or trades)
  const activeAgents = db.prepare(`
    SELECT COUNT(DISTINCT agent_name) as c FROM events
    WHERE timestamp >= ? AND timestamp <= ? AND type IN ('agent_heartbeat', 'agent_trade')
    AND agent_name IS NOT NULL
  `).get(dayStart, dayEnd);
  metrics.active_agents = activeAgents.c;

  // Verifications
  const verifs = db.prepare(`
    SELECT COUNT(*) as c FROM events
    WHERE timestamp >= ? AND timestamp <= ? AND type = 'x402_verification'
  `).get(dayStart, dayEnd);
  metrics.verifications = verifs.c;

  // Trades
  const trades = db.prepare(`
    SELECT COUNT(*) as c FROM events
    WHERE timestamp >= ? AND timestamp <= ? AND type = 'agent_trade'
  `).get(dayStart, dayEnd);
  metrics.trades = trades.c;

  // Registrations
  const regs = db.prepare(`
    SELECT COUNT(*) as c FROM events
    WHERE timestamp >= ? AND timestamp <= ? AND type = 'registration'
  `).get(dayStart, dayEnd);
  metrics.registrations = regs.c;

  // Agent actions (total authenticated API calls)
  const actions = db.prepare(`
    SELECT COUNT(*) as c FROM events
    WHERE timestamp >= ? AND timestamp <= ? AND type = 'agent_action'
  `).get(dayStart, dayEnd);
  metrics.agent_actions = actions.c;

  // Messages sent (DMs + channel messages)
  const msgs = db.prepare(`
    SELECT COUNT(*) as c FROM events
    WHERE timestamp >= ? AND timestamp <= ? AND type IN ('dm_sent', 'channel_message')
  `).get(dayStart, dayEnd);
  metrics.messages_sent = msgs.c;

  // Average session duration (seconds)
  const sessions = db.prepare(`
    SELECT metadata FROM events
    WHERE timestamp >= ? AND timestamp <= ? AND type = 'session_end'
  `).all(dayStart, dayEnd);
  let totalDuration = 0, sessionCount = 0;
  for (const s of sessions) {
    try {
      const meta = JSON.parse(s.metadata);
      if (meta.durationSec) { totalDuration += parseInt(meta.durationSec); sessionCount++; }
    } catch {}
  }
  metrics.avg_session_sec = sessionCount > 0 ? Math.round(totalDuration / sessionCount) : 0;

  // Upsert into daily_metrics
  const upsert = db.prepare(`
    INSERT INTO daily_metrics (date, metric, value)
    VALUES (?, ?, ?)
    ON CONFLICT(date, metric) DO UPDATE SET value = excluded.value
  `);

  const insertAll = db.transaction(() => {
    for (const [metric, value] of Object.entries(metrics)) {
      upsert.run(date, metric, value);
    }
  });
  insertAll();

  return metrics;
}

// Ensure all days up to yesterday are aggregated
function ensureAggregated() {
  if (!db) return;
  const today = new Date().toISOString().slice(0, 10);

  // Find the last aggregated date
  const last = db.prepare(`
    SELECT MAX(date) as d FROM daily_metrics
  `).get();

  // Find the earliest event/page_view date
  const earliest1 = db.prepare(`SELECT MIN(timestamp) as t FROM events`).get();
  const earliest2 = db.prepare(`SELECT MIN(timestamp) as t FROM page_views`).get();
  const earliestTs = [earliest1?.t, earliest2?.t].filter(Boolean).sort()[0];
  if (!earliestTs) return;

  const startDate = last?.d
    ? nextDay(last.d)
    : earliestTs.slice(0, 10);

  // Aggregate each missing day up to yesterday
  let current = startDate;
  while (current < today) {
    aggregateDaily(current);
    current = nextDay(current);
  }
}

function nextDay(dateStr) {
  const d = new Date(dateStr + 'T12:00:00Z');
  d.setUTCDate(d.getUTCDate() + 1);
  return d.toISOString().slice(0, 10);
}

// Get daily metric timeseries
function getDailyMetrics(metric, days) {
  if (!db) return [];
  ensureAggregated();

  const today = new Date().toISOString().slice(0, 10);
  const startDate = new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);

  // Get aggregated data for past days
  const rows = db.prepare(`
    SELECT date, value FROM daily_metrics
    WHERE metric = ? AND date >= ? AND date < ?
    ORDER BY date
  `).all(metric, startDate, today);

  // Add today's live data
  const todayValue = getTodayLive(metric);
  rows.push({ date: today, value: todayValue });

  // Fill gaps with zeros
  const result = [];
  let current = startDate;
  const dataMap = {};
  for (const r of rows) dataMap[r.date] = r.value;

  while (current <= today) {
    result.push({ date: current, value: dataMap[current] || 0 });
    current = nextDay(current);
  }

  return result;
}

// Get today's live count for a metric (not yet aggregated)
function getTodayLive(metric) {
  if (!db) return 0;
  const today = new Date().toISOString().slice(0, 10);
  const dayStart = `${today}T00:00:00`;
  const dayEnd = `${today}T23:59:59.999`;

  switch (metric) {
    case 'human_visits': {
      const r = db.prepare(`SELECT COUNT(*) as c FROM page_views WHERE timestamp >= ? AND timestamp <= ? AND is_bot = 0`).get(dayStart, dayEnd);
      return r.c;
    }
    case 'unique_humans': {
      const r = db.prepare(`SELECT COUNT(DISTINCT ip_hash) as c FROM page_views WHERE timestamp >= ? AND timestamp <= ? AND is_bot = 0 AND ip_hash IS NOT NULL`).get(dayStart, dayEnd);
      return r.c;
    }
    case 'active_agents': {
      const r = db.prepare(`SELECT COUNT(DISTINCT agent_name) as c FROM events WHERE timestamp >= ? AND timestamp <= ? AND type IN ('agent_heartbeat', 'agent_trade') AND agent_name IS NOT NULL`).get(dayStart, dayEnd);
      return r.c;
    }
    case 'verifications': {
      const r = db.prepare(`SELECT COUNT(*) as c FROM events WHERE timestamp >= ? AND timestamp <= ? AND type = 'x402_verification'`).get(dayStart, dayEnd);
      return r.c;
    }
    case 'trades': {
      const r = db.prepare(`SELECT COUNT(*) as c FROM events WHERE timestamp >= ? AND timestamp <= ? AND type = 'agent_trade'`).get(dayStart, dayEnd);
      return r.c;
    }
    case 'registrations': {
      const r = db.prepare(`SELECT COUNT(*) as c FROM events WHERE timestamp >= ? AND timestamp <= ? AND type = 'registration'`).get(dayStart, dayEnd);
      return r.c;
    }
    case 'agent_actions': {
      const r = db.prepare(`SELECT COUNT(*) as c FROM events WHERE timestamp >= ? AND timestamp <= ? AND type = 'agent_action'`).get(dayStart, dayEnd);
      return r.c;
    }
    case 'messages_sent': {
      const r = db.prepare(`SELECT COUNT(*) as c FROM events WHERE timestamp >= ? AND timestamp <= ? AND type IN ('dm_sent', 'channel_message')`).get(dayStart, dayEnd);
      return r.c;
    }
    case 'avg_session_sec': {
      const rows = db.prepare(`SELECT metadata FROM events WHERE timestamp >= ? AND timestamp <= ? AND type = 'session_end'`).all(dayStart, dayEnd);
      let total = 0, count = 0;
      for (const s of rows) {
        try { const m = JSON.parse(s.metadata); if (m.durationSec) { total += parseInt(m.durationSec); count++; } } catch {}
      }
      return count > 0 ? Math.round(total / count) : 0;
    }
    default:
      return 0;
  }
}

// Summary for dashboard cards
function getSummary() {
  if (!db) return null;
  ensureAggregated();

  const today = new Date().toISOString().slice(0, 10);
  const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);

  // Yesterday's aggregated values
  const getYesterday = (metric) => {
    const r = db.prepare(`SELECT value FROM daily_metrics WHERE date = ? AND metric = ?`).get(yesterday, metric);
    return r?.value || 0;
  };

  // Total verifications ever
  const totalVerifs = db.prepare(`SELECT COUNT(*) as c FROM events WHERE type = 'x402_verification'`).get();
  // Total registered agents
  const totalRegs = db.prepare(`SELECT COUNT(*) as c FROM events WHERE type = 'registration'`).get();

  return {
    humans: {
      today: getTodayLive('human_visits'),
      yesterday: getYesterday('human_visits'),
      uniqueToday: getTodayLive('unique_humans'),
      uniqueYesterday: getYesterday('unique_humans')
    },
    agents: {
      activeToday: getTodayLive('active_agents'),
      activeYesterday: getYesterday('active_agents'),
      totalRegistered: totalRegs.c,
      registeredInPeriod: getTodayLive('registrations'),
      registeredInPrev: getYesterday('registrations')
    },
    verifications: {
      today: getTodayLive('verifications'),
      yesterday: getYesterday('verifications'),
      total: totalVerifs.c
    },
    trades: {
      today: getTodayLive('trades'),
      yesterday: getYesterday('trades')
    },
    agentActions: {
      today: getTodayLive('agent_actions'),
      yesterday: getYesterday('agent_actions')
    },
    messages: {
      today: getTodayLive('messages_sent'),
      yesterday: getYesterday('messages_sent')
    },
    avgSession: {
      today: getTodayLive('avg_session_sec'),
      yesterday: getYesterday('avg_session_sec')
    }
  };
}

// Summary with period-relative comparison (current N days vs previous N days)
function getSummaryForPeriod(days) {
  if (!db) return null;
  ensureAggregated();

  const now = Date.now();
  const periodEnd = new Date(now).toISOString();
  const periodStart = new Date(now - days * 86400000).toISOString();
  const prevStart = new Date(now - days * 2 * 86400000).toISOString();
  const prevEnd = periodStart;

  function countPageViews(start, end) {
    return db.prepare(`SELECT COUNT(*) as c FROM page_views WHERE timestamp >= ? AND timestamp < ? AND is_bot = 0`).get(start, end).c;
  }
  function countUniqueHumans(start, end) {
    return db.prepare(`SELECT COUNT(DISTINCT ip_hash) as c FROM page_views WHERE timestamp >= ? AND timestamp < ? AND is_bot = 0 AND ip_hash IS NOT NULL`).get(start, end).c;
  }
  function countEvents(type, start, end) {
    return db.prepare(`SELECT COUNT(*) as c FROM events WHERE timestamp >= ? AND timestamp < ? AND type = ?`).get(start, end, type).c;
  }
  function countActiveAgents(start, end) {
    return db.prepare(`SELECT COUNT(DISTINCT agent_name) as c FROM events WHERE timestamp >= ? AND timestamp < ? AND type IN ('agent_heartbeat', 'agent_trade') AND agent_name IS NOT NULL`).get(start, end).c;
  }
  function countMultiEvents(types, start, end) {
    const placeholders = types.map(() => '?').join(',');
    return db.prepare(`SELECT COUNT(*) as c FROM events WHERE timestamp >= ? AND timestamp < ? AND type IN (${placeholders})`).get(start, end, ...types).c;
  }
  function avgSessionDuration(start, end) {
    const rows = db.prepare(`SELECT metadata FROM events WHERE timestamp >= ? AND timestamp < ? AND type = 'session_end'`).all(start, end);
    let total = 0, count = 0;
    for (const s of rows) {
      try { const m = JSON.parse(s.metadata); if (m.durationSec) { total += parseInt(m.durationSec); count++; } } catch {}
    }
    return count > 0 ? Math.round(total / count) : 0;
  }

  const totalVerifs = db.prepare(`SELECT COUNT(*) as c FROM events WHERE type = 'x402_verification'`).get();
  const totalRegs = db.prepare(`SELECT COUNT(*) as c FROM events WHERE type = 'registration'`).get();

  return {
    humans: {
      today: countPageViews(periodStart, periodEnd),
      yesterday: countPageViews(prevStart, prevEnd),
      uniqueToday: countUniqueHumans(periodStart, periodEnd),
      uniqueYesterday: countUniqueHumans(prevStart, prevEnd)
    },
    agents: {
      activeToday: countActiveAgents(periodStart, periodEnd),
      activeYesterday: countActiveAgents(prevStart, prevEnd),
      totalRegistered: totalRegs.c,
      registeredInPeriod: countEvents('registration', periodStart, periodEnd),
      registeredInPrev: countEvents('registration', prevStart, prevEnd)
    },
    verifications: {
      today: countEvents('x402_verification', periodStart, periodEnd),
      yesterday: countEvents('x402_verification', prevStart, prevEnd),
      total: totalVerifs.c
    },
    trades: {
      today: countEvents('agent_trade', periodStart, periodEnd),
      yesterday: countEvents('agent_trade', prevStart, prevEnd)
    },
    agentActions: {
      today: countEvents('agent_action', periodStart, periodEnd),
      yesterday: countEvents('agent_action', prevStart, prevEnd)
    },
    messages: {
      today: countMultiEvents(['dm_sent', 'channel_message'], periodStart, periodEnd),
      yesterday: countMultiEvents(['dm_sent', 'channel_message'], prevStart, prevEnd)
    },
    avgSession: {
      today: avgSessionDuration(periodStart, periodEnd),
      yesterday: avgSessionDuration(prevStart, prevEnd)
    }
  };
}

// Get hourly metric timeseries (for 24h view)
function getHourlyMetrics(metric, hours) {
  if (!db) return [];

  const now = new Date();
  const start = new Date(now.getTime() - hours * 3600000);
  const startISO = start.toISOString();

  const result = [];

  // Generate hour buckets
  for (let h = 0; h < hours; h++) {
    const bucketStart = new Date(start.getTime() + h * 3600000);
    const bucketEnd = new Date(start.getTime() + (h + 1) * 3600000);
    const bsISO = bucketStart.toISOString();
    const beISO = bucketEnd.toISOString();

    let value = 0;
    switch (metric) {
      case 'human_visits': {
        const r = db.prepare(`SELECT COUNT(*) as c FROM page_views WHERE timestamp >= ? AND timestamp < ? AND is_bot = 0`).get(bsISO, beISO);
        value = r.c;
        break;
      }
      case 'unique_humans': {
        const r = db.prepare(`SELECT COUNT(DISTINCT ip_hash) as c FROM page_views WHERE timestamp >= ? AND timestamp < ? AND is_bot = 0 AND ip_hash IS NOT NULL`).get(bsISO, beISO);
        value = r.c;
        break;
      }
      case 'active_agents': {
        const r = db.prepare(`SELECT COUNT(DISTINCT agent_name) as c FROM events WHERE timestamp >= ? AND timestamp < ? AND type IN ('agent_heartbeat', 'agent_trade') AND agent_name IS NOT NULL`).get(bsISO, beISO);
        value = r.c;
        break;
      }
      case 'verifications': {
        const r = db.prepare(`SELECT COUNT(*) as c FROM events WHERE timestamp >= ? AND timestamp < ? AND type = 'x402_verification'`).get(bsISO, beISO);
        value = r.c;
        break;
      }
      case 'trades': {
        const r = db.prepare(`SELECT COUNT(*) as c FROM events WHERE timestamp >= ? AND timestamp < ? AND type = 'agent_trade'`).get(bsISO, beISO);
        value = r.c;
        break;
      }
      case 'registrations': {
        const r = db.prepare(`SELECT COUNT(*) as c FROM events WHERE timestamp >= ? AND timestamp < ? AND type = 'registration'`).get(bsISO, beISO);
        value = r.c;
        break;
      }
      case 'agent_actions': {
        const r = db.prepare(`SELECT COUNT(*) as c FROM events WHERE timestamp >= ? AND timestamp < ? AND type = 'agent_action'`).get(bsISO, beISO);
        value = r.c;
        break;
      }
      case 'messages_sent': {
        const r = db.prepare(`SELECT COUNT(*) as c FROM events WHERE timestamp >= ? AND timestamp < ? AND type IN ('dm_sent', 'channel_message')`).get(bsISO, beISO);
        value = r.c;
        break;
      }
      case 'avg_session_sec': {
        const rows = db.prepare(`SELECT metadata FROM events WHERE timestamp >= ? AND timestamp < ? AND type = 'session_end'`).all(bsISO, beISO);
        let total = 0, count = 0;
        for (const s of rows) {
          try { const m = JSON.parse(s.metadata); if (m.durationSec) { total += parseInt(m.durationSec); count++; } } catch {}
        }
        value = count > 0 ? Math.round(total / count) : 0;
        break;
      }
    }

    // Label as HH:00
    const label = bucketStart.toISOString().slice(11, 16);
    result.push({ date: label, value });
  }

  return result;
}

// Top pages by views
function getTopPages(days) {
  if (!db) return [];
  const startDate = new Date(Date.now() - days * 86400000).toISOString();
  return db.prepare(`
    SELECT path, COUNT(*) as views
    FROM page_views
    WHERE timestamp >= ? AND is_bot = 0 AND path != ''
    GROUP BY path
    ORDER BY views DESC
    LIMIT 10
  `).all(startDate);
}

// Backfill from agents.json data
function backfillFromAgents(agents) {
  if (!db) return { events: 0 };
  let count = 0;

  // Check if already backfilled
  const existing = db.prepare(`SELECT COUNT(*) as c FROM events WHERE metadata LIKE '%backfill%'`).get();
  if (existing.c > 0) return { events: 0, message: 'Already backfilled' };

  const insert = db.transaction(() => {
    for (const [name, agent] of Object.entries(agents)) {
      // Registration events
      if (agent.registeredAt) {
        trackEventAt(agent.registeredAt, 'registration', name, { backfill: true });
        count++;
      }

      // x402 verifications
      if (agent.erc8004?.x402Support?.verifiedAt) {
        trackEventAt(agent.erc8004.x402Support.verifiedAt, 'x402_verification', name, { backfill: true });
        count++;
      }

      // Historical trades from transactions
      if (agent.transactions) {
        for (const tx of agent.transactions) {
          if (tx.type === 'swap' && tx.timestamp) {
            trackEventAt(tx.timestamp, 'agent_trade', name, {
              backfill: true,
              dex: tx.dex,
              pair: `${tx.sellToken?.symbol || '?'}→${tx.buyToken?.symbol || '?'}`
            });
            count++;
          }
        }
      }
    }
  });

  insert();

  // Clear any existing aggregations so they're recalculated
  db.prepare(`DELETE FROM daily_metrics`).run();

  return { events: count };
}

// Prune old page_views (keep last N days)
function prunePageViews(keepDays) {
  if (!db) return;
  const cutoff = new Date(Date.now() - keepDays * 86400000).toISOString();
  const result = db.prepare(`DELETE FROM page_views WHERE timestamp < ?`).run(cutoff);
  return result.changes;
}

module.exports = {
  initAnalytics,
  trackPageView,
  trackEvent,
  trackEventAt,
  getDailyMetrics,
  getHourlyMetrics,
  getSummary,
  getSummaryForPeriod,
  getTopPages,
  backfillFromAgents,
  prunePageViews,
  isBot,
  hashIP,
  getDb: () => db
};
