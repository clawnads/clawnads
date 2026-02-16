/* ============================================
   Clawnads Analytics Dashboard
   ============================================ */

let currentDays = 30;

// ===== Session Check =====

async function checkSession() {
  try {
    const resp = await fetch('/admin/api/session');
    const data = await resp.json();
    if (data.authenticated) {
      showAdminView();
    } else {
      showLoginView();
    }
  } catch {
    showLoginView();
  }
}

function showLoginView() {
  document.getElementById('login-view').style.display = 'block';
  document.getElementById('admin-view').style.display = 'none';
  lucide.createIcons();
}

function showAdminView() {
  document.getElementById('login-view').style.display = 'none';
  document.getElementById('admin-view').style.display = 'block';
  lucide.createIcons();
  loadAnalytics();
}

// ===== Data Loading =====

async function loadAnalytics() {
  await Promise.all([
    loadSummary(),
    loadTreasury(),
    loadCharts(),
    loadTopPages()
  ]);
}

async function loadSummary() {
  try {
    const days = currentDays === 'all' ? 'all' : currentDays;
    const resp = await fetch(`/admin/api/analytics/summary?days=${days}`);
    const data = await resp.json();

    // Row 1: Humans
    setCard('stat-unique', data.humans.uniqueToday, data.humans.uniqueYesterday);
    setCard('stat-visits', data.humans.today, data.humans.yesterday);

    // Avg Session — display as "Xm Ys"
    const avgSec = data.avgSession?.today || 0;
    const avgPrev = data.avgSession?.yesterday || 0;
    setCard('stat-session', avgSec, avgPrev);
    const sessEl = document.getElementById('stat-session');
    if (sessEl) {
      if (avgSec > 0) {
        const m = Math.floor(avgSec / 60);
        const s = avgSec % 60;
        sessEl.textContent = m > 0 ? m + 'm ' + s + 's' : s + 's';
      } else {
        sessEl.textContent = '--';
      }
    }
    // Fix session delta to also show time format
    const sessDelta = document.getElementById('stat-session-delta');
    if (sessDelta && (avgSec > 0 || avgPrev > 0)) {
      const diff = avgSec - avgPrev;
      const sign = diff > 0 ? '+' : '';
      const absDiff = Math.abs(diff);
      const dm = Math.floor(absDiff / 60);
      const ds = absDiff % 60;
      const fmtDiff = dm > 0 ? dm + 'm ' + ds + 's' : ds + 's';
      sessDelta.textContent = '\u0394 ' + sign + fmtDiff;
    }

    setCard('stat-trades', data.trades.today, data.trades.yesterday);

    // Row 2: Platform
    setCard('stat-agents', data.agents.activeToday, data.agents.activeYesterday);
    setCard('stat-actions', data.agentActions?.today || 0, data.agentActions?.yesterday || 0);
    setCard('stat-messages', data.messages?.today || 0, data.messages?.yesterday || 0);

    // Registered: total with period-over-period change
    setCard('stat-registered', data.agents.totalRegistered, null);
    const regPct = document.getElementById('stat-registered-pct');
    const regDelta = document.getElementById('stat-registered-delta');
    if (regPct && regDelta) {
      const cur = data.agents.registeredInPeriod || 0;
      const prev = data.agents.registeredInPrev || 0;
      const diff = cur - prev;
      const sign = diff > 0 ? '+' : '';
      regPct.classList.remove('an-up', 'an-down');
      if (prev === 0) {
        regPct.textContent = cur > 0 ? 'new' : '--';
        if (cur > 0) regPct.classList.add('an-up');
      } else {
        const pct = Math.round((diff / prev) * 100);
        if (pct > 0) { regPct.textContent = '\u2191' + pct + '%'; regPct.classList.add('an-up'); }
        else if (pct < 0) { regPct.textContent = '\u2193' + Math.abs(pct) + '%'; regPct.classList.add('an-down'); }
        else { regPct.textContent = '0%'; }
      }
      regDelta.textContent = '\u0394 ' + sign + diff;
    }
    setCard('stat-verifs-total', data.verifications.today, data.verifications.yesterday);
  } catch (e) {
    console.error('Failed to load summary:', e);
  }
}

async function loadTreasury() {
  try {
    const resp = await fetch('/admin/api/analytics/treasury');
    const data = await resp.json();
    const el = document.getElementById('stat-treasury');
    if (el) {
      const val = parseFloat(data.formatted);
      el.textContent = '$' + val.toFixed(val < 1 ? 4 : 2);
    }
  } catch (e) {
    console.error('Failed to load treasury:', e);
  }
}

function setCard(id, current, previous) {
  const el = document.getElementById(id);
  const pctEl = document.getElementById(id + '-pct');
  const deltaEl = document.getElementById(id + '-delta');
  if (!el) return;

  // Big number = absolute value
  el.textContent = current.toLocaleString();

  if (!pctEl || !deltaEl || previous === null || previous === undefined) return;

  const diff = current - previous;
  const sign = diff > 0 ? '+' : '';

  // % change line
  pctEl.classList.remove('an-up', 'an-down');
  if (previous === 0) {
    // No prior data to compare — show "new" or flat
    pctEl.textContent = current > 0 ? 'new' : '--';
    if (current > 0) pctEl.classList.add('an-up');
  } else {
    const pct = Math.round((diff / previous) * 100);
    if (pct > 0) {
      pctEl.textContent = '\u2191' + pct + '%';
      pctEl.classList.add('an-up');
    } else if (pct < 0) {
      pctEl.textContent = '\u2193' + Math.abs(pct) + '%';
      pctEl.classList.add('an-down');
    } else {
      pctEl.textContent = '0%';
    }
  }

  // Delta line
  deltaEl.textContent = '\u0394 ' + sign + diff;
}

async function loadCharts() {
  const days = currentDays === 'all' ? 3650 : currentDays;
  const isHourly = currentDays === 1;
  const granularity = isHourly ? 'hourly' : 'daily';
  const metrics = [
    { id: 'chart-unique-humans', metric: 'unique_humans', color: '#7c5cff', type: 'line', label: 'Unique Humans' },
    { id: 'chart-active-agents', metric: 'active_agents', color: '#22c55e', type: 'line', label: 'Active Agents' },
    { id: 'chart-agent-actions', metric: 'agent_actions', color: '#3b82f6', type: 'line', label: 'Agent Actions' },
    { id: 'chart-messages', metric: 'messages_sent', color: '#a855f7', type: 'bar', label: 'Messages Sent' },
    { id: 'chart-verifications', metric: 'verifications', color: '#f59e0b', type: 'bar', label: 'Verifications' }
  ];

  await Promise.all(metrics.map(async (m) => {
    try {
      const url = `/admin/api/analytics/timeseries?metric=${m.metric}&days=${days}` +
        (isHourly ? '&granularity=hourly' : '');
      const resp = await fetch(url);
      const data = await resp.json();
      const container = document.getElementById(m.id);
      if (!container) return;

      if (!data.data || data.data.length === 0 || data.data.every(d => d.value === 0)) {
        container.innerHTML = '<div class="an-chart-empty">No data yet</div>';
        return;
      }

      if (m.type === 'line') {
        drawLineChart(container, data.data, m.color, isHourly, m.label);
      } else {
        drawBarChart(container, data.data, m.color, isHourly, m.label);
      }
    } catch (e) {
      console.error(`Failed to load chart ${m.metric}:`, e);
    }
  }));
}

async function loadTopPages() {
  try {
    const days = currentDays === 'all' ? 3650 : currentDays;
    const resp = await fetch(`/admin/api/analytics/top-pages?days=${days}`);
    const pages = await resp.json();
    const container = document.getElementById('top-pages-list');
    if (!container) return;

    if (!pages || pages.length === 0) {
      container.innerHTML = '<div class="an-chart-empty">No page view data yet</div>';
      return;
    }

    const maxViews = pages[0].views;
    container.innerHTML = '<div class="an-top-pages">' + pages.map(p => `
      <div class="an-page-row">
        <div class="an-page-path" title="${p.path}">${p.path}</div>
        <div class="an-page-bar-wrap">
          <div class="an-page-bar" style="width: ${(p.views / maxViews * 100).toFixed(1)}%"></div>
        </div>
        <div class="an-page-count">${p.views}</div>
      </div>
    `).join('') + '</div>';
  } catch (e) {
    console.error('Failed to load top pages:', e);
  }
}

// ===== SVG Charts with Hover Tooltips =====

function drawLineChart(container, data, color, isHourly, metricLabel) {
  const W = 500, H = 130;
  const padL = 28, padR = 8, padT = 8, padB = 20;
  const chartW = W - padL - padR;
  const chartH = H - padT - padB;

  const values = data.map(d => d.value);
  const maxVal = Math.max(...values, 1);
  const range = maxVal || 1;

  const points = data.map((d, i) => {
    const x = padL + (i / Math.max(data.length - 1, 1)) * chartW;
    const y = padT + chartH - (d.value / range) * chartH;
    return { x, y, date: d.date, value: d.value };
  });

  const pathD = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ');
  const areaD = pathD +
    ` L ${points[points.length - 1].x.toFixed(1)} ${padT + chartH}` +
    ` L ${points[0].x.toFixed(1)} ${padT + chartH} Z`;

  const yLabels = [0, maxVal];
  const step = Math.max(1, Math.floor(data.length / 4));
  const xLabels = data.filter((_, i) => i % step === 0 || i === data.length - 1);

  let svg = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">`;

  yLabels.forEach(v => {
    const y = padT + chartH - (v / range) * chartH;
    svg += `<line x1="${padL}" y1="${y.toFixed(1)}" x2="${W - padR}" y2="${y.toFixed(1)}" stroke="rgba(63,63,70,0.3)" stroke-width="0.5"/>`;
    svg += `<text x="${padL - 4}" y="${(y + 3).toFixed(1)}" text-anchor="end" fill="#52525b" font-size="7" font-family="Inter,sans-serif">${v}</text>`;
  });

  svg += `<path d="${areaD}" fill="${color}" fill-opacity="0.08"/>`;
  svg += `<path d="${pathD}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>`;

  // Data points with hover targets
  points.forEach(p => {
    const label = isHourly ? p.date : p.date.slice(5);
    // Invisible larger hit area
    svg += `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="8" fill="transparent" class="an-hover-target"><title>${label}: ${p.value}</title></circle>`;
    // Visible dot
    svg += `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="1.5" fill="${color}" opacity="0.5" pointer-events="none"/>`;
  });

  xLabels.forEach(d => {
    const i = data.indexOf(d);
    const x = padL + (i / Math.max(data.length - 1, 1)) * chartW;
    const label = isHourly ? d.date : d.date.slice(5);
    svg += `<text x="${x.toFixed(1)}" y="${H - 3}" text-anchor="middle" fill="#52525b" font-size="7" font-family="Inter,sans-serif">${label}</text>`;
  });

  svg += '</svg>';
  container.innerHTML = svg;

  // Add interactive hover tooltip
  addChartTooltip(container, points, color, isHourly, metricLabel);
}

function drawBarChart(container, data, color, isHourly, metricLabel) {
  const W = 500, H = 130;
  const padL = 28, padR = 8, padT = 8, padB = 20;
  const chartW = W - padL - padR;
  const chartH = H - padT - padB;

  const values = data.map(d => d.value);
  const maxVal = Math.max(...values, 1);

  const barW = Math.max(2, (chartW / data.length) * 0.7);
  const gap = (chartW / data.length) * 0.3;

  const yLabels = [0, maxVal];
  const step = Math.max(1, Math.floor(data.length / 4));
  const xLabels = data.filter((_, i) => i % step === 0 || i === data.length - 1);

  let svg = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">`;

  yLabels.forEach(v => {
    const y = padT + chartH - (v / maxVal) * chartH;
    svg += `<line x1="${padL}" y1="${y.toFixed(1)}" x2="${W - padR}" y2="${y.toFixed(1)}" stroke="rgba(63,63,70,0.3)" stroke-width="0.5"/>`;
    svg += `<text x="${padL - 4}" y="${(y + 3).toFixed(1)}" text-anchor="end" fill="#52525b" font-size="7" font-family="Inter,sans-serif">${v}</text>`;
  });

  const barData = [];
  data.forEach((d, i) => {
    const x = padL + (i / data.length) * chartW + gap / 2;
    const barH = (d.value / maxVal) * chartH;
    const y = padT + chartH - barH;
    const label = isHourly ? d.date : d.date.slice(5);
    svg += `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barW.toFixed(1)}" height="${barH.toFixed(1)}" fill="${color}" rx="1" opacity="0.8"><title>${label}: ${d.value}</title></rect>`;
    barData.push({ x: x + barW / 2, y, date: d.date, value: d.value });
  });

  xLabels.forEach(d => {
    const i = data.indexOf(d);
    const x = padL + (i / data.length) * chartW + barW / 2;
    const label = isHourly ? d.date : d.date.slice(5);
    svg += `<text x="${x.toFixed(1)}" y="${H - 3}" text-anchor="middle" fill="#52525b" font-size="7" font-family="Inter,sans-serif">${label}</text>`;
  });

  svg += '</svg>';
  container.innerHTML = svg;

  // Add interactive hover tooltip
  addChartTooltip(container, barData, color, isHourly, metricLabel);
}

// Dune-style tooltip card that follows mouse over chart
function addChartTooltip(container, points, color, isHourly, metricLabel) {
  // Create tooltip card
  let tooltip = container.querySelector('.an-tt');
  if (!tooltip) {
    tooltip = document.createElement('div');
    tooltip.className = 'an-tt';
    container.appendChild(tooltip);
  }

  // Create crosshair line
  let crosshair = container.querySelector('.an-crosshair');
  if (!crosshair) {
    crosshair = document.createElement('div');
    crosshair.className = 'an-crosshair';
    container.appendChild(crosshair);
  }

  const svg = container.querySelector('svg');
  if (!svg) return;

  svg.addEventListener('mousemove', (e) => {
    const rect = svg.getBoundingClientRect();
    const svgW = 500;
    const svgH = 130;
    const relX = ((e.clientX - rect.left) / rect.width) * svgW;

    // Find nearest point
    let nearest = points[0];
    let minDist = Infinity;
    for (const p of points) {
      const d = Math.abs(p.x - relX);
      if (d < minDist) { minDist = d; nearest = p; }
    }

    // Format date
    const dateLabel = isHourly ? nearest.date : nearest.date;

    // Build tooltip card HTML
    tooltip.innerHTML =
      '<div class="an-tt-date">' + dateLabel + '</div>' +
      '<div class="an-tt-row">' +
        '<span class="an-tt-dot" style="background:' + color + '"></span>' +
        '<span class="an-tt-label">' + (metricLabel || '') + '</span>' +
        '<span class="an-tt-val">' + nearest.value.toLocaleString() + '</span>' +
      '</div>';
    tooltip.style.display = 'block';

    // Position tooltip — anchor to nearest data point
    const pxX = (nearest.x / svgW) * rect.width;

    // Keep tooltip inside container bounds
    const ttWidth = 180;
    let left = pxX - ttWidth / 2;
    if (left < 0) left = 0;
    if (left + ttWidth > rect.width) left = rect.width - ttWidth;
    tooltip.style.left = left + 'px';
    tooltip.style.top = '0px';

    // Position crosshair line
    crosshair.style.display = 'block';
    crosshair.style.left = pxX + 'px';
  });

  svg.addEventListener('mouseleave', () => {
    tooltip.style.display = 'none';
    crosshair.style.display = 'none';
  });
}

// ===== Event Handlers =====

document.querySelectorAll('.an-range-btn[data-days]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.an-range-btn[data-days]').forEach(b => b.classList.remove('an-range-btn-active'));
    btn.classList.add('an-range-btn-active');
    currentDays = btn.dataset.days === 'all' ? 'all' : parseInt(btn.dataset.days);
    loadAnalytics();
  });
});

document.getElementById('backfill-btn')?.addEventListener('click', async () => {
  const btn = document.getElementById('backfill-btn');
  const icon = '<i data-lucide="database" style="width:14px;height:14px"></i>';
  btn.disabled = true;
  btn.innerHTML = '<i data-lucide="loader-2" style="width:14px;height:14px" class="an-spin"></i>';
  lucide.createIcons({ nodes: [btn] });

  try {
    const resp = await fetch('/admin/api/analytics/backfill', { method: 'POST' });
    const result = await resp.json();
    btn.innerHTML = '<i data-lucide="check" style="width:14px;height:14px"></i>';
    lucide.createIcons({ nodes: [btn] });
    if (!result.message) await loadAnalytics();
  } catch (e) {
    btn.innerHTML = '<i data-lucide="x" style="width:14px;height:14px"></i>';
    lucide.createIcons({ nodes: [btn] });
    console.error('Backfill failed:', e);
  }

  setTimeout(() => {
    btn.disabled = false;
    btn.innerHTML = icon;
    lucide.createIcons({ nodes: [btn] });
  }, 2000);
});

// ===== Init =====
checkSession();
