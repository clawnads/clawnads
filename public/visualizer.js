// Trade Visualizer for Clawnads
// Sankey-style flow diagram showing money moving between tokens

const TOKEN_COLORS = {
  MON: '#22c55e',
  WMON: '#22c55e',
  USDC: '#2775ca',
  USDT: '#26a17b',
  USDT0: '#26a17b',
  WETH: '#627eea',
  WBTC: '#f7931a',
  Unknown: '#71717a'
};

const TOKEN_IMAGES = {
  MON: '/tokens/mon.svg',
  WMON: '/tokens/mon.svg',
  USDC: 'https://cryptologos.cc/logos/usd-coin-usdc-logo.svg',
  USDT: '/tokens/tether.svg',
  USDT0: '/tokens/tether.svg',
  WETH: '/tokens/eth-diamond-(gray).svg',
  WBTC: 'https://cryptologos.cc/logos/wrapped-bitcoin-wbtc-logo.svg'
};

function normalizeSymbol(symbol) {
  if (symbol === 'USDT0') return 'USDT';
  if (symbol === 'WMON') return 'MON';
  return symbol;
}

const AGENT_COLORS = [
  '#22c55e', '#3b82f6', '#f59e0b', '#ef4444', '#a855f7',
  '#ec4899', '#14b8a6', '#f97316', '#6366f1', '#84cc16'
];

class TradeVisualizer {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d');
    this.tokens = ['MON', 'USDC', 'USDT', 'WETH', 'WBTC'];
    this.agents = new Map();
    this.flows = new Map();
    this.flowParticles = [];
    this.trades = [];
    this.isRunning = false;
    this.lastTimestamp = null;
    this.animationId = null;
    this.frameCount = 0;

    // Time period filter (1h, 24h, 7d)
    this.timePeriod = '24h';

    // Node positions (calculated in setupCanvas)
    this.leftNodes = [];  // Source tokens (selling)
    this.rightNodes = []; // Destination tokens (buying)

    this.stats = {
      totalTrades: 0,
      totalVolume: 0,
      activeAgents: 0
    };

    this.tokenAliases = { 'USDT0': 'USDT', 'WMON': 'MON' };
    this.allTrades = []; // Store all fetched trades

    // Preloaded token images
    this.tokenImages = new Map();
    this.loadTokenImages();

    this.setupCanvas();
    this.setupTimePeriodSelector();

    // Use ResizeObserver with debounce to prevent flashing
    this.resizeTimeout = null;
    const debouncedResize = () => {
      clearTimeout(this.resizeTimeout);
      this.resizeTimeout = setTimeout(() => this.setupCanvas(), 100);
    };

    if (window.ResizeObserver) {
      this.resizeObserver = new ResizeObserver(debouncedResize);
      this.resizeObserver.observe(this.canvas.parentElement);
    } else {
      window.addEventListener('resize', debouncedResize);
    }
  }

  loadTokenImages() {
    this.tokens.forEach(symbol => {
      const img = new Image();
      img.crossOrigin = 'anonymous';
      img.src = TOKEN_IMAGES[symbol] || TOKEN_IMAGES.MON;
      img.onload = () => {
        this.tokenImages.set(symbol, img);
      };
    });
  }

  setupTimePeriodSelector() {
    const buttons = document.querySelectorAll('.viz-time-btn');
    buttons.forEach(btn => {
      btn.addEventListener('click', () => {
        buttons.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this.setTimePeriod(btn.dataset.period);
      });
    });
  }

  setTimePeriod(period) {
    this.timePeriod = period;
    // Re-filter existing trades for new period
    this.rebuildFromAllTrades();
    // Update period-specific stats
    this.updatePeriodStats();
  }

  getTimePeriodMs() {
    switch (this.timePeriod) {
      case '1h': return 60 * 60 * 1000;
      case '24h': return 24 * 60 * 60 * 1000;
      case '7d': return 7 * 24 * 60 * 60 * 1000;
      default: return 24 * 60 * 60 * 1000;
    }
  }

  rebuildFromAllTrades() {
    // Clear current state
    this.flows.clear();
    this.flowParticles = [];
    this.stats.totalTrades = 0;

    // Clear the feed
    const feedList = document.getElementById('trade-feed-list');
    if (feedList) {
      feedList.innerHTML = '<div class="viz-trades-empty">Loading...</div>';
    }

    // Filter trades by time period
    const periodMs = this.getTimePeriodMs();
    const cutoff = Date.now() - periodMs;
    const filteredTrades = this.allTrades.filter(t => new Date(t.timestamp).getTime() > cutoff);

    console.log(`[Visualizer] Period: ${this.timePeriod}, Cutoff: ${new Date(cutoff).toISOString()}`);
    console.log(`[Visualizer] All trades: ${this.allTrades.length}, Filtered: ${filteredTrades.length}`);

    // Rebuild flows and feed from filtered trades
    filteredTrades.slice().reverse().forEach((trade, i) => {
      if (trade.type === 'send' || trade.type === 'transfer' || trade.type === 'erc8004-register' || trade.type === 'x402-donation') {
        // Non-swap activity only goes in the feed, not the Sankey
        this.addTradeToFeed(trade);
      } else {
        const from = normalizeSymbol(trade.sellSymbol);
        const to = normalizeSymbol(trade.buySymbol);
        console.log(`[Visualizer] Trade ${i}: ${from} -> ${to}`);
        this.updateFlow(trade.sellSymbol, trade.buySymbol);
        this.addTradeToFeed(trade);

        // Spawn particles for recent trades
        const tradeAge = Date.now() - new Date(trade.timestamp);
        if (tradeAge < 300000) { // 5 min
          setTimeout(() => {
            this.spawnFlowParticles(trade.sellSymbol, trade.buySymbol, 8);
          }, i * 100);
        }
      }
    });

    console.log(`[Visualizer] Flows created:`, Array.from(this.flows.keys()));

    this.stats.totalTrades = filteredTrades.length;
    this.updateStats();
  }

  setupCanvas() {
    const rect = this.canvas.parentElement.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;

    this.canvas.width = rect.width * dpr;
    this.canvas.height = rect.height * dpr;
    this.canvas.style.width = rect.width + 'px';
    this.canvas.style.height = rect.height + 'px';

    this.ctx.scale(dpr, dpr);
    this.width = rect.width;
    this.height = rect.height;

    this.positionNodes();
  }

  positionNodes() {
    if (this.width === 0 || this.height === 0) return;

    const iconSize = 24;
    const maxSpacing = 50; // Tighter spacing between tokens
    const topPadding = 24; // Pin to top with small padding

    // Comfortable padding from edges
    const isMobile = window.innerWidth <= 768;
    const edgeMargin = isMobile ? 16 : 24;
    const leftX = edgeMargin + iconSize / 2;
    const rightX = this.width - edgeMargin - iconSize / 2;

    // Use max spacing, pinned to top
    const spacing = maxSpacing;
    const startY = topPadding + iconSize / 2;

    this.leftNodes = this.tokens.map((symbol, i) => ({
      symbol,
      x: leftX,
      y: startY + spacing * i,
      color: TOKEN_COLORS[symbol],
      size: iconSize
    }));

    this.rightNodes = this.tokens.map((symbol, i) => ({
      symbol,
      x: rightX,
      y: startY + spacing * i,
      color: TOKEN_COLORS[symbol],
      size: iconSize
    }));
  }

  getFlowKey(from, to) {
    return `${normalizeSymbol(from)}->${normalizeSymbol(to)}`;
  }

  updateFlow(fromSymbol, toSymbol, amount = 1) {
    const from = normalizeSymbol(fromSymbol);
    const to = normalizeSymbol(toSymbol);
    if (from === to) return;

    const key = this.getFlowKey(from, to);
    const existing = this.flows.get(key) || { from, to, volume: 0, lastTrade: 0 };
    existing.volume += amount;
    existing.lastTrade = Date.now();
    this.flows.set(key, existing);
  }

  getNodeBySymbol(nodes, symbol) {
    const normalized = this.tokenAliases[symbol] || symbol;
    return nodes.find(n => n.symbol === normalized);
  }

  spawnFlowParticles(fromSymbol, toSymbol, count = 5) {
    const from = normalizeSymbol(fromSymbol);
    const to = normalizeSymbol(toSymbol);

    const leftNode = this.getNodeBySymbol(this.leftNodes, from);
    const rightNode = this.getNodeBySymbol(this.rightNodes, to);

    if (!leftNode || !rightNode) return;

    const labelWidth = 50;

    for (let i = 0; i < count; i++) {
      this.flowParticles.push({
        fromX: leftNode.x + labelWidth,
        fromY: leftNode.y + (Math.random() - 0.5) * 6,
        toX: rightNode.x - labelWidth,
        toY: rightNode.y + (Math.random() - 0.5) * 6,
        progress: 0,
        delay: i * 30,
        startTime: Date.now(),
        duration: 800 + Math.random() * 300,
        color: leftNode.color,
        size: 2 + Math.random() * 1
      });
    }
  }

  setAgents(agents) {
    agents.forEach((agent, i) => {
      if (!this.agents.has(agent.name)) {
        this.agents.set(agent.name, {
          name: agent.name,
          color: AGENT_COLORS[i % AGENT_COLORS.length],
          karma: agent.karma,
          tradeCount: agent.tradeCount || 0
        });
      } else {
        const existing = this.agents.get(agent.name);
        existing.karma = agent.karma;
        existing.tradeCount = agent.tradeCount || 0;
      }
    });
    this.stats.activeAgents = this.agents.size;
    this.updateAgentLegend();
  }

  updateAgentLegend() {
    // Disabled for now - will add top traders tab later
  }

  addTradeToFeed(trade) {
    const feedList = document.getElementById('trade-feed-list');
    if (!feedList) return;

    const empty = feedList.querySelector('.viz-trades-empty');
    if (empty) empty.remove();

    const timeAgo = this.getTimeAgo(trade.timestamp);
    const tradeEl = document.createElement('div');
    tradeEl.className = 'viz-trade-item';

    if (trade.type === 'erc8004-register') {
      tradeEl.innerHTML = `
        <div class="viz-trade-header">
          <span class="viz-trade-agent">${trade.agentName}</span>
          <span class="viz-trade-time">${timeAgo}</span>
        </div>
        <div class="viz-trade-body">
          <span class="viz-activity-badge erc8004">ERC-8004</span>
          <span class="viz-trade-label">Registered identity</span>
        </div>
      `;
    } else if (trade.type === 'x402-donation') {
      tradeEl.innerHTML = `
        <div class="viz-trade-header">
          <span class="viz-trade-agent">${trade.agentName}</span>
          <span class="viz-trade-time">${timeAgo}</span>
        </div>
        <div class="viz-trade-body">
          <span class="viz-activity-badge x402">x402</span>
          <span class="viz-trade-label">Verified payments</span>
        </div>
      `;
    } else if (trade.type === 'send' || trade.type === 'transfer') {
      // Send/transfer: show "Sent X TOKEN → agent/address"
      const symbol = normalizeSymbol(trade.tokenSymbol || 'MON');
      const tokenImg = TOKEN_IMAGES[symbol] || TOKEN_IMAGES.MON;
      const recipient = trade.toAgent || (typeof resolveAgentName === 'function' && resolveAgentName(trade.toAddress)) || (trade.toAddress ? trade.toAddress.slice(0, 6) + '...' + trade.toAddress.slice(-4) : '?');

      // Decode amount
      let amount = '';
      if (trade.amount && trade.amount !== '0x0') {
        const decimals = symbol === 'USDC' || symbol === 'USDT0' || symbol === 'USDT' ? 6 : symbol === 'WBTC' ? 8 : 18;
        const raw = parseInt(trade.amount, 16);
        const val = raw / Math.pow(10, decimals);
        amount = val < 0.001 ? val.toExponential(2) : val < 1 ? val.toFixed(4) : val.toFixed(2);
      }

      tradeEl.innerHTML = `
        <div class="viz-trade-header">
          <span class="viz-trade-agent">${trade.agentName}</span>
          <span class="viz-trade-time">${timeAgo}</span>
        </div>
        <div class="viz-trade-body">
          <span class="viz-trade-label" style="color:var(--color-text-tertiary)">Sent</span>
          <img src="${tokenImg}" class="viz-trade-token-img" alt="${symbol}">
          <span class="viz-trade-label">${amount} ${symbol}</span>
          <span class="viz-trade-arrow">→</span>
          <span class="viz-trade-label">${recipient}</span>
        </div>
      `;
    } else {
      // Swap
      const sellSymbol = normalizeSymbol(trade.sellSymbol);
      const buySymbol = normalizeSymbol(trade.buySymbol);
      const sellImg = TOKEN_IMAGES[sellSymbol] || TOKEN_IMAGES.MON;
      const buyImg = TOKEN_IMAGES[buySymbol] || TOKEN_IMAGES.MON;

      tradeEl.innerHTML = `
        <div class="viz-trade-header">
          <span class="viz-trade-agent">${trade.agentName}</span>
          <span class="viz-trade-time">${timeAgo}</span>
        </div>
        <div class="viz-trade-body">
          <img src="${sellImg}" class="viz-trade-token-img" alt="${sellSymbol}">
          <span class="viz-trade-label">${sellSymbol}</span>
          <span class="viz-trade-arrow">→</span>
          <img src="${buyImg}" class="viz-trade-token-img" alt="${buySymbol}">
          <span class="viz-trade-label">${buySymbol}</span>
        </div>
      `;

      tradeEl.addEventListener('click', () => {
        this.spawnFlowParticles(trade.sellSymbol, trade.buySymbol, 12);
      });
    }

    feedList.insertBefore(tradeEl, feedList.firstChild);

    while (feedList.children.length > 50) {
      feedList.removeChild(feedList.lastChild);
    }

    this.stats.totalTrades++;
    this.updateStats();
  }

  getTimeAgo(timestamp) {
    const seconds = Math.floor((Date.now() - new Date(timestamp)) / 1000);
    if (seconds < 60) return 'just now';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  }

  updateStats() {
    const tradesEl = document.getElementById('stat-trades');
    if (tradesEl) tradesEl.textContent = this.stats.totalTrades;
  }

  formatUSD(value) {
    if (value >= 1000000) return '$' + (value / 1000000).toFixed(2) + 'M';
    if (value >= 1000) return '$' + (value / 1000).toFixed(2) + 'K';
    if (value >= 1) return '$' + value.toFixed(2);
    return '$' + value.toFixed(4);
  }

  formatChange(percent) {
    if (percent === 0) return { text: '0%', class: 'neutral' };
    const sign = percent > 0 ? '+' : '';
    const cls = percent > 0 ? 'positive' : 'negative';
    return { text: sign + percent.toFixed(1) + '%', class: cls };
  }

  async fetchStats() {
    try {
      const response = await fetch('/stats');
      const data = await response.json();
      if (!data.success) return;

      this.platformStats = data;

      // Update TVL (doesn't change with period)
      const tvlEl = document.getElementById('stat-tvl');
      if (tvlEl) tvlEl.textContent = this.formatUSD(data.tvl);

      // Update period-specific stats
      this.updatePeriodStats();
    } catch (err) {
      console.error('Failed to fetch stats:', err);
    }
  }

  updatePeriodStats() {
    if (!this.platformStats) return;

    const periodStats = this.platformStats.stats[this.timePeriod];
    if (!periodStats) return;

    // Update trades count
    const tradesEl = document.getElementById('stat-trades');
    if (tradesEl) tradesEl.textContent = periodStats.trades;

    // Update trades change
    const changeEl = document.getElementById('stat-trades-change');
    if (changeEl) {
      const change = this.formatChange(periodStats.tradesChange);
      changeEl.textContent = change.text;
      changeEl.className = 'viz-stat-change ' + change.class;
    }

    // Update volume
    const volumeEl = document.getElementById('stat-volume');
    if (volumeEl) volumeEl.textContent = this.formatUSD(periodStats.volumeUSD);
  }

  render() {
    const ctx = this.ctx;
    this.frameCount++;

    // Clear canvas
    ctx.fillStyle = '#09090b';
    ctx.fillRect(0, 0, this.width, this.height);

    // Draw column labels
    this.drawLabels();

    // Draw flow bands (Sankey style)
    this.drawFlowBands();

    // Draw nodes
    this.drawNodes();

    // Update and draw particles
    this.updateParticles();

    // Spawn continuous particles for active flows
    this.spawnContinuousParticles();
  }

  drawLabels() {
    // Labels removed - tokens are self-explanatory
  }

  drawFlowBands() {
    const ctx = this.ctx;
    const maxVolume = Math.max(1, ...Array.from(this.flows.values()).map(f => f.volume));
    const labelWidth = 50; // icon/2 + gap + text width

    this.flows.forEach((flow) => {
      const leftNode = this.getNodeBySymbol(this.leftNodes, flow.from);
      const rightNode = this.getNodeBySymbol(this.rightNodes, flow.to);

      if (!leftNode || !rightNode) return;

      // Thicker minimum lines, scale better with volume
      const thickness = Math.max(2, Math.min(10, (flow.volume / maxVolume) * 10));
      const age = Date.now() - flow.lastTrade;
      // Higher minimum visibility (0.4 instead of 0.15)
      const recency = Math.max(0.4, 1 - age / 600000);

      const startX = leftNode.x + labelWidth;
      const endX = rightNode.x - labelWidth;
      const controlX = (startX + endX) / 2;

      // Higher opacity (0.35 instead of 0.2)
      const alpha = Math.floor(recency * 0.35 * 255).toString(16).padStart(2, '0');
      const gradient = ctx.createLinearGradient(startX, 0, endX, 0);
      gradient.addColorStop(0, leftNode.color + alpha);
      gradient.addColorStop(1, rightNode.color + alpha);

      ctx.strokeStyle = gradient;
      ctx.lineWidth = thickness;
      ctx.lineCap = 'round';

      ctx.beginPath();
      ctx.moveTo(startX, leftNode.y);
      ctx.bezierCurveTo(controlX, leftNode.y, controlX, rightNode.y, endX, rightNode.y);
      ctx.stroke();
    });
  }

  drawNodes() {
    const ctx = this.ctx;

    // Draw left nodes (sources)
    this.leftNodes.forEach(node => {
      this.drawTokenNode(node, 'left');
    });

    // Draw right nodes (destinations)
    this.rightNodes.forEach(node => {
      this.drawTokenNode(node, 'right');
    });
  }

  drawTokenNode(node, side) {
    const ctx = this.ctx;
    const size = node.size || 24;
    const img = this.tokenImages.get(node.symbol);
    const gap = 6;

    ctx.save();

    // Draw icon
    ctx.fillStyle = '#18181b';
    ctx.beginPath();
    ctx.arc(node.x, node.y, size/2, 0, Math.PI * 2);
    ctx.fill();

    ctx.strokeStyle = '#27272a';
    ctx.lineWidth = 1;
    ctx.stroke();

    if (img && img.complete) {
      ctx.beginPath();
      ctx.arc(node.x, node.y, size/2 - 1, 0, Math.PI * 2);
      ctx.clip();
      ctx.drawImage(img, node.x - size/2 + 1, node.y - size/2 + 1, size - 2, size - 2);
    } else {
      ctx.fillStyle = node.color;
      ctx.beginPath();
      ctx.arc(node.x, node.y, size/2 - 1, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = '#09090b';
      ctx.font = 'bold 10px Inter, sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(node.symbol.charAt(0), node.x, node.y);
    }

    ctx.restore();

    // Text label
    ctx.fillStyle = '#a1a1aa';
    ctx.font = '500 10px Inter, sans-serif';
    ctx.textBaseline = 'middle';

    if (side === 'left') {
      ctx.textAlign = 'left';
      ctx.fillText(node.symbol, node.x + size/2 + gap, node.y);
    } else {
      ctx.textAlign = 'right';
      ctx.fillText(node.symbol, node.x - size/2 - gap, node.y);
    }
  }

  roundRect(ctx, x, y, width, height, radius) {
    ctx.beginPath();
    ctx.moveTo(x + radius, y);
    ctx.lineTo(x + width - radius, y);
    ctx.quadraticCurveTo(x + width, y, x + width, y + radius);
    ctx.lineTo(x + width, y + height - radius);
    ctx.quadraticCurveTo(x + width, y + height, x + width - radius, y + height);
    ctx.lineTo(x + radius, y + height);
    ctx.quadraticCurveTo(x, y + height, x, y + height - radius);
    ctx.lineTo(x, y + radius);
    ctx.quadraticCurveTo(x, y, x + radius, y);
    ctx.closePath();
  }

  spawnContinuousParticles() {
    if (this.frameCount % 30 !== 0) return;

    const labelWidth = 50;

    this.flows.forEach((flow) => {
      const age = Date.now() - flow.lastTrade;
      if (age > 300000) return;

      const leftNode = this.getNodeBySymbol(this.leftNodes, flow.from);
      const rightNode = this.getNodeBySymbol(this.rightNodes, flow.to);

      if (!leftNode || !rightNode) return;

      const spawnChance = Math.min(0.7, flow.volume / 6);
      if (Math.random() > spawnChance) return;

      this.flowParticles.push({
        fromX: leftNode.x + labelWidth,
        fromY: leftNode.y + (Math.random() - 0.5) * 4,
        toX: rightNode.x - labelWidth,
        toY: rightNode.y + (Math.random() - 0.5) * 4,
        progress: 0,
        delay: 0,
        startTime: Date.now(),
        duration: 1000 + Math.random() * 300,
        color: leftNode.color,
        size: 1.5 + Math.random() * 1
      });
    });

    if (this.flowParticles.length > 50) {
      this.flowParticles = this.flowParticles.slice(-40);
    }
  }

  updateParticles() {
    const ctx = this.ctx;
    const now = Date.now();

    this.flowParticles = this.flowParticles.filter(p => {
      const elapsed = now - p.startTime - p.delay;
      if (elapsed < 0) return true;

      p.progress = Math.min(1, elapsed / p.duration);
      if (p.progress >= 1) return false;

      // Ease in-out
      const eased = p.progress < 0.5
        ? 2 * p.progress * p.progress
        : 1 - Math.pow(-2 * p.progress + 2, 2) / 2;

      // Follow bezier curve
      const controlX = (p.fromX + p.toX) / 2;
      const t = eased;

      // Quadratic bezier
      const x = (1-t)*(1-t)*p.fromX + 2*(1-t)*t*controlX + t*t*p.toX;
      const y = (1-t)*(1-t)*p.fromY + 2*(1-t)*t*((p.fromY + p.toY)/2) + t*t*p.toY;

      // Fade at edges
      const fade = p.progress < 0.1 ? p.progress * 10 :
                   p.progress > 0.9 ? (1 - p.progress) * 10 : 1;

      ctx.fillStyle = p.color + Math.floor(fade * 255).toString(16).padStart(2, '0');
      ctx.beginPath();
      ctx.arc(x, y, p.size, 0, Math.PI * 2);
      ctx.fill();

      return true;
    });
  }

  start() {
    if (this.isRunning) return;
    this.isRunning = true;
    this.animate();
    this.startPolling();
    this.fetchStats();
  }

  stop() {
    this.isRunning = false;
    if (this.animationId) {
      cancelAnimationFrame(this.animationId);
      this.animationId = null;
    }
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }
  }

  animate() {
    if (!this.isRunning) return;
    this.render();
    this.animationId = requestAnimationFrame(() => this.animate());
  }

  startPolling() {
    this.fetchTrades();
    this.pollInterval = setInterval(() => this.fetchTrades(), 5000);
  }

  async refresh() {
    // Stop existing poll to prevent race conditions
    if (this.pollInterval) {
      clearInterval(this.pollInterval);
      this.pollInterval = null;
    }

    // Show trade feed skeletons
    const feedList = document.getElementById('trade-feed-list');
    if (feedList) {
      feedList.innerHTML = Array(5).fill(0).map(() => `
        <div class="viz-trade-item">
          <div class="viz-trade-header">
            <div class="skeleton skeleton-text" style="width:60px;height:12px;margin:0;"></div>
            <div class="skeleton skeleton-text" style="width:30px;height:10px;margin:0;"></div>
          </div>
          <div class="viz-trade-body">
            <div class="skeleton" style="width:18px;height:18px;border-radius:50%;flex-shrink:0;"></div>
            <div class="skeleton skeleton-text" style="width:32px;height:11px;margin:0;"></div>
            <span class="viz-trade-arrow" style="opacity:0.2;">→</span>
            <div class="skeleton" style="width:18px;height:18px;border-radius:50%;flex-shrink:0;"></div>
            <div class="skeleton skeleton-text" style="width:32px;height:11px;margin:0;"></div>
          </div>
        </div>
      `).join('');
    }

    // Reset stats to loading state
    const tradesEl = document.getElementById('stat-trades');
    if (tradesEl) tradesEl.textContent = '-';

    // Clear visualizer state and re-fetch
    this.allTrades = [];
    this.trades = [];
    this.flows.clear();
    this.flowParticles = [];
    this.lastTimestamp = null;
    this.stats.totalTrades = 0;

    // Fetch fresh data then restart polling
    await this.fetchTrades();
    this.fetchStats();
    this.pollInterval = setInterval(() => this.fetchTrades(), 5000);
  }

  async fetchTrades() {
    try {
      let url;
      if (this.lastTimestamp) {
        // Polling for new trades
        url = `/trades/recent?since=${encodeURIComponent(this.lastTimestamp)}&limit=20`;
      } else {
        // Initial load - fetch all trades (7 days worth)
        url = '/trades/recent?limit=200';
      }

      const response = await fetch(url);
      const data = await response.json();

      if (!data.success) return;

      if (data.agents) {
        this.setAgents(data.agents);
      }

      if (data.trades && data.trades.length > 0) {
        const isInitialLoad = this.allTrades.length === 0;

        if (isInitialLoad) {
          // Store all trades and rebuild with current time filter
          this.allTrades = data.trades;
          this.lastTimestamp = data.trades[0].timestamp;
          this.rebuildFromAllTrades();
        } else {
          // Add new trades to the beginning
          this.lastTimestamp = data.trades[0].timestamp;
          const newTrades = data.trades.reverse();

          newTrades.forEach(trade => {
            // Add to allTrades
            this.allTrades.unshift(trade);

            // Check if within current time period
            const periodMs = this.getTimePeriodMs();
            const cutoff = Date.now() - periodMs;
            if (new Date(trade.timestamp).getTime() > cutoff) {
              if (trade.type === 'send' || trade.type === 'transfer' || trade.type === 'erc8004-register' || trade.type === 'x402-donation') {
                // Non-swap activity only goes in the feed, not the Sankey
                this.addTradeToFeed(trade);
              } else {
                this.updateFlow(trade.sellSymbol, trade.buySymbol);
                this.addTradeToFeed(trade);
                this.spawnFlowParticles(trade.sellSymbol, trade.buySymbol, 10);
              }
              this.stats.totalTrades++;
              this.updateStats();
            }
          });

          // Keep allTrades limited
          if (this.allTrades.length > 200) {
            this.allTrades = this.allTrades.slice(0, 200);
          }
        }
      }
    } catch (err) {
      console.error('Failed to fetch trades:', err);
    }
  }
}

let visualizer = null;

function initVisualizer() {
  const canvas = document.getElementById('trade-canvas');
  if (!canvas) return;

  visualizer = new TradeVisualizer(canvas);

  const homeTab = document.getElementById('home-tab');
  if (homeTab && homeTab.classList.contains('active')) {
    visualizer.start();
  }
}

function handleTabChange(tabName) {
  if (!visualizer) return;
  if (tabName === 'home') {
    visualizer.start();
  } else {
    visualizer.stop();
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initVisualizer);
} else {
  initVisualizer();
}
