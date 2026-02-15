// ==================== Developer Portal — Clawnads (X Console Layout) ====================

const SCOPES = ['balance', 'swap', 'send', 'sign', 'messages', 'profile'];
const SCOPE_INFO = {
  balance:  { desc: 'View wallet balance',        access: 'ro' },
  swap:     { desc: 'Swap tokens within daily cap', access: 'rw' },
  send:     { desc: 'Send tokens within daily cap', access: 'rw' },
  sign:     { desc: 'Sign messages',               access: 'rw' },
  messages: { desc: 'Read and send messages',      access: 'rw' },
  profile:  { desc: 'View agent profile',          access: 'ro' }
};
// Compat alias
const SCOPE_DESCRIPTIONS = Object.fromEntries(Object.entries(SCOPE_INFO).map(([k, v]) => [k, v.desc]));

let currentDapps = [];
let selectedAppId = null;
let activeDetailTab = 'credentials';
let activeView = 'apps';

// ==================== Helpers ====================

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function escapeAttr(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function formatDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
}

function formatTimeRemaining(expiryMs) {
  const remaining = expiryMs - Date.now();
  if (remaining <= 0) return 'expired';
  const hours = Math.floor(remaining / 3600000);
  const days = Math.floor(hours / 24);
  if (days > 0) return `${days}d ${hours % 24}h remaining`;
  if (hours > 0) return `${hours}h remaining`;
  const mins = Math.floor(remaining / 60000);
  return `${mins}m remaining`;
}

function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text);
  if (btn) {
    const original = btn.innerHTML;
    btn.innerHTML = '<i data-lucide="check"></i>';
    btn.classList.add('copied');
    lucide.createIcons({ nodes: [btn] });
    setTimeout(() => {
      btn.innerHTML = original;
      btn.classList.remove('copied');
      lucide.createIcons({ nodes: [btn] });
    }, 2000);
  }
}

function defaultIconHtml(cls) {
  return `<img class="dev-app-icon-default" src="/default-dapp-icon.svg" alt="">`;
}

// ==================== Modal ====================

function showModal(html) {
  const overlay = document.getElementById('modal-overlay');
  const body = document.getElementById('modal-body');
  body.innerHTML = html;
  overlay.style.display = 'flex';
  lucide.createIcons({ nodes: [body] });
}

function hideModal() {
  document.getElementById('modal-overlay').style.display = 'none';
  document.getElementById('modal-body').innerHTML = '';
}

function isModalOpen() {
  return document.getElementById('modal-overlay').style.display === 'flex';
}

document.getElementById('modal-overlay')?.addEventListener('click', (e) => {
  if (e.target === e.currentTarget) hideModal();
});

// ==================== Toast ====================

function showToast(message) {
  let toast = document.getElementById('dev-toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'dev-toast';
    toast.className = 'dev-toast';
    document.body.appendChild(toast);
  }
  toast.textContent = message;
  toast.classList.add('show');
  clearTimeout(toast._timeout);
  toast._timeout = setTimeout(() => { toast.classList.remove('show'); }, 3000);
}

// ==================== Session ====================

const urlParams = new URLSearchParams(window.location.search);
const oauthError = urlParams.get('error');
if (oauthError) {
  history.replaceState(null, '', '/developers');
}

async function checkSession() {
  try {
    const resp = await fetch('/developers/api/session');
    const data = await resp.json();
    if (data.authenticated) {
      showDashboard(data.username, data.avatar);
    } else {
      showLoginView();
    }
  } catch {
    showLoginView();
  }
}

function showLoginView() {
  document.getElementById('login-view').style.display = 'block';
  document.getElementById('dashboard-view').style.display = 'none';
  if (oauthError) {
    const errorEl = document.getElementById('login-error');
    const messages = {
      oauth_denied: 'Authorization was denied.',
      auth_failed: 'Authentication failed. Please try again.'
    };
    errorEl.textContent = messages[oauthError] || 'Login failed.';
    errorEl.style.display = 'block';
  }
  lucide.createIcons();
}

function showDashboard(username, avatarUrl) {
  document.getElementById('login-view').style.display = 'none';
  document.getElementById('dashboard-view').style.display = 'flex';
  renderProfileDropdown(username, avatarUrl);
  lucide.createIcons();
  loadDapps();
}

// ==================== Profile Dropdown ====================

function renderProfileDropdown(username, avatarUrl) {
  const container = document.getElementById('dev-nav-profile');
  if (!container) return;
  const initials = (username || '??').slice(0, 2).toUpperCase();
  const avatarInner = avatarUrl
    ? `<img class="anav-avatar-img" src="${escapeAttr(avatarUrl)}" alt="" style="width:26px;height:26px;border-radius:50%;object-fit:cover;">`
    : escapeHtml(initials);

  container.innerHTML = `
    <div class="anav-wrap" id="anav-wrap">
      <button class="anav-btn" id="anav-btn">
        <span class="anav-circle">${avatarInner}</span>
      </button>
      <div class="anav-dropdown" id="anav-dropdown">
        <div class="anav-dropdown-user">@${escapeHtml(username)}</div>
        <button class="anav-dropdown-item anav-dropdown-danger" id="anav-logout">Log out</button>
      </div>
    </div>
  `;

  document.getElementById('anav-btn').addEventListener('click', (e) => {
    e.stopPropagation();
    document.getElementById('anav-wrap').classList.toggle('open');
  });
  document.addEventListener('click', () => {
    const w = document.getElementById('anav-wrap');
    if (w) w.classList.remove('open');
  });
  document.getElementById('anav-logout').addEventListener('click', () => {
    fetch('/developers/auth/logout', { method: 'POST' }).then(() => window.location.reload());
  });
}

// ==================== Load dApps ====================

async function loadDapps() {
  try {
    const resp = await fetch('/developers/api/dapps');
    if (resp.status === 401) return showLoginView();
    const data = await resp.json();
    currentDapps = data.dapps || [];

    // Sort: active first, then newest first
    currentDapps.sort((a, b) => {
      if (a.active !== b.active) return a.active ? -1 : 1;
      return new Date(b.registeredAt) - new Date(a.registeredAt);
    });

    renderAppList();

    // Auto-select: preserve current selection, or pick first
    if (selectedAppId && currentDapps.find(d => d.clientId === selectedAppId)) {
      selectApp(selectedAppId);
    } else if (currentDapps.length > 0) {
      selectApp(currentDapps[0].clientId);
    } else {
      selectedAppId = null;
      renderAppList();
      showDetailEmpty();
    }
  } catch (err) {
    console.error('Failed to load dApps:', err);
  }
}

// ==================== App List (Sidebar) ====================

function renderAppList() {
  const list = document.getElementById('app-list');
  const empty = document.getElementById('app-list-empty');

  if (currentDapps.length === 0) {
    list.innerHTML = '';
    empty.style.display = 'flex';
    return;
  }

  empty.style.display = 'none';

  list.innerHTML = currentDapps.map(d => {
    const isActive = d.clientId === selectedAppId;
    const iconHtml = d.iconUrl
      ? `<img src="${escapeAttr(d.iconUrl)}" alt="">`
      : defaultIconHtml();

    return `
      <div class="dev-app-item ${isActive ? 'active' : ''} ${d.active ? '' : 'inactive-app'}"
           data-client-id="${escapeAttr(d.clientId)}"
           data-action="select-app">
        <div class="dev-app-icon">${iconHtml}</div>
        <div class="dev-app-info">
          <div class="dev-app-name">${escapeHtml(d.name)}</div>
          ${d.description ? `<div class="dev-app-desc-preview">${escapeHtml(d.description)}</div>` : ''}
        </div>
        <div class="dev-status-dot ${d.active ? 'active' : 'inactive'}"></div>
      </div>
    `;
  }).join('');
}

// ==================== Select App ====================

function selectApp(clientId) {
  selectedAppId = clientId;
  renderAppList();
  renderDetailPanel(clientId);

  // Mobile: show detail panel
  const shell = document.getElementById('dashboard-view');
  if (shell) shell.classList.add('detail-active');

  // Update mobile bar
  const dapp = currentDapps.find(d => d.clientId === clientId);
  const mobileAppName = document.getElementById('mobile-app-name');
  if (mobileAppName && dapp) mobileAppName.textContent = dapp.name;
}

function showDetailEmpty() {
  document.getElementById('detail-empty').style.display = 'flex';
  document.getElementById('detail-content').style.display = 'none';
}

// Mobile back
document.getElementById('mobile-back')?.addEventListener('click', () => {
  const shell = document.getElementById('dashboard-view');
  if (shell) shell.classList.remove('detail-active');
});

// ==================== Detail Panel ====================

function renderDetailPanel(clientId) {
  const dapp = currentDapps.find(d => d.clientId === clientId);
  if (!dapp) return showDetailEmpty();

  document.getElementById('detail-empty').style.display = 'none';
  const content = document.getElementById('detail-content');
  content.style.display = 'block';

  const iconHtml = dapp.iconUrl
    ? `<img src="${escapeAttr(dapp.iconUrl)}" alt="">`
    : defaultIconHtml();

  const graceBadge = dapp.hasPreviousSecret && dapp.previousSecretExpiry
    ? `<div class="dev-grace-badge"><i data-lucide="clock" style="width:10px;height:10px"></i> Old secret: ${escapeHtml(formatTimeRemaining(dapp.previousSecretExpiry))}</div>`
    : '';

  // Build app switcher options for tablet (shared between active + deactivated paths)
  const appSwitcherOptions = currentDapps.map(d =>
    `<option value="${escapeAttr(d.clientId)}" ${d.clientId === clientId ? 'selected' : ''}>${escapeHtml(d.name)}${d.active ? '' : ' (inactive)'}</option>`
  ).join('');

  const appSwitcherHtml = `
    <div class="dev-app-switcher">
      <select class="dev-app-switcher-select" id="app-switcher-select">
        ${appSwitcherOptions}
      </select>
      <button class="admin-btn admin-btn-primary dev-sidebar-create" id="btn-create-tablet">
        <i data-lucide="plus" class="admin-btn-icon"></i>Create
      </button>
    </div>
  `;

  // Wire tablet switcher helper
  function wireTabletSwitcher() {
    document.getElementById('app-switcher-select')?.addEventListener('change', (e) => {
      selectApp(e.target.value);
    });
    document.getElementById('btn-create-tablet')?.addEventListener('click', showCreateModal);
  }

  // Deactivated apps: show header + deactivated message + usage history
  if (!dapp.active) {
    content.innerHTML = `
      ${appSwitcherHtml}
      <div class="dev-detail-header">
        <div class="dev-detail-icon-wrap" style="cursor:default;">
          <div class="dev-detail-icon">${iconHtml}</div>
        </div>
        <div class="dev-detail-info">
          <div class="dev-detail-name">
            ${escapeHtml(dapp.name)}
            <span class="dev-status-badge inactive">Inactive</span>
          </div>
          ${dapp.description ? `<div class="dev-detail-desc">${escapeHtml(dapp.description)}</div>` : ''}
          <div class="dev-detail-meta">Created ${formatDate(dapp.registeredAt)}</div>
        </div>
      </div>
      <div class="dev-danger-zone" style="border-color:var(--color-border);background:none;margin-top:var(--space-8);">
        <div class="dev-danger-title" style="color:var(--color-text-tertiary)">App Deactivated</div>
        <div class="dev-danger-desc">This app has been deactivated. All OAuth flows using its credentials have stopped working.</div>
      </div>
      <div class="dev-tab-content active" id="tab-usage" style="margin-top:var(--space-6);"></div>
    `;
    wireTabletSwitcher();
    renderUsageTab(dapp);
    lucide.createIcons({ nodes: [content] });
    return;
  }

  content.innerHTML = `
    ${appSwitcherHtml}

    <!-- Header -->
    <div class="dev-detail-header">
      <div class="dev-detail-icon-wrap" id="icon-upload-trigger" title="Click to upload icon">
        <div class="dev-detail-icon">${iconHtml}</div>
        <div class="dev-icon-upload-overlay"><i data-lucide="camera"></i></div>
      </div>
      <div class="dev-detail-info">
        <div class="dev-detail-name">
          ${escapeHtml(dapp.name)}
          <span class="dev-status-badge active">Active</span>
        </div>
        ${dapp.description ? `<div class="dev-detail-desc">${escapeHtml(dapp.description)}</div>` : ''}
        <div class="dev-detail-meta">Created ${formatDate(dapp.registeredAt)}</div>
      </div>
    </div>

    ${graceBadge}

    <!-- Tabs -->
    <div class="dev-detail-tabs">
      <button class="dev-detail-tab ${activeDetailTab === 'credentials' ? 'active' : ''}" data-tab="credentials">Credentials</button>
      <button class="dev-detail-tab ${activeDetailTab === 'settings' ? 'active' : ''}" data-tab="settings">Settings</button>
      <button class="dev-detail-tab ${activeDetailTab === 'usage' ? 'active' : ''}" data-tab="usage">Usage</button>
      <button class="dev-detail-tab ${activeDetailTab === 'skilldoc' ? 'active' : ''}" data-tab="skilldoc">Skill Doc</button>
      <button class="dev-detail-tab danger ${activeDetailTab === 'danger' ? 'active' : ''}" data-tab="danger">Danger Zone</button>
    </div>

    <!-- Tab Contents -->
    <div class="dev-tab-content ${activeDetailTab === 'credentials' ? 'active' : ''}" id="tab-credentials"></div>
    <div class="dev-tab-content ${activeDetailTab === 'settings' ? 'active' : ''}" id="tab-settings"></div>
    <div class="dev-tab-content ${activeDetailTab === 'usage' ? 'active' : ''}" id="tab-usage"></div>
    <div class="dev-tab-content ${activeDetailTab === 'skilldoc' ? 'active' : ''}" id="tab-skilldoc"></div>
    <div class="dev-tab-content ${activeDetailTab === 'danger' ? 'active' : ''}" id="tab-danger"></div>
  `;

  // Render tab contents
  renderCredentialsTab(dapp);
  renderSettingsTab(dapp);
  renderUsageTab(dapp);
  renderSkillTab(dapp);
  renderDangerTab(dapp);

  // Wire tab switching
  content.querySelectorAll('.dev-detail-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      activeDetailTab = tab.dataset.tab;
      content.querySelectorAll('.dev-detail-tab').forEach(t => t.classList.remove('active'));
      content.querySelectorAll('.dev-tab-content').forEach(c => c.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(`tab-${activeDetailTab}`).classList.add('active');
    });
  });

  // Wire icon upload
  wireIconUpload(clientId);

  // Wire tablet app switcher
  wireTabletSwitcher();

  lucide.createIcons({ nodes: [content] });
}

// ==================== Credentials Tab ====================

function renderCredentialsTab(dapp) {
  const container = document.getElementById('tab-credentials');

  container.innerHTML = `
    <!-- Client ID -->
    <div class="dev-key-section">
      <div class="dev-key-label">Client ID</div>
      <div class="dev-key-row">
        <span class="dev-key-value">${escapeHtml(dapp.clientId)}</span>
        <button class="dev-key-copy" data-action="copy" data-copy-value="${escapeAttr(dapp.clientId)}" title="Copy">
          <i data-lucide="copy" style="width:14px;height:14px"></i>
        </button>
      </div>
    </div>

    <!-- Client Secret -->
    <div class="dev-key-section">
      <div class="dev-key-label">Client Secret</div>
      <div class="dev-key-row" style="background:none;border:1px dashed var(--color-border);">
        <span class="dev-key-value" style="color:var(--color-text-muted);font-family:var(--font-sans);">Hidden — rotate to get a new one</span>
      </div>
    </div>

    <!-- Redirect URI -->
    <div class="dev-key-section">
      <div class="dev-key-label">Redirect URI</div>
      ${dapp.redirectUris.length > 0 ? `
        ${dapp.redirectUris.map(uri => `
          <div class="dev-key-row">
            <span class="dev-key-value">${escapeHtml(uri)}</span>
            <button class="dev-key-copy" data-action="copy" data-copy-value="${escapeAttr(uri)}" title="Copy">
              <i data-lucide="copy" style="width:14px;height:14px"></i>
            </button>
          </div>
        `).join('')}
      ` : `
        <div class="dev-uri-warning">
          <i data-lucide="alert-triangle" style="width:14px;height:14px;flex-shrink:0;"></i>
          <span>No redirect URIs configured — OAuth authorization will fail. <a href="#" onclick="event.preventDefault(); activeDetailTab = 'settings'; document.querySelector('[data-tab=settings]').click();">Add one in Settings</a></span>
        </div>
      `}
    </div>

    <!-- Rotate Secret -->
    ${dapp.secretRotatedAt ? `
    <div class="dev-rotate-section">
      <div class="dev-rotate-title">Rotate Secret</div>
      <div class="dev-rotate-desc">Generate a new client secret. Choose how long the old secret remains valid during migration.</div>
      <div class="dev-rotate-row">
        <select class="dev-grace-select" id="cred-grace-select">
          <option value="24h" selected>24 hours</option>
          <option value="1h">1 hour</option>
          <option value="3d">3 days</option>
          <option value="7d">7 days</option>
          <option value="immediately">Immediately</option>
        </select>
        <button class="admin-btn admin-btn-primary" id="btn-rotate" style="white-space:nowrap;">
          <i data-lucide="refresh-cw" class="admin-btn-icon"></i>Rotate
        </button>
      </div>
      <div class="dev-revoke-section">
        <div class="dev-revoke-label">Secret compromised?</div>
        <button class="dev-btn-danger" id="btn-revoke">
          <i data-lucide="shield-alert" class="admin-btn-icon" style="width:14px;height:14px;margin-right:4px;"></i>Emergency Revoke
        </button>
      </div>
    </div>
    ` : `
    <div class="dev-rotate-section">
      <div class="dev-rotate-title">Generate Secret</div>
      <div class="dev-rotate-desc">Generate a new client secret. Your current secret will be replaced immediately.</div>
      <div class="dev-rotate-row">
        <button class="admin-btn admin-btn-primary" id="btn-rotate" style="white-space:nowrap;">
          <i data-lucide="key-round" class="admin-btn-icon"></i>Generate Secret
        </button>
      </div>
    </div>
    `}
  `;

  // Wire rotate
  document.getElementById('btn-rotate')?.addEventListener('click', () => {
    rotateSecret(dapp.clientId);
  });

  // Wire revoke
  document.getElementById('btn-revoke')?.addEventListener('click', () => {
    showRevokeModal(dapp.clientId);
  });
}

// ==================== Settings Tab ====================

function renderSettingsTab(dapp) {
  const container = document.getElementById('tab-settings');

  container.innerHTML = `
    <div class="dev-settings-form">
      <div class="dev-field">
        <label class="dev-field-label">App Name</label>
        <input type="text" id="settings-name" class="admin-input" value="${escapeAttr(dapp.name)}" maxlength="64">
      </div>
      <div class="dev-field">
        <label class="dev-field-label">Description</label>
        <input type="text" id="settings-desc" class="admin-input" value="${escapeAttr(dapp.description || '')}" placeholder="What does your app do?">
      </div>
      <div class="dev-field">
        <label class="dev-field-label">Redirect URIs</label>
        ${dapp.redirectUris.length === 0 ? `
          <div class="dev-uri-warning" style="margin-bottom:var(--space-3);">
            <i data-lucide="alert-triangle" style="width:14px;height:14px;flex-shrink:0;"></i>
            <span>Required for OAuth — add at least one redirect URI.</span>
          </div>
        ` : ''}
        <div id="settings-uris" class="dev-uri-list">
          ${dapp.redirectUris.map(uri => `
            <div class="dev-uri-row">
              <input type="url" class="admin-input settings-uri-input" value="${escapeAttr(uri)}">
              <button class="dev-uri-remove" onclick="this.parentElement.remove()"><i data-lucide="x"></i></button>
            </div>
          `).join('')}
        </div>
        <button class="admin-btn" style="margin-top:var(--space-2)" onclick="addSettingsUriRow()">
          <i data-lucide="plus" class="admin-btn-icon"></i>Add URI
        </button>
      </div>
      <div class="dev-field">
        <label class="dev-field-label">Permissions</label>
        <div id="settings-scopes" style="display:flex;flex-direction:column;gap:var(--space-2);">
          ${SCOPES.map(s => {
            const info = SCOPE_INFO[s] || { desc: s, access: 'ro' };
            const accessLabel = info.access === 'rw' ? 'Read & write' : 'Read only';
            return `
            <label class="dev-scope-checkbox" style="display:flex;align-items:center;gap:var(--space-3);padding:var(--space-2) 0;">
              <input type="checkbox" value="${s}" ${dapp.scopes.includes(s) ? 'checked' : ''}>
              <div style="flex:1;min-width:0;">
                <span style="font-weight:600;">${s}</span>
                <span style="font-size:var(--text-xs);color:var(--color-text-muted);margin-left:var(--space-2);">${escapeHtml(info.desc)}</span>
              </div>
              <span class="dev-scope-badge ${info.access}">${accessLabel}</span>
            </label>`;
          }).join('')}
        </div>
      </div>
      <div class="dev-settings-save">
        <button class="admin-btn admin-btn-primary" id="btn-save-settings">
          <i data-lucide="save" class="admin-btn-icon"></i>Save Changes
        </button>
      </div>
    </div>
  `;

  document.getElementById('btn-save-settings')?.addEventListener('click', () => {
    saveDappSettings(dapp.clientId);
  });
}

function addSettingsUriRow() {
  const container = document.getElementById('settings-uris');
  if (!container) return;
  const row = document.createElement('div');
  row.className = 'dev-uri-row';
  row.innerHTML = `
    <input type="url" class="admin-input settings-uri-input" placeholder="https://yourapp.com/callback">
    <button class="dev-uri-remove" onclick="this.parentElement.remove()"><i data-lucide="x"></i></button>
  `;
  container.appendChild(row);
  lucide.createIcons({ nodes: [row] });
  row.querySelector('input').focus();
}

async function saveDappSettings(clientId) {
  const name = document.getElementById('settings-name').value.trim();
  const description = document.getElementById('settings-desc').value.trim();
  const uriInputs = document.querySelectorAll('.settings-uri-input');
  const redirectUris = Array.from(uriInputs).map(i => i.value.trim()).filter(Boolean);
  const scopes = Array.from(document.querySelectorAll('#settings-scopes input:checked')).map(i => i.value);

  if (!name) return showToast('App name is required');

  const btn = document.getElementById('btn-save-settings');
  if (btn) { btn.disabled = true; btn.textContent = 'Saving...'; }

  try {
    const resp = await fetch(`/developers/api/dapps/${clientId}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, description: description || null, redirectUris, scopes })
    });
    if (resp.status === 401) return showLoginView();
    const data = await resp.json();

    if (data.success) {
      showToast('Settings saved');
      loadDapps();
    } else {
      showToast(data.error || 'Failed to save');
      if (btn) { btn.disabled = false; btn.innerHTML = '<i data-lucide="save" class="admin-btn-icon"></i>Save Changes'; lucide.createIcons({ nodes: [btn] }); }
    }
  } catch (err) {
    console.error('Failed to save settings:', err);
    showToast('Network error');
    if (btn) { btn.disabled = false; btn.innerHTML = '<i data-lucide="save" class="admin-btn-icon"></i>Save Changes'; lucide.createIcons({ nodes: [btn] }); }
  }
}

// ==================== Usage Tab ====================

function formatTimeAgo(iso) {
  if (!iso) return 'Never';
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function formatEventTime(iso) {
  const d = new Date(iso);
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) + ' ' +
    d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
}

async function renderUsageTab(dapp) {
  const container = document.getElementById('tab-usage');

  container.innerHTML = `
    <div class="dev-usage-loading">
      <div style="color:var(--color-text-muted);font-size:var(--text-sm);">Loading usage data...</div>
    </div>
  `;

  try {
    const resp = await fetch(`/developers/api/dapps/${dapp.clientId}/usage`);
    if (resp.status === 401) return showLoginView();
    const data = await resp.json();

    if (!data.success) {
      container.innerHTML = `<div class="an-chart-empty">Failed to load usage data</div>`;
      return;
    }

    const s = data.summary;

    container.innerHTML = `
      <div class="an-cards-row">
        <div class="an-card">
          <div class="an-card-label">Total Requests</div>
          <div class="an-card-value">${s.totalRequests.toLocaleString()}</div>
        </div>
        <div class="an-card">
          <div class="an-card-label">Token Exchanges</div>
          <div class="an-card-value">${s.tokenExchanges.toLocaleString()}</div>
        </div>
        <div class="an-card">
          <div class="an-card-label">Unique Agents</div>
          <div class="an-card-value">${s.uniqueAgents.toLocaleString()}</div>
        </div>
        <div class="an-card">
          <div class="an-card-label">Last Request</div>
          <div class="an-card-value" style="font-size:var(--text-sm);font-weight:600;">${formatTimeAgo(s.lastRequest)}</div>
        </div>
      </div>
      ${s.totalRequests === 0
        ? '<div class="an-chart-empty" style="padding:var(--space-12);">No events yet</div>'
        : ''}
    `;

  } catch (err) {
    console.error('Failed to load usage:', err);
    container.innerHTML = `<div class="an-chart-empty">Network error loading usage data</div>`;
  }
}

// ==================== Skill Doc Tab ====================

function generateSkillMd(dapp) {
  const scopeLines = (dapp.scopes || []).map(s => {
    const desc = SCOPE_DESCRIPTIONS[s] || s;
    const access = (['balance', 'profile'].includes(s)) ? 'Read only' : 'Read & write';
    return `- **${s}** — ${desc} (${access})`;
  }).join('\n');

  // Direct auth link on Clawnads (operators click this, not the dApp URL)
  const connectUrl = `https://tormund.io/oauth/connect/${dapp.clientId}`;

  return `---
name: ${(dapp.name || 'my-dapp').toLowerCase().replace(/\s+/g, '-')}
description: ${dapp.description || dapp.name}
url: ${connectUrl}
scopes: ${(dapp.scopes || []).join(', ')}
---

# ${dapp.name}

${dapp.description || dapp.name}

## Connect (Login with Clawnads)

This dApp uses **Login with Clawnads** — an OAuth flow where your operator approves access on the Clawnads consent screen. You don't need to do anything technical — just relay the authorization link below to your operator.

**Prerequisite:** Your operator must have linked their X account to your agent. If they haven't, generate a claim link first: \`POST /agents/YOUR_NAME/auth/claim\` and send them the URL (replace localhost with \`https://claw.tormund.io\`).

**What to do:** Send your operator this message:

> **${dapp.name}** wants to connect with the following permissions. Authorize here: [tormund.io/oauth/connect](${connectUrl})

Your operator opens the link, signs in with X, reviews the requested permissions, and approves or denies. That's it — Clawnads handles the rest.

### Requested permissions

${scopeLines}

All dApp transactions count against your same daily trading cap — no dApp can bypass your limits. You can revoke access anytime: \`POST /oauth/revoke\` with \`{ "client_id": "CLIENT_ID" }\` using your bearer token.`;
}

function renderSkillTab(dapp) {
  const container = document.getElementById('tab-skilldoc');
  const skillMd = generateSkillMd(dapp);

  container.innerHTML = `
    <div style="margin-bottom:var(--space-4);">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:var(--space-3);">
        <div>
          <div class="dev-section-title" style="margin-bottom:var(--space-1);">Agent Skill Doc</div>
          <div style="font-size:var(--text-xs);color:var(--color-text-muted);line-height:var(--leading-relaxed);">Give this to your agent so it knows how to connect. Generated from your app registration.</div>
        </div>
        <button class="dev-key-copy" title="Copy" onclick="copyToClipboard(document.getElementById('skill-md-content').textContent, this)">
          <i data-lucide="copy"></i>
        </button>
      </div>
      <div style="background:var(--color-bg-elevated);border:1px solid var(--color-border);border-radius:var(--radius-lg);padding:var(--space-5) var(--space-6);max-height:400px;overflow-y:auto;">
        <pre id="skill-md-content" style="margin:0;font-family:var(--font-mono);font-size:var(--text-xs);color:var(--color-text-secondary);white-space:pre-wrap;word-break:break-word;line-height:var(--leading-relaxed);">${escapeHtml(skillMd)}</pre>
      </div>
    </div>
  `;

  lucide.createIcons({ nodes: [container] });
}

// ==================== Danger Zone Tab ====================

function renderDangerTab(dapp) {
  const container = document.getElementById('tab-danger');

  if (!dapp.active) {
    container.innerHTML = `
      <div class="dev-danger-zone" style="border-color:var(--color-border);background:none;">
        <div class="dev-danger-title" style="color:var(--color-text-tertiary)">App Deactivated</div>
        <div class="dev-danger-desc">This app has been deactivated. All OAuth flows using its credentials have stopped working.</div>
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <div class="dev-danger-zone">
      <div class="dev-danger-title">Deactivate App</div>
      <div class="dev-danger-desc">
        This will deactivate <strong>${escapeHtml(dapp.name)}</strong>. All OAuth flows using this app's credentials will stop working immediately.
      </div>
      <button class="dev-btn-danger" id="btn-deactivate">Deactivate</button>
      <div class="dev-danger-confirm" id="deactivate-confirm">
        <p style="margin-bottom:var(--space-3)">Are you sure? This cannot be undone easily.</p>
        <div style="display:flex;gap:var(--space-3)">
          <button class="admin-btn" id="btn-deactivate-cancel">Cancel</button>
          <button class="dev-btn-danger" id="btn-deactivate-confirm">Yes, Deactivate</button>
        </div>
      </div>
    </div>
  `;

  document.getElementById('btn-deactivate')?.addEventListener('click', () => {
    document.getElementById('deactivate-confirm').classList.add('show');
    document.getElementById('btn-deactivate').style.display = 'none';
  });

  document.getElementById('btn-deactivate-cancel')?.addEventListener('click', () => {
    document.getElementById('deactivate-confirm').classList.remove('show');
    document.getElementById('btn-deactivate').style.display = '';
  });

  document.getElementById('btn-deactivate-confirm')?.addEventListener('click', () => {
    deactivateDapp(dapp.clientId);
  });
}

async function deactivateDapp(clientId) {
  const btn = document.getElementById('btn-deactivate-confirm');
  if (btn) { btn.disabled = true; btn.textContent = 'Deactivating...'; }

  try {
    const resp = await fetch(`/developers/api/dapps/${clientId}`, { method: 'DELETE' });
    if (resp.status === 401) return showLoginView();
    const data = await resp.json();

    if (data.success) {
      showToast('App deactivated');
      loadDapps();
    } else {
      showToast(data.error || 'Failed to deactivate');
      if (btn) { btn.disabled = false; btn.textContent = 'Yes, Deactivate'; }
    }
  } catch (err) {
    console.error('Failed to deactivate:', err);
    showToast('Network error');
    if (btn) { btn.disabled = false; btn.textContent = 'Yes, Deactivate'; }
  }
}

// ==================== Rotate Secret ====================

async function rotateSecret(clientId) {
  const graceSelect = document.getElementById('cred-grace-select');
  const grace = graceSelect ? graceSelect.value : 'immediately';
  const btn = document.getElementById('btn-rotate');
  if (btn) { btn.disabled = true; btn.textContent = 'Rotating...'; }

  try {
    const resp = await fetch(`/developers/api/dapps/${clientId}/rotate-secret`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ grace })
    });
    if (resp.status === 401) return showLoginView();
    const data = await resp.json();

    if (data.success) {
      showSecretModal(clientId, data.clientSecret, false);
      loadDapps();
    } else {
      showToast(data.error || 'Failed to rotate secret');
      if (btn) { btn.disabled = false; btn.innerHTML = '<i data-lucide="refresh-cw" class="admin-btn-icon"></i>Rotate'; lucide.createIcons({ nodes: [btn] }); }
    }
  } catch (err) {
    console.error('Failed to rotate secret:', err);
    showToast('Network error');
    if (btn) { btn.disabled = false; btn.innerHTML = '<i data-lucide="refresh-cw" class="admin-btn-icon"></i>Rotate'; lucide.createIcons({ nodes: [btn] }); }
  }
}

// ==================== Emergency Revoke (still a modal — critical action) ====================

function showRevokeModal(clientId) {
  showModal(`
    <div class="modal-title" style="color:var(--color-error)">Emergency Revoke</div>
    <div class="dev-modal-subtitle">
      This will <strong>immediately invalidate all existing secrets</strong> for this app. Any active integrations will break instantly. A new secret will be generated.
    </div>
    <div class="dev-secret-warning" style="border-color:rgba(239,68,68,0.2);background:rgba(239,68,68,0.06);">
      <i data-lucide="alert-triangle" style="width:16px;height:16px;color:var(--color-error);flex-shrink:0;margin-top:1px"></i>
      <span class="dev-secret-warning-text" style="color:var(--color-error)">
        This action cannot be undone. Use this only if your secret has been compromised.
      </span>
    </div>
    <div class="modal-actions">
      <button class="admin-btn" onclick="hideModal()">Cancel</button>
      <button class="dev-btn-danger" id="modal-revoke-btn">Revoke All Secrets</button>
    </div>
  `);

  document.getElementById('modal-revoke-btn').addEventListener('click', () => revokeSecret(clientId));
}

async function revokeSecret(clientId) {
  const btn = document.getElementById('modal-revoke-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Revoking...'; }

  try {
    const resp = await fetch(`/developers/api/dapps/${clientId}/revoke-secret`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    if (resp.status === 401) return showLoginView();
    const data = await resp.json();

    if (data.success) {
      showSecretModal(clientId, data.clientSecret, false);
      loadDapps();
    } else {
      showToast(data.error || 'Failed to revoke secret');
      if (btn) { btn.disabled = false; btn.textContent = 'Revoke All Secrets'; }
    }
  } catch (err) {
    console.error('Failed to revoke secret:', err);
    showToast('Network error');
    if (btn) { btn.disabled = false; btn.textContent = 'Revoke All Secrets'; }
  }
}

// ==================== Create App Modal ====================

function showCreateModal() {
  showModal(`
    <div class="modal-title">Create App</div>
    <div class="dev-modal-subtitle">You can configure redirect URIs and scopes in Settings after creation.</div>
    <div class="modal-form">
      <div class="modal-field">
        <label class="admin-label">App Name</label>
        <input type="text" id="modal-app-name" class="admin-input" placeholder="My dApp" maxlength="64" autofocus>
      </div>
      <div class="modal-field">
        <label class="admin-label">Description <span style="color:var(--color-text-muted)">(optional)</span></label>
        <input type="text" id="modal-app-desc" class="admin-input" placeholder="What does your app do?">
      </div>
    </div>
    <div class="modal-actions">
      <button class="admin-btn" onclick="hideModal()">Cancel</button>
      <button class="admin-btn admin-btn-primary" id="modal-create-btn">Create</button>
    </div>
  `);

  document.getElementById('modal-create-btn').addEventListener('click', createDapp);
  document.getElementById('modal-app-name').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') createDapp();
  });
}

async function createDapp() {
  const name = document.getElementById('modal-app-name').value.trim();
  const description = document.getElementById('modal-app-desc').value.trim();

  if (!name) return showToast('App name is required');

  const btn = document.getElementById('modal-create-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'Creating...'; }

  try {
    const resp = await fetch('/developers/api/dapps', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, description: description || undefined })
    });
    if (resp.status === 401) return showLoginView();
    const data = await resp.json();

    if (data.success) {
      // Select the new app
      selectedAppId = data.clientId;
      activeDetailTab = 'credentials';
      showSecretModal(data.clientId, data.clientSecret, true);
      loadDapps();
    } else {
      showToast(data.error || 'Failed to create dApp');
      if (btn) { btn.disabled = false; btn.textContent = 'Create'; }
    }
  } catch (err) {
    console.error('Failed to create dApp:', err);
    showToast('Network error');
    if (btn) { btn.disabled = false; btn.textContent = 'Create'; }
  }
}

// ==================== Show-Once Secret Modal ====================

function showSecretModal(clientId, clientSecret, isNew) {
  showModal(`
    <div class="modal-title">${isNew ? 'App Created' : 'Secret Rotated'}</div>
    <div class="dev-secret-warning">
      <i data-lucide="alert-triangle" class="dev-secret-warning-icon"></i>
      <span class="dev-secret-warning-text">
        Copy your client secret now. It will only be shown once and cannot be retrieved later.
      </span>
    </div>
    <div class="modal-field" style="margin-bottom:var(--space-4)">
      <label class="admin-label">Client ID</label>
      <div class="dev-key-row">
        <span class="dev-key-value">${escapeHtml(clientId)}</span>
        <button class="dev-key-copy" data-action="copy" data-copy-value="${escapeAttr(clientId)}" title="Copy">
          <i data-lucide="copy" style="width:14px;height:14px"></i>
        </button>
      </div>
    </div>
    <div class="modal-field" style="margin-bottom:var(--space-6)">
      <label class="admin-label">Client Secret</label>
      <div class="dev-key-row">
        <span class="dev-key-value">${escapeHtml(clientSecret)}</span>
        <button class="dev-key-copy" data-action="copy" data-copy-value="${escapeAttr(clientSecret)}" title="Copy">
          <i data-lucide="copy" style="width:14px;height:14px"></i>
        </button>
      </div>
    </div>
    <div class="modal-actions">
      <button class="admin-btn admin-btn-primary" data-action="hide-modal">Done</button>
    </div>
  `);

  navigator.clipboard.writeText(clientSecret).catch(() => {});
}

// ==================== Icon Upload ====================

function wireIconUpload(clientId) {
  const trigger = document.getElementById('icon-upload-trigger');
  if (!trigger) return;

  const input = document.createElement('input');
  input.type = 'file';
  input.accept = 'image/png,image/jpeg,image/gif,image/webp';
  input.style.display = 'none';
  document.body.appendChild(input);

  trigger.addEventListener('click', () => input.click());

  input.addEventListener('change', async () => {
    const file = input.files[0];
    if (!file) return;

    if (file.size > 512 * 1024) {
      showToast('Image too large (max 512KB)');
      input.value = '';
      return;
    }

    // Show loading state on the icon
    const iconEl = trigger.querySelector('.dev-detail-icon');
    const overlayEl = trigger.querySelector('.dev-icon-upload-overlay');
    if (iconEl) iconEl.innerHTML = '<div class="dev-icon-loading"><div class="dev-icon-spinner"></div></div>';
    if (overlayEl) overlayEl.style.display = 'none';

    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const resp = await fetch(`/developers/api/dapps/${clientId}/icon`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ image: reader.result })
        });
        const data = await resp.json();

        if (data.success) {
          showToast('Icon uploaded');
          loadDapps();
        } else {
          showToast(data.error || 'Failed to upload icon');
          // Restore the panel on error
          if (selectedAppId) renderDetailPanel(selectedAppId);
        }
      } catch (err) {
        console.error('Icon upload failed:', err);
        showToast('Network error');
        if (selectedAppId) renderDetailPanel(selectedAppId);
      }
    };
    reader.readAsDataURL(file);
    input.value = '';
  });

  // Cleanup on next render
  trigger._iconInput = input;
}

// ==================== Keyboard Shortcuts ====================

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && isModalOpen()) {
    hideModal();
    return;
  }
  // Don't trigger shortcuts when typing in inputs
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') return;

  if (e.key === 'c' && !e.metaKey && !e.ctrlKey && !isModalOpen()) {
    showCreateModal();
    return;
  }

  // Arrow key navigation for app list
  if ((e.key === 'ArrowUp' || e.key === 'ArrowDown') && !isModalOpen() && currentDapps.length > 0) {
    e.preventDefault();
    const currentIdx = currentDapps.findIndex(d => d.clientId === selectedAppId);
    let newIdx;
    if (e.key === 'ArrowUp') {
      newIdx = currentIdx <= 0 ? currentDapps.length - 1 : currentIdx - 1;
    } else {
      newIdx = currentIdx >= currentDapps.length - 1 ? 0 : currentIdx + 1;
    }
    selectApp(currentDapps[newIdx].clientId);
  }
});

// ==================== Event Delegation (replaces inline onclick) ====================

document.addEventListener('click', (e) => {
  // Find the closest element with a data-action attribute
  const target = e.target.closest('[data-action]');
  if (!target) return;

  const action = target.dataset.action;

  if (action === 'select-app') {
    const clientId = target.dataset.clientId;
    if (clientId) selectApp(clientId);
  } else if (action === 'copy') {
    const value = target.dataset.copyValue;
    if (value) copyToClipboard(value, target);
  } else if (action === 'hide-modal') {
    hideModal();
  }
});

// ==================== Top-Level View Switching ====================

function switchView(view) {
  activeView = view;
  document.querySelectorAll('.dev-nav-item').forEach(t => {
    t.classList.toggle('active', t.dataset.view === view);
  });
  document.getElementById('view-apps').style.display = view === 'apps' ? '' : 'none';
  document.getElementById('view-usage').style.display = view === 'usage' ? '' : 'none';

  // Hide app list sidebar when not on Apps view
  const sidebar = document.getElementById('dev-sidebar');
  if (sidebar) sidebar.style.display = view === 'apps' ? '' : 'none';

  if (view === 'usage') {
    renderAggregateUsage();
  } else {
    usageShellRendered = false;
  }
}

document.querySelectorAll('.dev-nav-item').forEach(tab => {
  tab.addEventListener('click', () => switchView(tab.dataset.view));
});

// ==================== Aggregate Usage View ====================
// Chart pattern matches /analytics (line charts + area fill, Dune-style tooltips)

let usageDays = 1;
let usageFilterApp = null; // null = all apps, or clientId string
let usageShellRendered = false; // true once the static chrome is in place

function niceYLabels(maxVal) {
  // Returns evenly spaced Y labels with nice round numbers
  const minTicks = 3;
  if (maxVal <= 0) return [0, 1, 2, 3, 4, 5];
  if (maxVal <= 5) {
    const labels = [];
    for (let i = 0; i <= Math.max(maxVal, 5); i++) labels.push(i);
    return labels;
  }
  // Find a nice step: 1, 2, 5, 10, 20, 50, etc.
  const rawStep = maxVal / (minTicks - 1);
  const magnitude = Math.pow(10, Math.floor(Math.log10(rawStep)));
  let step;
  if (rawStep / magnitude < 1.5) step = magnitude;
  else if (rawStep / magnitude < 3.5) step = 2 * magnitude;
  else if (rawStep / magnitude < 7.5) step = 5 * magnitude;
  else step = 10 * magnitude;
  const labels = [];
  for (let v = 0; v <= maxVal + step * 0.01; v += step) {
    labels.push(Math.round(v));
  }
  // Ensure maxVal is at least covered
  if (labels[labels.length - 1] < maxVal) labels.push(Math.ceil(maxVal / step) * step);
  return labels;
}

function drawUsageLineChart(container, data, color, metricLabel) {
  const W = 500, H = 160;
  const padL = 32, padR = 8, padT = 8, padB = 20;
  const chartW = W - padL - padR;
  const chartH = H - padT - padB;

  const values = data.map(d => d.value);
  const rawMax = Math.max(...values, 1);
  const yLabels = niceYLabels(rawMax);
  const maxVal = yLabels[yLabels.length - 1];
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

  points.forEach(p => {
    const label = p.date.slice(5);
    svg += `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="8" fill="transparent" class="an-hover-target"><title>${label}: ${p.value}</title></circle>`;
    svg += `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="1.5" fill="${color}" opacity="0.5" pointer-events="none"/>`;
  });

  xLabels.forEach(d => {
    const i = data.indexOf(d);
    const x = padL + (i / Math.max(data.length - 1, 1)) * chartW;
    const label = d.date.slice(5);
    svg += `<text x="${x.toFixed(1)}" y="${H - 3}" text-anchor="middle" fill="#52525b" font-size="7" font-family="Inter,sans-serif">${label}</text>`;
  });

  svg += '</svg>';
  container.innerHTML = svg;

  addUsageTooltip(container, points, color, metricLabel);
}

function drawUsageBarChart(container, data, color, metricLabel) {
  const W = 500, H = 160;
  const padL = 32, padR = 8, padT = 8, padB = 20;
  const chartW = W - padL - padR;
  const chartH = H - padT - padB;

  const values = data.map(d => d.value);
  const rawMax = Math.max(...values, 1);
  const yLabels = niceYLabels(rawMax);
  const maxVal = yLabels[yLabels.length - 1];

  const barW = Math.max(2, (chartW / data.length) * 0.7);
  const gap = (chartW / data.length) * 0.3;

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
    const label = d.date.slice(5);
    svg += `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barW.toFixed(1)}" height="${barH.toFixed(1)}" fill="${color}" rx="1" opacity="0.8"><title>${label}: ${d.value}</title></rect>`;
    barData.push({ x: x + barW / 2, y, date: d.date, value: d.value });
  });

  xLabels.forEach(d => {
    const i = data.indexOf(d);
    const x = padL + (i / data.length) * chartW + barW / 2;
    const label = d.date.slice(5);
    svg += `<text x="${x.toFixed(1)}" y="${H - 3}" text-anchor="middle" fill="#52525b" font-size="7" font-family="Inter,sans-serif">${label}</text>`;
  });

  svg += '</svg>';
  container.innerHTML = svg;

  addUsageTooltip(container, barData, color, metricLabel);
}

function addUsageTooltip(container, points, color, metricLabel) {
  let tooltip = container.querySelector('.an-tt');
  if (!tooltip) {
    tooltip = document.createElement('div');
    tooltip.className = 'an-tt';
    container.appendChild(tooltip);
  }

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
    const relX = ((e.clientX - rect.left) / rect.width) * 500;

    let nearest = points[0];
    let minDist = Infinity;
    for (const p of points) {
      const d = Math.abs(p.x - relX);
      if (d < minDist) { minDist = d; nearest = p; }
    }

    tooltip.innerHTML =
      '<div class="an-tt-date">' + nearest.date + '</div>' +
      '<div class="an-tt-row">' +
        '<span class="an-tt-dot" style="background:' + color + '"></span>' +
        '<span class="an-tt-label">' + (metricLabel || '') + '</span>' +
        '<span class="an-tt-val">' + nearest.value.toLocaleString() + '</span>' +
      '</div>';
    tooltip.style.display = 'block';

    const pxX = (nearest.x / 500) * rect.width;
    const ttWidth = 180;
    let left = pxX - ttWidth / 2;
    if (left < 0) left = 0;
    if (left + ttWidth > rect.width) left = rect.width - ttWidth;
    tooltip.style.left = left + 'px';
    tooltip.style.top = '0px';

    crosshair.style.display = 'block';
    crosshair.style.left = pxX + 'px';
  });

  svg.addEventListener('mouseleave', () => {
    tooltip.style.display = 'none';
    crosshair.style.display = 'none';
  });
}

function renderUsageShell() {
  const container = document.getElementById('usage-view-content');
  const activeApps = currentDapps.filter(d => d.active);
  const filterHtml = activeApps.length > 1 ? `
    <div class="dev-usage-filter" id="usage-filter-pills">
      <button class="dev-usage-filter-btn ${!usageFilterApp ? 'active' : ''}" data-app="">All Apps</button>
      ${activeApps.map(d => `
        <button class="dev-usage-filter-btn ${usageFilterApp === d.clientId ? 'active' : ''}" data-app="${escapeAttr(d.clientId)}">${escapeHtml(d.name)}</button>
      `).join('')}
    </div>
  ` : '';

  const filterLabel = usageFilterApp
    ? escapeHtml(currentDapps.find(d => d.clientId === usageFilterApp)?.name || 'App')
    : 'All apps';

  const daysLabel = usageDays === 1 ? '24 hours' : `${usageDays} days`;

  container.innerHTML = `
    <div class="an-header">
      <div>
        <h2 class="dev-agg-title">USAGE</h2>
        <div class="dev-agg-subtitle" id="usage-subtitle">${filterLabel} · last ${daysLabel}</div>
      </div>
      <div class="an-range-btns">
        <button class="an-range-btn ${usageDays === 1 ? 'an-range-btn-active' : ''}" data-days="1">24h</button>
        <button class="an-range-btn ${usageDays === 7 ? 'an-range-btn-active' : ''}" data-days="7">7d</button>
        <button class="an-range-btn ${usageDays === 30 ? 'an-range-btn-active' : ''}" data-days="30">30d</button>
        <button class="an-range-btn ${usageDays === 90 ? 'an-range-btn-active' : ''}" data-days="90">90d</button>
      </div>
    </div>

    ${filterHtml}

    <div id="usage-data-section">
    </div>
  `;

  // Wire range buttons (persistent — no re-render of shell)
  container.querySelectorAll('.an-range-btn[data-days]').forEach(btn => {
    btn.addEventListener('click', () => {
      usageDays = parseInt(btn.dataset.days);
      // Update active state immediately (no blink)
      container.querySelectorAll('.an-range-btn').forEach(b => b.classList.remove('an-range-btn-active'));
      btn.classList.add('an-range-btn-active');
      const dl = usageDays === 1 ? '24 hours' : `${usageDays} days`;
      const fl = usageFilterApp
        ? escapeHtml(currentDapps.find(d => d.clientId === usageFilterApp)?.name || 'App')
        : 'All apps';
      document.getElementById('usage-subtitle').textContent = `${fl} · last ${dl}`;
      refreshUsageData();
    });
  });

  // Wire app filter buttons
  container.querySelectorAll('.dev-usage-filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      usageFilterApp = btn.dataset.app || null;
      // Update active state immediately
      container.querySelectorAll('.dev-usage-filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const dl = usageDays === 1 ? '24 hours' : `${usageDays} days`;
      const fl = usageFilterApp
        ? escapeHtml(currentDapps.find(d => d.clientId === usageFilterApp)?.name || 'App')
        : 'All apps';
      document.getElementById('usage-subtitle').textContent = `${fl} · last ${dl}`;
      refreshUsageData();
    });
  });

  usageShellRendered = true;
}

function showUsageSkeleton() {
  const section = document.getElementById('usage-data-section');
  if (!section) return;
  section.innerHTML = `
    <div class="an-cards-row">
      <div class="an-card"><div class="an-card-label">Total Requests</div><div class="skeleton" style="height:24px;width:48px;margin-top:var(--space-2);"></div></div>
      <div class="an-card"><div class="an-card-label">Token Exchanges</div><div class="skeleton" style="height:24px;width:48px;margin-top:var(--space-2);"></div></div>
      <div class="an-card"><div class="an-card-label">Unique Agents</div><div class="skeleton" style="height:24px;width:48px;margin-top:var(--space-2);"></div></div>
      <div class="an-card"><div class="an-card-label">Last Request</div><div class="skeleton" style="height:14px;width:72px;margin-top:var(--space-2);"></div></div>
    </div>
    <div class="an-charts-grid">
      <div class="an-chart-cell">
        <div class="an-chart-title">Requests</div>
        <div class="an-chart-wrap"><div class="skeleton" style="height:100%;width:100%;border-radius:var(--radius-sm);"></div></div>
      </div>
      <div class="an-chart-cell">
        <div class="an-chart-title">Token Exchanges</div>
        <div class="an-chart-wrap"><div class="skeleton" style="height:100%;width:100%;border-radius:var(--radius-sm);"></div></div>
      </div>
    </div>
  `;
}

async function refreshUsageData() {
  showUsageSkeleton();

  const url = usageFilterApp
    ? `/developers/api/dapps/${usageFilterApp}/usage?days=${usageDays}`
    : `/developers/api/usage?days=${usageDays}`;

  try {
    const resp = await fetch(url);
    if (resp.status === 401) return showLoginView();
    const data = await resp.json();

    const section = document.getElementById('usage-data-section');
    if (!section) return;

    if (!data.success) {
      section.innerHTML = `<div class="an-chart-empty">Failed to load usage data</div>`;
      return;
    }

    const s = data.summary;
    const ts = data.timeseries || [];

    section.innerHTML = `
      <div class="an-cards-row">
        <div class="an-card">
          <div class="an-card-label">Total Requests</div>
          <div class="an-card-value">${s.totalRequests.toLocaleString()}</div>
        </div>
        <div class="an-card">
          <div class="an-card-label">Token Exchanges</div>
          <div class="an-card-value">${(s.tokenExchanges || 0).toLocaleString()}</div>
        </div>
        <div class="an-card">
          <div class="an-card-label">Unique Agents</div>
          <div class="an-card-value">${s.uniqueAgents.toLocaleString()}</div>
        </div>
        <div class="an-card">
          <div class="an-card-label">Last Request</div>
          <div class="an-card-value" style="font-size:var(--text-sm);font-weight:600;">${formatTimeAgo(s.lastRequest)}</div>
        </div>
      </div>

      <div class="an-charts-grid">
        <div class="an-chart-cell">
          <div class="an-chart-title">Requests</div>
          <div class="an-chart-wrap" id="usage-chart-requests"></div>
        </div>
        <div class="an-chart-cell">
          <div class="an-chart-title">Token Exchanges</div>
          <div class="an-chart-wrap" id="usage-chart-tokens"></div>
        </div>
      </div>
    `;

    // Draw charts
    const reqContainer = document.getElementById('usage-chart-requests');
    const tokContainer = document.getElementById('usage-chart-tokens');

    const reqData = ts.map(d => ({ date: d.date, value: d.requests }));
    const tokData = ts.map(d => ({ date: d.date, value: d.tokenExchanges }));

    if (reqData.some(d => d.value > 0)) {
      drawUsageLineChart(reqContainer, reqData, '#7c5cff', 'Requests');
    } else {
      reqContainer.innerHTML = '<div class="an-chart-empty">No data yet</div>';
    }

    if (tokData.some(d => d.value > 0)) {
      drawUsageBarChart(tokContainer, tokData, '#22c55e', 'Token Exchanges');
    } else {
      tokContainer.innerHTML = '<div class="an-chart-empty">No data yet</div>';
    }

  } catch (err) {
    console.error('Failed to load aggregate usage:', err);
    const section = document.getElementById('usage-data-section');
    if (section) section.innerHTML = `<div class="an-chart-empty">Network error loading usage data</div>`;
  }
}

async function renderAggregateUsage() {
  if (!usageShellRendered) {
    renderUsageShell();
  }
  refreshUsageData();
}

// ==================== Event Listeners ====================

document.getElementById('btn-create')?.addEventListener('click', showCreateModal);

// ==================== Init ====================

checkSession();
