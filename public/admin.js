/* ============================================
   Clawnads Admin
   ============================================ */

// Check for OAuth error in URL
const urlParams = new URLSearchParams(window.location.search);
const oauthError = urlParams.get('error');
if (oauthError) {
  history.replaceState(null, '', '/admin');
}

// ===== Session Check =====

async function checkSession() {
  try {
    const resp = await fetch('/admin/api/session');
    const data = await resp.json();
    if (data.authenticated) {
      showAdminView(data.username, data.avatar);
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

  if (oauthError) {
    const errorEl = document.getElementById('login-error');
    const messages = {
      oauth_denied: 'Authorization was denied.',
      not_authorized: 'Your X account is not authorized for admin access.',
      auth_failed: 'Authentication failed. Please try again.',
      missing_params: 'Invalid OAuth callback.',
      invalid_state: 'OAuth state mismatch. Please try again.'
    };
    errorEl.textContent = messages[oauthError] || 'Login failed.';
    errorEl.style.display = 'block';
  }

  lucide.createIcons();
  checkWebAuthnAvailable();
}

function showAdminView(username, avatarUrl) {
  document.getElementById('login-view').style.display = 'none';
  document.getElementById('admin-view').style.display = 'block';

  lucide.createIcons();
  loadKeys();
}

function closeAvatarDropdown() {
  const wrap = document.getElementById('avatar-wrap');
  if (wrap) wrap.classList.remove('open');
}

async function logout() {
  await fetch('/admin/auth/logout', { method: 'POST' });
  window.location.reload();
}

// ===== WebAuthn (Fingerprint / Touch ID) =====

// Helper: base64url encode/decode for WebAuthn credential IDs
function base64urlToBuffer(base64url) {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4 === 0 ? '' : '='.repeat(4 - (base64.length % 4));
  const binary = atob(base64 + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Check if fingerprint login is available (called on page load)
async function checkWebAuthnAvailable() {
  try {
    if (!window.PublicKeyCredential) return;
    const resp = await fetch('/admin/auth/webauthn/authenticate-options', { method: 'POST', headers: { 'Content-Type': 'application/json' } });
    const data = await resp.json();
    if (data.success && data.options) {
      const btn = document.getElementById('webauthn-login-btn');
      const divider = document.getElementById('webauthn-divider');
      if (btn) btn.style.display = '';
      if (divider) divider.style.display = '';
      // Cache the options so we don't need to re-fetch on click
      window._webauthnAuthOptions = data;
    }
  } catch (e) { /* No credentials registered, hide button */ }
}

// Authenticate with fingerprint
async function webauthnAuthenticate() {
  const btn = document.getElementById('webauthn-login-btn');
  const errorEl = document.getElementById('login-error');
  try {
    btn.disabled = true;
    btn.textContent = 'Waiting for fingerprint...';

    // Get fresh options if cache is stale
    let data = window._webauthnAuthOptions;
    if (!data) {
      const resp = await fetch('/admin/auth/webauthn/authenticate-options', { method: 'POST', headers: { 'Content-Type': 'application/json' } });
      data = await resp.json();
      if (!data.success) throw new Error(data.error || 'No credentials');
    }
    window._webauthnAuthOptions = null; // Clear cache

    const { options, challengeId } = data;

    // Convert base64url IDs to ArrayBuffers for the browser API
    const publicKeyOptions = {
      challenge: base64urlToBuffer(options.challenge),
      rpId: options.rpId,
      timeout: options.timeout || 60000,
      userVerification: options.userVerification || 'required',
      allowCredentials: (options.allowCredentials || []).map(c => ({
        id: base64urlToBuffer(c.id),
        type: 'public-key',
        transports: c.transports
      }))
    };

    const credential = await navigator.credentials.get({ publicKey: publicKeyOptions });

    // Serialize the response for the server
    const assertion = {
      id: credential.id,
      rawId: bufferToBase64url(credential.rawId),
      type: credential.type,
      response: {
        authenticatorData: bufferToBase64url(credential.response.authenticatorData),
        clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
        signature: bufferToBase64url(credential.response.signature),
        userHandle: credential.response.userHandle ? bufferToBase64url(credential.response.userHandle) : null
      },
      authenticatorAttachment: credential.authenticatorAttachment || null,
      clientExtensionResults: credential.getClientExtensionResults()
    };

    const verifyResp = await fetch('/admin/auth/webauthn/authenticate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId, assertion })
    });
    const result = await verifyResp.json();

    if (result.success) {
      window.location.href = result.redirect || '/analytics';
    } else {
      throw new Error(result.error || 'Authentication failed');
    }
  } catch (e) {
    if (e.name === 'NotAllowedError') {
      // User cancelled the prompt
      btn.disabled = false;
      btn.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:8px"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>Sign in with fingerprint';
      return;
    }
    if (errorEl) {
      errorEl.textContent = e.message || 'Fingerprint login failed';
      errorEl.style.display = 'block';
    }
    btn.disabled = false;
    btn.innerHTML = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:8px"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>Sign in with fingerprint';
  }
}

// ===== Modal System =====

function showModal(content) {
  const overlay = document.getElementById('modal-overlay');
  const body = document.getElementById('modal-body');
  body.innerHTML = `<button class="modal-close-x" onclick="hideModal()" title="Close (Esc)"><i data-lucide="x"></i></button>${content}`;
  overlay.classList.remove('closing');
  overlay.style.display = 'flex';
  lucide.createIcons({ nodes: [body] });
}

function hideModal() {
  const overlay = document.getElementById('modal-overlay');
  if (overlay.style.display === 'none') return;
  overlay.classList.add('closing');
  // Wait for animation to finish before hiding
  setTimeout(() => {
    overlay.style.display = 'none';
    overlay.classList.remove('closing');
    document.getElementById('modal-body').innerHTML = '';
  }, 120);
}

function isModalOpen() {
  const overlay = document.getElementById('modal-overlay');
  return overlay && overlay.style.display !== 'none';
}

// Close modal on overlay click
document.addEventListener('click', (e) => {
  if (e.target.id === 'modal-overlay') hideModal();
});

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
  // Escape or Cmd+. closes modal or dropdown
  if (e.key === 'Escape' || (e.key === '.' && (e.metaKey || e.ctrlKey) && isModalOpen())) {
    if (isModalOpen()) { e.preventDefault(); hideModal(); return; }
    closeAvatarDropdown();
    return;
  }

  const adminView = document.getElementById('admin-view');
  const isLoggedIn = adminView && adminView.style.display !== 'none';
  if (!isLoggedIn) return;

  // C — create new key (single key, like Linear)
  if (e.key === 'c' && !e.metaKey && !e.ctrlKey && !e.altKey && !isModalOpen()) {
    // Don't trigger if typing in an input
    if (document.activeElement?.tagName === 'INPUT' || document.activeElement?.tagName === 'TEXTAREA') return;
    e.preventDefault();
    showGenerateModal();
  }

  // ⌥⇧Q — Log out (use e.code for macOS compat — ⌥⇧ produces special chars)
  if (e.altKey && e.shiftKey && e.code === 'KeyQ') {
    e.preventDefault();
    logout();
  }
});

// ===== Generated Keys (session-only, raw keys available for copy) =====
const generatedKeys = []; // { label, key } — accumulated during this session

// ===== Skeleton Loading =====

function showSkeletons() {
  const tbody = document.getElementById('keys-list');
  document.getElementById('keys-empty').style.display = 'none';
  const rows = Array.from({ length: 4 }, () => `
    <tr>
      <td><div class="skeleton" style="height:12px;width:80px;border-radius:var(--radius-sm)"></div></td>
      <td><div class="skeleton" style="height:12px;width:52px;border-radius:var(--radius-sm)"></div></td>
      <td><div class="skeleton" style="height:12px;width:30px;border-radius:var(--radius-sm)"></div></td>
      <td><div class="skeleton" style="height:12px;width:60px;border-radius:var(--radius-sm)"></div></td>
      <td><div class="skeleton" style="height:12px;width:50px;border-radius:var(--radius-sm)"></div></td>
      <td></td>
    </tr>
  `).join('');
  tbody.innerHTML = rows;
}

// ===== Keys Management =====

async function loadKeys() {
  showSkeletons();
  try {
    const resp = await fetch('/admin/api/registration-keys');
    if (resp.status === 401) return showLoginView();
    const data = await resp.json();
    renderKeys(data.keys || []);
  } catch (err) {
    console.error('Failed to load keys:', err);
  }
}

function renderKeys(keys) {
  const tbody = document.getElementById('keys-list');
  const emptyEl = document.getElementById('keys-empty');

  if (keys.length === 0) {
    tbody.innerHTML = '';
    emptyEl.style.display = 'block';
    return;
  }

  emptyEl.style.display = 'none';

  // Sort: available first, then used, then revoked; within each group, newest first
  keys.sort((a, b) => {
    const order = { available: 0, used: 1, revoked: 2 };
    if (order[a.status] !== order[b.status]) return order[a.status] - order[b.status];
    return new Date(b.createdAt) - new Date(a.createdAt);
  });

  tbody.innerHTML = keys.map(k => {
    const copyBtn = k.rawKey ? `<button class="key-action-btn btn-copy-key" data-key="${escapeAttr(k.rawKey)}" title="Copy key"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg></button>` : '';
    const revokeBtn = k.status === 'available' ? `<button class="key-action-btn btn-revoke" data-label="${escapeAttr(k.label)}" title="Revoke key"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"></line></svg></button>` : '';
    const rowClass = k.status === 'revoked' ? ' class="row-revoked"' : '';
    return `
    <tr data-label="${escapeAttr(k.label)}"${rowClass}>
      <td class="key-label-cell">${escapeHtml(k.label)}</td>
      <td><span class="key-status ${k.status}">${k.status}</span></td>
      <td>${k.used}${k.maxUses ? ' / ' + k.maxUses : ''}</td>
      <td>${k.usedBy.length ? k.usedBy.map(escapeHtml).join(', ') : '-'}</td>
      <td style="color:var(--color-text-tertiary)">${formatDate(k.createdAt)}</td>
      <td class="key-actions">${copyBtn}${revokeBtn}</td>
    </tr>`;
  }).join('');

  // Bind revoke buttons
  tbody.querySelectorAll('.btn-revoke').forEach(btn => {
    btn.addEventListener('click', () => confirmRevoke(btn.dataset.label));
  });

  // Bind copy buttons for keys generated this session
  tbody.querySelectorAll('.btn-copy-key').forEach(btn => {
    btn.addEventListener('click', () => {
      navigator.clipboard.writeText(btn.dataset.key);
      btn.classList.add('copied');
      btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
      setTimeout(() => {
        btn.classList.remove('copied');
        btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';
      }, 2000);
    });
  });
}

// ===== Generate Key (modal) =====

function showGenerateModal() {
  showModal(`
    <div class="modal-title">New Invite Key</div>
    <div class="modal-form">
      <div class="modal-field">
        <label class="admin-label" for="modal-key-label">Label</label>
        <input type="text" id="modal-key-label" class="admin-input" placeholder="e.g. alice">
      </div>
      <div class="modal-field">
        <label class="admin-label" for="modal-key-uses">Max Uses</label>
        <input type="number" id="modal-key-uses" class="admin-input" value="1" min="1">
      </div>
    </div>
    <div class="modal-actions">
      <button class="admin-btn admin-btn-primary" id="modal-generate-btn">Generate</button>
    </div>
  `);

  document.getElementById('modal-generate-btn').addEventListener('click', generateKey);

  // Focus label input
  document.getElementById('modal-key-label').focus();

  // Enter to submit
  document.getElementById('modal-key-uses').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') generateKey();
  });
  document.getElementById('modal-key-label').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') generateKey();
  });
}

async function generateKey() {
  const labelInput = document.getElementById('modal-key-label');
  const maxUsesInput = document.getElementById('modal-key-uses');
  const label = labelInput.value.trim();
  const maxUses = parseInt(maxUsesInput.value) || 1;

  // Disable the button while generating
  const genBtn = document.getElementById('modal-generate-btn');
  if (genBtn) { genBtn.disabled = true; genBtn.textContent = 'Generating...'; }

  try {
    const resp = await fetch('/admin/api/registration-keys', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label: label || undefined, maxUses })
    });
    if (resp.status === 401) return showLoginView();
    const data = await resp.json();

    if (data.success) {
      // Store raw key for this session so it stays copyable in the table
      generatedKeys.push({ label: data.label, key: data.key });

      // Auto-copy to clipboard
      navigator.clipboard.writeText(data.key);

      // Show success modal with the key
      showModal(`
        <div class="modal-icon">
          <img src="/happy-crab.svg" class="empty-state-icon" style="width:64px;height:64px;opacity:0.63;margin-bottom:-6px;" alt="">
        </div>
        <div class="modal-title">Key created</div>
        <div class="modal-subtitle">Copied to clipboard</div>
        <div class="modal-key-row">
          <div class="modal-key-value">${escapeHtml(data.key)}</div>
          <button class="icon-btn" id="modal-copy-btn" title="Copy key"><i data-lucide="copy"></i></button>
        </div>
        <div class="modal-actions">
          <button class="admin-btn-primary admin-btn" onclick="hideModal()">Done</button>
        </div>
      `);
      lucide.createIcons();

      // Bind modal buttons
      document.getElementById('modal-copy-btn').addEventListener('click', () => {
        navigator.clipboard.writeText(data.key);
        const btn = document.getElementById('modal-copy-btn');
        btn.innerHTML = '<i data-lucide="check"></i>';
        btn.classList.add('copied');
        lucide.createIcons({ nodes: [btn] });
        setTimeout(() => {
          if (btn) {
            btn.innerHTML = '<i data-lucide="copy"></i>';
            btn.classList.remove('copied');
            lucide.createIcons({ nodes: [btn] });
          }
        }, 2000);
      });

      loadKeys();
    }
  } catch (err) {
    console.error('Failed to generate key:', err);
  }
}

// ===== Revoke Key (modal confirm) =====

function confirmRevoke(label) {
  showModal(`
    <div class="modal-icon">
      <img src="/sad-crab.svg" class="empty-state-icon" style="width:64px;height:64px;opacity:0.63;margin-bottom:-6px;" alt="">
    </div>
    <div class="modal-title">Revoke key</div>
    <div class="modal-subtitle">Are you sure you want to revoke <strong>${escapeHtml(label)}</strong>? This cannot be undone.</div>
    <div class="modal-actions">
      <button class="btn-revoke-confirm" id="modal-revoke-btn">Revoke</button>
    </div>
  `);

  document.getElementById('modal-revoke-btn').addEventListener('click', () => {
    hideModal();
    executeRevoke(label);
  });
}

async function executeRevoke(label) {
  const row = document.querySelector(`tr[data-label="${CSS.escape(label)}"]`);

  try {
    const resp = await fetch(`/admin/api/registration-keys/${encodeURIComponent(label)}`, {
      method: 'DELETE'
    });

    if (resp.status === 401) return showLoginView();
    const data = await resp.json();

    if (data.success && row) {
      const statusCell = row.querySelector('.key-status');
      if (statusCell) {
        statusCell.textContent = 'revoked';
        statusCell.className = 'key-status revoked';
      }
      const revokeBtn = row.querySelector('.btn-revoke');
      if (revokeBtn) revokeBtn.remove();
      row.classList.add('row-revoked');
      row.style.transition = 'opacity 0.3s ease';
      row.style.opacity = '0.5';
    } else if (!data.success) {
      console.error('Revoke failed:', data.error);
    }
  } catch (err) {
    console.error('Failed to revoke key:', err);
  }
}

// ===== Helpers =====

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function escapeAttr(str) {
  return str.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;');
}

function formatDate(iso) {
  const d = new Date(iso);
  const now = new Date();
  const diffMs = now - d;

  if (diffMs < 3600000) {
    const mins = Math.floor(diffMs / 60000);
    return mins <= 1 ? 'just now' : `${mins}m ago`;
  }
  if (diffMs < 86400000) {
    return `${Math.floor(diffMs / 3600000)}h ago`;
  }
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

// ===== Init =====
checkSession();
