/* Shared admin nav — session check, avatar, logout dropdown, mobile hamburger.
   Include on any admin page. Requires an element with id="admin-nav-profile". */

(function () {
  // ===== Profile dropdown =====
  const container = document.getElementById('admin-nav-profile');
  if (container) {
    fetch('/admin/api/session')
      .then(r => r.json())
      .then(data => {
        if (!data.authenticated) return;
        renderProfile(data.username, data.avatar);
      })
      .catch(() => {});
  }

  function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
  function escAttr(s) { return s.replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/'/g,'&#39;').replace(/</g,'&lt;'); }

  function renderProfile(username, avatarUrl) {
    const initials = username.slice(0, 2).toUpperCase();
    const avatarInner = avatarUrl
      ? `<img class="anav-avatar-img" src="${escAttr(avatarUrl)}" alt="">`
      : esc(initials);

    container.innerHTML = `
      <div class="anav-wrap" id="anav-wrap">
        <button class="anav-btn" id="anav-btn">
          <span class="anav-circle">${avatarInner}</span>
        </button>
        <div class="anav-dropdown" id="anav-dropdown">
          <div class="anav-dropdown-user">${esc(username)}</div>
          <button class="anav-dropdown-item" id="anav-add-passkey">
            <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;vertical-align:-1px;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>Add passkey
          </button>
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

    document.getElementById('anav-add-passkey').addEventListener('click', () => {
      document.getElementById('anav-wrap').classList.remove('open');
      registerPasskey();
    });

    document.getElementById('anav-logout').addEventListener('click', () => {
      fetch('/admin/auth/logout', { method: 'POST' }).then(() => window.location.reload());
    });
  }

  // ===== WebAuthn passkey registration =====

  function b64urlToBuffer(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4 === 0 ? '' : '='.repeat(4 - (base64.length % 4));
    const binary = atob(base64 + pad);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }

  function bufferToB64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  async function registerPasskey() {
    if (!window.PublicKeyCredential) {
      alert('WebAuthn is not supported in this browser.');
      return;
    }

    try {
      // Get registration options
      const optResp = await fetch('/admin/auth/webauthn/register-options', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      const optData = await optResp.json();
      if (!optData.success) throw new Error(optData.error || 'Failed to get options');

      const { options, challengeId } = optData;

      // Convert for browser API
      const publicKeyOptions = {
        challenge: b64urlToBuffer(options.challenge),
        rp: { name: options.rp.name, id: options.rp.id },
        user: {
          id: b64urlToBuffer(options.user.id),
          name: options.user.name,
          displayName: options.user.displayName
        },
        pubKeyCredParams: options.pubKeyCredParams,
        timeout: options.timeout || 60000,
        authenticatorSelection: options.authenticatorSelection,
        attestation: options.attestation || 'none',
        excludeCredentials: (options.excludeCredentials || []).map(c => ({
          id: b64urlToBuffer(c.id),
          type: 'public-key',
          transports: c.transports
        }))
      };

      // Prompt Touch ID / fingerprint
      const credential = await navigator.credentials.create({ publicKey: publicKeyOptions });

      // Serialize for server
      const attestation = {
        id: credential.id,
        rawId: bufferToB64url(credential.rawId),
        type: credential.type,
        response: {
          attestationObject: bufferToB64url(credential.response.attestationObject),
          clientDataJSON: bufferToB64url(credential.response.clientDataJSON),
          transports: credential.response.getTransports ? credential.response.getTransports() : []
        },
        authenticatorAttachment: credential.authenticatorAttachment || null,
        clientExtensionResults: credential.getClientExtensionResults()
      };

      // Verify and store on server
      const regResp = await fetch('/admin/auth/webauthn/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ challengeId, attestation, label: 'Touch ID' })
      });
      const result = await regResp.json();

      if (result.success) {
        // Brief visual confirmation
        const btn = document.getElementById('anav-add-passkey');
        if (btn) {
          btn.textContent = 'Passkey added!';
          btn.style.color = '#4ade80';
          setTimeout(() => {
            btn.innerHTML = '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;vertical-align:-1px;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>Add passkey';
            btn.style.color = '';
          }, 2000);
        }
      } else {
        throw new Error(result.error || 'Registration failed');
      }
    } catch (e) {
      if (e.name === 'NotAllowedError') return; // User cancelled
      alert('Passkey registration failed: ' + (e.message || 'Unknown error'));
    }
  }

  // ===== Mobile hamburger menu =====
  const nav = document.querySelector('.admin-nav');
  if (!nav) return;

  // Collect nav links for the mobile menu
  const links = nav.querySelectorAll('.admin-nav-link');
  if (links.length === 0) return;

  // Create hamburger button
  const hamburger = document.createElement('button');
  hamburger.className = 'admin-nav-hamburger';
  hamburger.setAttribute('aria-label', 'Menu');
  hamburger.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>';

  // Insert hamburger after the logo
  const logo = nav.querySelector('.admin-nav-logo');
  if (logo && logo.nextSibling) {
    nav.insertBefore(hamburger, logo.nextSibling);
  } else {
    nav.appendChild(hamburger);
  }

  // Create mobile dropdown menu
  const menu = document.createElement('div');
  menu.className = 'admin-nav-mobile-menu';
  menu.id = 'admin-nav-mobile-menu';

  links.forEach(link => {
    const a = document.createElement('a');
    a.href = link.href;
    a.textContent = link.textContent;
    if (link.classList.contains('admin-nav-active')) {
      a.classList.add('admin-nav-active');
    }
    menu.appendChild(a);
  });

  document.body.appendChild(menu);

  // Toggle
  hamburger.addEventListener('click', (e) => {
    e.stopPropagation();
    menu.classList.toggle('open');
    // Swap icon between hamburger and X
    if (menu.classList.contains('open')) {
      hamburger.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
    } else {
      hamburger.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>';
    }
  });

  // Close on outside click
  document.addEventListener('click', () => {
    if (menu.classList.contains('open')) {
      menu.classList.remove('open');
      hamburger.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>';
    }
  });
})();
