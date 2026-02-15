// landing.js — Cursor glow, conversion tracking, progressive 3D loader
// Loaded as type="module" from landing.html

// ── Cursor glow ──
const glow = document.querySelector('.cursor-glow');
if (glow && window.matchMedia('(pointer: fine)').matches) {
  document.addEventListener('mousemove', (e) => {
    glow.style.left = e.clientX + 'px';
    glow.style.top = e.clientY + 'px';
  });
}

// ── Shrinking nav on scroll ──
const navBar = document.querySelector('.nav-bar');
const topNav = document.querySelector('.top-nav');
if (navBar && topNav) {
  let scrolled = false;
  const threshold = 80; // px before shrink kicks in
  const onScroll = () => {
    const now = window.scrollY > threshold;
    if (now !== scrolled) {
      scrolled = now;
      navBar.classList.toggle('scrolled', now);
      topNav.classList.toggle('scrolled', now);
    }
  };
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll(); // check initial state
}

// ── Conversion tracking ──
const hovered = { agent: false, developer: false };

function trackCTA(path) {
  if (window.__beacon) window.__beacon('landing_cta', { path });
}

function trackHover(card) {
  if (hovered[card]) return;
  hovered[card] = true;
  if (window.__beacon) window.__beacon('landing_hover', { card });
}

document.getElementById('cta-agent')?.addEventListener('click', () => trackCTA('agent'));
document.getElementById('cta-developer')?.addEventListener('click', () => trackCTA('developer'));
document.getElementById('card-agent')?.addEventListener('mouseenter', () => trackHover('agent'));
document.getElementById('card-developer')?.addEventListener('mouseenter', () => trackHover('developer'));

// ── Make whole card clickable on touch devices ──
if ('ontouchstart' in window || window.matchMedia('(pointer: coarse)').matches) {
  const cardAgent = document.getElementById('card-agent');
  const cardDev = document.getElementById('card-developer');
  if (cardAgent) {
    cardAgent.style.cursor = 'pointer';
    cardAgent.addEventListener('click', (e) => {
      if (e.target.closest('a')) return; // let CTA handle itself
      trackCTA('agent');
      window.location.href = 'https://claw.tormund.io';
    });
  }
  if (cardDev) {
    cardDev.style.cursor = 'pointer';
    cardDev.addEventListener('click', (e) => {
      if (e.target.closest('a')) return;
      trackCTA('developer');
      window.location.href = 'https://console.tormund.io';
    });
  }
}

// ── Progressive 3D loader ──
// Load Three.js + GLTFLobster after first paint, replace thumbnail with live 3D
async function init3D() {
  const container = document.getElementById('agent-visual');
  const thumb = document.getElementById('agent-thumb');
  if (!container || !thumb) return;

  // Wait for idle moment
  await new Promise(r => {
    if ('requestIdleCallback' in window) requestIdleCallback(r);
    else setTimeout(r, 200);
  });

  try {
    const THREE = await import('https://cdn.jsdelivr.net/npm/three@0.170.0/build/three.module.js');
    const { GLTFLobster } = await import('/character/gltf-lobster.js');

    // Preload the red variant
    await GLTFLobster.preload('red', '/models');

    // Create scene
    const scene = new THREE.Scene();
    const w = container.clientWidth;
    const h = container.clientHeight;
    const camera = new THREE.PerspectiveCamera(35, w / h, 0.1, 50);
    camera.position.set(0, 1.0, 3.2);
    camera.lookAt(0, 0.65, 0);

    const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
    renderer.setSize(w, h);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.2;

    // Lighting
    const ambient = new THREE.AmbientLight(0xffffff, 0.6);
    scene.add(ambient);
    const key = new THREE.DirectionalLight(0xffffff, 1.4);
    key.position.set(3, 4, 2);
    scene.add(key);
    const fill = new THREE.DirectionalLight(0x9b7dff, 0.3);
    fill.position.set(-2, 2, 3);
    scene.add(fill);

    // Create lobster
    const lobster = new GLTFLobster({ variant: 'red' });
    lobster.mesh.position.set(0, 0, 0);
    scene.add(lobster.mesh);

    // Start with idle, load a dance clip
    lobster.playExtra('dance-funny2').catch(() => {});

    // Insert canvas
    const canvas = renderer.domElement;
    canvas.style.position = 'absolute';
    canvas.style.inset = '0';
    canvas.style.width = '100%';
    canvas.style.height = '100%';
    canvas.style.borderRadius = 'var(--radius-lg)';
    canvas.style.opacity = '0';
    canvas.style.transition = 'opacity 0.6s ease';
    container.appendChild(canvas);

    // Crossfade: hide thumbnail, show canvas
    requestAnimationFrame(() => {
      canvas.style.opacity = '1';
      thumb.style.opacity = '0';
    });

    // Remove thumbnail after fade
    setTimeout(() => thumb.remove(), 700);

    // Render loop
    const clock = new THREE.Clock();
    function animate() {
      requestAnimationFrame(animate);
      const delta = clock.getDelta();
      lobster.tick(delta);

      // Gentle turntable rotation
      lobster.mesh.rotation.y += delta * 0.15;

      renderer.render(scene, camera);
    }
    animate();

  } catch (err) {
    // 3D load failed — thumbnail stays, no harm done
    console.warn('3D init failed:', err);
  }
}

init3D();

// ── Scroll-reveal (IntersectionObserver) ──
const reveals = document.querySelectorAll('.reveal');
if (reveals.length) {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        observer.unobserve(entry.target);
      }
    });
  }, {
    threshold: 0.15,
    rootMargin: '0px 0px -40px 0px'
  });
  reveals.forEach(el => observer.observe(el));
}
