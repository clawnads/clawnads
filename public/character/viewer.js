// Clawnads Character Viewer v2 — Scene, Camera, Controls, Render Loop
// Standalone viewer for inspecting 3D characters with animation controls

import * as THREE from 'three';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { ChibiLobster } from './lobster.js';
import { SimpleHuman } from './human.js';
import { GLTFLobster } from './gltf-lobster.js';
import { SAMPLE_ACCESSORIES, CAPE_PRESETS } from './accessories.js';

class CharacterViewer {
  constructor() {
    this._container = document.getElementById('canvas-container');
    this._fpsEl = document.getElementById('char-fps');
    this._panel = document.getElementById('char-panel');

    this._version = 'v2'; // 'v1' | 'v2'
    this._characterType = 'gltf-lobster'; // 'lobster' | 'human' | 'gltf-lobster'
    this._modelVariant = 'red'; // 'red' | 'blue' | 'gold'
    this._spawnCounter = 0;    // guards against concurrent spawns
    this._capePreset = null; // current cape color key or null
    this._capeLogo = false;

    this._initScene();
    this._initCamera();
    this._initRenderer();
    this._initControls();
    this._initLighting();
    this._initGround();
    // UI setup BEFORE character spawn so version/controls are correct
    this._initVersionToggle();
    this._initCharacterToggle();
    this._initAccessoryUI();
    this._initCapeUI();
    this._initAnimationUI();
    this._initV2AnimationUI();
    this._initModelVariantToggle();
    this._initDanceUI();
    this._initTextureToggle();
    this._initClickToMove();
    this._initResize();
    // Spawn character LAST (after UI is ready)
    this._initCharacter();

    // FPS tracking
    this._frameCount = 0;
    this._fpsTime = 0;

    // 60 FPS for smoother StandardMaterial rendering
    this._frameInterval = 1000 / 60;
    this._lastFrame = 0;

    this._animate = this._animate.bind(this);
    requestAnimationFrame(this._animate);
  }

  _initScene() {
    this.scene = new THREE.Scene();
    this.scene.background = new THREE.Color('#09090b');
  }

  _initCamera() {
    const aspect = this._container.clientWidth / this._container.clientHeight;
    this.camera = new THREE.PerspectiveCamera(40, aspect, 0.1, 50);
    // Full body view
    this.camera.position.set(0.6, 0.6, 1.8);
  }

  _initRenderer() {
    this.renderer = new THREE.WebGLRenderer({ antialias: true });
    this.renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
    this.renderer.setSize(this._container.clientWidth, this._container.clientHeight);
    this.renderer.outputColorSpace = THREE.SRGBColorSpace;
    this.renderer.toneMapping = THREE.ACESFilmicToneMapping;
    this.renderer.toneMappingExposure = 1.1;
    this._container.appendChild(this.renderer.domElement);
  }

  _initControls() {
    this.controls = new OrbitControls(this.camera, this.renderer.domElement);
    // Full body orbit target
    this.controls.target.set(0, 0.50, 0);
    this.controls.enableDamping = true;
    this.controls.dampingFactor = 0.08;
    this.controls.minDistance = 0.8;
    this.controls.maxDistance = 5.0;
    this.controls.maxPolarAngle = Math.PI * 0.85;
    this.controls.autoRotate = true;
    this.controls.autoRotateSpeed = 1.2;

    this._autoRotateTimer = null;
    this.controls.addEventListener('start', () => {
      this.controls.autoRotate = false;
      clearTimeout(this._autoRotateTimer);
    });
    this.controls.addEventListener('end', () => {
      this._autoRotateTimer = setTimeout(() => {
        this.controls.autoRotate = true;
      }, 3000);
    });
  }

  _initLighting() {
    // Warm ambient for soft fill
    this.scene.add(new THREE.AmbientLight('#4a3a30', 0.8));

    // Key light (warm, upper front-right) — strong for StandardMaterial
    const key = new THREE.DirectionalLight('#ffeedd', 1.2);
    key.position.set(3, 5, 4);
    this.scene.add(key);

    // Fill light (cool from left)
    const fill = new THREE.DirectionalLight('#88aacc', 0.5);
    fill.position.set(-4, 3, 2);
    this.scene.add(fill);

    // Rim light (green tint from behind — brand signature)
    const rim = new THREE.DirectionalLight('#22c55e', 0.3);
    rim.position.set(0, 2, -4);
    this.scene.add(rim);

    // Subtle bottom fill to prevent completely dark underside
    const bottom = new THREE.DirectionalLight('#332222', 0.3);
    bottom.position.set(0, -2, 0);
    this.scene.add(bottom);

    // Hemisphere light for natural sky/ground fill
    const hemi = new THREE.HemisphereLight('#1a1a2e', '#0a0a0c', 0.4);
    this.scene.add(hemi);
  }

  _initGround() {
    // Larger dark ground plane for walk-around space
    const planeGeo = new THREE.PlaneGeometry(10, 10);
    const planeMat = new THREE.MeshStandardMaterial({
      color: '#0c0c0e',
      roughness: 0.95,
      metalness: 0.0
    });
    this._groundPlane = new THREE.Mesh(planeGeo, planeMat);
    this._groundPlane.rotation.x = -Math.PI / 2;
    this._groundPlane.position.y = -0.001;
    this.scene.add(this._groundPlane);

    // Subtle grid (renderOrder -1 so it never draws over characters)
    const grid = new THREE.GridHelper(10, 40, '#1a1a1f', '#131316');
    grid.position.y = 0.002;
    grid.material.opacity = 0.3;
    grid.material.transparent = true;
    grid.material.depthWrite = false;
    grid.renderOrder = -1;
    this.scene.add(grid);
    this._grid = grid;
  }

  _initCharacter() {
    this.character = null;
    this._spawnCharacter(this._characterType);
  }

  async _spawnCharacter(type) {
    // Guard against concurrent spawns (rapid model switching)
    const spawnId = ++this._spawnCounter;

    // Save position/rotation if existing character
    let savedPos = null;
    let savedRotY = 0;
    if (this.character) {
      savedPos = this.character.group.position.clone();
      savedRotY = this.character.group.rotation.y;
      this.scene.remove(this.character.group);
      this.character.dispose();
      this.character = null;
    }

    this._characterType = type;

    let newChar;
    if (type === 'gltf-lobster') {
      await GLTFLobster.preload('/models', this._modelVariant);
      // Bail if a newer spawn was triggered while we were loading
      if (spawnId !== this._spawnCounter) return;
      newChar = GLTFLobster.createSync({ variant: this._modelVariant });
    } else if (type === 'human') {
      newChar = new SimpleHuman({ hue: 220 });
    } else {
      newChar = new ChibiLobster();
    }

    // Final check — another spawn may have started
    if (spawnId !== this._spawnCounter) {
      newChar.dispose();
      return;
    }

    this.character = newChar;
    this.scene.add(this.character.group);

    // --- Shadow variant: backlight glow so black silhouette is visible ---
    if (this._shadowGlow) {
      this.scene.remove(this._shadowGlow);
      this._shadowGlow = null;
    }
    const isShadow = (type === 'gltf-lobster' && this._modelVariant === 'shadow');
    this.scene.background = new THREE.Color(isShadow ? '#18181b' : '#09090b');
    if (isShadow) {
      // Soft radial glow sprite behind the character
      const canvas = document.createElement('canvas');
      canvas.width = 256; canvas.height = 256;
      const ctx = canvas.getContext('2d');
      const grad = ctx.createRadialGradient(128, 128, 0, 128, 128, 128);
      grad.addColorStop(0, 'rgba(63, 63, 70, 0.5)');
      grad.addColorStop(0.5, 'rgba(39, 39, 42, 0.25)');
      grad.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, 256, 256);
      const tex = new THREE.CanvasTexture(canvas);
      const mat = new THREE.SpriteMaterial({ map: tex, transparent: true, depthWrite: false });
      this._shadowGlow = new THREE.Sprite(mat);
      this._shadowGlow.scale.set(2.0, 2.0, 1);
      this._shadowGlow.position.set(0, 0.5, -0.3);
      this.scene.add(this._shadowGlow);
    }

    // Dismiss loading overlay
    const overlay = document.getElementById('loading-overlay');
    if (overlay) overlay.remove();

    // Restore position
    if (savedPos) {
      this.character.group.position.copy(savedPos);
      this.character.group.rotation.y = savedRotY;
    }

    // Alias for backward compat (lobster reference used throughout)
    this.lobster = this.character;

    // Clear accessories
    this._equippedAccessories?.clear();
    this._panel?.querySelectorAll('button.active').forEach(b => b.classList.remove('active'));
    this._capePreset = null;
    this._capeLogo = false;

    // V1: show/hide accessories + cape for lobster vs human
    if (this._version === 'v1') {
      const isLobster = type === 'lobster';
      if (this._panel) this._panel.style.display = isLobster ? '' : 'none';
      const capePanel = document.getElementById('char-cape');
      if (capePanel) capePanel.style.display = isLobster ? '' : 'none';
    }

    // Reset cape UI
    this._updateCapeUI();

    // V2 auto-plays idle clip from constructor, just sync button state
    if (type === 'gltf-lobster') {
      this._setV2AnimBtnState('idle');
      this._updateDanceUI();
    } else {
      this._setAnimBtnState('idle');
      this._setV2AnimBtnState('idle');
    }
  }

  // =====================================================
  // VERSION TOGGLE (V1 Primitives / V2 Meshy)
  // =====================================================
  _initVersionToggle() {
    this._v1Btn = document.getElementById('toggle-v1');
    this._v2Btn = document.getElementById('toggle-v2');
    this._v1Controls = document.getElementById('v1-controls');
    this._v2Controls = document.getElementById('v2-controls');

    // Set initial UI state to match default version
    if (this._version === 'v2') {
      this._v1Btn?.classList.remove('active');
      this._v2Btn?.classList.add('active');
      if (this._v1Controls) this._v1Controls.style.display = 'none';
      if (this._v2Controls) this._v2Controls.style.display = 'flex';
    }

    if (this._v1Btn) {
      this._v1Btn.addEventListener('click', () => {
        if (this._version === 'v1') return;
        this._version = 'v1';
        this._v1Btn.classList.add('active');
        this._v2Btn.classList.remove('active');
        if (this._v1Controls) this._v1Controls.style.display = '';
        if (this._v2Controls) this._v2Controls.style.display = 'none';
        this._spawnCharacter('lobster');
        // Reset V1 character toggle
        this._lobsterBtn?.classList.add('active');
        this._humanBtn?.classList.remove('active');
      });
    }
    if (this._v2Btn) {
      this._v2Btn.addEventListener('click', async () => {
        if (this._version === 'v2') return;
        this._v2Btn.textContent = '⏳ Loading…';
        this._version = 'v2';
        this._v1Btn.classList.remove('active');
        this._v2Btn.classList.add('active');
        if (this._v1Controls) this._v1Controls.style.display = 'none';
        if (this._v2Controls) this._v2Controls.style.display = 'flex';
        await this._spawnCharacter('gltf-lobster');
        this._v2Btn.textContent = 'V2 — Meshy';
      });
    }
  }

  _initCharacterToggle() {
    const togglePanel = document.getElementById('char-toggle');
    if (!togglePanel) return;

    this._lobsterBtn = document.getElementById('toggle-lobster');
    this._humanBtn = document.getElementById('toggle-human');

    const allBtns = [this._lobsterBtn, this._humanBtn].filter(Boolean);
    const setActive = (btn) => {
      allBtns.forEach(b => b.classList.remove('active'));
      if (btn) btn.classList.add('active');
    };

    if (this._lobsterBtn) {
      this._lobsterBtn.classList.add('active');
      this._lobsterBtn.addEventListener('click', () => {
        if (this._characterType === 'lobster') return;
        this._spawnCharacter('lobster');
        setActive(this._lobsterBtn);
      });
    }
    if (this._humanBtn) {
      this._humanBtn.addEventListener('click', () => {
        if (this._characterType === 'human') return;
        this._spawnCharacter('human');
        setActive(this._humanBtn);
      });
    }
  }

  _initAccessoryUI() {
    this._equippedAccessories = new Map();

    for (const acc of SAMPLE_ACCESSORIES) {
      const btn = document.createElement('button');
      btn.textContent = acc.name;
      btn.dataset.accName = acc.name;
      btn.addEventListener('click', () => this._toggleAccessory(acc, btn));
      this._panel.appendChild(btn);
    }
  }

  _initCapeUI() {
    const capePanel = document.getElementById('char-cape');
    if (!capePanel) return;

    // Color swatch row
    const swatchRow = capePanel.querySelector('.cape-swatches');
    if (!swatchRow) return;

    // Build color dot buttons from CAPE_PRESETS
    this._capeSwatchBtns = [];
    for (const preset of CAPE_PRESETS) {
      const colors = ChibiLobster.CAPE_COLORS[preset.key];
      const btn = document.createElement('button');
      btn.className = 'cape-swatch';
      btn.title = preset.name;
      btn.style.background = colors.color;
      btn.dataset.capeKey = preset.key;
      btn.addEventListener('click', () => this._selectCape(preset.key));
      swatchRow.appendChild(btn);
      this._capeSwatchBtns.push(btn);
    }

    // "None" button to remove cape
    const noneBtn = document.createElement('button');
    noneBtn.className = 'cape-swatch cape-none';
    noneBtn.title = 'No Cape';
    noneBtn.textContent = '✕';
    noneBtn.addEventListener('click', () => this._removeCape());
    swatchRow.appendChild(noneBtn);
    this._capeNoneBtn = noneBtn;

    // Logo toggle
    this._logoBtn = document.getElementById('cape-logo-toggle');
    if (this._logoBtn) {
      this._logoBtn.addEventListener('click', () => {
        this._capeLogo = !this._capeLogo;
        this._logoBtn.classList.toggle('active', this._capeLogo);
        // Re-equip cape with logo change if one is active
        if (this._capePreset) {
          this._equipCape(this._capePreset);
        }
      });
    }
  }

  _selectCape(presetKey) {
    this._capePreset = presetKey;
    this._equipCape(presetKey);
    this._updateCapeUI();
  }

  _removeCape() {
    this._capePreset = null;
    if (this.lobster.unequip) {
      this.lobster.unequip('back');
    }
    this._updateCapeUI();
  }

  _equipCape(presetKey) {
    if (!this.lobster.equip) return;
    const cape = ChibiLobster.buildCape(presetKey, undefined, undefined, { logo: this._capeLogo });
    this.lobster.equip('back', cape);
  }

  _updateCapeUI() {
    if (!this._capeSwatchBtns) return;
    for (const btn of this._capeSwatchBtns) {
      btn.classList.toggle('active', btn.dataset.capeKey === this._capePreset);
    }
    if (this._capeNoneBtn) {
      this._capeNoneBtn.classList.toggle('active', !this._capePreset);
    }
  }

  _initAnimationUI() {
    const animPanel = document.getElementById('char-anim');
    if (!animPanel) return;

    this._idleBtn = document.getElementById('anim-idle');
    this._walkBtn = document.getElementById('anim-walk');
    this._runBtn = document.getElementById('anim-run');

    if (this._idleBtn) {
      this._idleBtn.classList.add('active');
      this._idleBtn.addEventListener('click', () => {
        this.lobster.stopWalk();
        this._setAnimBtnState('idle');
      });
    }
    if (this._walkBtn) {
      this._walkBtn.addEventListener('click', () => {
        this.lobster.startWalk();
        this._setAnimBtnState('walk');
      });
    }
    if (this._runBtn) {
      this._runBtn.addEventListener('click', () => {
        this.lobster.startRun();
        this._setAnimBtnState('run');
      });
    }
  }

  _setAnimBtnState(state) {
    this._idleBtn?.classList.toggle('active', state === 'idle');
    this._walkBtn?.classList.toggle('active', state === 'walk' || state === 'moving');
    this._runBtn?.classList.toggle('active', state === 'run');
  }

  // V2 animation select (base anim dropdown for Meshy GLTF)
  _initV2AnimationUI() {
    this._animBaseSelect = document.getElementById('anim-base-select');
    if (!this._animBaseSelect) return;

    this._animBaseSelect.addEventListener('change', () => {
      const val = this._animBaseSelect.value;
      if (val === 'idle') {
        this.lobster.stopWalk();
      } else if (val === 'walk') {
        this.lobster.startWalk();
      } else if (val === 'run') {
        this.lobster.startRun();
      }
      // Reset all extras dropdowns when switching base anim
      this._resetExtrasSelects();
    });
  }

  _setV2AnimBtnState(state) {
    if (this._animBaseSelect) {
      if (state === 'idle' || state === 'walk' || state === 'run') {
        this._animBaseSelect.value = state;
      } else if (state === 'moving') {
        this._animBaseSelect.value = 'walk';
      }
    }
    // Reset extras dropdowns when switching to core anim
    this._resetExtrasSelects();
  }

  /** Reset all extras category selects to their placeholder */
  _resetExtrasSelects() {
    const ids = ['extras-dance-select', 'extras-exercise-select', 'extras-fight-select'];
    for (const id of ids) {
      const sel = document.getElementById(id);
      if (sel) sel.selectedIndex = 0;
    }
  }

  // =====================================================
  // MODEL VARIANT TOGGLE (Red / Blue / Gold)
  // =====================================================
  _initModelVariantToggle() {
    this._variantSelect = document.getElementById('model-variant-select');
    if (!this._variantSelect) return;

    this._variantSelect.addEventListener('change', async () => {
      const key = this._variantSelect.value;
      if (this._modelVariant === key || this._modelSwitching) return;
      this._modelSwitching = true;
      this._modelVariant = key;
      this._variantSelect.disabled = true;
      await this._spawnCharacter('gltf-lobster');
      this._variantSelect.disabled = false;
      this._modelSwitching = false;
    });
  }

  // =====================================================
  // EXTRAS UI (Dance / Exercise / Fight dropdowns)
  // =====================================================

  // Animation metadata: display name + category
  static ANIM_META = {
    'dance-boom':       { label: 'Boom',       category: 'dance' },
    'dance-funny1':     { label: 'Funny 1',    category: 'dance' },
    'dance-funny2':     { label: 'Funny 2',    category: 'dance' },
    'dance-funny3':     { label: 'Funny 3',    category: 'dance' },
    'dance-hiphop':     { label: 'Hip Hop',    category: 'dance' },
    'dance-hiphop3':    { label: 'Hip Hop 2',  category: 'dance' },
    'dance-allnight':   { label: 'All Night',  category: 'dance' },
    'dance-cardio':     { label: 'Cardio',     category: 'exercise' },
    'dance-cherish':    { label: 'Cherish',    category: 'dance' },
    'dance-superlove':  { label: 'Superlove',  category: 'dance' },
    'dance-squat':      { label: 'Squat',      category: 'exercise' },
    'dance-jazz':       { label: 'Jazz',       category: 'dance' },
    'dance-shakeoff':   { label: 'Shake Off',  category: 'dance' },
    'dance-lovepop':    { label: 'Love Pop',   category: 'dance' },
    'dance-boxing':     { label: 'Boxing',     category: 'fight' },
    'dance-sweepkick':  { label: 'Sweep Kick', category: 'fight' },
    'dance-bicepcurl':  { label: 'Bicep Curl', category: 'exercise' },
  };

  // Category → select element ID mapping
  static CATEGORY_SELECTS = {
    dance:    'extras-dance-select',
    exercise: 'extras-exercise-select',
    fight:    'extras-fight-select',
  };

  // Category → parent panel ID mapping
  static CATEGORY_PANELS = {
    dance:    'char-extras-v2',
    exercise: 'char-exercise-v2',
    fight:    'char-fight-v2',
  };

  _initDanceUI() {
    // Wire up change handlers for each category select
    for (const [cat, selId] of Object.entries(CharacterViewer.CATEGORY_SELECTS)) {
      const sel = document.getElementById(selId);
      if (!sel) continue;
      sel.addEventListener('change', async () => {
        const animName = sel.value;
        if (!animName || !this.character) return;

        // Reset base anim select visual (no base anim is active during extras)
        if (this._animBaseSelect) this._animBaseSelect.value = 'idle';

        // Reset other category selects (only one extra plays at a time)
        for (const [otherCat, otherId] of Object.entries(CharacterViewer.CATEGORY_SELECTS)) {
          if (otherCat !== cat) {
            const otherSel = document.getElementById(otherId);
            if (otherSel) otherSel.selectedIndex = 0;
          }
        }

        // Show loading state
        const label = sel.options[sel.selectedIndex].text;
        sel.options[sel.selectedIndex].text = '⏳ Loading…';
        sel.disabled = true;

        await this.character.playExtra(animName);

        // Restore label
        sel.options[sel.selectedIndex].text = label;
        sel.disabled = false;
      });
    }
  }

  _updateDanceUI() {
    // Only show for characters with extra clips
    const hasExtras = this.character && this.character.getExtraClipNames;
    const extras = hasExtras ? this.character.getExtraClipNames() : [];

    // Group extras by category
    const groups = {};
    for (const name of extras) {
      const meta = CharacterViewer.ANIM_META[name] || { label: name, category: 'dance' };
      if (!groups[meta.category]) groups[meta.category] = [];
      groups[meta.category].push({ name, label: meta.label });
    }

    // Populate each category select
    for (const [cat, selId] of Object.entries(CharacterViewer.CATEGORY_SELECTS)) {
      const sel = document.getElementById(selId);
      const panel = document.getElementById(CharacterViewer.CATEGORY_PANELS[cat]);
      if (!sel) continue;

      const items = groups[cat] || [];

      // Clear and rebuild options
      sel.innerHTML = '';

      if (items.length === 0) {
        // No anims for this category — disable and hide panel
        const opt = document.createElement('option');
        opt.value = '';
        opt.textContent = 'None available';
        sel.appendChild(opt);
        sel.disabled = true;
        if (panel) panel.style.display = 'none';
      } else {
        // Placeholder option
        const placeholder = document.createElement('option');
        placeholder.value = '';
        placeholder.textContent = `Select (${items.length})`;
        sel.appendChild(placeholder);

        for (const { name, label } of items) {
          const opt = document.createElement('option');
          opt.value = name;
          opt.textContent = label;
          sel.appendChild(opt);
        }
        sel.disabled = false;
        if (panel) panel.style.display = '';
      }
    }
  }

  // =====================================================
  // TEXTURE TOGGLE (Meshy Textured / Base Clay)
  // =====================================================
  _initTextureToggle() {
    this._textureMode = 'meshy'; // 'meshy' | 'clay'
    this._textureSelect = document.getElementById('texture-select');

    if (this._textureSelect) {
      this._textureSelect.addEventListener('change', () => {
        const val = this._textureSelect.value;
        if (this._textureMode === val) return;
        this._textureMode = val;
        this._applyTextureMode();
      });
    }
  }

  _applyTextureMode() {
    if (!this.character || this._characterType !== 'gltf-lobster') return;
    this.character.setTextureMode(this._textureMode);
  }

  // =====================================================
  // SPRITE CAPTURE (for Sprite Lab multi-angle renders)
  // =====================================================

  /**
   * Render the scene from a specific azimuth angle and return a data URL.
   * @param {number} azimuthDeg  Horizontal angle in degrees (0 = front, 90 = right)
   * @param {number} resolution  Square image size in px (default 512)
   * @returns {string} PNG data URL
   */
  captureAngle(azimuthDeg, resolution = 512) {
    const rad = (azimuthDeg * Math.PI) / 180;
    const radius = 2.0;
    const camY = 0.6;
    const targetY = 0.45;

    // Save state
    const savedW = this.renderer.domElement.width;
    const savedH = this.renderer.domElement.height;
    const savedAspect = this.camera.aspect;
    const savedPos = this.camera.position.clone();
    const savedPixelRatio = this.renderer.getPixelRatio();

    // Set up square capture
    this.renderer.setPixelRatio(1);
    this.renderer.setSize(resolution, resolution);
    this.camera.aspect = 1;
    this.camera.updateProjectionMatrix();

    // Position camera
    this.camera.position.set(
      Math.sin(rad) * radius,
      camY,
      Math.cos(rad) * radius
    );
    this.camera.lookAt(0, targetY, 0);

    // Render and capture
    this.renderer.render(this.scene, this.camera);
    const dataUrl = this.renderer.domElement.toDataURL('image/png');

    // Restore
    this.renderer.setPixelRatio(savedPixelRatio);
    this.renderer.setSize(savedW / savedPixelRatio, savedH / savedPixelRatio);
    this.camera.aspect = savedAspect;
    this.camera.position.copy(savedPos);
    this.camera.updateProjectionMatrix();

    return dataUrl;
  }

  /**
   * Capture the character from multiple angles in clay mode.
   * @param {number} count  Number of angles (4 or 6)
   * @param {number} resolution  Square image size in px
   * @returns {Array<{name: string, azimuth: number, dataUrl: string}>}
   */
  captureAllAngles(count = 4, resolution = 512) {
    const ANGLES_4 = [
      { name: 'Front',  azimuth: 0 },
      { name: 'Right',  azimuth: 90 },
      { name: 'Back',   azimuth: 180 },
      { name: 'Left',   azimuth: 270 },
    ];
    const ANGLES_6 = [
      { name: 'Front',     azimuth: 0 },
      { name: 'Front ¾',   azimuth: 45 },
      { name: 'Right',     azimuth: 90 },
      { name: 'Back ¾',    azimuth: 135 },
      { name: 'Back',      azimuth: 180 },
      { name: 'Left',      azimuth: 270 },
    ];
    const angles = count === 6 ? ANGLES_6 : ANGLES_4;

    if (!this.character) return [];

    // Save state
    const savedAutoRotate = this.controls.autoRotate;
    const savedCamPos = this.camera.position.clone();
    const savedTarget = this.controls.target.clone();
    const savedTextureMode = this._textureMode;
    const savedCharPos = this.character.group.position.clone();
    const savedCharRot = this.character.group.rotation.y;

    // Prepare for capture
    this.controls.autoRotate = false;
    this.character.group.position.set(0, 0, 0);
    this.character.group.rotation.y = 0;

    // Hide ground plane, grid, and walk marker for clean captures
    const savedGroundVis = this._groundPlane.visible;
    const savedGridVis = this._grid.visible;
    const savedMarkerVis = this._targetMarker.visible;
    this._groundPlane.visible = false;
    this._grid.visible = false;
    this._targetMarker.visible = false;

    // Also hide the character's ground ring if present
    const groundRing = this.character.groundRing;
    const savedRingVis = groundRing ? groundRing.visible : false;
    if (groundRing) groundRing.visible = false;

    // Switch to neutral gray clay for Sprite Lab captures
    if (this._characterType === 'gltf-lobster' && this.character.setTextureMode) {
      this.character.setTextureMode('sprite-clay');
    }

    // --- Even lighting for sprite captures ---
    // Dim existing directional/hemisphere lights and add flat fill
    const savedLightStates = [];
    this.scene.traverse(node => {
      if (node.isDirectionalLight || node.isHemisphereLight || node.isAmbientLight) {
        savedLightStates.push({ light: node, intensity: node.intensity });
        node.intensity = 0;
      }
    });
    // Flat ambient + 4 evenly-spaced directional fills (white, equal intensity)
    const spriteLights = [];
    const amb = new THREE.AmbientLight('#ffffff', 1.2);
    spriteLights.push(amb);
    this.scene.add(amb);
    const fillPositions = [
      [0, 3, 4],   // front
      [0, 3, -4],  // back
      [4, 3, 0],   // right
      [-4, 3, 0],  // left
    ];
    for (const pos of fillPositions) {
      const fl = new THREE.DirectionalLight('#ffffff', 0.4);
      fl.position.set(pos[0], pos[1], pos[2]);
      spriteLights.push(fl);
      this.scene.add(fl);
    }

    // Capture all angles
    const results = [];
    for (const angle of angles) {
      const dataUrl = this.captureAngle(angle.azimuth, resolution);
      results.push({ name: angle.name, azimuth: angle.azimuth, dataUrl });
    }

    // Remove temporary sprite lights & restore originals
    for (const sl of spriteLights) this.scene.remove(sl);
    for (const s of savedLightStates) s.light.intensity = s.intensity;

    // Restore everything
    this._groundPlane.visible = savedGroundVis;
    this._grid.visible = savedGridVis;
    this._targetMarker.visible = savedMarkerVis;
    if (groundRing) groundRing.visible = savedRingVis;
    this.character.group.position.copy(savedCharPos);
    this.character.group.rotation.y = savedCharRot;
    if (this._characterType === 'gltf-lobster' && this.character.setTextureMode) {
      this.character.setTextureMode(savedTextureMode);
    }
    this.camera.position.copy(savedCamPos);
    this.controls.target.copy(savedTarget);
    this.controls.autoRotate = savedAutoRotate;
    this.camera.updateProjectionMatrix();

    return results;
  }

  _initClickToMove() {
    this._raycaster = new THREE.Raycaster();
    this._mouse = new THREE.Vector2();

    // Walk target marker (green ring that appears where you click)
    const markerGeo = new THREE.RingGeometry(0.06, 0.09, 24);
    const markerMat = new THREE.MeshBasicMaterial({
      color: '#22c55e',
      transparent: true,
      opacity: 0,
      side: THREE.DoubleSide
    });
    this._targetMarker = new THREE.Mesh(markerGeo, markerMat);
    this._targetMarker.rotation.x = -Math.PI / 2;
    this._targetMarker.position.y = 0.005;
    this.scene.add(this._targetMarker);

    // Marker pulse animation state
    this._markerAge = 0;
    this._markerVisible = false;

    // Double-click to set walk target (single click is orbit)
    this._container.addEventListener('dblclick', (e) => this._onDoubleClick(e));

    // Touch: long-press to distinguish from orbit
    let touchStart = null;
    let touchTimer = null;
    this._container.addEventListener('touchstart', (e) => {
      if (e.touches.length !== 1) return;
      touchStart = { x: e.touches[0].clientX, y: e.touches[0].clientY, t: Date.now() };
      touchTimer = setTimeout(() => {
        if (touchStart) this._castMoveTarget(touchStart.x, touchStart.y);
        touchStart = null;
      }, 400);
    }, { passive: true });
    this._container.addEventListener('touchmove', () => {
      touchStart = null;
      clearTimeout(touchTimer);
    }, { passive: true });
    this._container.addEventListener('touchend', () => {
      clearTimeout(touchTimer);
      // Quick tap (< 200ms, minimal move) = walk target
      if (touchStart && Date.now() - touchStart.t < 200) {
        // Let orbit handle short taps; only double-tap handled via dblclick
      }
      touchStart = null;
    }, { passive: true });
  }

  _onDoubleClick(e) {
    this._castMoveTarget(e.clientX, e.clientY);
  }

  _castMoveTarget(clientX, clientY) {
    const rect = this._container.getBoundingClientRect();
    this._mouse.x = ((clientX - rect.left) / rect.width) * 2 - 1;
    this._mouse.y = -((clientY - rect.top) / rect.height) * 2 + 1;

    this._raycaster.setFromCamera(this._mouse, this.camera);
    const hits = this._raycaster.intersectObject(this._groundPlane);
    if (hits.length > 0) {
      const point = hits[0].point;
      // Clamp within reasonable area
      point.x = Math.max(-4.5, Math.min(4.5, point.x));
      point.z = Math.max(-4.5, Math.min(4.5, point.z));

      this.lobster.moveTo(point);
      this._setAnimBtnState('moving');

      // Show marker
      this._targetMarker.position.x = point.x;
      this._targetMarker.position.z = point.z;
      this._targetMarker.material.opacity = 0.8;
      this._markerAge = 0;
      this._markerVisible = true;
    }
  }

  _toggleAccessory(acc, btn) {
    if (this._equippedAccessories.has(acc.name)) {
      this.lobster.unequip(acc.slot);
      this._equippedAccessories.delete(acc.name);
      btn.classList.remove('active');
    } else {
      const group = acc.create();
      this.lobster.equip(acc.slot, group);
      this._equippedAccessories.set(acc.name, group);
      btn.classList.add('active');
    }
  }

  _initResize() {
    const ro = new ResizeObserver(() => {
      const w = this._container.clientWidth;
      const h = this._container.clientHeight;
      this.camera.aspect = w / h;
      this.camera.updateProjectionMatrix();
      this.renderer.setSize(w, h);
    });
    ro.observe(this._container);
  }

  _animate(now) {
    requestAnimationFrame(this._animate);

    if (now - this._lastFrame < this._frameInterval) return;
    const delta = (now - this._lastFrame) / 1000;
    this._lastFrame = now;

    this.controls.update();
    this.lobster.tick(delta);

    // Update target marker
    if (this._markerVisible) {
      this._markerAge += delta;
      // Pulse effect
      const pulse = 0.5 + 0.3 * Math.sin(this._markerAge * 4);
      this._targetMarker.material.opacity = Math.max(0, (0.8 - this._markerAge * 0.3)) * pulse;
      this._targetMarker.scale.setScalar(1 + Math.sin(this._markerAge * 3) * 0.1);
      if (this._targetMarker.material.opacity <= 0.01 || this.lobster.state === 'idle') {
        this._targetMarker.material.opacity = 0;
        this._markerVisible = false;
      }
    }

    // Sync UI when lobster arrives at target
    if (this.lobster.state === 'idle' && this._idleBtn && !this._idleBtn.classList.contains('active')) {
      this._setAnimBtnState('idle');
    }

    // Follow camera: gently track lobster position
    const lp = this.lobster.group.position;
    this.controls.target.lerp(new THREE.Vector3(lp.x, 0.50, lp.z), 0.03);

    this.renderer.render(this.scene, this.camera);

    // FPS counter
    this._frameCount++;
    this._fpsTime += delta;
    if (this._fpsTime >= 1) {
      this._fpsEl.textContent = `${Math.round(this._frameCount / this._fpsTime)} fps`;
      this._frameCount = 0;
      this._fpsTime = 0;
    }
  }
}

// Boot — expose globally for Sprite Lab access
window.characterViewer = new CharacterViewer();
