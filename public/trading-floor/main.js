// Clawnads 3D Trading Floor Simulator — Main Entry Point
// Scene setup, render loop, camera, orchestration

import * as THREE from 'three';
import { CSS2DRenderer } from 'three/addons/renderers/CSS2DRenderer.js';
import { OrbitControls } from 'three/addons/controls/OrbitControls.js';
import { TradingFloorEnvironment } from './environment.js';
import { AgentCharacter, loadGLTFLobster } from './characters.js';
import { ActivityManager } from './activity-manager.js';
import { tickAnimations } from './animations.js';

// Deterministic hash from name → integer (for zone wait spot selection)
function nameHash(name) {
  let h = 0;
  for (let i = 0; i < name.length; i++) {
    h = ((h << 5) - h) + name.charCodeAt(i);
    h |= 0;
  }
  return Math.abs(h);
}

// Resolve a target position so it doesn't overlap agents or furniture.
// Checks agent-to-agent distance AND zone furniture bounding boxes.
const MIN_DIST = 0.9;
function resolvePosition(x, z, characters, excludeName, environment) {
  let rx = x, rz = z;
  // Collect furniture boxes from zone groups (desk/screen areas agents shouldn't stand in)
  const boxes = [];
  if (environment && environment.zoneGroups) {
    for (const [, group] of Object.entries(environment.zoneGroups)) {
      const gx = group.position.x, gz = group.position.z;
      // Each zone has furniture roughly ±1.2 in x and ±0.8 in z from the group center
      boxes.push({ cx: gx, cz: gz, hw: 1.3, hd: 0.9 });
    }
  }
  // Also add kiosk if present
  if (environment && environment.draggableGroups && environment.draggableGroups['kiosk']) {
    const k = environment.draggableGroups['kiosk'].position;
    boxes.push({ cx: k.x, cz: k.z, hw: 1.4, hd: 1.4 });
  }
  // Colonnade — wide but shallow footprint
  if (environment && environment.draggableGroups && environment.draggableGroups['colonnade']) {
    const c = environment.draggableGroups['colonnade'].position;
    boxes.push({ cx: c.x, cz: c.z, hw: 3.0, hd: 0.5 });
  }
  // Bronze statue
  if (environment && environment.draggableGroups && environment.draggableGroups['statue']) {
    const s = environment.draggableGroups['statue'].position;
    boxes.push({ cx: s.x, cz: s.z, hw: 0.4, hd: 0.4 });
  }

  for (let attempt = 0; attempt < 8; attempt++) {
    let conflict = false;

    // Check agent-to-agent overlap
    for (const [name, char] of characters) {
      if (name === excludeName) continue;
      const pos = char.getPosition();
      const dx = rx - pos.x, dz = rz - pos.z;
      const dist = Math.sqrt(dx * dx + dz * dz);
      if (dist < MIN_DIST) {
        conflict = true;
        if (dist < 0.01) {
          const angle = (nameHash(excludeName || '') % 360) * Math.PI / 180;
          rx += Math.cos(angle) * MIN_DIST;
          rz += Math.sin(angle) * MIN_DIST;
        } else {
          const push = (MIN_DIST - dist) + 0.1;
          rx += (dx / dist) * push;
          rz += (dz / dist) * push;
        }
      }
    }

    // Check furniture box overlap — push agent to nearest edge
    for (const box of boxes) {
      const localX = rx - box.cx, localZ = rz - box.cz;
      if (Math.abs(localX) < box.hw && Math.abs(localZ) < box.hd) {
        conflict = true;
        // Push to nearest edge
        const pushRight = box.hw - localX;
        const pushLeft = box.hw + localX;
        const pushFront = box.hd - localZ;
        const pushBack = box.hd + localZ;
        const minPush = Math.min(pushRight, pushLeft, pushFront, pushBack);
        if (minPush === pushRight) rx = box.cx + box.hw + 0.2;
        else if (minPush === pushLeft) rx = box.cx - box.hw - 0.2;
        else if (minPush === pushFront) rz = box.cz + box.hd + 0.2;
        else rz = box.cz - box.hd - 0.2;
      }
    }

    if (!conflict) break;
  }
  return { x: rx, z: rz };
}

class TradingFloor {
  constructor(container) {
    this.container = container;
    this.characters = new Map(); // name → AgentCharacter
    this.isRunning = false;
    this.lastFrameTime = 0;
    this.frameInterval = 1000 / 30; // 30fps cap
    this.clock = new THREE.Clock();
    this.fpsFrames = 0;
    this.fpsLastTime = performance.now();

    this._initScene();
    this._initCamera();
    this._initLights();
    this._initRenderers();
    this._initControls();
    this._initEnvironment();
    this._initActivityManager();
    this._initResize();
    this._initVisibility();
    if (!window.__simDisableDrag) this._initDevDrag();
  }

  _initScene() {
    this.scene = new THREE.Scene();
    this.scene.background = new THREE.Color('#09090b');
    // No fog — ground texture bg matches scene bg exactly, so edges are seamless
  }

  _initCamera() {
    const aspect = this.container.clientWidth / this.container.clientHeight;
    this.isPortrait = aspect < 1;

    // Portrait: top-down view of stacked vertical layout
    // Landscape: classic isometric view of triangle layout
    const frustumSize = this.isPortrait ? 22 : 14;
    this.frustumSize = frustumSize;

    this.camera = new THREE.OrthographicCamera(
      -frustumSize * aspect / 2,
      frustumSize * aspect / 2,
      frustumSize / 2,
      -frustumSize / 2,
      0.1,
      500
    );

    this._applyCameraMode();
  }

  _applyCameraMode() {
    const isoDistance = 20;
    if (this.isPortrait) {
      // Near top-down with slight angle so props have dimension
      const angle = Math.PI / 5;
      const elevation = Math.PI / 2.6; // ~69 degrees — very steep
      this.camera.position.set(
        isoDistance * Math.cos(angle) * Math.cos(elevation),
        isoDistance * Math.sin(elevation),
        isoDistance * Math.sin(angle) * Math.cos(elevation)
      );
      this.cameraLookAt = { x: 0, y: 0, z: 0 };
      this.cameraBaseAngle = angle;
      this.cameraDriftSpeed = 0.02;
      this.cameraDriftAmount = 0.05; // very subtle on mobile
      this.cameraElevation = elevation;
    } else {
      // Classic isometric
      const angle = Math.PI / 6;
      const elevation = Math.PI / 5;
      this.camera.position.set(
        isoDistance * Math.cos(angle) * Math.cos(elevation),
        isoDistance * Math.sin(elevation),
        isoDistance * Math.sin(angle) * Math.cos(elevation)
      );
      this.cameraLookAt = { x: 0, y: 0, z: 0 };
      this.cameraBaseAngle = angle;
      this.cameraDriftSpeed = 0.03;
      this.cameraDriftAmount = 0.15;
      this.cameraElevation = elevation;
    }
    this.camera.lookAt(this.cameraLookAt.x, this.cameraLookAt.y, this.cameraLookAt.z);
    // Sync controls target if controls exist
    if (this.controls) {
      this.controls.target.set(this.cameraLookAt.x, this.cameraLookAt.y, this.cameraLookAt.z);
      this.controls.update();
    }
  }

  _initLights() {
    // Neutral ambient — warm gray so character colors read true
    const ambient = new THREE.AmbientLight('#2a2a2e', 0.7);
    this.scene.add(ambient);

    // Warm directional (main light)
    const dir = new THREE.DirectionalLight('#f5f0e8', 0.8);
    dir.position.set(8, 15, 5);
    dir.castShadow = false; // keep it simple for perf
    this.scene.add(dir);

    // Neutral fill light from opposite side (no blue tint)
    const fill = new THREE.DirectionalLight('#c0bfbd', 0.25);
    fill.position.set(-6, 8, -4);
    this.scene.add(fill);

    // Green point lights near zone centers (subtle glow)
    const zoneGlow = new THREE.PointLight('#22c55e', 0.15, 8);
    zoneGlow.position.set(0, 0.5, 2); // Trading pit area
    this.scene.add(zoneGlow);

    const zoneGlow2 = new THREE.PointLight('#22c55e', 0.1, 6);
    zoneGlow2.position.set(-4, 0.5, -3); // Signals desk area
    this.scene.add(zoneGlow2);

    const zoneGlow3 = new THREE.PointLight('#22c55e', 0.1, 6);
    zoneGlow3.position.set(4, 0.5, -3); // Skills desk area
    this.scene.add(zoneGlow3);
  }

  _initRenderers() {
    // WebGL renderer
    this.renderer = new THREE.WebGLRenderer({
      antialias: true,
      alpha: false,
      powerPreference: 'default'
    });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    this.renderer.setSize(this.container.clientWidth, this.container.clientHeight);
    this.renderer.outputColorSpace = THREE.SRGBColorSpace;
    this.container.appendChild(this.renderer.domElement);

    // CSS2D renderer for labels (layered on top)
    this.labelRenderer = new CSS2DRenderer();
    this.labelRenderer.setSize(this.container.clientWidth, this.container.clientHeight);
    this.labelRenderer.domElement.style.position = 'absolute';
    this.labelRenderer.domElement.style.top = '0';
    this.labelRenderer.domElement.style.left = '0';
    this.labelRenderer.domElement.style.pointerEvents = 'none';
    this.container.appendChild(this.labelRenderer.domElement);
  }

  _initControls() {
    this.controls = new OrbitControls(this.camera, this.renderer.domElement);
    this.controls.enableZoom = true;
    this.controls.enablePan = false; // no panning, just rotate + zoom
    this.controls.enableRotate = true;
    this.controls.enableDamping = true;
    this.controls.dampingFactor = 0.08;
    this.controls.rotateSpeed = 0.5;
    this.controls.zoomSpeed = 0.8;

    // Constrain vertical angle: don't go below the floor or fully top-down
    this.controls.minPolarAngle = Math.PI / 8;   // ~22° from top
    this.controls.maxPolarAngle = Math.PI / 2.2;  // ~82° from top (near horizon)

    // Zoom limits for orthographic camera
    this.controls.minZoom = 0.4;
    this.controls.maxZoom = 2.5;

    // Target = center of the floor
    this.controls.target.set(this.cameraLookAt.x, this.cameraLookAt.y, this.cameraLookAt.z);

    // Once the user interacts, auto-drift is permanently disabled
    // (until explicit reset via R key / reset button)
    this.userHasInteracted = false;
    this.userInteracting = false;

    const onInteractStart = () => {
      this.userHasInteracted = true;
      this.userInteracting = true;
    };
    const onInteractEnd = () => {
      this.userInteracting = false;
    };

    this.controls.addEventListener('start', onInteractStart);
    this.controls.addEventListener('end', onInteractEnd);
  }

  _initEnvironment() {
    this.environment = new TradingFloorEnvironment(this.scene, this.isPortrait);
  }

  _initActivityManager() {
    this.activityManager = new ActivityManager(this);
  }

  _initResize() {
    this._resizeTimeout = null;
    const debouncedResize = () => {
      clearTimeout(this._resizeTimeout);
      this._resizeTimeout = setTimeout(() => this.resize(), 100);
    };

    if (window.ResizeObserver) {
      this._resizeObserver = new ResizeObserver(debouncedResize);
      this._resizeObserver.observe(this.container);
    } else {
      window.addEventListener('resize', debouncedResize);
    }
  }

  _initVisibility() {
    // Pause when tab is not visible
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        this._wasRunning = this.isRunning;
        if (this.isRunning) this.stop();
      } else if (this._wasRunning) {
        this.start();
      }
    });
  }

  resize() {
    const w = this.container.clientWidth;
    const h = this.container.clientHeight;
    if (w === 0 || h === 0) return;
    const aspect = w / h;
    const wasPortrait = this.isPortrait;
    this.isPortrait = aspect < 1;

    // Recalculate frustum
    this.frustumSize = this.isPortrait ? 22 : 14;

    this.camera.left = -this.frustumSize * aspect / 2;
    this.camera.right = this.frustumSize * aspect / 2;
    this.camera.top = this.frustumSize / 2;
    this.camera.bottom = -this.frustumSize / 2;

    // If orientation changed, rebuild environment with new layout + reposition agents
    if (wasPortrait !== this.isPortrait) {
      this._applyCameraMode();
      this._rebuildForOrientation();
    }

    this.camera.updateProjectionMatrix();
    this.renderer.setSize(w, h);
    this.labelRenderer.setSize(w, h);
  }

  async _rebuildForOrientation() {
    // Save current agent zone positions
    const agentZones = new Map();
    for (const [name] of this.characters) {
      const char = this.characters.get(name);
      if (char) {
        const pos = char.getPosition();
        agentZones.set(name, this._findNearestZone(pos));
      }
    }

    // Rebuild environment with new layout
    this.environment.dispose();
    this.environment = new TradingFloorEnvironment(this.scene, this.isPortrait);

    // Apply saved layout for this orientation
    await this.environment.applySavedLayout();

    // Reposition all characters to their zones in the new layout
    let idleIdx = 0;
    for (const [name, char] of this.characters) {
      const zone = agentZones.get(name);
      if (zone) {
        const spotIndex = nameHash(name) % 5;
        const pos = this.environment.getZoneWaitSpot(zone, spotIndex);
        const resolved = resolvePosition(pos.x, pos.z, this.characters, name, this.environment);
        char.setPosition(resolved.x, resolved.z);
        const center = this.environment.getZoneCenter(zone);
        char.faceToward(center.x, center.z);
      } else {
        const pos = this.environment.getIdlePosition(idleIdx++);
        char.setPosition(pos.x, pos.z);
      }
    }
  }

  _findNearestZone(pos) {
    const zones = ['trading-pit', 'signals-desk', 'skills-desk', 'open-center'];
    let nearest = null;
    let nearestDist = Infinity;
    for (const zone of zones) {
      const center = this.environment.getZoneCenter(zone);
      const dx = pos.x - center.x;
      const dz = pos.z - center.z;
      const dist = dx * dx + dz * dz;
      if (dist < nearestDist) {
        nearestDist = dist;
        nearest = zone;
      }
    }
    return nearest;
  }

  // --- Agent management ---

  addAgent(name, options = {}) {
    if (this.characters.has(name)) return this.characters.get(name);

    // Pass V2 flag to character constructor
    if (window.__charVersion === 'v2') {
      options.useGLTF = true;
    }
    const character = new AgentCharacter(name, this.scene, options);
    const idx = this.characters.size;
    const pos = this.environment.getIdlePosition(idx);
    const resolved = resolvePosition(pos.x, pos.z, this.characters, name, this.environment);
    character.setPosition(resolved.x, resolved.z);
    if (this._isDancing) {
      // Party mode — walk new agent to center and dance
      const env = this.environment;
      const center = env.getZoneCenter('open-center');
      const count = this.characters.size + 1;
      const radius = Math.max(1.0, count * 0.3);
      const angle = (count / (count + 1)) * Math.PI * 2 - Math.PI / 2;
      const spot = { x: center.x + Math.cos(angle) * radius, z: center.z + Math.sin(angle) * radius };
      if (!this._partyHomePositions) this._partyHomePositions = new Map();
      this._partyHomePositions.set(name, { x: pos.x, z: pos.z });
      character.walkTo(spot.x, spot.z, () => {
        if (this._musicMode === 'party') {
          character.faceToward(center.x, center.z);
          character.playDance();
        }
      });
    } else {
      character.playIdle();
    }
    this.characters.set(name, character);
    return character;
  }

  removeAgent(name) {
    const character = this.characters.get(name);
    if (character) {
      character.dispose();
      this.characters.delete(name);
    }
  }

  getCharacter(name) {
    return this.characters.get(name);
  }

  // --- Music modes ---
  // 'off'   — no music, normal behavior
  // 'lofi'  — music plays, agents continue normal activities (no dance)
  // 'party' — music plays, all agents walk to open-center and dance

  setMusicMode(mode) {
    const prevMode = this._musicMode || 'off';
    this._musicMode = mode;

    if (mode === 'party') {
      this._isDancing = true;
      if (!this._partyHomePositions) this._partyHomePositions = new Map();

      const env = this.environment;
      const center = env.getZoneCenter('open-center');
      const agents = [...this.characters.entries()];
      const count = agents.length;

      // Generate circle formation spots around center
      const radius = Math.max(1.0, count * 0.3);
      const partySpots = agents.map((_, i) => {
        const angle = (i / count) * Math.PI * 2 - Math.PI / 2;
        return { x: center.x + Math.cos(angle) * radius, z: center.z + Math.sin(angle) * radius };
      });

      agents.forEach(([name, char], i) => {
        if (!this._partyHomePositions.has(name)) {
          this._partyHomePositions.set(name, char.getPosition());
        }
        const spot = partySpots[i];
        const pos = char.getPosition();
        const dx = spot.x - pos.x;
        const dz = spot.z - pos.z;
        const dist = Math.sqrt(dx * dx + dz * dz);

        if (dist < 0.8) {
          // Already close — just dance in place
          char.faceToward(center.x, center.z);
          char.playDance();
        } else {
          // Fast walk to party spot (speed: 0.15 = ~2.5x faster than normal)
          char.walkTo(spot.x, spot.z, () => {
            // Guard: only dance if still in party mode when walk finishes
            if (this._musicMode === 'party') {
              char.faceToward(center.x, center.z);
              char.playDance();
            }
          }, { speed: 0.15 });
        }
      });
    } else if (prevMode === 'party') {
      // Leaving party mode — walk agents back
      this._isDancing = false;
      const homes = this._partyHomePositions;
      for (const [name, char] of this.characters) {
        const home = homes ? homes.get(name) : null;
        char.stopDance();
        if (home) {
          char.walkTo(home.x, home.z, () => { char.playIdle(); });
        } else {
          char.playIdle();
        }
      }
      this._partyHomePositions = null;
    } else {
      // lofi or off — no dance override
      this._isDancing = false;
    }
  }

  // Backward compat
  setDancing(on) {
    this.setMusicMode(on ? 'party' : 'off');
  }

  // --- Render loop ---

  async start() {
    if (this.isRunning) return;
    this.isRunning = true;
    this.clock.start();
    this.lastFrameTime = performance.now();
    this._animate();

    // Apply saved layout positions before placing agents
    await this.environment.applySavedLayout();

    // Load agents and start activity polling
    this._loadAgents();
    this.activityManager.start();

    // Update loading text
    const el = document.getElementById('sim-loading');
    if (el) el.textContent = '';
  }

  stop() {
    this.isRunning = false;
    this.clock.stop();
    this.activityManager.stop();
    if (this._simStatusTimer) {
      clearInterval(this._simStatusTimer);
      this._simStatusTimer = null;
    }
    if (this._animationId) {
      cancelAnimationFrame(this._animationId);
      this._animationId = null;
    }
  }

  _animate() {
    if (!this.isRunning) return;
    this._animationId = requestAnimationFrame(() => this._animate());

    const now = performance.now();
    const elapsed = now - this.lastFrameTime;
    if (elapsed < this.frameInterval) return;
    this.lastFrameTime = now - (elapsed % this.frameInterval);

    const delta = this.clock.getDelta();
    const time = this.clock.getElapsedTime();

    this._updateCamera(time);
    tickAnimations(delta);
    this.activityManager.tick(delta);
    this.environment.tick(time);

    // Tick character internals (cape flutter, etc.)
    // TODO: When V2 GLTF characters are enabled, this also drives AnimationMixer
    for (const [, char] of this.characters) {
      if (char._lobster && char._lobster.tick) {
        char._lobster.tick(delta);
      }
    }

    this.renderer.render(this.scene, this.camera);
    this.labelRenderer.render(this.scene, this.camera);

    // FPS counter
    this.fpsFrames++;
    if (now - this.fpsLastTime >= 1000) {
      const fps = Math.round(this.fpsFrames * 1000 / (now - this.fpsLastTime));
      const el = document.getElementById('sim-fps');
      if (el) el.textContent = `${fps} fps`;
      this.fpsFrames = 0;
      this.fpsLastTime = now;
    }
  }

  _updateCamera(time) {
    if (this.userHasInteracted) {
      // User has interacted — hold their view, just run damping
      this.controls.update();
    } else {
      // No interaction yet — gentle auto-drift for ambient feel
      const angle = this.cameraBaseAngle + Math.sin(time * this.cameraDriftSpeed) * this.cameraDriftAmount;
      const isoDistance = 20;
      const elevation = this.cameraElevation;

      this.camera.position.set(
        isoDistance * Math.cos(angle) * Math.cos(elevation),
        isoDistance * Math.sin(elevation),
        isoDistance * Math.sin(angle) * Math.cos(elevation)
      );
      this.camera.lookAt(0, 0, 0);
      this.camera.updateProjectionMatrix();

      this.controls.target.set(0, 0, 0);
      this.controls.update();
    }
  }

  async _loadAgents() {
    try {
      // Fetch verified agents
      const res = await fetch('/agents/');
      const data = await res.json();
      const agents = (data.agents || data || []).filter(a => a.x402Verified);

      // Normalize store skin IDs (e.g. "skin:shadow") to variant names ("shadow")
      const skinToVariant = (s) => s && s.startsWith('skin:') ? s.slice(5) : s;

      // Check if V2 GLTF characters are enabled — dynamic import to avoid blocking V1
      const useV2 = window.__charVersion === 'v2';
      if (useV2) {
        const el = document.getElementById('sim-loading');
        if (el) el.textContent = 'Loading V2 models…';
        const GLTFLobster = await loadGLTFLobster();

        // Collect unique skin variants needed by agents (default 'red')
        const neededVariants = new Set(['red']); // always preload red as fallback
        for (const agent of agents) {
          if (agent.characterSkin) neededVariants.add(skinToVariant(agent.characterSkin));
        }
        // Preload all variants in parallel
        if (el) el.textContent = `Loading ${neededVariants.size} model variant${neededVariants.size > 1 ? 's' : ''}…`;
        await Promise.all([...neededVariants].map(v => GLTFLobster.preload('/models', v)));
      }

      // Fetch recent activity to determine starting positions + last activity per agent
      let lastZones = {}; // agentName → zone
      let lastEvents = {}; // agentName → event (for bubble text)
      try {
        const actRes = await fetch('/activity/recent?limit=100');
        const activities = await actRes.json();
        for (const act of [...activities].reverse()) {
          if (act.agent && act.zone) {
            lastZones[act.agent] = act.zone;
            lastEvents[act.agent] = act;
          }
          if (act.target && act.zone) {
            lastZones[act.target] = act.zone;
            if (!lastEvents[act.target]) lastEvents[act.target] = act;
          }
        }
      } catch (e) { /* ignore */ }

      // Create agent characters and place at last known zone (or idle)
      for (const agent of agents) {
        const character = this.addAgent(agent.name, {
          variant: skinToVariant(agent.characterSkin) || 'red',
        });
        const lastZone = lastZones[agent.name];
        if (lastZone && character) {
          const env = this.environment;
          const spotIndex = nameHash(agent.name) % 5;
          const pos = env.getZoneWaitSpot(lastZone, spotIndex);
          const resolved = resolvePosition(pos.x, pos.z, this.characters, agent.name, this.environment);
          character.setPosition(resolved.x, resolved.z);
          const center = env.getZoneCenter(lastZone);
          character.faceToward(center.x, center.z);
        }
        const lastEvent = lastEvents[agent.name];
        if (lastEvent && character) {
          const emoji = { trade: '📊', swap: '📊', send: '💸', transfer: '💸', message: '💬', channel_post: '📡', skill_ack: '🔧', erc8004: '🪪', x402: '✅', task_update: '📋' };
          const em = emoji[lastEvent.type] || '⚡';
          const summary = lastEvent.summary || lastEvent.type || 'active';
          const short = summary.length > 24 ? summary.slice(0, 22) + '…' : summary;
          character.setLastActivity(`${em} ${short}`);
        }
      }

      // Add Claude Code — purple cape with Claude spark logo, driven by /sim/status
      const claudeCode = this.addAgent('Claude Code', {
        hue: 25,
        cape: { preset: 'royal', logo: true }
      });
      const ccIdx = this.characters.size - 1;
      const ccPos = this.environment.getIdlePosition(ccIdx);
      claudeCode.setPosition(ccPos.x, ccPos.z);
      if (!this._isDancing) claudeCode.playIdle();

      // Start polling sim status for Claude Code + activity polling for agents
      this._pollSimStatus();
      this._simStatusTimer = setInterval(() => this._pollSimStatus(), 8000);

      const el = document.getElementById('sim-loading');
      if (el) el.textContent = `${agents.length + 1} characters loaded`;
      setTimeout(() => { if (el) el.textContent = ''; }, 3000);
    } catch (err) {
      console.error('Failed to load agents:', err);
    }
  }

  async _pollSimStatus() {
    try {
      const res = await fetch('/sim/status');
      if (!res.ok) return;
      const status = await res.json();
      // status: { zone: 'trading-pit'|'signals-desk'|'skills-desk'|'open-center', activity: 'string', type: 'trading'|'reading'|'signaling'|'talking' }

      const character = this.getCharacter('Claude Code');
      if (!character) return;

      // Don't override animations while dancing
      if (this._isDancing) return;

      const currentZone = this._claudeCodeZone || null;
      const newZone = status.zone || 'open-center';

      if (newZone !== currentZone) {
        this._claudeCodeZone = newZone;

        // Walk to the new zone
        const env = this.environment;
        const target = env.getZoneWaitSpot(newZone, nameHash('Claude Code') % 5);
        const resolved = resolvePosition(target.x, target.z, this.characters, 'Claude Code', this.environment);
        character.stopIdleBubbleCycle();

        if (status.activity) {
          character.showBubble(status.activity, 0);
        }

        character.walkTo(resolved.x, resolved.z, () => {
          const center = env.getZoneCenter(newZone);
          character.faceToward(center.x, center.z);
          const activityType = status.type || 'trading';
          character.playActivity(activityType);
        });
      } else if (status.activity) {
        // Same zone, just update the bubble text
        const lastActivity = character._lastActivityText;
        if (status.activity !== lastActivity) {
          character.showBubble(status.activity, 6);
          character.setLastActivity(status.activity);
        }
      }
    } catch (err) {
      // Silent fail — will retry
    }
  }

  // --- Dev drag-and-drop for signs/kiosks/zones ---
  // Hover: highlight + tooltip ("Hold Shift + drag to move")
  // Shift+click: grab, drag on floor plane, toast coords on release
  // Zone drags also update layout data + walk nearby agents to new positions

  _onDragEnd(canvas) {
    if (!this._dragTarget) return;
    const p = this._dragTarget.position;
    const name = this._dragName;
    const coords = `x=${p.x.toFixed(1)}, z=${p.z.toFixed(1)}`;
    console.log(`[dev-drag] ${name}: ${coords}`);

    // If this is a zone group, find agents BEFORE updating layout, then walk them
    if (this.environment.zoneGroups[name]) {
      const agentsInZone = [];
      for (const [agentName, char] of this.characters) {
        const pos = char.getPosition();
        if (this._findNearestZone(pos) === name) {
          agentsInZone.push({ agentName, char });
        }
      }
      this.environment.updateZonePosition(name, p.x, p.z);
      const env = this.environment;
      const center = env.getZoneCenter(name);
      for (const { agentName, char } of agentsInZone) {
        const spotIndex = nameHash(agentName) % 5;
        const spot = env.getZoneWaitSpot(name, spotIndex);
        const resolved = resolvePosition(spot.x, spot.z, this.characters, agentName, this.environment);
        char.walkTo(resolved.x, resolved.z, () => {
          char.faceToward(center.x, center.z);
          char.playIdle();
        });
      }
    }

    // Persist to server keyed by orientation (admin session cookie sent automatically)
    const orient = this.isPortrait ? 'portrait' : 'landscape';
    fetch('/sim/layout', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ orientation: orient, positions: { [name]: { x: p.x, z: p.z } } })
    }).then(r => {
      if (r.ok) this._showDragToast(`✓ ${name} saved · ${coords}`);
      else this._showDragToast(`⚠ ${name} save failed · ${coords}`);
    }).catch(() => {
      this._showDragToast(`⚠ ${name} save failed · ${coords}`);
    });

    this._dragTarget = null;
    this._dragName = null;
    this.controls.enabled = true;
  }

  _initDevDrag() {
    this._dragRaycaster = new THREE.Raycaster();
    this._dragMouse = new THREE.Vector2();
    this._dragPlane = new THREE.Plane(new THREE.Vector3(0, 1, 0), 0);
    this._dragTarget = null;
    this._dragName = null;
    this._dragOffset = new THREE.Vector3();
    this._dragIntersect = new THREE.Vector3();

    // Hover state
    this._hoverGroup = null;
    this._hoverName = null;
    this._highlightColor = new THREE.Color('#e4e4e7');

    // Tooltip element
    this._dragTooltip = document.createElement('div');
    this._dragTooltip.style.cssText = 'position:fixed;pointer-events:none;background:#27272a;color:#e4e4e7;padding:5px 10px;border-radius:6px;font:12px Inter,system-ui,sans-serif;z-index:9999;opacity:0;transition:opacity 0.15s;white-space:nowrap;border:1px solid #3f3f46;';
    document.body.appendChild(this._dragTooltip);

    const canvas = this.renderer.domElement;

    // Build mesh→group lookup (rebuilt each time draggableGroups could change)
    const getDraggableMeshes = () => {
      const groups = this.environment.draggableGroups;
      const allMeshes = [];
      const meshToGroup = new Map();
      for (const [name, group] of Object.entries(groups)) {
        group.traverse(child => {
          if (child.isMesh) {
            allMeshes.push(child);
            meshToGroup.set(child, { name, group });
          }
        });
      }
      return { allMeshes, meshToGroup };
    };

    // --- Highlight helpers ---
    const setGroupHighlight = (group, on) => {
      group.traverse(child => {
        if (!child.isMesh || !child.material) return;
        const mats = Array.isArray(child.material) ? child.material : [child.material];
        for (const mat of mats) {
          if (!mat.emissive) continue; // MeshBasicMaterial has no emissive
          if (on) {
            mat._origEmissive = mat.emissive.clone();
            mat.emissive.copy(this._highlightColor);
            mat.emissiveIntensity = 0.08;
          } else if (mat._origEmissive) {
            mat.emissive.copy(mat._origEmissive);
            mat.emissiveIntensity = 0;
            delete mat._origEmissive;
          }
        }
      });
    };

    const clearHover = () => {
      if (this._hoverGroup) {
        setGroupHighlight(this._hoverGroup, false);
        this._hoverGroup = null;
        this._hoverName = null;
      }
      this._dragTooltip.style.opacity = '0';
      canvas.style.cursor = '';
    };

    // --- Pointer events ---

    canvas.addEventListener('pointerdown', (e) => {
      if (!e.shiftKey) return;
      this._updateDragMouse(e);
      const { allMeshes, meshToGroup } = getDraggableMeshes();

      this._dragRaycaster.setFromCamera(this._dragMouse, this.camera);
      const hits = this._dragRaycaster.intersectObjects(allMeshes);
      if (hits.length > 0) {
        const info = meshToGroup.get(hits[0].object);
        if (info) {
          this._dragTarget = info.group;
          this._dragName = info.name;
          this._dragRaycaster.ray.intersectPlane(this._dragPlane, this._dragIntersect);
          this._dragOffset.copy(this._dragTarget.position).sub(this._dragIntersect);
          this.controls.enabled = false;
          this._dragTooltip.style.opacity = '0';
          canvas.style.cursor = 'grabbing';
          e.preventDefault();
          e.stopPropagation();
        }
      }
    });

    canvas.addEventListener('pointermove', (e) => {
      // If dragging, move the target
      if (this._dragTarget) {
        this._updateDragMouse(e);
        this._dragRaycaster.setFromCamera(this._dragMouse, this.camera);
        this._dragRaycaster.ray.intersectPlane(this._dragPlane, this._dragIntersect);
        this._dragTarget.position.x = this._dragIntersect.x + this._dragOffset.x;
        this._dragTarget.position.z = this._dragIntersect.z + this._dragOffset.z;
        return;
      }

      // Hover detection
      this._updateDragMouse(e);
      const { allMeshes, meshToGroup } = getDraggableMeshes();
      this._dragRaycaster.setFromCamera(this._dragMouse, this.camera);
      const hits = this._dragRaycaster.intersectObjects(allMeshes);

      if (hits.length > 0) {
        const info = meshToGroup.get(hits[0].object);
        if (info && info.group !== this._hoverGroup) {
          clearHover();
          this._hoverGroup = info.group;
          this._hoverName = info.name;
          setGroupHighlight(info.group, true);
        }
        // Show tooltip near cursor (clamped to viewport)
        if (this._hoverName) {
          this._dragTooltip.textContent = `⇧ Shift + drag`;
          this._dragTooltip.style.opacity = '1';
          // Measure tooltip dimensions after setting text
          const tipRect = this._dragTooltip.getBoundingClientRect();
          const vw = window.innerWidth;
          const vh = window.innerHeight;
          const pad = 8;
          let tx = e.clientX + 14;
          let ty = e.clientY - 30;
          // Clamp right edge
          if (tx + tipRect.width + pad > vw) tx = e.clientX - tipRect.width - 14;
          // Clamp left edge
          if (tx < pad) tx = pad;
          // Clamp top edge
          if (ty < pad) ty = e.clientY + 20;
          // Clamp bottom edge
          if (ty + tipRect.height + pad > vh) ty = vh - tipRect.height - pad;
          this._dragTooltip.style.left = tx + 'px';
          this._dragTooltip.style.top = ty + 'px';
          canvas.style.cursor = 'grab';
        }
      } else {
        clearHover();
      }
    });

    canvas.addEventListener('pointerleave', () => {
      this._onDragEnd(canvas);
      clearHover();
    });

    canvas.addEventListener('pointerup', () => {
      if (!this._dragTarget) return;
      this._onDragEnd(canvas);
      canvas.style.cursor = this._hoverGroup ? 'grab' : '';
    });
  }

  _updateDragMouse(e) {
    const rect = this.renderer.domElement.getBoundingClientRect();
    this._dragMouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
    this._dragMouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
  }

  _showDragToast(msg) {
    let toast = document.getElementById('dev-drag-toast');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'dev-drag-toast';
      toast.style.cssText = 'position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:#27272a;color:#a1a1aa;padding:8px 16px;border-radius:8px;font:13px/1.4 monospace;z-index:9999;opacity:0;transition:opacity 0.3s;pointer-events:none;border:1px solid #3f3f46;';
      document.body.appendChild(toast);
    }
    // Split checkmark portion to color it green
    const isSaved = msg.startsWith('✓');
    if (isSaved) {
      toast.innerHTML = `<span style="color:#22c55e">✓</span> ${msg.slice(2).replace(' · ', ' <span style="color:#52525b">·</span> ')}`;
    } else {
      toast.textContent = msg;
    }
    toast.style.opacity = '1';
    clearTimeout(this._dragToastTimer);
    this._dragToastTimer = setTimeout(() => { toast.style.opacity = '0'; }, 4000);
  }

  dispose() {
    this.stop();
    for (const [, char] of this.characters) {
      char.dispose();
    }
    this.characters.clear();
    this.environment.dispose();
    if (this.controls) this.controls.dispose();
    this.renderer.dispose();
    if (this._resizeObserver) this._resizeObserver.disconnect();
    clearTimeout(this._interactionTimeout);
  }
}

// --- Auto-init on page load ---
const container = document.getElementById('canvas-container');
if (container) {
  const floor = new TradingFloor(container);
  floor.start();
  // Expose for debugging
  window.__tradingFloor = floor;
}
