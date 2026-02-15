// Clawnads 3D Trading Floor — Environment
// Floor, zone outlines, props, signage, ticker

import * as THREE from 'three';
import { CSS2DObject } from 'three/addons/renderers/CSS2DRenderer.js';
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js';
import { DRACOLoader } from 'three/addons/loaders/DRACOLoader.js';

// --- Layout definitions: landscape (triangle) vs portrait (stacked vertical) ---

const LAYOUTS = {
  landscape: {
    zones: {
      'trading-pit':  { x: 0,    z: 3,  width: 7, depth: 4, label: 'Trading Pit' },
      'signals-desk': { x: -4.5, z: -3, width: 4, depth: 3, label: 'Signals Desk' },
      'skills-desk':  { x: 4.5,  z: -3, width: 4, depth: 3, label: 'Skills Desk' },
      'open-center':  { x: 0,    z: 0,  width: 0, depth: 0, label: null }
    },
    waitSpots: {
      // Agents stand in front of the curved desk (positive z, facing back toward monitors)
      'trading-pit':  [{ x: -1.5, z: 4.8 }, { x: 0, z: 5.2 }, { x: 1.5, z: 4.8 }, { x: -2.5, z: 4.2 }, { x: 2.5, z: 4.2 }],
      // Agents stand in front of the desk (positive z side, facing the screen)
      'signals-desk': [{ x: -5.2, z: -1.8 }, { x: -4.5, z: -1.6 }, { x: -3.8, z: -1.8 }, { x: -5.5, z: -2.4 }, { x: -3.5, z: -2.4 }],
      'skills-desk':  [{ x: 5.2, z: -1.8 }, { x: 4.5, z: -1.6 }, { x: 3.8, z: -1.8 }, { x: 5.5, z: -2.4 }, { x: 3.5, z: -2.4 }],
      'open-center':  [{ x: -0.8, z: 0 }, { x: 0.8, z: 0 }, { x: 0, z: -0.8 }, { x: 0, z: 0.8 }]
    },
    idle: [
      { x: -7, z: -5 }, { x: -5, z: -6 }, { x: -3, z: -6.5 },
      { x: 0, z: -6 }, { x: 3, z: -6.5 }, { x: 5, z: -6 },
      { x: 7, z: -5 }, { x: 8, z: -2 }, { x: 8, z: 1 },
      { x: 7, z: 4 }, { x: -7, z: 4 }, { x: -8, z: 1 },
      { x: -8, z: -2 }, { x: 6, z: 6 }, { x: -6, z: 6 },
      { x: -3, z: 7 }, { x: 3, z: 7 }, { x: 0, z: 7.5 },
      { x: -9, z: 3 }, { x: 9, z: 3 }
    ],
    floor: { width: 24, height: 18 }
  },
  portrait: {
    zones: {
      'trading-pit':  { x: 0,    z: -6,  width: 5, depth: 3.5, label: 'Trading Pit' },
      'open-center':  { x: 0,    z: 0,   width: 0, depth: 0,   label: null },
      'signals-desk': { x: -2.8, z: 6,   width: 3.5, depth: 3, label: 'Signals' },
      'skills-desk':  { x: 2.8,  z: 6,   width: 3.5, depth: 3, label: 'Skills' },
    },
    waitSpots: {
      'trading-pit':  [{ x: -1.5, z: -4.2 }, { x: 0, z: -3.8 }, { x: 1.5, z: -4.2 }, { x: -2.5, z: -5 }, { x: 2.5, z: -5 }],
      'signals-desk': [{ x: -3.5, z: 4.8 }, { x: -2.8, z: 4.6 }, { x: -2.1, z: 4.8 }, { x: -3.8, z: 5.5 }, { x: -1.8, z: 5.5 }],
      'skills-desk':  [{ x: 3.5, z: 4.8 }, { x: 2.8, z: 4.6 }, { x: 2.1, z: 4.8 }, { x: 3.8, z: 5.5 }, { x: 1.8, z: 5.5 }],
      'open-center':  [{ x: -0.8, z: 0 }, { x: 0.8, z: 0 }, { x: 0, z: -0.8 }, { x: 0, z: 0.8 }]
    },
    idle: [
      { x: -4, z: -9 }, { x: 0, z: -9.5 }, { x: 4, z: -9 },
      { x: -5, z: -3 }, { x: 5, z: -3 },
      { x: -5, z: 3 }, { x: 5, z: 3 },
      { x: -4, z: 9 }, { x: 0, z: 9.5 }, { x: 4, z: 9 },
      { x: -5.5, z: 0 }, { x: 5.5, z: 0 },
      { x: -3, z: -4 }, { x: 3, z: -4 },
      { x: -3, z: 9 }, { x: 3, z: 9 }
    ],
    floor: { width: 14, height: 24 }
  }
};

function getLayout(portrait) {
  return portrait ? LAYOUTS.portrait : LAYOUTS.landscape;
}

export class TradingFloorEnvironment {
  constructor(scene, portrait = false) {
    this.scene = scene;
    this.portrait = portrait;
    this.layout = getLayout(portrait);
    this.tickerOffset = 0;
    this.tickerCanvas = null;
    this.tickerCtx = null;
    this.tickerTexture = null;
    this.tickerText = 'CLAWNADS  ///  MON  ///  USDC  ///  WETH  ///  WBTC  ///  ';
    this.monitorCanvases = [];
    this.monitorTextures = [];
    this.frameCount = 0;
    this._sceneObjects = []; // track all added objects for cleanup
    this.draggableGroups = {}; // name → THREE.Group, for dev drag-and-drop

    this.zoneGroups = {}; // id → THREE.Group

    this._buildFloor();
    this._buildZones();
    this._buildSignage();
    this._buildPriceKiosk();
    this._buildColonnade();
    this._buildBronzeStatue();
  }

  // --- Zone position accessors (use layout data) ---

  getZoneCenter(zone) {
    const z = this.layout.zones[zone];
    return z ? { x: z.x, z: z.z } : { x: 0, z: 0 };
  }

  getZoneWaitSpot(zone, index) {
    const spots = this.layout.waitSpots[zone] || this.layout.waitSpots['open-center'];
    return spots[index % spots.length];
  }

  getIdlePosition(agentIndex) {
    const idle = this.layout.idle;
    return idle[agentIndex % idle.length];
  }

  // Load saved layout from server and apply to groups + layout data
  async applySavedLayout() {
    try {
      const res = await fetch('/sim/layout');
      if (!res.ok) return;
      const saved = await res.json();
      // Layout is keyed by orientation (landscape/portrait)
      const orient = this.portrait ? 'portrait' : 'landscape';
      const positions = saved[orient];
      if (!positions) return;
      for (const [name, pos] of Object.entries(positions)) {
        const group = this.draggableGroups[name];
        if (group) {
          group.position.x = pos.x;
          group.position.z = pos.z;
        }
        // Also update layout data for zones so wait spots + centers stay in sync
        if (this.zoneGroups[name]) {
          this.updateZonePosition(name, pos.x, pos.z);
        }
      }
    } catch (e) { /* silent — use defaults */ }
  }

  // Update layout data when a zone group is dragged to a new position
  updateZonePosition(zoneId, newX, newZ) {
    const zone = this.layout.zones[zoneId];
    if (!zone) return;
    const dx = newX - zone.x;
    const dz = newZ - zone.z;
    zone.x = newX;
    zone.z = newZ;
    // Shift all wait spots by the same delta
    const spots = this.layout.waitSpots[zoneId];
    if (spots) {
      for (const s of spots) {
        s.x += dx;
        s.z += dz;
      }
    }
  }

  // --- Floor ---

  _addToScene(obj) {
    this.scene.add(obj);
    this._sceneObjects.push(obj);
  }

  _buildFloor() {
    // Solid ground plane — huge, matches scene bg exactly
    const groundSize = 1000;
    const solidGround = new THREE.Mesh(
      new THREE.PlaneGeometry(groundSize, groundSize),
      new THREE.MeshBasicMaterial({ color: new THREE.Color('#09090b') })
    );
    solidGround.rotation.x = -Math.PI / 2;
    solidGround.position.y = -0.01;
    this._addToScene(solidGround);

    // Grid overlay — axis-aligned to match zone outlines
    const gridSize = 200;
    const cellSize = 2; // 2-unit cells align with zone edges
    const divisions = gridSize / cellSize;
    const grid = new THREE.GridHelper(gridSize, divisions, 0x1a1a1f, 0x1a1a1f);
    grid.material.transparent = true;
    grid.material.opacity = 0.4;
    grid.position.y = 0;
    this._addToScene(grid);
  }

  // --- Zones (outline + label + props in draggable groups) ---

  _buildZones() {
    for (const [id, zone] of Object.entries(this.layout.zones)) {
      if (id === 'open-center') continue;

      const group = new THREE.Group();
      group.position.set(zone.x, 0, zone.z);
      group.name = `zone-${id}`;

      // Outline
      const outline = this._createRectOutline(zone.width, zone.depth, '#22c55e', 0.6);
      outline.position.y = 0.01;
      group.add(outline);

      // Glow outline
      const glow = this._createRectOutline(zone.width + 0.3, zone.depth + 0.3, '#22c55e', 0.12);
      glow.position.y = 0.008;
      group.add(glow);

      // Glow plane (also serves as hit target for drag raycasting)
      const glowPlane = new THREE.Mesh(
        new THREE.PlaneGeometry(zone.width, zone.depth),
        new THREE.MeshBasicMaterial({ color: '#22c55e', transparent: true, opacity: 0.02 })
      );
      glowPlane.rotation.x = -Math.PI / 2;
      glowPlane.position.y = 0.006;
      group.add(glowPlane);

      // Label
      if (zone.label) {
        const div = document.createElement('div');
        div.className = 'zone-label';
        div.textContent = zone.label;
        const label = new CSS2DObject(div);
        label.position.set(0, 2.4, 0);
        group.add(label);
      }

      // Zone-specific props (all positioned relative to 0,0,0 within the group)
      if (id === 'trading-pit') this._addTradingPitProps(group);
      if (id === 'signals-desk') this._addSignalsDeskProps(group);
      if (id === 'skills-desk') this._addSkillsDeskProps(group);

      this._addToScene(group);
      this.zoneGroups[id] = group;
      this.draggableGroups[id] = group;
    }
  }

  _createRectOutline(width, depth, color, opacity) {
    const hw = width / 2;
    const hd = depth / 2;
    const points = [
      new THREE.Vector3(-hw, 0, -hd),
      new THREE.Vector3(hw, 0, -hd),
      new THREE.Vector3(hw, 0, hd),
      new THREE.Vector3(-hw, 0, hd),
      new THREE.Vector3(-hw, 0, -hd)
    ];
    const geometry = new THREE.BufferGeometry().setFromPoints(points);
    const material = new THREE.LineBasicMaterial({ color, transparent: true, opacity });
    return new THREE.Line(geometry, material);
  }

  // --- Trading Pit props (relative to group origin) ---

  _addTradingPitProps(group) {
    const deskMat = new THREE.MeshLambertMaterial({ color: '#27272a' });
    const darkMat = new THREE.MeshLambertMaterial({ color: '#1c1c1f' });

    // Curved desk
    const deskSegments = 7;
    const deskRadius = 2;
    const deskArcStart = -Math.PI * 0.6;
    const deskArcEnd = Math.PI * 0.6;
    for (let i = 0; i < deskSegments; i++) {
      const t = i / (deskSegments - 1);
      const angle = deskArcStart + t * (deskArcEnd - deskArcStart);
      const seg = new THREE.Mesh(new THREE.BoxGeometry(0.6, 0.4, 0.15), deskMat);
      seg.position.set(
        Math.sin(angle) * deskRadius,
        0.2,
        -0.5 + Math.cos(angle) * deskRadius * 0.5
      );
      seg.rotation.y = -angle;
      group.add(seg);
    }

    // Monitors
    for (let i = -1; i <= 1; i++) {
      const monitorCanvas = document.createElement('canvas');
      monitorCanvas.width = 128;
      monitorCanvas.height = 96;
      this._drawMonitorContent(monitorCanvas.getContext('2d'), i);
      const monitorTex = new THREE.CanvasTexture(monitorCanvas);
      monitorTex.needsUpdate = true;

      const screen = new THREE.Mesh(
        new THREE.BoxGeometry(0.5, 0.35, 0.03),
        [darkMat, darkMat, darkMat, darkMat, new THREE.MeshBasicMaterial({ map: monitorTex }), darkMat]
      );
      screen.position.set(i * 0.8, 0.6, -0.5);
      screen.rotation.x = -0.1;
      group.add(screen);
      this.monitorCanvases.push(monitorCanvas);
      this.monitorTextures.push(monitorTex);
    }

    // Ticker tape
    this.tickerCanvas = document.createElement('canvas');
    this.tickerCanvas.width = 512;
    this.tickerCanvas.height = 32;
    this.tickerCtx = this.tickerCanvas.getContext('2d');
    this._drawTicker();
    this.tickerTexture = new THREE.CanvasTexture(this.tickerCanvas);
    const tickerPlane = new THREE.Mesh(
      new THREE.PlaneGeometry(6, 0.25),
      new THREE.MeshBasicMaterial({ map: this.tickerTexture, transparent: true })
    );
    tickerPlane.position.set(0, 1.8, -1.2);
    tickerPlane.rotation.x = -0.15;
    group.add(tickerPlane);
  }

  _drawMonitorContent(ctx, variant) {
    ctx.fillStyle = '#0a0f0a';
    ctx.fillRect(0, 0, 128, 96);

    // Fake chart lines
    ctx.strokeStyle = '#22c55e';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(4, 70);
    for (let x = 4; x < 124; x += 4) {
      const y = 50 + Math.sin((x + variant * 40) * 0.08) * 20 + Math.random() * 8;
      ctx.lineTo(x, y);
    }
    ctx.stroke();

    // Fake numbers
    ctx.fillStyle = '#22c55e';
    ctx.font = '10px monospace';
    const symbols = ['MON', 'USDC', 'WETH'];
    ctx.fillText(symbols[variant + 1] || 'MON', 4, 14);

    ctx.fillStyle = '#3f3f46';
    ctx.font = '8px monospace';
    ctx.fillText('24h vol', 4, 90);
  }

  // --- Signals Desk props (relative to group origin) ---

  _addSignalsDeskProps(group) {
    const deskMat = new THREE.MeshLambertMaterial({ color: '#27272a' });

    // Desk
    const desk = new THREE.Mesh(new THREE.BoxGeometry(1.8, 0.06, 0.9), deskMat);
    desk.position.set(0, 0.35, 0);
    group.add(desk);

    const legMat = new THREE.MeshLambertMaterial({ color: '#1c1c1f' });
    const legGeo = new THREE.BoxGeometry(0.06, 0.35, 0.06);
    for (const [lx, lz] of [[-0.8, -0.35], [0.8, -0.35], [-0.8, 0.35], [0.8, 0.35]]) {
      const leg = new THREE.Mesh(legGeo, legMat);
      leg.position.set(lx, 0.175, lz);
      group.add(leg);
    }

    const screenCanvas = document.createElement('canvas');
    screenCanvas.width = 160;
    screenCanvas.height = 96;
    const sctx = screenCanvas.getContext('2d');
    sctx.fillStyle = '#0a0a14';
    sctx.fillRect(0, 0, 160, 96);
    sctx.fillStyle = '#22c55e';
    sctx.font = 'bold 14px monospace';
    sctx.fillText('SIGNALS', 40, 30);
    sctx.fillStyle = '#3f3f46';
    sctx.font = '9px monospace';
    sctx.fillText('Channel feed', 40, 50);
    sctx.fillText('live', 40, 65);

    const screenTex = new THREE.CanvasTexture(screenCanvas);
    const screen = new THREE.Mesh(
      new THREE.BoxGeometry(1.4, 0.9, 0.04),
      new THREE.MeshBasicMaterial({ map: screenTex })
    );
    screen.position.set(0, 1.0, -0.6);
    group.add(screen);

    const stand = new THREE.Mesh(
      new THREE.BoxGeometry(0.08, 0.6, 0.08),
      new THREE.MeshLambertMaterial({ color: '#27272a' })
    );
    stand.position.set(0, 0.65, -0.6);
    group.add(stand);

    const antennaPole = new THREE.Mesh(
      new THREE.CylinderGeometry(0.02, 0.02, 0.8),
      new THREE.MeshLambertMaterial({ color: '#52525b' })
    );
    antennaPole.position.set(1.2, 1.0, -0.4);
    group.add(antennaPole);

    const antennaTop = new THREE.Mesh(
      new THREE.SphereGeometry(0.05, 8, 8),
      new THREE.MeshBasicMaterial({ color: '#ef4444' })
    );
    antennaTop.position.set(1.2, 1.42, -0.4);
    group.add(antennaTop);
  }

  // --- Skills Desk props (relative to group origin) ---

  _addSkillsDeskProps(group) {
    const deskMat = new THREE.MeshLambertMaterial({ color: '#27272a' });
    const desk = new THREE.Mesh(new THREE.BoxGeometry(1.5, 0.06, 0.8), deskMat);
    desk.position.set(0, 0.35, 0);
    group.add(desk);

    const legMat = new THREE.MeshLambertMaterial({ color: '#1c1c1f' });
    const legGeo = new THREE.BoxGeometry(0.06, 0.35, 0.06);
    for (const [lx, lz] of [[-0.65, -0.3], [0.65, -0.3], [-0.65, 0.3], [0.65, 0.3]]) {
      const leg = new THREE.Mesh(legGeo, legMat);
      leg.position.set(lx, 0.175, lz);
      group.add(leg);
    }

    const docMat = new THREE.MeshLambertMaterial({ color: '#a1a1aa' });
    for (let i = 0; i < 4; i++) {
      const doc = new THREE.Mesh(
        new THREE.BoxGeometry(0.4, 0.02, 0.5),
        i === 0 ? new THREE.MeshLambertMaterial({ color: '#7c5cff' }) : docMat
      );
      doc.position.set(-0.3, 0.4 + i * 0.025, 0);
      doc.rotation.y = (i - 1.5) * 0.08;
      group.add(doc);
    }

    const gear = new THREE.Mesh(
      new THREE.TorusGeometry(0.12, 0.03, 8, 6),
      new THREE.MeshLambertMaterial({ color: '#52525b' })
    );
    gear.position.set(0.4, 0.45, 0);
    gear.rotation.x = -Math.PI / 2;
    group.add(gear);
  }

  // --- Signage ---

  _buildSignage() {
    // Vertical billboard sign, rotated 90° on Y to face the default camera.
    // Portrait: between trading pit (z=-6) and signals desk (z=6), on the left side
    // Landscape: behind the zones, centered
    const isP = this.portrait;
    const scale = 1;

    // Portrait: left side of scene, between trading pit & signals desk
    // Landscape: centered behind the floor
    const signX = isP ? -5.5 : 0;
    const signZ = isP ? 0 : -7;
    // Rotate on Y to face the camera — portrait camera comes from angle π/5 (~36°)
    // so rotate sign ~90° on Y to face along the Z axis toward the viewer
    const signRotY = isP ? Math.PI / 2 : 0;

    const postMat = new THREE.MeshLambertMaterial({ color: '#27272a' });
    const frameMat = new THREE.MeshLambertMaterial({ color: '#18181b' });

    // Two tall posts
    const postH = 3.5 * scale;
    const postGeo = new THREE.BoxGeometry(0.08, postH, 0.08);
    const panelW = 5 * scale;
    const panelH = 1.56 * scale;
    const postSpacing = panelW / 2 + 0.1;

    // Build sign in a group so we can rotate the whole thing
    const signGroup = new THREE.Group();
    signGroup.position.set(signX, 0, signZ);
    signGroup.rotation.y = signRotY;

    const postL = new THREE.Mesh(postGeo, postMat);
    postL.position.set(-postSpacing, postH / 2, 0);
    signGroup.add(postL);

    const postR = new THREE.Mesh(postGeo, postMat);
    postR.position.set(postSpacing, postH / 2, 0);
    signGroup.add(postR);

    // Horizontal crossbar on top
    const crossbar = new THREE.Mesh(
      new THREE.BoxGeometry(postSpacing * 2 + 0.4, 0.06, 0.06),
      postMat
    );
    crossbar.position.set(0, postH, 0);
    signGroup.add(crossbar);

    // Main sign panel canvas
    const signCanvas = document.createElement('canvas');
    signCanvas.width = 512;
    signCanvas.height = 160;
    const sctx = signCanvas.getContext('2d');

    sctx.fillStyle = '#0d0d0f';
    sctx.fillRect(0, 0, 512, 160);

    sctx.strokeStyle = '#22c55e';
    sctx.lineWidth = 2;
    sctx.strokeRect(1, 1, 510, 158);

    sctx.fillStyle = '#fafafa';
    sctx.font = 'bold 64px Inter, sans-serif';
    sctx.textAlign = 'center';
    sctx.textBaseline = 'middle';
    sctx.fillText('CLAWNADS', 256, 70);

    sctx.fillStyle = '#52525b';
    sctx.font = '500 18px Inter, sans-serif';
    sctx.fillText('agent trading floor', 256, 120);

    sctx.fillStyle = '#22c55e';
    sctx.beginPath();
    sctx.arc(130, 120, 3, 0, Math.PI * 2);
    sctx.arc(382, 120, 3, 0, Math.PI * 2);
    sctx.fill();

    const signTex = new THREE.CanvasTexture(signCanvas);
    const panelY = postH - panelH / 2 - 0.1;

    // Front face
    const signFace = new THREE.Mesh(
      new THREE.PlaneGeometry(panelW, panelH),
      new THREE.MeshBasicMaterial({ map: signTex })
    );
    signFace.position.set(0, panelY, -0.06);
    signGroup.add(signFace);

    // Back face
    const signBack = new THREE.Mesh(
      new THREE.PlaneGeometry(panelW, panelH),
      frameMat
    );
    signBack.position.set(0, panelY, 0.06);
    signBack.rotation.y = Math.PI;
    signGroup.add(signBack);

    // Scrolling version banner strip underneath
    const bannerY = panelY - panelH / 2 - 0.14;
    this.bannerCanvas = document.createElement('canvas');
    this.bannerCanvas.width = 512;
    this.bannerCanvas.height = 32;
    this.bannerCtx = this.bannerCanvas.getContext('2d');
    this.bannerOffset = 0;
    this.bannerText = '  v9.3  ///  CLAWNADS  ///  v9.3  ///  AGENT TRADING FLOOR  ///  ';
    this._drawBanner();

    this.bannerTexture = new THREE.CanvasTexture(this.bannerCanvas);
    const bannerPlane = new THREE.Mesh(
      new THREE.PlaneGeometry(panelW, 0.18 * scale),
      new THREE.MeshBasicMaterial({ map: this.bannerTexture })
    );
    bannerPlane.position.set(0, bannerY, -0.06);
    signGroup.add(bannerPlane);

    this._addToScene(signGroup);
    this.draggableGroups['sign'] = signGroup;
  }

  // --- NYSE-style 4-sided price kiosk ---
  // Wide squat pedestal + wide squat screen box, single BoxGeometry with 6 materials

  _buildPriceKiosk() {
    const isP = this.portrait;
    // Landscape: left of signals desk, above trading pit
    // Portrait: right side, directly opposite the CLAWNADS sign (which is at -5.5, 0)
    const kx = isP ? 5.5 : -8;
    const kz = isP ? 0 : -1;

    const pedestalMat = new THREE.MeshLambertMaterial({ color: '#111113' });
    const frameMat = new THREE.MeshLambertMaterial({ color: '#1c1c1f' });

    const group = new THREE.Group();
    group.position.set(kx, 0, kz);

    // --- Wide squat pedestal ---
    const pedW = 1.6, pedD = 1.6, pedH = 2.0;
    const pedestal = new THREE.Mesh(
      new THREE.BoxGeometry(pedW, pedH, pedD),
      pedestalMat
    );
    pedestal.position.y = pedH / 2;
    group.add(pedestal);

    // Base plate
    const basePlate = new THREE.Mesh(
      new THREE.BoxGeometry(pedW + 0.3, 0.08, pedD + 0.3),
      frameMat
    );
    basePlate.position.y = 0.04;
    group.add(basePlate);

    // --- Wide squat screen box on top (single BoxGeometry, 6 materials) ---
    const screenBoxW = 2.2, screenBoxH = 1.4, screenBoxD = 2.2;
    const screenBoxY = pedH + screenBoxH / 2 + 0.04;

    this.kioskCanvases = [];
    this.kioskTextures = [];

    this.kioskData = { price: 0, volume24h: 0, trades24h: 0, tvl: 0 };
    this._fetchKioskData();

    // Load Monad logo
    this.kioskLogoReady = false;
    this.kioskLogo = new Image();
    this.kioskLogo.crossOrigin = 'anonymous';
    this.kioskLogo.src = '/monad-logomark.svg';
    this.kioskLogo.onload = () => { this.kioskLogoReady = true; };

    // Create 4 canvases for the 4 side faces
    const sideMaterials = [];
    for (let i = 0; i < 4; i++) {
      const canvas = document.createElement('canvas');
      canvas.width = 320;
      canvas.height = 272;
      this._drawKioskFace(canvas.getContext('2d'));
      const tex = new THREE.CanvasTexture(canvas);
      sideMaterials.push(new THREE.MeshBasicMaterial({ map: tex }));
      this.kioskCanvases.push(canvas);
      this.kioskTextures.push(tex);
    }

    // BoxGeometry material order: +X, -X, +Y, -Y, +Z, -Z
    const screenBox = new THREE.Mesh(
      new THREE.BoxGeometry(screenBoxW, screenBoxH, screenBoxD),
      [
        sideMaterials[0],   // +X (right)
        sideMaterials[1],   // -X (left)
        frameMat,           // +Y (top) — dark frame
        frameMat,           // -Y (bottom) — dark frame
        sideMaterials[2],   // +Z (back)
        sideMaterials[3],   // -Z (front)
      ]
    );
    screenBox.position.y = screenBoxY;
    group.add(screenBox);

    // Top cap overhang
    const topCap = new THREE.Mesh(
      new THREE.BoxGeometry(screenBoxW + 0.1, 0.06, screenBoxD + 0.1),
      frameMat
    );
    topCap.position.y = screenBoxY + screenBoxH / 2 + 0.03;
    group.add(topCap);

    // Bottom lip
    const bottomLip = new THREE.Mesh(
      new THREE.BoxGeometry(screenBoxW + 0.1, 0.06, screenBoxD + 0.1),
      frameMat
    );
    bottomLip.position.y = screenBoxY - screenBoxH / 2 - 0.03;
    group.add(bottomLip);

    this._addToScene(group);
    this.draggableGroups['kiosk'] = group;
  }

  _fetchKioskData() {
    fetch('/stats')
      .then(r => r.json())
      .then(data => {
        if (data.success) {
          this.kioskData.price = data.monPriceUSD || 0;
          this.kioskData.volume24h = data.stats?.['24h']?.volumeUSD || 0;
          this.kioskData.trades24h = data.stats?.['24h']?.trades || 0;
          this.kioskData.tvl = data.tvl || 0;
        }
      })
      .catch(() => {});
  }

  _drawKioskFace(ctx) {
    const w = 320, h = 272;
    const d = this.kioskData;
    const purple = '#836EF9';
    const purpleDim = '#6b5acc';

    // Background
    ctx.fillStyle = '#0c0c10';
    ctx.fillRect(0, 0, w, h);

    // Subtle border
    ctx.strokeStyle = purple;
    ctx.lineWidth = 1.5;
    ctx.strokeRect(2, 2, w - 4, h - 4);

    // Top accent bar
    ctx.fillStyle = purple;
    ctx.fillRect(0, 0, w, 3);

    // Monad logo
    if (this.kioskLogoReady) {
      const logoSize = 28;
      ctx.drawImage(this.kioskLogo, w / 2 - logoSize / 2, 18, logoSize, logoSize);
    }

    // $MON symbol
    ctx.fillStyle = '#fafafa';
    ctx.font = 'bold 22px Inter, sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('$MON', w / 2, 66);

    // Price — large
    const priceStr = d.price > 0 ? '$' + d.price.toFixed(4) : '—';
    ctx.fillStyle = purple;
    ctx.font = 'bold 38px monospace';
    ctx.fillText(priceStr, w / 2, 108);

    // Divider
    ctx.fillStyle = '#27272a';
    ctx.fillRect(40, 136, w - 80, 1);

    // Stats row — Volume | Trades | TVL
    const cols = [
      { label: '24H VOL', value: d.volume24h > 0 ? '$' + d.volume24h.toFixed(2) : '—' },
      { label: 'TRADES', value: d.trades24h.toString() },
      { label: 'TVL', value: d.tvl > 0 ? '$' + d.tvl.toFixed(2) : '—' },
    ];

    const colW = (w - 40) / 3;
    const startX = 20;
    for (let i = 0; i < cols.length; i++) {
      const cx = startX + colW * i + colW / 2;

      ctx.fillStyle = '#71717a';
      ctx.font = '11px Inter, sans-serif';
      ctx.fillText(cols[i].label, cx, 162);

      ctx.fillStyle = '#e4e4e7';
      ctx.font = 'bold 16px monospace';
      ctx.fillText(cols[i].value, cx, 184);
    }

    // Divider
    ctx.fillStyle = '#27272a';
    ctx.fillRect(40, 204, w - 80, 1);

    // Bottom branding
    ctx.fillStyle = purpleDim;
    ctx.font = 'bold 11px Inter, sans-serif';
    ctx.fillText('CLAWNADS', w / 2, 228);
    ctx.fillStyle = '#52525b';
    ctx.font = '9px Inter, sans-serif';
    ctx.fillText('agent trading floor', w / 2, 246);
  }

  // --- NYSE-style freestanding colonnade with "CRAWL STREET" ---

  _buildColonnade() {
    const isP = this.portrait;
    const cx = 0;
    const cz = isP ? -10.5 : -6;

    const group = new THREE.Group();
    group.position.set(cx, 0, cz);
    // Scale the whole colonnade down to 55% — build at comfortable sizes, shrink once
    group.scale.setScalar(0.55);

    const stoneMat = new THREE.MeshLambertMaterial({ color: '#d4cfc6' });
    const stoneLight = new THREE.MeshLambertMaterial({ color: '#e8e4dc' });
    const stoneDark = new THREE.MeshLambertMaterial({ color: '#b8b2a6' });
    const accentMat = new THREE.MeshLambertMaterial({ color: '#c9c3b6' });

    // ---- Dimensions (build at natural proportions, group.scale shrinks it) ----
    const numColumns = 6;
    const colSpacing = 1.3;
    const totalWidth = (numColumns - 1) * colSpacing; // 6.5
    const colRadius = 0.18;  // chunky columns
    const colHeight = 3.0;
    const depth = 0.65;      // shared depth for entablature and pediment

    // ---- Stepped base (stylobate) ----
    for (let s = 0; s < 3; s++) {
      const inset = s * 0.12;
      const step = new THREE.Mesh(
        new THREE.BoxGeometry(totalWidth + 1.4 - inset * 2, 0.06, 1.4 - inset * 2),
        s === 0 ? stoneDark : accentMat
      );
      step.position.y = 0.03 + s * 0.06;
      group.add(step);
    }
    const stylobateTop = 0.18;

    // ---- Columns ----
    const colBaseH = 0.12;
    const colCapH = 0.14;
    const shaftH = colHeight - colBaseH - colCapH;
    const startX = -totalWidth / 2;

    for (let i = 0; i < numColumns; i++) {
      const colX = startX + i * colSpacing;

      // Plinth
      const plinth = new THREE.Mesh(
        new THREE.BoxGeometry(colRadius * 3.2, colBaseH, colRadius * 3.2),
        stoneDark
      );
      plinth.position.set(colX, stylobateTop + colBaseH / 2, 0);
      group.add(plinth);

      // Shaft — chunky with slight taper
      const shaft = new THREE.Mesh(
        new THREE.CylinderGeometry(colRadius * 0.92, colRadius, shaftH, 16),
        stoneMat
      );
      shaft.position.set(colX, stylobateTop + colBaseH + shaftH / 2, 0);
      group.add(shaft);

      // Capital — wider block
      const cap = new THREE.Mesh(
        new THREE.BoxGeometry(colRadius * 3.6, colCapH, colRadius * 3.6),
        stoneLight
      );
      cap.position.set(colX, stylobateTop + colBaseH + shaftH + colCapH / 2, 0);
      group.add(cap);
    }

    const colTopY = stylobateTop + colHeight;

    // ---- Entablature ----
    const architraveH = 0.1;
    const friezeH = 0.36;
    const corniceH = 0.08;
    const entW = totalWidth + 1.2;

    // Architrave
    const architrave = new THREE.Mesh(
      new THREE.BoxGeometry(entW, architraveH, depth),
      stoneMat
    );
    architrave.position.y = colTopY + architraveH / 2;
    group.add(architrave);

    // Frieze with "CRAWL STREET" text
    const friezeCanvas = document.createElement('canvas');
    friezeCanvas.width = 1024;
    friezeCanvas.height = 128;
    const fctx = friezeCanvas.getContext('2d');

    fctx.fillStyle = '#d4cfc6';
    fctx.fillRect(0, 0, 1024, 128);
    // Shadow (carved-in)
    fctx.fillStyle = '#8a8478';
    fctx.font = 'bold 68px "Times New Roman", Georgia, serif';
    fctx.textAlign = 'center';
    fctx.textBaseline = 'middle';
    fctx.fillText('CRAWL  STREET', 512, 66);
    // Highlight (emboss)
    fctx.fillStyle = '#ece8e0';
    fctx.fillText('CRAWL  STREET', 511, 64);

    const friezeTex = new THREE.CanvasTexture(friezeCanvas);

    const frieze = new THREE.Mesh(
      new THREE.BoxGeometry(entW, friezeH, depth),
      [
        accentMat,                                         // +X
        accentMat,                                         // -X
        accentMat,                                         // +Y
        accentMat,                                         // -Y
        accentMat,                                         // +Z back
        new THREE.MeshBasicMaterial({ map: friezeTex })    // -Z front
      ]
    );
    frieze.position.y = colTopY + architraveH + friezeH / 2;
    group.add(frieze);

    // Cornice — overhanging ledge
    const cornice = new THREE.Mesh(
      new THREE.BoxGeometry(entW + 0.24, corniceH, depth + 0.16),
      stoneDark
    );
    cornice.position.y = colTopY + architraveH + friezeH + corniceH / 2;
    group.add(cornice);

    const corniceTopY = colTopY + architraveH + friezeH + corniceH;

    // ---- Triangular pediment ----
    const pedH = 0.7;
    const pedW = entW + 0.24;
    const pedD = depth + 0.16;

    // Shape in XY, extruded along Z, then translate geometry to center on Z
    const tri = new THREE.Shape();
    tri.moveTo(-pedW / 2, 0);
    tri.lineTo(pedW / 2, 0);
    tri.lineTo(0, pedH);
    tri.closePath();

    const pedGeo = new THREE.ExtrudeGeometry(tri, { depth: pedD, bevelEnabled: false });
    pedGeo.translate(0, 0, -pedD / 2);

    const pediment = new THREE.Mesh(pedGeo, stoneLight);
    pediment.position.set(0, corniceTopY, 0);
    group.add(pediment);

    // Acroterion at peak
    const peak = new THREE.Mesh(new THREE.SphereGeometry(0.08, 8, 8), accentMat);
    peak.position.set(0, corniceTopY + pedH + 0.08, 0);
    group.add(peak);

    // Corner acroteria
    for (const sx of [-1, 1]) {
      const corner = new THREE.Mesh(new THREE.SphereGeometry(0.06, 8, 8), accentMat);
      corner.position.set(sx * pedW / 2, corniceTopY + 0.06, 0);
      group.add(corner);
    }

    this._addToScene(group);
    this.draggableGroups['colonnade'] = group;
  }

  // Freestanding bronze Molty statue — V2 GLTF model in bucking bull pose
  _buildBronzeStatue() {
    const isP = this.portrait;
    const sx = isP ? 3.5 : 5;
    const sz = isP ? -4 : -4;

    // Create group immediately so draggableGroups is set for collision detection
    const group = new THREE.Group();
    group.position.set(sx, 0, sz);
    this._addToScene(group);
    this.draggableGroups['statue'] = group;

    const bronzeDark = new THREE.MeshStandardMaterial({
      color: '#6B4F10', roughness: 0.4, metalness: 0.8
    });
    const bronze = new THREE.MeshStandardMaterial({
      color: '#8B6914', roughness: 0.35, metalness: 0.85
    });

    // -- Pedestal (built immediately) --
    const pedBase = new THREE.Mesh(new THREE.BoxGeometry(1.4, 0.1, 1.0), bronzeDark);
    pedBase.position.y = 0.05;
    group.add(pedBase);

    const pedMid = new THREE.Mesh(new THREE.BoxGeometry(1.2, 0.5, 0.8), bronzeDark);
    pedMid.position.y = 0.35;
    group.add(pedMid);

    const pedTop = new THREE.Mesh(new THREE.BoxGeometry(1.3, 0.06, 0.9), bronze);
    pedTop.position.y = 0.63;
    group.add(pedTop);

    // Nameplate — bronze embossed like the colonnade frieze
    const plateCanvas = document.createElement('canvas');
    plateCanvas.width = 512;
    plateCanvas.height = 128;
    const pctx = plateCanvas.getContext('2d');
    // Bronze base
    pctx.fillStyle = '#7A5C18';
    pctx.fillRect(0, 0, 512, 128);
    // Subtle border
    pctx.strokeStyle = '#9B7A2F';
    pctx.lineWidth = 3;
    pctx.strokeRect(8, 8, 496, 112);
    // Shadow pass (recessed)
    pctx.fillStyle = '#4A3810';
    pctx.font = 'bold 56px "Times New Roman", Georgia, serif';
    pctx.textAlign = 'center';
    pctx.textBaseline = 'middle';
    pctx.fillText('MOLTY', 257, 67);
    // Highlight pass (raised emboss)
    pctx.fillStyle = '#C4A84E';
    pctx.fillText('MOLTY', 256, 65);
    const plateTex = new THREE.CanvasTexture(plateCanvas);
    const namePlate = new THREE.Mesh(
      new THREE.PlaneGeometry(0.8, 0.2),
      new THREE.MeshBasicMaterial({ map: plateTex })
    );
    namePlate.position.set(0, 0.35, 0.401);
    group.add(namePlate);

    // -- Load V2 GLTF model asynchronously --
    const loader = new GLTFLoader();
    const draco = new DRACOLoader();
    draco.setDecoderPath('https://cdn.jsdelivr.net/npm/three@0.170.0/examples/jsm/libs/draco/');
    loader.setDRACOLoader(draco);

    loader.loadAsync('/models/lobster-base.glb').then(gltf => {
      draco.dispose();

      const model = gltf.scene;

      // Replace all materials with bronze
      model.traverse(node => {
        if (node.isMesh || node.isSkinnedMesh) {
          node.material = bronze.clone();
          node.castShadow = false;
          node.receiveShadow = false;
          if (node.isSkinnedMesh) {
            node.frustumCulled = false;
          }
        }
      });

      // Collect bones
      const bones = {};
      model.traverse(node => {
        if (node.isBone) bones[node.name] = node;
      });

      // Scale: 2× normal agent height
      const box = new THREE.Box3().setFromObject(model);
      const rawH = box.max.y - box.min.y;
      const targetH = 1.7;
      const scale = rawH > 0 ? targetH / rawH : 1.0;

      model.scale.setScalar(scale);
      model.position.y = 0.66;

      // ---- Proud stance: upright, claws raised, tail straight back ----
      // Slight forward lean — heroic, not hunched
      if (bones['Hips']) {
        bones['Hips'].rotation.x = 0.15;
      }

      // Spine straight / slight upward curve
      if (bones['Spine'])   bones['Spine'].rotation.x = -0.05;
      if (bones['Spine01']) bones['Spine01'].rotation.x = -0.05;
      if (bones['Spine02']) bones['Spine02'].rotation.x = -0.1;

      // Head up, looking forward
      if (bones['Head']) bones['Head'].rotation.x = -0.15;

      // Arms raised — claws up like a victory pose
      if (bones['LeftArm']) {
        bones['LeftArm'].rotation.x = -0.6;   // raise up
        bones['LeftArm'].rotation.z = 0.8;    // out to side
      }
      if (bones['RightArm']) {
        bones['RightArm'].rotation.x = -0.6;
        bones['RightArm'].rotation.z = -0.8;
      }
      if (bones['LeftForeArm']) {
        bones['LeftForeArm'].rotation.x = -0.4;
      }
      if (bones['RightForeArm']) {
        bones['RightForeArm'].rotation.x = -0.4;
      }

      // Legs planted — natural standing, slight outward angle
      if (bones['LeftUpLeg']) {
        bones['LeftUpLeg'].rotation.z = -0.1;
      }
      if (bones['RightUpLeg']) {
        bones['RightUpLeg'].rotation.z = 0.1;
      }

      // Force skeleton update
      model.traverse(node => {
        if (node.isBone) node.updateMatrixWorld(true);
        if (node.isSkinnedMesh && node.skeleton) {
          node.skeleton.update();
        }
      });

      group.add(model);
    }).catch(err => {
      console.warn('Bronze statue failed to load:', err);
    });
  }

  _drawBanner() {
    const ctx = this.bannerCtx;
    const w = this.bannerCanvas.width;
    const h = this.bannerCanvas.height;

    ctx.fillStyle = '#111113';
    ctx.fillRect(0, 0, w, h);

    // Top accent line
    ctx.fillStyle = '#22c55e';
    ctx.fillRect(0, 0, w, 1);

    ctx.fillStyle = '#22c55e';
    ctx.font = 'bold 16px monospace';
    ctx.textBaseline = 'middle';

    const text = this.bannerText + this.bannerText;
    const textWidth = ctx.measureText(text).width;
    const x = -this.bannerOffset % (textWidth / 2);
    ctx.fillText(text, x, 18);
  }

  // --- Ticker animation ---

  _drawTicker() {
    const ctx = this.tickerCtx;
    const w = this.tickerCanvas.width;
    const h = this.tickerCanvas.height;

    ctx.fillStyle = '#0a0f0a';
    ctx.fillRect(0, 0, w, h);

    ctx.fillStyle = '#22c55e';
    ctx.font = 'bold 14px monospace';

    // Scrolling text
    const text = this.tickerText + this.tickerText; // double for seamless loop
    const textWidth = ctx.measureText(text).width;
    const x = -this.tickerOffset % (textWidth / 2);

    ctx.fillText(text, x, 22);
  }

  updateTicker(text) {
    if (text) this.tickerText = text;
  }

  tick(time) {
    this.frameCount++;

    // Update ticker every 2 frames
    if (this.tickerCtx && this.frameCount % 2 === 0) {
      this.tickerOffset += 1.5;
      this._drawTicker();
      this.tickerTexture.needsUpdate = true;
    }

    // Update version banner every 2 frames
    if (this.bannerCtx && this.frameCount % 2 === 0) {
      this.bannerOffset += 1;
      this._drawBanner();
      this.bannerTexture.needsUpdate = true;
    }

    // Update monitors every 60 frames (~2 sec at 30fps)
    if (this.frameCount % 60 === 0) {
      this.monitorCanvases.forEach((canvas, i) => {
        const ctx = canvas.getContext('2d');
        this._drawMonitorContent(ctx, i - 1);
        this.monitorTextures[i].needsUpdate = true;
      });
    }

    // Update price kiosk every 90 frames (~3 sec) for canvas redraw,
    // re-fetch data every 900 frames (~30 sec)
    if (this.kioskCanvases && this.frameCount % 900 === 0) {
      this._fetchKioskData();
    }
    if (this.kioskCanvases && this.frameCount % 90 === 0) {
      this.kioskCanvases.forEach((canvas, i) => {
        this._drawKioskFace(canvas.getContext('2d'));
        this.kioskTextures[i].needsUpdate = true;
      });
    }
  }

  dispose() {
    // Remove all tracked scene objects
    for (const obj of this._sceneObjects) {
      // Clean up CSS2DObject DOM elements (they linger in the overlay div after scene.remove)
      if (obj.traverse) {
        obj.traverse(child => {
          if (child.isCSS2DObject && child.element && child.element.parentNode) {
            child.element.parentNode.removeChild(child.element);
          }
          if (child.geometry) child.geometry.dispose();
          if (child.material) {
            if (Array.isArray(child.material)) child.material.forEach(m => m.dispose());
            else child.material.dispose();
          }
        });
      }
      this.scene.remove(obj);
    }
    this._sceneObjects = [];
    this.draggableGroups = {};
    this.zoneGroups = {};
    this.monitorTextures.forEach(t => t.dispose());
    if (this.tickerTexture) this.tickerTexture.dispose();
    if (this.bannerTexture) this.bannerTexture.dispose();
    if (this.kioskTextures) this.kioskTextures.forEach(t => t.dispose());
    this.monitorCanvases = [];
    this.monitorTextures = [];
    this.kioskCanvases = [];
    this.kioskTextures = [];
  }
}
