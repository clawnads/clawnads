// GLTFLobster — Meshy-generated 3D lobster loaded from GLTF
// Drop-in replacement for ChibiLobster with same API surface
// Uses AnimationMixer for walk/run, procedural idle for breathing/sway

import * as THREE from 'three';
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js';
import { DRACOLoader } from 'three/addons/loaders/DRACOLoader.js';
import * as SkeletonUtils from 'three/addons/utils/SkeletonUtils.js';

// Reusable smooth step
function smoothStep(t) {
  return t * t * (3 - 2 * t);
}

// Simple oscillator (same pattern as ChibiLobster)
class Oscillator {
  constructor(target, key, center, amplitude, period, options = {}) {
    this.target = target;
    this.key = key;
    this.center = center;
    this.amplitude = amplitude;
    this.period = period;
    this.phase = options.phase || 0;
    this.elapsed = 0;
  }
  tick(delta) {
    this.elapsed += delta;
    const t = (this.elapsed / this.period + this.phase) * Math.PI * 2;
    const parts = this.key.split('.');
    let obj = this.target;
    for (let i = 0; i < parts.length - 1; i++) obj = obj[parts[i]];
    obj[parts[parts.length - 1]] = this.center + Math.sin(t) * this.amplitude;
  }
}

// Model variant definitions — each variant lists the GLB files to load
const MODEL_VARIANTS = {
  red: {
    files: {
      base: 'lobster-base.glb',
      idle: 'lobster-idle.glb',
      walk: 'lobster-walk.glb',
      run:  'lobster-run.glb',
    },
    extraAnims: {
      'dance-funny2': 'lobster-dance-funny2.glb',
    },
  },
  blue: {
    // Blue model: each GLB has full mesh + one animation
    // Use idle as the base (mesh source), others for anim clips only
    files: {
      base: 'blue-idle.glb',
      idle: 'blue-idle.glb',
      walk: 'blue-walk.glb',
      run:  'blue-run.glb',
    },
    extraAnims: {
      'dance-boom':    'blue-dance-boom.glb',
      'dance-funny1':  'blue-dance-funny1.glb',
      'dance-funny3':  'blue-dance-funny3.glb',
      'dance-hiphop':  'blue-dance-hiphop.glb',
      'dance-hiphop3': 'blue-dance-hiphop3.glb',
    },
  },
  gold: {
    files: {
      base: 'gold-idle.glb',
      idle: 'gold-idle.glb',
      walk: 'gold-walk.glb',
      run:  'gold-run.glb',
    },
    extraAnims: {
      'dance-boom':      'gold-dance-boom.glb',
      'dance-allnight':  'gold-dance-allnight.glb',
      'dance-cardio':    'gold-dance-cardio.glb',
      'dance-cherish':   'gold-dance-cherish.glb',
      'dance-superlove': 'gold-dance-superlove.glb',
      'dance-squat':     'gold-dance-squat.glb',
    },
  },
  purple: {
    files: {
      base: 'purple-idle.glb',
      idle: 'purple-idle.glb',
      walk: 'purple-walk.glb',
      run:  'purple-run.glb',
    },
    extraAnims: {
      'dance-funny1':   'purple-dance-funny1.glb',
      'dance-funny2':   'purple-dance-funny2.glb',
      'dance-funny3':   'purple-dance-funny3.glb',
      'dance-hiphop':   'purple-dance-hiphop.glb',
      'dance-jazz':     'purple-dance-jazz.glb',
      'dance-shakeoff':  'purple-dance-shakeoff.glb',
      'dance-lovepop':   'purple-dance-lovepop.glb',
      'dance-boxing':    'purple-dance-boxing.glb',
      'dance-sweepkick': 'purple-dance-sweepkick.glb',
      'dance-bicepcurl': 'purple-dance-bicepcurl.glb',
    },
  },
  // Shadow: flat black silhouette — used for unrevealed/gated store items
  // Reuses red's GLB mesh, auto-applies shadow texture on creation
  shadow: {
    files: {
      base: 'lobster-base.glb',
      idle: 'lobster-idle.glb',
      walk: 'lobster-walk.glb',
      run:  'lobster-run.glb',
    },
    extraAnims: {},
    shadow: true, // flag: auto-apply shadow material after construction
  },
};

export class GLTFLobster {
  // ========================================================
  // Static: keyed asset cache — one entry per variant
  // ========================================================
  static _caches = {};       // { red: cache, blue: cache }
  static _loadings = {};     // { red: Promise, blue: Promise }

  static async preload(basePath = '/models', variant = 'red') {
    if (GLTFLobster._caches[variant]) return GLTFLobster._caches[variant];
    if (GLTFLobster._loadings[variant]) return GLTFLobster._loadings[variant];

    const def = MODEL_VARIANTS[variant];
    if (!def) throw new Error(`Unknown model variant: ${variant}`);

    const loader = new GLTFLoader();
    const draco = new DRACOLoader();
    draco.setDecoderPath('https://cdn.jsdelivr.net/npm/three@0.170.0/examples/jsm/libs/draco/');
    loader.setDRACOLoader(draco);

    // Core files only: base, idle, walk, run (extra anims lazy-loaded on demand)
    const coreKeys = Object.keys(def.files);
    const corePromises = coreKeys.map(k => loader.loadAsync(`${basePath}/${def.files[k]}`));

    GLTFLobster._loadings[variant] = Promise.all(corePromises).then((coreGltfs) => {
      const coreMap = {};
      coreKeys.forEach((k, i) => { coreMap[k] = coreGltfs[i]; });

      // Measure raw geometry height
      let rawHeight = 0;
      coreMap.base.scene.traverse(node => {
        if (node.isSkinnedMesh || node.isMesh) {
          const geo = node.geometry;
          if (geo) {
            geo.computeBoundingBox();
            const h = geo.boundingBox.max.y - geo.boundingBox.min.y;
            if (h > rawHeight) rawHeight = h;
          }
        }
      });

      // Store extra anim file paths (lazy-loaded) and names
      const extraAnimFiles = {};
      for (const [k, file] of Object.entries(def.extraAnims)) {
        extraAnimFiles[k] = `${basePath}/${file}`;
      }

      const cache = {
        variant,
        baseScene: coreMap.base.scene,
        idleClip: coreMap.idle.animations[0],
        walkClip: coreMap.walk.animations[0],
        runClip:  coreMap.run.animations[0],
        extraAnimFiles,          // { name: path } — lazy-loaded
        extraClips: {},          // { name: AnimationClip } — populated on demand
        rawHeight,
      };
      GLTFLobster._caches[variant] = cache;
      draco.dispose();
      return cache;
    });

    return GLTFLobster._loadings[variant];
  }

  static isReady(variant = 'red') {
    return !!GLTFLobster._caches[variant];
  }

  /** Synchronous create — call only after preload() resolves */
  static createSync(options = {}) {
    const variant = options.variant || 'red';
    if (!GLTFLobster._caches[variant]) throw new Error(`GLTFLobster.preload('${variant}') must complete first`);
    return new GLTFLobster({ ...options, variant });
  }

  // ========================================================
  // Instance
  // ========================================================
  constructor(options = {}) {
    const variant = options.variant || 'red';
    if (!GLTFLobster._caches[variant]) throw new Error(`Call GLTFLobster.preload('${variant}') first`);
    const { baseScene, idleClip, walkClip, runClip, extraClips, rawHeight } = GLTFLobster._caches[variant];
    this._variant = variant;

    // --- Clone scene (independent skeleton per instance) ---
    const cloned = SkeletonUtils.clone(baseScene);

    // Auto-scale from cached geometry measurement (skinned mesh bbox is unreliable)
    const TARGET_HEIGHT = 0.85;
    const MODEL_SCALE = rawHeight > 0 ? TARGET_HEIGHT / rawHeight : 1.0;

    // Wrapper group (identity scale) contains scaled model + world-scale ground ring
    this.group = new THREE.Group();
    this.group.name = 'gltf-lobster';

    this._modelGroup = cloned;
    this._modelGroup.scale.setScalar(MODEL_SCALE);
    this.group.add(this._modelGroup);

    // --- Find bones ---
    this._bones = {};
    this._skinMesh = null;
    this._modelGroup.traverse(node => {
      if (node.isBone) this._bones[node.name] = node;
      if (node.isSkinnedMesh) this._skinMesh = node;
    });

    // --- API surface: bone references ---
    this.head = this._bones['Head'] || this._bones['neck'] || this.group;
    this.body = this._bones['Spine02'] || this._bones['Hips'] || this.group;
    this.leftArmPivot = this._bones['LeftArm'] || this.group;
    this.rightArmPivot = this._bones['RightArm'] || this.group;
    this.leftLegPivot = this._bones['LeftUpLeg'] || this.group;
    this.rightLegPivot = this._bones['RightUpLeg'] || this.group;
    // Extra references for trading floor animations.js compatibility
    this.leftForearmPivot = this._bones['LeftForeArm'] || null;
    this.rightForearmPivot = this._bones['RightForeArm'] || null;
    this.tailPivot = null; // GLTF model has no tail bone
    this.leftAntennaPivot = null;
    this.rightAntennaPivot = null;

    // --- Hue tinting ---
    this._baseHue = options.hue !== undefined ? options.hue : null;
    if (this._baseHue !== null) {
      this._applyHueTint(this._baseHue);
    }

    // --- Clone materials so tinting is per-instance ---
    this._cloneMaterials();

    // --- Shadow variant: auto-apply flat black material ---
    const variantDef = MODEL_VARIANTS[variant];
    if (variantDef && variantDef.shadow) {
      this.setTextureMode('shadow');
    }

    // --- AnimationMixer ---
    this._mixer = new THREE.AnimationMixer(this._modelGroup);
    this._actions = {};

    if (idleClip) {
      this._actions.idle = this._mixer.clipAction(idleClip);
      this._actions.idle.setLoop(THREE.LoopRepeat);
    }
    if (walkClip) {
      this._actions.walk = this._mixer.clipAction(walkClip);
      this._actions.walk.setLoop(THREE.LoopRepeat);
    }
    if (runClip) {
      this._actions.run = this._mixer.clipAction(runClip);
      this._actions.run.setLoop(THREE.LoopRepeat);
      this._actions.run.timeScale = 1.2; // slightly faster feel
    }

    // Extra animations (dance clips, etc.) — lazy-loaded on first play
    const cache = GLTFLobster._caches[variant];
    this._extraAnimFiles = cache.extraAnimFiles || {};
    this._extraClipNames = Object.keys(this._extraAnimFiles);
    this._extraLoading = {}; // track in-flight loads

    // Auto-play idle clip so the model is always animated
    this._activeAction = null;
    this._mixerActive = false;
    if (this._actions.idle) {
      this._actions.idle.play();
      this._activeAction = this._actions.idle;
      this._mixerActive = true;
    }

    // --- State ---
    this.state = 'idle';
    this._target = null;
    this._moveSpeed = 0.6;
    this._turnSpeed = 5.0;
    this._arrivalDist = 0.08;
    this._walkBlend = 0;
    this._blendSpeed = 4.0;
    this._walkElapsed = 0;
    this._tweens = [];

    // --- External animation mode ---
    // When true, idle oscillators are skipped (trading floor drives them)
    this._externalAnimationMode = options.externalAnimation || false;

    // --- Ground ring ---
    this._buildGroundRing();

    // --- Accessory slots ---
    this.slots = new Map();
    this._buildSlots();

    // --- Idle oscillators ---
    this._oscillators = [];
    this._initIdleAnimation();
  }

  // ========================================================
  // Material cloning & hue tinting
  // ========================================================
  _cloneMaterials() {
    this._savedMeshyMaterials = []; // for texture switching
    this._meshNodes = [];

    this._modelGroup.traverse(node => {
      if (node.isMesh && node.material) {
        node.material = node.material.clone();
        // Keep the Meshy baked texture but improve material for Three.js rendering
        node.material.depthWrite = true;
        node.material.transparent = false;
        node.material.alphaTest = 0;
        node.material.opacity = 1.0;
        // Warm boost to enhance Meshy baked textures (all variants)
        node.material.color.setRGB(1.15, 1.05, 1.0);
        node.material.roughness = 0.75;
        node.material.metalness = 0.0;
        if (node.material.map) {
          node.material.map.colorSpace = THREE.SRGBColorSpace;
        }
        // Save reference for texture switching
        this._savedMeshyMaterials.push(node.material.clone());
        this._meshNodes.push(node);
      }
    });
  }

  // Switch between Meshy textured and base clay material
  setTextureMode(mode) {
    if (!this._meshNodes) return;
    for (let i = 0; i < this._meshNodes.length; i++) {
      const node = this._meshNodes[i];
      if (mode === 'clay' || mode === 'sprite-clay') {
        // Clay mode: orange for viewer toggle, neutral gray for Sprite Lab captures
        const clayColor = mode === 'sprite-clay'
          ? new THREE.Color(0.65, 0.65, 0.65)   // Neutral gray — unbiased for AI retexture
          : new THREE.Color().setHSL(6 / 360, 0.78, 0.45);  // Original orange
        const clay = new THREE.MeshStandardMaterial({
          color: clayColor,
          roughness: 0.85,
          metalness: 0.0,
          depthWrite: true,
          transparent: false,
        });
        node.material = clay;
      } else if (mode === 'shadow') {
        // Shadow mode: flat black silhouette — unrevealed/upcoming sprite placeholder
        node.material = new THREE.MeshBasicMaterial({
          color: 0x000000,
          depthWrite: true,
          transparent: false,
        });
      } else {
        // Restore Meshy textured material
        node.material = this._savedMeshyMaterials[i].clone();
      }
    }
  }

  _applyHueTint(hue) {
    // Shift the multiplicative color to tint the texture
    const tintColor = new THREE.Color().setHSL(hue / 360, 0.6, 0.7);
    this._modelGroup.traverse(node => {
      if (node.isMesh && node.material) {
        node.material = node.material.clone();
        node.material.color.copy(tintColor);
      }
    });
    this._tintColor = tintColor;
  }

  // ========================================================
  // Ground ring
  // ========================================================
  _buildGroundRing() {
    // Variant-specific ground ring color (no hue tinting for GLTF models)
    const VARIANT_RING_COLORS = { red: '#c45033', blue: '#2563eb', gold: '#a16207', purple: '#7c3aed', shadow: '#27272a' };
    const color = this._tintColor || new THREE.Color(VARIANT_RING_COLORS[this._variant] || '#c45033');
    const ringMat = new THREE.MeshBasicMaterial({
      color,
      transparent: true,
      opacity: 0.3,
      side: THREE.DoubleSide,
    });
    const ringGeo = new THREE.RingGeometry(0.20, 0.24, 32);
    this.groundRing = new THREE.Mesh(ringGeo, ringMat);
    this.groundRing.rotation.x = -Math.PI / 2;
    this.groundRing.position.y = 0.005;
    this.group.add(this.groundRing); // at wrapper level (world scale)
  }

  // ========================================================
  // Accessory slots (anchored to bones)
  // ========================================================
  _buildSlots() {
    // Slot offsets in BONE local space (tiny because model is scaled up)
    // These will need visual tuning
    const slotDefs = [
      { name: 'head', bone: 'Head', offset: [0, 0.005, 0] },
      { name: 'face', bone: 'headfront', offset: [0, 0, 0] },
      { name: 'back', bone: 'Spine', offset: [0, 0, -0.005] },
      { name: 'left-claw', bone: 'LeftHand', offset: [0, 0, 0] },
      { name: 'right-claw', bone: 'RightHand', offset: [0, 0, 0] },
    ];

    for (const { name, bone, offset } of slotDefs) {
      const boneRef = this._bones[bone];
      // Fallback: attach to model group if bone missing
      const parent = boneRef || this._modelGroup;
      const anchor = new THREE.Group();
      anchor.name = `slot-${name}`;
      anchor.position.set(...offset);
      parent.add(anchor);
      this.slots.set(name, { anchor, equipped: null });
    }
  }

  // ========================================================
  // Idle animation (procedural oscillators on bones)
  // ========================================================
  _initIdleAnimation() {
    // Breathing — whole group bobs
    this._oscillators.push(new Oscillator(this.group, 'position.y', 0, 0.012, 2.2));

    // Arm sway
    if (this._bones['LeftArm']) {
      this._oscillators.push(new Oscillator(this.leftArmPivot, 'rotation.x', 0, 0.04, 3.0, { phase: 0 }));
      this._oscillators.push(new Oscillator(this.rightArmPivot, 'rotation.x', 0, 0.04, 3.0, { phase: 0.5 }));
    }

    // Head tilt
    if (this._bones['Head']) {
      this._oscillators.push(new Oscillator(this.head, 'rotation.z', 0, 0.015, 4.5));
      this._oscillators.push(new Oscillator(this.head, 'rotation.y', 0, 0.02, 5.0, { phase: 0.3 }));
    }
  }

  // ========================================================
  // Walk / Run / Stop
  // ========================================================
  startWalk() {
    if (this.state === 'walk') return;
    this.state = 'walk';
    this._walkElapsed = 0;
    this._playAction('walk');
  }

  startRun() {
    if (this.state === 'run') return;
    this.state = 'run';
    this._walkElapsed = this._walkElapsed || 0;
    this._playAction('run');
  }

  /** Play a named extra animation (dance, emote, etc.) — lazy-loads GLB on first use */
  async playExtra(name) {
    // Already loaded — just play
    if (this._actions[name]) {
      this.state = name;
      this._playAction(name);
      return;
    }

    // Need to lazy-load the clip
    const filePath = this._extraAnimFiles[name];
    if (!filePath) return;

    // Deduplicate concurrent loads for same clip
    if (!this._extraLoading[name]) {
      const loader = new GLTFLoader();
      const draco = new DRACOLoader();
      draco.setDecoderPath('https://cdn.jsdelivr.net/npm/three@0.170.0/examples/jsm/libs/draco/');
      loader.setDRACOLoader(draco);
      this._extraLoading[name] = loader.loadAsync(filePath).then(gltf => {
        draco.dispose();
        const clip = gltf.animations && gltf.animations[0];
        if (clip) {
          this._actions[name] = this._mixer.clipAction(clip);
          this._actions[name].setLoop(THREE.LoopRepeat);
        }
        delete this._extraLoading[name];
        return clip;
      });
    }

    const clip = await this._extraLoading[name];
    if (clip && this._actions[name]) {
      this.state = name;
      this._playAction(name);
    }
  }

  /** Get list of available extra animation names */
  getExtraClipNames() {
    return this._extraClipNames.slice();
  }

  stopWalk() {
    this.state = 'idle';
    this._target = null;
    // Crossfade back to idle clip instead of stopping
    if (this._actions.idle) {
      this._playAction('idle');
    } else {
      this._stopAction();
    }
  }

  _playAction(name) {
    const action = this._actions[name];
    if (!action) return;

    // Crossfade from current action
    if (this._activeAction && this._activeAction !== action) {
      action.reset();
      action.play();
      this._activeAction.crossFadeTo(action, 0.25, true);
    } else {
      action.reset();
      action.play();
    }

    this._activeAction = action;
    this._mixerActive = true;
  }

  _stopAction() {
    if (this._activeAction) {
      this._activeAction.fadeOut(0.3);
      setTimeout(() => {
        if (!this._mixerActive) {
          this._activeAction = null;
        }
      }, 300);
    }
    this._mixerActive = false;
  }

  // ========================================================
  // Motion target system (same as ChibiLobster)
  // ========================================================
  moveTo(target) {
    this._target = target.clone();
    this.state = 'moving';
    this._walkElapsed = this._walkElapsed || 0;
    this._playAction('walk');
  }

  _tickMotion(delta) {
    if (!this._target) return;

    const pos = this.group.position;
    const dx = this._target.x - pos.x;
    const dz = this._target.z - pos.z;
    const dist = Math.sqrt(dx * dx + dz * dz);

    if (dist < this._arrivalDist) {
      this._target = null;
      this.state = 'idle';
      if (this._actions.idle) {
        this._playAction('idle');
      } else {
        this._stopAction();
      }
      return;
    }

    const targetAngle = Math.atan2(dx, dz);
    let angleDiff = targetAngle - this.group.rotation.y;
    while (angleDiff > Math.PI) angleDiff -= Math.PI * 2;
    while (angleDiff < -Math.PI) angleDiff += Math.PI * 2;

    const turnAmount = Math.sign(angleDiff) * Math.min(Math.abs(angleDiff), this._turnSpeed * delta);
    this.group.rotation.y += turnAmount;

    const facingFactor = Math.max(0, 1 - Math.abs(angleDiff) / Math.PI);
    const approachFactor = Math.min(1, dist / 0.3);
    const speed = this._moveSpeed * facingFactor * smoothStep(approachFactor);
    pos.x += Math.sin(this.group.rotation.y) * speed * delta;
    pos.z += Math.cos(this.group.rotation.y) * speed * delta;
  }

  // ========================================================
  // Tick — called every frame
  // ========================================================
  tick(delta) {
    const isWalking = this.state === 'walk' || this.state === 'run' || this.state === 'moving';

    // Update AnimationMixer (for walk/run clips)
    if (this._mixerActive) {
      this._mixer.update(delta);
    }

    // Motion toward target
    if (this.state === 'moving') {
      this._tickMotion(delta);
    }

    // Procedural idle oscillators: only when no mixer clip is active (fallback)
    if (!this._externalAnimationMode && !this._mixerActive) {
      for (const osc of this._oscillators) {
        osc.tick(delta);
      }
    }

    // Tweens
    for (let i = this._tweens.length - 1; i >= 0; i--) {
      this._tweens[i].tick(delta);
      if (this._tweens[i].done) this._tweens.splice(i, 1);
    }

    // Cape flutter (same as ChibiLobster)
    const backSlot = this.slots.get('back');
    if (backSlot && backSlot.equipped && backSlot.equipped.userData.capePivot) {
      const pivot = backSlot.equipped.userData.capePivot;
      this._capeElapsed = (this._capeElapsed || 0) + delta;
      const t = this._capeElapsed;
      const base = 0.40;

      let rotX = base + Math.sin(t * 1.6 + 0.4) * 0.03;
      let rotY = Math.sin(t * 1.9) * 0.04;
      let rotZ = Math.sin(t * 2.3 + 0.7) * 0.015;

      if (isWalking) {
        rotX += Math.sin(t * 5.5) * 0.08;
        rotY += Math.sin(t * 4.2) * 0.06;
        rotZ += Math.sin(t * 6.0 + 1.0) * 0.03;
      }

      pivot.rotation.set(rotX, rotY, rotZ);
    }
  }

  // ========================================================
  // Accessory equip/unequip (same API as ChibiLobster)
  // ========================================================
  equip(slotName, accessoryGroup) {
    const slot = this.slots.get(slotName);
    if (!slot) return false;
    if (slot.equipped) this.unequip(slotName);
    slot.anchor.add(accessoryGroup);
    slot.equipped = accessoryGroup;
    return true;
  }

  unequip(slotName) {
    const slot = this.slots.get(slotName);
    if (!slot || !slot.equipped) return false;
    slot.anchor.remove(slot.equipped);
    slot.equipped = null;
    return true;
  }

  // ========================================================
  // Dispose
  // ========================================================
  dispose() {
    this._mixer.stopAllAction();
    this._mixer.uncacheRoot(this._modelGroup);

    this.group.traverse(child => {
      if (child.geometry) child.geometry.dispose();
      if (child.material) {
        if (child.material.map) child.material.map.dispose();
        child.material.dispose();
      }
    });
  }
}
