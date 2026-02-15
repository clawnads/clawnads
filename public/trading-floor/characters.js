// Clawnads 3D Trading Floor — Agent Character System
// Uses ChibiLobster for the character mesh, adds labels + bubbles + animation interface

import * as THREE from 'three';
import { CSS2DObject } from 'three/addons/renderers/CSS2DRenderer.js';
import { ChibiLobster } from '../character/lobster.js';
import { createIdleAnimation, createWalkAnimation, createActivityAnimation, createDanceAnimation, getDanceStyle, killAll } from './animations.js';

// GLTFLobster is loaded dynamically to avoid blocking V1 mode
let GLTFLobster = null;
export async function loadGLTFLobster() {
  if (!GLTFLobster) {
    const mod = await import('../character/gltf-lobster.js');
    GLTFLobster = mod.GLTFLobster;
  }
  return GLTFLobster;
}
// Synchronous check — only works after loadGLTFLobster + preload have been called
function getGLTFLobster() { return GLTFLobster; }

// Deterministic hue from agent name
function nameToHue(name) {
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = ((hash << 5) - hash) + name.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash) % 360;
}

export class AgentCharacter {
  constructor(name, scene, options = {}) {
    this.name = name;
    this.scene = scene;
    this.state = 'idle'; // idle, walking, activity
    this._tweens = [];

    // Create character — V2 GLTF or V1 Primitives
    const hue = options.hue !== undefined ? options.hue : nameToHue(name);
    const variant = options.variant || 'red';
    this.variant = variant;
    const GLTF = getGLTFLobster();
    this._useGLTF = !!options.useGLTF && GLTF && GLTF.isReady(variant);

    if (this._useGLTF) {
      // GLTF models have baked textures — skip hue tinting (it corrupts the colors).
      // Only pass hue for V1 primitives or explicit override.
      const gltfOpts = { variant, externalAnimation: true };
      if (options.hue !== undefined) gltfOpts.hue = options.hue;
      this._lobster = GLTF.createSync(gltfOpts);
      // GLTF model is already scaled by auto-scale; apply same 0.85 factor for sim
      this._lobster.group.scale.setScalar(0.85);
    } else {
      this._lobster = new ChibiLobster({ hue });
      this._lobster.group.scale.setScalar(0.85);
    }

    this.group = this._lobster.group;
    this.group.name = `agent-${name}`;

    // Expose body parts for animation system compatibility
    // animations.js references: body, head, leftArmPivot, rightArmPivot, leftLegPivot, rightLegPivot
    this.body = this._lobster.body;
    this.head = this._lobster.head;
    this.leftArmPivot = this._lobster.leftArmPivot;
    this.rightArmPivot = this._lobster.rightArmPivot;
    this.leftLegPivot = this._lobster.leftLegPivot;
    this.rightLegPivot = this._lobster.rightLegPivot;

    // Save body rest position for dynamic reset (instead of hardcoded 0.50)
    this._bodyRestY = this.body ? this.body.position.y : 0;

    // GLTF bones: capture actual rest-pose transforms so stopAll() can restore
    // them correctly (GLTF bones have non-zero rest rotations — resetting to 0
    // collapses the skeleton).
    if (this._useGLTF) {
      this._boneRestPoses = {};
      const bones = [
        ['body', this.body],
        ['head', this.head],
        ['leftArmPivot', this.leftArmPivot],
        ['rightArmPivot', this.rightArmPivot],
        ['leftLegPivot', this.leftLegPivot],
        ['rightLegPivot', this.rightLegPivot],
      ];
      // Let mixer play one frame at time 0 to set bind pose, then capture
      if (this._lobster._mixer && this._lobster._actions.idle) {
        this._lobster._mixer.stopAllAction();
        this._lobster._actions.idle.reset().play();
        this._lobster._mixer.update(0);
      }
      for (const [name, bone] of bones) {
        if (bone && bone !== this.group) {
          this._boneRestPoses[name] = {
            rx: bone.rotation.x,
            ry: bone.rotation.y,
            rz: bone.rotation.z,
            px: bone.position.x,
            py: bone.position.y,
            pz: bone.position.z,
          };
        }
      }
    }

    this._buildLabel();

    // Equip accessories (V1 only — V2 GLTF doesn't support V1 capes yet)
    if (!this._useGLTF && options.cape) {
      if (typeof options.cape === 'string') {
        const cape = ChibiLobster.buildCape(options.cape);
        this._lobster.equip('back', cape);
      } else if (options.cape.preset) {
        const cape = ChibiLobster.buildCape(options.cape.preset, undefined, undefined, { logo: !!options.cape.logo });
        this._lobster.equip('back', cape);
      } else {
        this.equipCape(options.cape.color, options.cape.trim);
      }
    }

    scene.add(this.group);
  }

  _buildLabel() {
    const div = document.createElement('div');
    div.className = 'agent-label';
    div.textContent = this.name;

    const label = new CSS2DObject(div);
    label.position.set(0, 1.3, 0); // above lobster head (scaled)
    this.group.add(label);

    // Activity bubble
    this._bubbleWrapper = document.createElement('div');
    this._bubbleWrapper.className = 'bubble-wrapper';
    this._bubbleWrapper.style.display = 'none';

    this._bubbleInner = document.createElement('div');
    this._bubbleInner.className = 'activity-bubble';
    this._bubbleWrapper.appendChild(this._bubbleInner);

    this._bubbleLabel = new CSS2DObject(this._bubbleWrapper);
    this._bubbleLabel.position.set(0, 1.55, 0);
    this.group.add(this._bubbleLabel);
    this._bubbleTimeout = null;
    this._bubbleHideTimeout = null;
    this._lastActivityText = null;
    this._idleBubbleTimer = null;
  }

  // --- Activity bubble (Sims-style: pop in -> bob -> shrink out) ---

  showBubble(text, duration = 4) {
    this._bubbleInner.textContent = text;
    this._bubbleWrapper.style.display = '';
    this._bubbleInner.classList.remove('bubble-enter', 'bubble-exit', 'bubble-bob');
    void this._bubbleInner.offsetWidth;
    this._bubbleInner.classList.add('bubble-enter');

    clearTimeout(this._bubbleTimeout);
    clearTimeout(this._bubbleHideTimeout);
    this._bubbleTimeout = setTimeout(() => {
      this._bubbleInner.classList.remove('bubble-enter');
      this._bubbleInner.classList.add('bubble-bob');
    }, 400);

    if (duration > 0) {
      this._bubbleHideTimeout = setTimeout(() => {
        this._dismissBubble();
      }, duration * 1000);
    }
  }

  _dismissBubble() {
    this._bubbleInner.classList.remove('bubble-enter', 'bubble-bob');
    void this._bubbleInner.offsetWidth;
    this._bubbleInner.classList.add('bubble-exit');
    clearTimeout(this._bubbleTimeout);
    this._bubbleTimeout = setTimeout(() => {
      this._bubbleWrapper.style.display = 'none';
      this._bubbleInner.classList.remove('bubble-exit');
    }, 1300);
  }

  hideBubble() {
    this._bubbleWrapper.style.display = 'none';
    this._bubbleInner.classList.remove('bubble-enter', 'bubble-bob', 'bubble-exit');
    clearTimeout(this._bubbleTimeout);
    clearTimeout(this._bubbleHideTimeout);
  }

  setLastActivity(text) {
    this._lastActivityText = text;
    this._startIdleBubbleCycle();
  }

  _startIdleBubbleCycle() {
    if (this._idleBubbleTimer) clearTimeout(this._idleBubbleTimer);
    if (this._lastActivityText) {
      const initialDelay = Math.random() * 6000 + 1000;
      this._idleBubbleTimer = setTimeout(() => {
        this.showBubble(this._lastActivityText, 6);
        this._scheduleNextIdleBubble();
      }, initialDelay);
    }
  }

  _scheduleNextIdleBubble() {
    if (this._idleBubbleTimer) clearTimeout(this._idleBubbleTimer);
    const interval = 14000 + Math.random() * 11000;
    this._idleBubbleTimer = setTimeout(() => {
      if (this.state === 'idle' && this._lastActivityText) {
        this.showBubble(this._lastActivityText, 6);
      }
      this._scheduleNextIdleBubble();
    }, interval);
  }

  stopIdleBubbleCycle() {
    if (this._idleBubbleTimer) {
      clearTimeout(this._idleBubbleTimer);
      this._idleBubbleTimer = null;
    }
  }

  // --- Positioning ---

  setPosition(x, z) {
    this.group.position.set(x, 0, z);
  }

  getPosition() {
    return { x: this.group.position.x, z: this.group.position.z };
  }

  faceToward(x, z) {
    const dx = x - this.group.position.x;
    const dz = z - this.group.position.z;
    if (Math.abs(dx) > 0.01 || Math.abs(dz) > 0.01) {
      this.group.rotation.y = Math.atan2(dx, dz);
    }
  }

  // --- Animations ---

  playIdle() {
    this.stopAll();
    this.state = 'idle';
    // Resume GLTF mixer idle clip (was paused by stopAll)
    if (this._useGLTF && this._lobster._mixer) {
      this._lobster._mixerActive = true;
      if (this._lobster._actions.idle) {
        this._lobster._actions.idle.reset().play();
      }
    }
    this._tweens = createIdleAnimation(this);
  }

  walkTo(x, z, onComplete, options = {}) {
    this.stopAll();
    this.state = 'walking';
    this.faceToward(x, z);
    this._tweens = createWalkAnimation(this, x, z, () => {
      this.state = 'idle';
      if (onComplete) onComplete();
    }, options);
  }

  playActivity(type) {
    this.stopAll();
    this.state = 'activity';
    this._tweens = createActivityAnimation(this, type);
  }

  playDance(style) {
    this.stopAll();
    this._preDanceState = this.state;
    this.state = 'dancing';

    if (this._useGLTF && this._lobster.getExtraClipNames) {
      // GLTF: use baked dance animations via mixer (much better than procedural)
      const clips = this._lobster.getExtraClipNames().filter(n => n.startsWith('dance-'));
      if (clips.length > 0) {
        // Pick a random dance clip for variety
        const clip = clips[Math.floor(Math.random() * clips.length)];
        this._lobster._mixerActive = true;
        this._lobster.playExtra(clip);
        this._tweens = []; // mixer handles everything
        return;
      }
    }

    // V1 primitives (or GLTF with no dance clips): procedural Oscillator dance
    if (this._lobster) this._lobster.externalAnimation = true;
    const danceStyle = style || getDanceStyle(this.variant);
    this._tweens = createDanceAnimation(this, danceStyle);
  }

  stopDance() {
    if (this.state !== 'dancing') return;
    this.playIdle();
  }

  stopAll() {
    killAll(this._tweens);
    this._tweens = [];
    // Re-enable V1 internal oscillators
    if (this._lobster) this._lobster.externalAnimation = false;
    // Pause GLTF mixer so it doesn't overwrite bone transforms from Oscillators
    if (this._useGLTF && this._lobster._mixer) {
      this._lobster._mixer.stopAllAction();
      this._lobster._mixerActive = false;
    }

    if (this._useGLTF && this._boneRestPoses) {
      // GLTF: restore bones to their actual rest pose (captured at init)
      // Setting bones to 0 would collapse the skeleton — GLTF bones have non-zero rest rotations
      const rest = this._boneRestPoses;
      for (const [name, bone] of [
        ['body', this.body], ['head', this.head],
        ['leftArmPivot', this.leftArmPivot], ['rightArmPivot', this.rightArmPivot],
        ['leftLegPivot', this.leftLegPivot], ['rightLegPivot', this.rightLegPivot],
      ]) {
        const r = rest[name];
        if (r && bone && bone !== this.group) {
          bone.rotation.set(r.rx, r.ry, r.rz);
          bone.position.set(r.px, r.py, r.pz);
        }
      }
      // Reset group Y (dance bob targets group, not bones)
      this.group.position.y = 0;
    } else {
      // V1 primitives: reset pivot rotations to 0 (these are isolated groups, not skeleton bones)
      if (this.leftArmPivot) this.leftArmPivot.rotation.x = 0;
      if (this.rightArmPivot) this.rightArmPivot.rotation.x = 0;
      if (this.leftLegPivot) this.leftLegPivot.rotation.x = 0;
      if (this.rightLegPivot) this.rightLegPivot.rotation.x = 0;
      if (this.head) {
        this.head.rotation.x = 0;
        this.head.rotation.y = 0;
      }
      if (this.body) {
        this.body.position.y = this._bodyRestY;
        this.body.rotation.z = 0;
      }
    }
  }

  // --- Accessories ---

  equipCape(color, trimColor) {
    const cape = ChibiLobster.buildCape(color, trimColor);
    this._lobster.equip('back', cape);
  }

  // --- Cleanup ---

  dispose() {
    this.stopAll();
    this.stopIdleBubbleCycle();
    clearTimeout(this._bubbleTimeout);
    clearTimeout(this._bubbleHideTimeout);
    this.scene.remove(this.group);
    this._lobster.dispose();
  }
}
