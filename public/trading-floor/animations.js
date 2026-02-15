// Clawnads 3D Trading Floor — Animation System
// Pure JS tweens (no GSAP dependency — runs inside the Three.js render loop)

// Simple easing functions
const ease = {
  inOut: t => t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t,
  sine: t => (Math.sin(t * Math.PI * 2) + 1) / 2,
  linear: t => t
};

// Lightweight tween that uses rAF internally
class Tween {
  constructor(target, props, duration, options = {}) {
    this.target = target;
    this.props = props; // { propertyPath: endValue }
    this.duration = duration;
    this.easing = options.easing || ease.inOut;
    this.onComplete = options.onComplete || null;
    this.delay = options.delay || 0;
    this.repeat = options.repeat || 0; // -1 = infinite
    this.yoyo = options.yoyo || false;
    this.killed = false;

    this.startValues = {};
    this.elapsed = -this.delay;
    this.repeatCount = 0;
    this.forward = true;

    // Capture start values
    for (const [key, end] of Object.entries(this.props)) {
      this.startValues[key] = this._getValue(key);
    }

    // Register in global tick pool
    _activeTweens.add(this);
  }

  _getValue(key) {
    const parts = key.split('.');
    let obj = this.target;
    for (const p of parts) obj = obj[p];
    return obj;
  }

  _setValue(key, value) {
    const parts = key.split('.');
    let obj = this.target;
    for (let i = 0; i < parts.length - 1; i++) obj = obj[parts[i]];
    obj[parts[parts.length - 1]] = value;
  }

  tick(delta) {
    if (this.killed) return true;
    this.elapsed += delta;
    if (this.elapsed < 0) return false; // still in delay

    let t = Math.min(this.elapsed / this.duration, 1);
    const easedT = this.easing(this.forward ? t : 1 - t);

    for (const [key, end] of Object.entries(this.props)) {
      const start = this.startValues[key];
      this._setValue(key, start + (end - start) * easedT);
    }

    if (t >= 1) {
      if (this.repeat === -1 || this.repeatCount < this.repeat) {
        this.elapsed = 0;
        this.repeatCount++;
        if (this.yoyo) this.forward = !this.forward;
        return false;
      }
      if (this.onComplete) this.onComplete();
      return true; // done
    }
    return false;
  }

  kill() {
    this.killed = true;
    _activeTweens.delete(this);
  }
}

// Oscillator — continuous sine-wave oscillation on a property
class Oscillator {
  constructor(target, key, center, amplitude, period, options = {}) {
    this.target = target;
    this.key = key;
    this.center = center;
    this.amplitude = amplitude;
    this.period = period;
    this.phase = options.phase || 0;
    this.elapsed = 0;
    this.killed = false;
    _activeTweens.add(this);
  }

  _setValue(key, value) {
    const parts = key.split('.');
    let obj = this.target;
    for (let i = 0; i < parts.length - 1; i++) obj = obj[parts[i]];
    obj[parts[parts.length - 1]] = value;
  }

  tick(delta) {
    if (this.killed) return true;
    this.elapsed += delta;
    const t = (this.elapsed / this.period + this.phase) * Math.PI * 2;
    this._setValue(this.key, this.center + Math.sin(t) * this.amplitude);
    return false;
  }

  kill() {
    this.killed = true;
    _activeTweens.delete(this);
  }
}

// Global tween pool — ticked from main render loop
const _activeTweens = new Set();

export function tickAnimations(delta) {
  for (const tween of _activeTweens) {
    const done = tween.tick(delta);
    if (done) _activeTweens.delete(tween);
  }
}

export function killAll(tweens) {
  if (!tweens) return;
  for (const t of tweens) {
    if (t && t.kill) t.kill();
  }
}

// --- Helper: get rest pose rotation for a GLTF bone (or 0 for V1 primitives) ---
function _restRot(character, boneName, axis) {
  if (!character._useGLTF || !character._boneRestPoses) return 0;
  const r = character._boneRestPoses[boneName];
  if (!r) return 0;
  return r['r' + axis] || 0;
}

// --- Character animation factories ---

export function createIdleAnimation(character) {
  const tweens = [];
  const gltf = !!character._useGLTF;

  // Breathing — body bobs up/down
  // GLTF: bob the wrapper group (not a bone), V1: bob the body mesh
  const idleBobTarget = gltf ? character.group : character.body;
  const bodyRestY = gltf ? 0 : (character._bodyRestY !== undefined ? character._bodyRestY : character.body.position.y);
  tweens.push(new Oscillator(
    idleBobTarget, 'position.y', bodyRestY, gltf ? 0.008 : 0.015, 2.0
  ));

  // Arm sway — GLTF: oscillate around actual rest rotation, not 0
  const laRestX = _restRot(character, 'leftArmPivot', 'x');
  const raRestX = _restRot(character, 'rightArmPivot', 'x');
  tweens.push(new Oscillator(
    character.leftArmPivot, 'rotation.x', laRestX, gltf ? 0.03 : 0.08, 3.0, { phase: 0 }
  ));
  tweens.push(new Oscillator(
    character.rightArmPivot, 'rotation.x', raRestX, gltf ? 0.03 : 0.08, 3.0, { phase: 0.5 }
  ));

  // Occasional head turn (using slow oscillation)
  const headRestY = _restRot(character, 'head', 'y');
  tweens.push(new Oscillator(
    character.head, 'rotation.y', headRestY, gltf ? 0.04 : 0.15, 6.0
  ));

  return tweens;
}

export function createWalkAnimation(character, targetX, targetZ, onComplete, options = {}) {
  const tweens = [];
  const startX = character.group.position.x;
  const startZ = character.group.position.z;
  const dx = targetX - startX;
  const dz = targetZ - startZ;
  const distance = Math.sqrt(dx * dx + dz * dz);
  const speed = options.speed || 0.4; // seconds per unit distance (lower = faster)
  const duration = Math.max(0.4, Math.min(distance * speed, 3.0));

  // Face toward target
  character.faceToward(targetX, targetZ);

  // Position tween
  tweens.push(new Tween(
    character.group.position,
    { x: targetX, z: targetZ },
    duration,
    {
      easing: ease.inOut,
      onComplete: () => {
        // Stop walk cycle, call completion
        killAll(walkCycleTweens);
        if (onComplete) onComplete();
      }
    }
  ));

  // Walk cycle — legs oscillate
  const gltf = !!character._useGLTF;
  const llRestX = _restRot(character, 'leftLegPivot', 'x');
  const rlRestX = _restRot(character, 'rightLegPivot', 'x');
  const laRestX = _restRot(character, 'leftArmPivot', 'x');
  const raRestX = _restRot(character, 'rightArmPivot', 'x');

  const walkCycleTweens = [];
  walkCycleTweens.push(new Oscillator(
    character.leftLegPivot, 'rotation.x', llRestX, gltf ? 0.1 : 0.35, 0.4
  ));
  walkCycleTweens.push(new Oscillator(
    character.rightLegPivot, 'rotation.x', rlRestX, gltf ? 0.1 : 0.35, 0.4, { phase: 0.5 }
  ));

  // Arms swing opposite to legs
  walkCycleTweens.push(new Oscillator(
    character.leftArmPivot, 'rotation.x', laRestX, gltf ? 0.06 : 0.25, 0.4, { phase: 0.5 }
  ));
  walkCycleTweens.push(new Oscillator(
    character.rightArmPivot, 'rotation.x', raRestX, gltf ? 0.06 : 0.25, 0.4
  ));

  // Body bob during walk
  const walkBobTarget = gltf ? character.group : character.body;
  const walkBodyY = gltf ? 0 : (character._bodyRestY !== undefined ? character._bodyRestY : 0.50);
  walkCycleTweens.push(new Oscillator(
    walkBobTarget, 'position.y', walkBodyY, gltf ? 0.015 : 0.025, 0.2
  ));

  tweens.push(...walkCycleTweens);
  return tweens;
}

// Dance style variants — each skin color gets a default style
const DANCE_STYLES = {
  red:    'bounce',   // energetic bounce + arm pump
  blue:   'sway',     // smooth side-to-side sway
  gold:   'stomp',    // heavy stomp + head bob
  purple: 'sway',     // smooth sway for purple
};

export function getDanceStyle(variant) {
  return DANCE_STYLES[variant] || 'bounce';
}

export function createDanceAnimation(character, style) {
  const s = style || 'bounce';
  const tweens = [];
  const gltf = !!character._useGLTF;

  // GLTF skinned meshes need much smaller bone rotations (bones cascade through skeleton).
  // V1 primitives use isolated pivot groups — full rotation range is safe.
  // For body bob: GLTF uses the wrapper group Y, V1 uses the body mesh Y.
  const bobTarget = gltf ? character.group : character.body;
  const bobCenter = gltf ? 0 : (character._bodyRestY !== undefined ? character._bodyRestY : 0.50);

  // GLTF rest-pose centers — oscillate around actual rest rotation, not 0
  const llRestX = _restRot(character, 'leftLegPivot', 'x');
  const rlRestX = _restRot(character, 'rightLegPivot', 'x');
  const laRestX = _restRot(character, 'leftArmPivot', 'x');
  const raRestX = _restRot(character, 'rightArmPivot', 'x');
  const headRestX = _restRot(character, 'head', 'x');
  const headRestY = _restRot(character, 'head', 'y');
  const bodyRestZ = _restRot(character, 'body', 'z');

  if (s === 'bounce') {
    // Energetic bounce — arms up, fast body bob
    tweens.push(new Oscillator(bobTarget, 'position.y', bobCenter, gltf ? 0.04 : 0.07, 0.25));
    tweens.push(new Oscillator(character.leftLegPivot, 'rotation.x', llRestX, gltf ? 0.08 : 0.3, 0.5));
    tweens.push(new Oscillator(character.rightLegPivot, 'rotation.x', rlRestX, gltf ? 0.08 : 0.3, 0.5, { phase: 0.5 }));
    tweens.push(new Oscillator(character.leftArmPivot, 'rotation.x', gltf ? laRestX - 0.15 : -1.0, gltf ? 0.1 : 0.35, 0.5));
    tweens.push(new Oscillator(character.rightArmPivot, 'rotation.x', gltf ? raRestX - 0.15 : -1.0, gltf ? 0.1 : 0.35, 0.5, { phase: 0.5 }));
    tweens.push(new Oscillator(character.head, 'rotation.y', headRestY, gltf ? 0.06 : 0.15, 0.5));
    tweens.push(new Oscillator(character.head, 'rotation.x', headRestX, gltf ? 0.04 : 0.1, 0.25));
  } else if (s === 'sway') {
    // Smooth sway — body rocks side to side, arms flow
    tweens.push(new Oscillator(bobTarget, 'position.y', bobCenter, gltf ? 0.02 : 0.03, 0.5));
    tweens.push(new Oscillator(character.body, 'rotation.z', bodyRestZ, gltf ? 0.04 : 0.1, 1.0));
    tweens.push(new Oscillator(character.leftLegPivot, 'rotation.x', llRestX, gltf ? 0.05 : 0.15, 1.0));
    tweens.push(new Oscillator(character.rightLegPivot, 'rotation.x', rlRestX, gltf ? 0.05 : 0.15, 1.0, { phase: 0.5 }));
    tweens.push(new Oscillator(character.leftArmPivot, 'rotation.x', gltf ? laRestX - 0.08 : -0.5, gltf ? 0.08 : 0.3, 1.0));
    tweens.push(new Oscillator(character.rightArmPivot, 'rotation.x', gltf ? raRestX - 0.08 : -0.5, gltf ? 0.08 : 0.3, 1.0, { phase: 0.5 }));
    tweens.push(new Oscillator(character.head, 'rotation.y', headRestY, gltf ? 0.06 : 0.2, 1.0));
  } else if (s === 'stomp') {
    // Heavy stomp — big leg kicks, head bob, arms swing
    tweens.push(new Oscillator(bobTarget, 'position.y', bobCenter, gltf ? 0.03 : 0.05, 0.3));
    tweens.push(new Oscillator(character.leftLegPivot, 'rotation.x', llRestX, gltf ? 0.12 : 0.45, 0.6));
    tweens.push(new Oscillator(character.rightLegPivot, 'rotation.x', rlRestX, gltf ? 0.12 : 0.45, 0.6, { phase: 0.5 }));
    tweens.push(new Oscillator(character.leftArmPivot, 'rotation.x', gltf ? laRestX - 0.06 : -0.3, gltf ? 0.08 : 0.25, 0.6));
    tweens.push(new Oscillator(character.rightArmPivot, 'rotation.x', gltf ? raRestX - 0.06 : -0.3, gltf ? 0.08 : 0.25, 0.6, { phase: 0.5 }));
    tweens.push(new Oscillator(character.head, 'rotation.x', headRestX, gltf ? 0.05 : 0.15, 0.3));
    tweens.push(new Oscillator(character.head, 'rotation.y', headRestY, gltf ? 0.04 : 0.1, 0.6));
  }

  return tweens;
}

export function createActivityAnimation(character, type) {
  const tweens = [];
  const gltf = !!character._useGLTF;

  // GLTF rest-pose centers for all activity types
  const laRestX = _restRot(character, 'leftArmPivot', 'x');
  const raRestX = _restRot(character, 'rightArmPivot', 'x');
  const raRestZ = _restRot(character, 'rightArmPivot', 'z');
  const headRestX = _restRot(character, 'head', 'x');
  const headRestY = _restRot(character, 'head', 'y');
  const bodyRestX = _restRot(character, 'body', 'x');

  switch (type) {
    case 'trading':
      // Typing pose — arms forward (offset from rest)
      tweens.push(new Tween(
        character.leftArmPivot.rotation, { x: gltf ? laRestX - 0.12 : -0.7 }, 0.3
      ));
      tweens.push(new Tween(
        character.rightArmPivot.rotation, { x: gltf ? raRestX - 0.12 : -0.7 }, 0.3
      ));
      // Subtle typing oscillation on arms
      tweens.push(new Oscillator(
        character.leftArmPivot, 'rotation.x', gltf ? laRestX - 0.12 : -0.7, gltf ? 0.03 : 0.08, 0.3, { phase: 0 }
      ));
      tweens.push(new Oscillator(
        character.rightArmPivot, 'rotation.x', gltf ? raRestX - 0.12 : -0.7, gltf ? 0.03 : 0.08, 0.3, { phase: 0.5 }
      ));
      // Slight lean forward
      tweens.push(new Tween(
        character.body.rotation, { x: gltf ? bodyRestX - 0.03 : -0.1 }, 0.4
      ));
      break;

    case 'signaling':
      // One arm raised
      tweens.push(new Tween(
        character.rightArmPivot.rotation, { x: gltf ? raRestX - 0.2 : -1.2 }, 0.4
      ));
      // Subtle wave
      tweens.push(new Oscillator(
        character.rightArmPivot, 'rotation.z', raRestZ, gltf ? 0.04 : 0.15, 0.8
      ));
      // Other arm at side
      tweens.push(new Oscillator(
        character.leftArmPivot, 'rotation.x', laRestX, gltf ? 0.02 : 0.05, 2.0
      ));
      break;

    case 'reading':
      // Head tilted down
      tweens.push(new Tween(
        character.head.rotation, { x: gltf ? headRestX - 0.06 : -0.25 }, 0.3
      ));
      // Arms at sides, very subtle sway
      tweens.push(new Oscillator(
        character.leftArmPivot, 'rotation.x', laRestX, gltf ? 0.015 : 0.03, 3.0
      ));
      tweens.push(new Oscillator(
        character.rightArmPivot, 'rotation.x', raRestX, gltf ? 0.015 : 0.03, 3.0, { phase: 0.5 }
      ));
      break;

    case 'talking':
      // Head bobs (like nodding in conversation)
      tweens.push(new Oscillator(
        character.head, 'rotation.x', headRestX, gltf ? 0.03 : 0.08, 0.8
      ));
      tweens.push(new Oscillator(
        character.head, 'rotation.y', headRestY, gltf ? 0.04 : 0.1, 1.2
      ));
      // Gentle arm gestures
      tweens.push(new Oscillator(
        character.rightArmPivot, 'rotation.x', gltf ? raRestX - 0.06 : -0.3, gltf ? 0.04 : 0.15, 1.0
      ));
      tweens.push(new Oscillator(
        character.leftArmPivot, 'rotation.x', laRestX, gltf ? 0.03 : 0.1, 1.5
      ));
      break;

    default:
      // Fallback to idle-like
      return createIdleAnimation(character);
  }

  // Always add breathing
  const actBobTarget = gltf ? character.group : character.body;
  const activityBodyY = gltf ? 0 : (character._bodyRestY !== undefined ? character._bodyRestY : 0.50);
  tweens.push(new Oscillator(
    actBobTarget, 'position.y', activityBodyY, gltf ? 0.006 : 0.01, 2.0
  ));

  return tweens;
}
