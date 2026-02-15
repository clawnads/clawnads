// Clawnads Character Viewer — Chibi Lobster (simplified)
// Clean primitive shapes: spheres + capsules only
// Placeholder until proper 3D model is generated
// Built entirely from Three.js primitives — no GLTF

import * as THREE from 'three';

// --- Lightweight animation helpers ---

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

class Tween {
  constructor(target, key, from, to, duration, options = {}) {
    this.target = target;
    this.key = key;
    this.from = from;
    this.to = to;
    this.duration = duration;
    this.elapsed = 0;
    this.ease = options.ease || 'sine';
    this.yoyo = options.yoyo || false;
    this.repeat = options.repeat || 0;
    this._dir = 1;
    this._count = 0;
    this.done = false;
  }
  tick(delta) {
    if (this.done) return;
    this.elapsed += delta;
    let t = Math.min(this.elapsed / this.duration, 1);
    if (this.ease === 'sine') t = 0.5 - 0.5 * Math.cos(t * Math.PI);
    else if (this.ease === 'inOut') t = t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
    if (this._dir === -1) t = 1 - t;
    const val = this.from + (this.to - this.from) * t;
    const parts = this.key.split('.');
    let obj = this.target;
    for (let i = 0; i < parts.length - 1; i++) obj = obj[parts[i]];
    obj[parts[parts.length - 1]] = val;
    if (this.elapsed >= this.duration) {
      if (this.yoyo) {
        this._dir *= -1;
        this.elapsed = 0;
        this._count++;
        if (this.repeat !== -1 && this._count >= this.repeat * 2) this.done = true;
      } else if (this.repeat === -1 || this._count < this.repeat) {
        this.elapsed = 0;
        this._count++;
      } else {
        this.done = true;
      }
    }
  }
}

// Smooth curve from points using CatmullRom
function createTubeFromPoints(points, radius, segments, radialSegs) {
  const curve = new THREE.CatmullRomCurve3(points);
  return new THREE.TubeGeometry(curve, segments, radius, radialSegs, false);
}

// Smooth step for eased walk cycles
function smoothStep(t) {
  return t * t * (3 - 2 * t);
}

// --- ChibiLobster (simplified) ---

export class ChibiLobster {
  constructor(options = {}) {
    this.group = new THREE.Group();
    this.group.name = 'chibi-lobster';
    this.slots = new Map();
    this._oscillators = [];
    this._tweens = [];
    this._walkTweens = [];
    this.state = 'idle'; // 'idle' | 'walk' | 'run' | 'moving'
    this.externalAnimation = false; // when true, skip internal oscillators (dance mode)
    this._walkElapsed = 0;

    // Motion target system
    this._target = null;
    this._moveSpeed = 0.6;
    this._turnSpeed = 5.0;
    this._arrivalDist = 0.08;
    this._walkBlend = 0;
    this._blendSpeed = 4.0;

    // Warm orange-red palette
    const baseHue = options.hue || 10;
    this.colors = {
      shell:      new THREE.Color().setHSL(baseHue / 360, 0.75, 0.45),
      shellLight: new THREE.Color().setHSL(baseHue / 360, 0.70, 0.52),
      shellDark:  new THREE.Color().setHSL(baseHue / 360, 0.80, 0.30),
      belly:      new THREE.Color().setHSL(baseHue / 360, 0.55, 0.56),
    };

    this._mat = {
      shell:      new THREE.MeshStandardMaterial({ color: this.colors.shell, roughness: 0.82, metalness: 0.02 }),
      shellLight: new THREE.MeshStandardMaterial({ color: this.colors.shellLight, roughness: 0.80, metalness: 0.02 }),
      shellDark:  new THREE.MeshStandardMaterial({ color: this.colors.shellDark, roughness: 0.85, metalness: 0.02 }),
      belly:      new THREE.MeshStandardMaterial({ color: this.colors.belly, roughness: 0.78, metalness: 0.0 }),
      eyeBlack:   new THREE.MeshBasicMaterial({ color: '#111111' }),
      ring:       new THREE.MeshBasicMaterial({ color: this.colors.shell, transparent: true, opacity: 0.3, side: THREE.DoubleSide }),
    };

    this._buildHead();
    this._buildEyes();
    this._buildAntennae();
    this._buildBody();
    this._buildArms();
    this._buildLegs();
    this._buildTail();
    this._buildGroundRing();
    this._buildSlots();
    this._initIdleAnimation();
  }

  // =====================================================
  // HEAD — Big round sphere + subtle muzzle bump
  // =====================================================
  _buildHead() {
    const craniumGeo = new THREE.SphereGeometry(0.34, 32, 24);
    this.head = new THREE.Mesh(craniumGeo, this._mat.shell);
    this.head.position.set(0, 0.78, 0);
    this.head.scale.set(1.0, 1.05, 0.92);
    this.group.add(this.head);

    // Muzzle — same material, deeply buried in head (barely visible)
    const muzzleGeo = new THREE.SphereGeometry(0.16, 24, 18);
    const muzzle = new THREE.Mesh(muzzleGeo, this._mat.shell);
    muzzle.position.set(0, 0.70, 0.14);
    muzzle.scale.set(1.2, 0.45, 0.50);
    this.group.add(muzzle);

    // W-mouth — thin dark tube tracing a W on the muzzle surface
    const mouthPts = [
      new THREE.Vector3(-0.10, 0.68, 0.30),
      new THREE.Vector3(-0.05, 0.66, 0.32),
      new THREE.Vector3( 0.00, 0.68, 0.31),
      new THREE.Vector3( 0.05, 0.66, 0.32),
      new THREE.Vector3( 0.10, 0.68, 0.30),
    ];
    const mouthGeo = createTubeFromPoints(mouthPts, 0.008, 16, 6);
    const mouth = new THREE.Mesh(mouthGeo, this._mat.shellDark);
    this.group.add(mouth);
  }

  // =====================================================
  // EYES — Simple black ovals
  // =====================================================
  _buildEyes() {
    for (const side of [-1, 1]) {
      const eyeGeo = new THREE.SphereGeometry(0.045, 16, 12);
      const eye = new THREE.Mesh(eyeGeo, this._mat.eyeBlack);
      eye.position.set(side * 0.115, 0.82, 0.29);
      eye.scale.set(0.8, 1.2, 0.4);
      this.group.add(eye);
    }
  }

  // =====================================================
  // ANTENNAE — Smooth tube curves from forehead, tapering
  // =====================================================
  _buildAntennae() {
    this.leftAntennaPivot = new THREE.Group();
    this.leftAntennaPivot.position.set(-0.18, 0.97, 0.16);
    this.rightAntennaPivot = new THREE.Group();
    this.rightAntennaPivot.position.set(0.18, 0.97, 0.16);

    for (const [pivot, side] of [[this.leftAntennaPivot, -1], [this.rightAntennaPivot, 1]]) {
      const points = [
        new THREE.Vector3(0, 0, 0),
        new THREE.Vector3(side * 0.02, 0.08, 0.10),
        new THREE.Vector3(side * 0.04, 0.20, 0.08),
        new THREE.Vector3(side * 0.05, 0.32, -0.02),
      ];
      const mainGeo = createTubeFromPoints(points, 0.028, 20, 10);
      pivot.add(new THREE.Mesh(mainGeo, this._mat.shell));

      const tipPoints = [
        new THREE.Vector3(side * 0.05, 0.32, -0.02),
        new THREE.Vector3(side * 0.055, 0.40, -0.06),
      ];
      const tipGeo = createTubeFromPoints(tipPoints, 0.015, 10, 8);
      pivot.add(new THREE.Mesh(tipGeo, this._mat.shell));

      const cap = new THREE.Mesh(new THREE.SphereGeometry(0.015, 10, 10), this._mat.shell);
      cap.position.copy(tipPoints[tipPoints.length - 1]);
      pivot.add(cap);

      this.group.add(pivot);
    }
  }

  // =====================================================
  // BODY — 3 stacked plates with dark rims
  // =====================================================
  _buildBody() {
    this.bodySegments = [];
    // 'body' alias for animation compat (trading floor animations reference character.body)
    // Points to the first plate so body.position.y can be animated for breathing

    const plates = [
      { r: 0.24, h: 0.10, y: 0.50 },
      { r: 0.22, h: 0.10, y: 0.38 },
      { r: 0.20, h: 0.08, y: 0.27 },
    ];

    for (let i = 0; i < plates.length; i++) {
      const p = plates[i];
      const plateGeo = new THREE.CapsuleGeometry(p.r, p.h, 8, 16);
      const plateMesh = new THREE.Mesh(plateGeo, this._mat.shell);
      plateMesh.position.set(0, p.y, 0);
      plateMesh.scale.set(1, 1, 0.85);
      this.group.add(plateMesh);
      this.bodySegments.push(plateMesh);
      if (i === 0) this.body = plateMesh; // alias for animation compat

      // Dark rim between plates
      if (i < plates.length - 1) {
        const lipGeo = new THREE.TorusGeometry(p.r - 0.01, 0.015, 6, 20);
        const lip = new THREE.Mesh(lipGeo, this._mat.shellDark);
        lip.position.set(0, p.y - p.h / 2 - 0.02, 0);
        lip.rotation.x = Math.PI / 2;
        lip.scale.set(1, 1, 0.85);
        this.group.add(lip);
      }
    }

    // Belly highlight
    const bellyGeo = new THREE.SphereGeometry(0.14, 14, 12);
    const belly = new THREE.Mesh(bellyGeo, this._mat.shellLight);
    belly.position.set(0, 0.38, 0.14);
    belly.scale.set(0.6, 1.1, 0.30);
    this.group.add(belly);
  }

  // =====================================================
  // ARMS — Simple: shoulder → arm → claw (sphere + 2 capsule pincers)
  // =====================================================
  _buildArms() {
    this.leftArmPivot = new THREE.Group();
    this.leftArmPivot.position.set(-0.26, 0.48, 0.02);
    this.rightArmPivot = new THREE.Group();
    this.rightArmPivot.position.set(0.26, 0.48, 0.02);

    this.leftForearmPivot = null;
    this.rightForearmPivot = null;

    for (const [pivot, side] of [[this.leftArmPivot, -1], [this.rightArmPivot, 1]]) {
      // Shoulder ball
      const shoulderGeo = new THREE.SphereGeometry(0.065, 10, 8);
      const shoulder = new THREE.Mesh(shoulderGeo, this._mat.shell);
      pivot.add(shoulder);

      // Upper arm
      const upperGeo = new THREE.CapsuleGeometry(0.050, 0.10, 6, 8);
      const upper = new THREE.Mesh(upperGeo, this._mat.shell);
      upper.position.set(side * 0.02, -0.09, 0);
      upper.rotation.z = side * 0.15;
      pivot.add(upper);

      // Forearm pivot
      const forearmPivot = new THREE.Group();
      forearmPivot.position.set(side * 0.03, -0.18, 0);
      pivot.add(forearmPivot);

      // Forearm
      const forearmGeo = new THREE.CapsuleGeometry(0.045, 0.06, 6, 8);
      const forearm = new THREE.Mesh(forearmGeo, this._mat.shell);
      forearm.position.set(0, -0.05, 0.01);
      forearmPivot.add(forearm);

      // === CLAW — simple oval ===
      const clawGeo = new THREE.SphereGeometry(0.10, 12, 10);
      const claw = new THREE.Mesh(clawGeo, this._mat.shell);
      claw.position.set(0, -0.12, 0.03);
      claw.scale.set(0.9, 0.7, 1.2); // oval: narrow, flat, long forward
      claw.rotation.x = -0.4;
      forearmPivot.add(claw);

      this.group.add(pivot);

      if (side === -1) {
        this.leftForearmPivot = forearmPivot;
      } else {
        this.rightForearmPivot = forearmPivot;
      }
    }
  }

  // =====================================================
  // LEGS — Simple pegs
  // =====================================================
  _buildLegs() {
    this.leftLegPivot = new THREE.Group();
    this.leftLegPivot.position.set(-0.12, 0.20, 0);
    this.rightLegPivot = new THREE.Group();
    this.rightLegPivot.position.set(0.12, 0.20, 0);

    for (const [pivot] of [[this.leftLegPivot, -1], [this.rightLegPivot, 1]]) {
      const legGeo = new THREE.CapsuleGeometry(0.045, 0.12, 6, 8);
      const leg = new THREE.Mesh(legGeo, this._mat.shell);
      leg.position.y = -0.08;
      pivot.add(leg);

      this.group.add(pivot);
    }
  }

  // =====================================================
  // TAIL — Stem + fan blades (capsules)
  // =====================================================
  _buildTail() {
    this.tailPivot = new THREE.Group();
    this.tailPivot.position.set(0, 0.22, -0.18);

    // Stem
    const stemGeo = new THREE.CapsuleGeometry(0.06, 0.10, 6, 8);
    const stem = new THREE.Mesh(stemGeo, this._mat.shell);
    stem.position.set(0, -0.02, -0.03);
    stem.rotation.x = 0.7;
    stem.scale.set(1.0, 0.6, 1);
    this.tailPivot.add(stem);

    // Fan — 5 flat capsule blades
    const angles = [-0.7, -0.35, 0, 0.35, 0.7];
    const sizes = [0.7, 0.85, 1.0, 0.85, 0.7];
    for (let i = 0; i < angles.length; i++) {
      const s = sizes[i];
      const fanGeo = new THREE.CapsuleGeometry(0.042 * s, 0.12 * s, 5, 6);
      const fan = new THREE.Mesh(fanGeo, i % 2 === 0 ? this._mat.shellDark : this._mat.shell);
      fan.position.set(
        Math.sin(angles[i]) * 0.08,
        -0.10,
        -0.05 - Math.abs(angles[i]) * 0.02
      );
      fan.rotation.x = 0.85;
      fan.rotation.z = angles[i] * 0.35;
      fan.scale.set(1, 0.4, 1.4);
      this.tailPivot.add(fan);
    }

    this.group.add(this.tailPivot);
  }

  // =====================================================
  // Ground ring
  // =====================================================
  _buildGroundRing() {
    const ringGeo = new THREE.RingGeometry(0.20, 0.24, 32);
    this.groundRing = new THREE.Mesh(ringGeo, this._mat.ring);
    this.groundRing.rotation.x = -Math.PI / 2;
    this.groundRing.position.y = 0.005;
    this.group.add(this.groundRing);
  }

  // =====================================================
  // Accessory slots
  // =====================================================
  _buildSlots() {
    const slotDefs = [
      { name: 'head', pos: [0, 1.16, 0], parent: this.group },
      { name: 'face', pos: [0, 0.76, 0.30], parent: this.group },
      { name: 'back', pos: [0, 0.48, -0.18], parent: this.group },
    ];
    if (this.leftForearmPivot) {
      slotDefs.push({ name: 'left-claw', pos: [0, -0.28, 0], parent: this.leftForearmPivot });
      slotDefs.push({ name: 'right-claw', pos: [0, -0.28, 0], parent: this.rightForearmPivot });
    }
    for (const { name, pos, parent } of slotDefs) {
      const anchor = new THREE.Group();
      anchor.name = `slot-${name}`;
      anchor.position.set(...pos);
      parent.add(anchor);
      this.slots.set(name, { anchor, equipped: null });
    }
  }

  // =====================================================
  // IDLE ANIMATION
  // =====================================================
  _initIdleAnimation() {
    this._oscillators = [];

    // Breathing bob
    this._oscillators.push(new Oscillator(this.group, 'position.y', 0, 0.015, 2.2));

    // Antenna sway
    if (this.leftAntennaPivot) {
      this._oscillators.push(new Oscillator(this.leftAntennaPivot, 'rotation.z', 0, 0.06, 2.8, { phase: 0 }));
      this._oscillators.push(new Oscillator(this.rightAntennaPivot, 'rotation.z', 0, 0.06, 2.8, { phase: 0.5 }));
      this._oscillators.push(new Oscillator(this.leftAntennaPivot, 'rotation.x', 0, 0.04, 3.5, { phase: 0.2 }));
      this._oscillators.push(new Oscillator(this.rightAntennaPivot, 'rotation.x', 0, 0.04, 3.5, { phase: 0.7 }));
    }

    // Arms sway
    if (this.leftArmPivot) {
      this._oscillators.push(new Oscillator(this.leftArmPivot, 'rotation.x', 0, 0.05, 3.0, { phase: 0 }));
      this._oscillators.push(new Oscillator(this.rightArmPivot, 'rotation.x', 0, 0.05, 3.0, { phase: 0.5 }));
      this._oscillators.push(new Oscillator(this.leftArmPivot, 'rotation.z', 0, 0.03, 2.5, { phase: 0.3 }));
      this._oscillators.push(new Oscillator(this.rightArmPivot, 'rotation.z', 0, 0.03, 2.5, { phase: 0.8 }));
    }
    if (this.leftForearmPivot) {
      this._oscillators.push(new Oscillator(this.leftForearmPivot, 'rotation.x', 0, 0.04, 3.6, { phase: 0.1 }));
      this._oscillators.push(new Oscillator(this.rightForearmPivot, 'rotation.x', 0, 0.04, 3.6, { phase: 0.6 }));
    }
    if (this.tailPivot) {
      this._oscillators.push(new Oscillator(this.tailPivot, 'rotation.y', 0, 0.05, 3.8));
    }

    // Head tilt
    this._oscillators.push(new Oscillator(this.head, 'rotation.z', 0, 0.02, 4.5));
    this._oscillators.push(new Oscillator(this.head, 'rotation.y', 0, 0.03, 5.0, { phase: 0.3 }));

    // Cape flutter (if equipped on back slot)
    this._capeOscillators = [
      // These get applied in tick() only if a cape is equipped
      { key: 'rotation.y', center: 0, amplitude: 0.04, period: 2.8, phase: 0 },
      { key: 'rotation.x', center: 0.15, amplitude: 0.03, period: 3.2, phase: 0.4 },
    ];
  }

  // =====================================================
  // WALK / RUN
  // =====================================================
  startWalk() {
    if (this.state === 'walk') return;
    this.state = 'walk';
    this._walkElapsed = 0;
  }

  stopWalk() {
    this.state = 'idle';
    this._target = null;
  }

  startRun() {
    if (this.state === 'run') return;
    this.state = 'run';
    this._walkElapsed = this._walkElapsed || 0;
  }

  // --- MOTION TARGET SYSTEM ---
  moveTo(target) {
    this._target = target.clone();
    this.state = 'moving';
    this._walkElapsed = this._walkElapsed || 0;
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

    if (this.groundRing) {
      this.groundRing.position.x = 0;
      this.groundRing.position.z = 0;
    }
  }

  _tickWalkCycle(delta, blend) {
    const isRunning = this.state === 'run';
    this._walkElapsed += delta;
    const t = this._walkElapsed;

    const speed = isRunning ? 9.0 : 5.5;
    const phase = (t * speed) % (Math.PI * 2);

    const legCurve = Math.sin(phase);
    const legCurveOpp = Math.sin(phase + Math.PI);
    const legSwing = (isRunning ? 0.65 : 0.38) * blend;
    const armSwing = (isRunning ? 0.45 : 0.22) * blend;
    const forearmSwing = (isRunning ? 0.35 : 0.18) * blend;

    // Legs
    if (this.leftLegPivot) {
      this.leftLegPivot.rotation.x = legCurve * legSwing;
      this.rightLegPivot.rotation.x = legCurveOpp * legSwing;
    }

    // Arms
    if (this.leftArmPivot) {
      this.leftArmPivot.rotation.x = legCurveOpp * armSwing;
      this.rightArmPivot.rotation.x = legCurve * armSwing;
      if (isRunning) {
        this.leftArmPivot.rotation.z = -0.15 * blend;
        this.rightArmPivot.rotation.z = 0.15 * blend;
      }
    }

    // Forearms
    const forearmPhase = phase - (isRunning ? 0.5 : 0.3);
    if (this.leftForearmPivot) {
      this.leftForearmPivot.rotation.x = Math.sin(forearmPhase + Math.PI) * forearmSwing;
      this.rightForearmPivot.rotation.x = Math.sin(forearmPhase) * forearmSwing;
    }

    // Body bob
    const bobPhase = Math.sin(phase * 2);
    const bobHeight = isRunning ? 0.045 : 0.018;
    this.group.position.y = Math.max(0, bobPhase) * bobHeight * blend;

    // Body sway
    const sway = isRunning ? 0.04 : 0.025;
    this.group.rotation.z = Math.sin(phase) * sway * blend;
    this.group.rotation.x = isRunning ? -0.12 * blend : 0;

    // Antennae
    const antennaSwing = (isRunning ? 0.22 : 0.10) * blend;
    const antennaFreq = isRunning ? 1.6 : 1.3;
    this.leftAntennaPivot.rotation.x = Math.sin(phase * antennaFreq + 0.3) * antennaSwing;
    this.rightAntennaPivot.rotation.x = Math.sin(phase * antennaFreq + 0.8) * antennaSwing;
    this.leftAntennaPivot.rotation.z = Math.sin(phase * 0.8) * (isRunning ? 0.08 : 0.04) * blend;
    this.rightAntennaPivot.rotation.z = -Math.sin(phase * 0.8) * (isRunning ? 0.08 : 0.04) * blend;

    // Tail
    if (this.tailPivot) {
      this.tailPivot.rotation.y = Math.sin(phase * 0.7) * (isRunning ? 0.14 : 0.06) * blend;
      this.tailPivot.rotation.x = Math.sin(phase * 1.2) * (isRunning ? 0.08 : 0.03) * blend;
    }

    // Head bob
    this.head.rotation.y = Math.sin(phase * 0.5) * (isRunning ? 0.04 : 0.02) * blend;
  }

  // =====================================================
  // TICK
  // =====================================================
  tick(delta) {
    const isWalking = this.state === 'walk' || this.state === 'run' || this.state === 'moving';

    const targetBlend = isWalking ? 1 : 0;
    this._walkBlend += (targetBlend - this._walkBlend) * Math.min(1, this._blendSpeed * delta);
    if (this._walkBlend < 0.01) this._walkBlend = 0;
    if (this._walkBlend > 0.99) this._walkBlend = 1;

    if (this.state === 'moving') {
      this._tickMotion(delta);
    }

    if (this._walkBlend > 0) {
      this._tickWalkCycle(delta, this._walkBlend);
    }

    if (this._walkBlend < 1 && !this.externalAnimation) {
      const idleBlend = 1 - this._walkBlend;
      for (const osc of this._oscillators) {
        const parts = osc.key.split('.');
        let obj = osc.target;
        for (let i = 0; i < parts.length - 1; i++) obj = obj[parts[i]];
        const prop = parts[parts.length - 1];
        const current = obj[prop];
        osc.tick(delta);
        const oscValue = obj[prop];
        obj[prop] = current * this._walkBlend + oscValue * idleBlend;
      }
    }

    for (let i = this._tweens.length - 1; i >= 0; i--) {
      this._tweens[i].tick(delta);
      if (this._tweens[i].done) this._tweens.splice(i, 1);
    }

    // Cape flutter animation — rotate the pivot
    const backSlot = this.slots.get('back');
    if (backSlot && backSlot.equipped && backSlot.equipped.userData.capePivot) {
      const pivot = backSlot.equipped.userData.capePivot;
      this._capeElapsed = (this._capeElapsed || 0) + delta;
      const t = this._capeElapsed;
      const base = 0.40; // match buildCape angle

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

  // =====================================================
  // Accessory equip/unequip
  // =====================================================
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

  // =====================================================
  // CAPE — Accessory that attaches to back slot
  // =====================================================

  // Cape color presets — Claude brand palette + extras
  static CAPE_COLORS = {
    // Claude / Anthropic brand
    'claude-rust':   { color: '#C15F3C', trim: '#d97757', clasp: '#d4af37' },  // Crail → warm orange
    'claude-sand':   { color: '#b0aea5', trim: '#e8e6dc', clasp: '#C15F3C' },  // Cloudy → pampas
    'claude-dark':   { color: '#141413', trim: '#b0aea5', clasp: '#d97757' },  // Anthropic dark → grey
    'claude-orange': { color: '#d97757', trim: '#faf9f5', clasp: '#C15F3C' },  // Anthropic orange → cream

    // Classic capes
    'royal':         { color: '#6d28d9', trim: '#a78bfa', clasp: '#d4af37' },  // Purple → lavender
    'crimson':       { color: '#991b1b', trim: '#fca5a5', clasp: '#d4af37' },  // Deep red → pink
    'emerald':       { color: '#065f46', trim: '#6ee7b7', clasp: '#d4af37' },  // Forest → mint
    'midnight':      { color: '#1e1b4b', trim: '#818cf8', clasp: '#c0c0c0' },  // Indigo → blue
  };

  // Claude spark SVG path data (94x94 viewBox)
  static CLAUDE_SPARK_PATH = 'M18.7657 62.4437L37.1822 52.1167L37.4857 51.2122L37.1822 50.7085H36.2715L33.1852 50.5208L22.6615 50.2391L13.5545 49.8636L4.70044 49.3942L2.47428 48.9248L0.399902 46.1553L0.602281 44.794L2.47428 43.5266L5.15579 43.7613L11.0754 44.1837L19.98 44.794L26.4055 45.1695L35.9679 46.1553H37.4857L37.6881 45.545L37.1822 45.1695L36.7774 44.794L27.5692 38.5508L17.6021 31.9791L12.3908 28.1769L9.60812 26.2524L8.19147 24.4686L7.58433 20.5256L10.1141 17.7091L13.5545 17.9438L14.4146 18.1785L17.9056 20.8542L25.343 26.6279L35.0572 33.7629L36.4739 34.9364L37.0443 34.5514L37.1316 34.2792L36.4739 33.1996L31.212 23.6706L25.596 13.9539L23.0663 9.91695L22.4086 7.52296C22.1538 6.51831 22.0038 5.68714 22.0038 4.65957L24.8877 0.716544L26.5067 0.200195L30.4025 0.716544L32.0215 2.12477L34.4501 7.66379L38.3458 16.3478L44.4172 28.1769L46.188 31.6975L47.1493 34.9364L47.5035 35.9222H48.1106V35.3589L48.6166 28.6933L49.5273 20.5256L50.438 10.0108L50.7415 7.05356L52.2088 3.48605L55.1433 1.56148L57.42 2.64112L59.292 5.31674L59.039 7.05356L57.926 14.2824L55.7504 25.5952L54.3337 33.1996H55.1433L56.1046 32.2138L59.9497 27.1442L66.3752 19.0704L69.2085 15.8784L72.5478 12.3579L74.6728 10.668H78.7203L81.6548 15.0804L80.3394 19.6337L76.1906 24.8911L72.7502 29.3504L67.8172 35.9595L64.7562 41.2734L65.0307 41.7118L65.7681 41.6489L76.8989 39.255L82.9197 38.1753L90.1041 36.9549L93.3422 38.457L93.6963 40.006L92.4315 43.151L84.7411 45.0287L75.7353 46.8594L62.3244 50.0164L62.1759 50.1358L62.3512 50.3958L68.399 50.9432L70.9794 51.084H77.3037L89.0922 51.9759L92.1785 53.9944L93.9999 56.4822L93.6963 58.4068L88.9404 60.8008L82.5655 59.2987L67.6401 55.7312L62.5301 54.4638H61.8217V54.8862L66.0717 59.064L73.9139 66.1051L83.6786 75.2116L84.1845 77.4648L82.9197 79.2485L81.6042 79.0608L73.0032 72.5829L69.6639 69.6726L62.1759 63.3356H61.67V63.9928L63.3902 66.5276L72.5478 80.2812L73.0032 84.5059L72.3454 85.8672L69.9675 86.7121L67.3871 86.2427L61.9735 78.6852L56.4587 70.2359L52.0064 62.6315L51.4687 62.971L48.8189 91.2654L47.6047 92.7206L44.7714 93.8002L42.3934 92.0164L41.1286 89.1061L42.3934 83.3324L43.9113 75.8219L45.1255 69.8604L46.2386 62.4437L46.9184 59.9661L46.8583 59.8003L46.3153 59.8916L40.7238 67.5603L32.2239 79.0608L25.4948 86.2427L23.8758 86.8999L21.0931 85.4447L21.3461 82.863L22.9145 80.5629L32.2239 68.7338L37.8399 61.3641L41.4594 57.1337L41.4242 56.5218L41.2244 56.5048L16.489 72.6299L12.0873 73.1932L10.1647 71.4094L10.4176 68.4991L11.3283 67.5603L18.7657 62.4437Z';

  static buildCape(color = '#d97757', trimColor = '#faf9f5', claspColor = '#C15F3C', options = {}) {
    // Accept a preset name string
    if (typeof color === 'string' && ChibiLobster.CAPE_COLORS[color]) {
      const preset = ChibiLobster.CAPE_COLORS[color];
      return ChibiLobster.buildCape(preset.color, preset.trim, preset.clasp, options);
    }

    const capeGroup = new THREE.Group();
    capeGroup.name = 'cape';

    // Build cape material — with or without logo texture
    let capeMat;
    if (options.logo) {
      const logoTex = ChibiLobster._createLogoTexture(color, trimColor);
      capeMat = new THREE.MeshStandardMaterial({
        map: logoTex,
        roughness: 0.62,
        metalness: 0.04,
        side: THREE.DoubleSide,
      });
    } else {
      capeMat = new THREE.MeshStandardMaterial({
        color,
        roughness: 0.62,
        metalness: 0.04,
        side: THREE.DoubleSide,
      });
    }

    const trimMat = new THREE.MeshStandardMaterial({
      color: trimColor,
      roughness: 0.50,
      metalness: 0.08,
      side: THREE.DoubleSide,
    });
    const claspMat = new THREE.MeshStandardMaterial({
      color: claspColor,
      roughness: 0.30,
      metalness: 0.5,
    });

    // Back slot is at (0, 0.48, -0.18) in lobster space.
    // Simple approach: shoulder tube + flat cape on a pivot angled steeply outward.

    const capeWidth = 0.54;
    const capeLength = 0.52;
    const widthSegs = 10;
    const heightSegs = 14;

    // --- Shoulder tube ---
    const span = capeWidth * 0.82;
    const sPts = [
      new THREE.Vector3(-span / 2, 0, 0),
      new THREE.Vector3(0, 0, 0.005),
      new THREE.Vector3(span / 2, 0, 0),
    ];
    const sCurve = new THREE.CatmullRomCurve3(sPts);
    const sGeo = new THREE.TubeGeometry(sCurve, 10, 0.020, 8, false);
    const shoulderTube = new THREE.Mesh(sGeo, trimMat);
    shoulderTube.position.set(0, 0.06, -0.02);
    capeGroup.add(shoulderTube);

    // --- Cape plane with gentle billow ---
    const geo = new THREE.PlaneGeometry(capeWidth, capeLength, widthSegs, heightSegs);
    const pos = geo.attributes.position;
    for (let i = 0; i < pos.count; i++) {
      const x = pos.getX(i);
      const y = pos.getY(i);
      const t = 1 - (y + capeLength / 2) / capeLength; // 0=top, 1=bottom
      const xN = Math.abs(x) / (capeWidth / 2);
      const fan = t * t * 0.08;
      const billow = Math.sin(t * Math.PI) * 0.02 * (1 - xN * 0.4);
      pos.setX(i, x * (1 + fan));
      pos.setZ(i, -billow);
    }
    geo.computeVertexNormals();

    // Pivot at shoulder tube — cape hangs from top edge, rotated outward
    const capePivot = new THREE.Group();
    capePivot.position.set(0, 0.06, -0.02);   // same as shoulder tube
    capePivot.rotation.x = 0.40;               // ~23° outward — clears everything
    capeGroup.add(capePivot);

    const capeMesh = new THREE.Mesh(geo, capeMat);
    capeMesh.position.set(0, -capeLength / 2, 0); // top edge at pivot origin
    capePivot.add(capeMesh);

    // Lining
    const liningMat = new THREE.MeshStandardMaterial({
      color: new THREE.Color(color).multiplyScalar(0.5),
      roughness: 0.75, metalness: 0.02, side: THREE.BackSide,
    });
    const lining = new THREE.Mesh(geo.clone(), liningMat);
    lining.position.copy(capeMesh.position);
    lining.position.z += 0.003;
    capePivot.add(lining);

    // --- Hem trim ---
    const trimPts = [];
    for (let i = 0; i <= widthSegs; i++) {
      const fx = (i / widthSegs - 0.5) * capeWidth;
      const fan = 0.08;
      trimPts.push(new THREE.Vector3(fx * (1 + fan), -capeLength, 0));
    }
    const trimCurve = new THREE.CatmullRomCurve3(trimPts);
    const trimGeo = new THREE.TubeGeometry(trimCurve, 16, 0.012, 6, false);
    capePivot.add(new THREE.Mesh(trimGeo, trimMat));

    // --- Clasp ---
    const claspGeo = new THREE.OctahedronGeometry(0.022, 0);
    const clasp = new THREE.Mesh(claspGeo, claspMat);
    clasp.position.set(0, 0.06, 0.01);
    clasp.rotation.z = Math.PI / 4;
    clasp.scale.set(1, 1, 0.5);
    capeGroup.add(clasp);

    // Store refs for animation
    capeGroup.userData.capeMesh = capeMesh;
    capeGroup.userData.capePivot = capePivot;
    capeGroup.userData.lining = lining;

    return capeGroup;
  }

  // Render the Claude spark SVG path onto a canvas texture for the cape
  static _createLogoTexture(baseColor, logoColor) {
    const size = 512;
    const canvas = document.createElement('canvas');
    canvas.width = size;
    canvas.height = size;
    const ctx = canvas.getContext('2d');

    // Fill with base cape color
    ctx.fillStyle = baseColor;
    ctx.fillRect(0, 0, size, size);

    // Draw the Claude spark logo centered in upper-middle of cape
    // SVG viewBox is 0 0 94 94 — scale and center it
    const logoSize = size * 0.35;
    const scale = logoSize / 94;
    const offsetX = (size - logoSize) / 2;
    const offsetY = size * 0.22; // upper-middle area of cape

    ctx.save();
    ctx.translate(offsetX, offsetY);
    ctx.scale(scale, scale);

    const path = new Path2D(ChibiLobster.CLAUDE_SPARK_PATH);
    ctx.fillStyle = logoColor;
    ctx.fill(path);
    ctx.restore();

    const texture = new THREE.CanvasTexture(canvas);
    texture.colorSpace = THREE.SRGBColorSpace;
    return texture;
  }

  // =====================================================
  // Cleanup
  // =====================================================
  dispose() {
    this.group.traverse(child => {
      if (child.geometry) child.geometry.dispose();
    });
    for (const m of Object.values(this._mat)) m.dispose();
  }
}
