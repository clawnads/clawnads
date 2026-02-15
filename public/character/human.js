// Clawnads Character — Simple Human (capsule-body stick figure)
// The original trading floor character before the lobster redesign
// Built entirely from Three.js primitives

import * as THREE from 'three';

export class SimpleHuman {
  constructor(options = {}) {
    this.group = new THREE.Group();
    this.group.name = 'simple-human';
    this.state = 'idle';
    this._walkElapsed = 0;
    this._walkBlend = 0;
    this._blendSpeed = 4.0;
    this._target = null;
    this._moveSpeed = 0.6;
    this._turnSpeed = 5.0;
    this._arrivalDist = 0.08;

    // Color from hue
    const hue = options.hue || 200;
    const skinColor = new THREE.Color().setHSL(hue / 360, 0.35, 0.65);
    const shirtColor = new THREE.Color().setHSL(hue / 360, 0.55, 0.45);
    const pantsColor = new THREE.Color().setHSL(hue / 360, 0.20, 0.25);

    this._mat = {
      skin: new THREE.MeshStandardMaterial({ color: skinColor, roughness: 0.8, metalness: 0.02 }),
      shirt: new THREE.MeshStandardMaterial({ color: shirtColor, roughness: 0.75, metalness: 0.02 }),
      pants: new THREE.MeshStandardMaterial({ color: pantsColor, roughness: 0.85, metalness: 0.02 }),
      shoes: new THREE.MeshStandardMaterial({ color: '#27272a', roughness: 0.9, metalness: 0.0 }),
      hair: new THREE.MeshStandardMaterial({ color: '#2a1f14', roughness: 0.85, metalness: 0.02 }),
      eyeBlack: new THREE.MeshBasicMaterial({ color: '#111111' }),
      eyeWhite: new THREE.MeshBasicMaterial({ color: '#f5f5f5' }),
    };

    this._buildHead();
    this._buildBody();
    this._buildArms();
    this._buildLegs();
    this._buildGroundRing();
  }

  _buildHead() {
    // Head sphere
    this.head = new THREE.Mesh(
      new THREE.SphereGeometry(0.18, 20, 16),
      this._mat.skin
    );
    this.head.position.set(0, 0.92, 0);
    this.group.add(this.head);

    // Hair cap (slightly larger hemisphere on top)
    const hairGeo = new THREE.SphereGeometry(0.19, 20, 12, 0, Math.PI * 2, 0, Math.PI * 0.55);
    const hair = new THREE.Mesh(hairGeo, this._mat.hair);
    hair.position.set(0, 0.92, 0);
    this.group.add(hair);

    // Eyes
    for (const side of [-1, 1]) {
      // White
      const whiteGeo = new THREE.SphereGeometry(0.032, 10, 8);
      const white = new THREE.Mesh(whiteGeo, this._mat.eyeWhite);
      white.position.set(side * 0.07, 0.94, 0.16);
      white.scale.set(0.8, 1.0, 0.4);
      this.group.add(white);

      // Pupil
      const pupilGeo = new THREE.SphereGeometry(0.018, 8, 6);
      const pupil = new THREE.Mesh(pupilGeo, this._mat.eyeBlack);
      pupil.position.set(side * 0.07, 0.94, 0.175);
      pupil.scale.set(0.8, 1.0, 0.4);
      this.group.add(pupil);
    }

    // Simple mouth — small dark sphere (slight frown)
    const mouthGeo = new THREE.SphereGeometry(0.02, 8, 6);
    const mouth = new THREE.Mesh(mouthGeo, this._mat.eyeBlack);
    mouth.position.set(0, 0.86, 0.17);
    mouth.scale.set(2.0, 0.6, 0.4);
    this.group.add(mouth);
  }

  _buildBody() {
    // Torso (shirt)
    this.body = new THREE.Mesh(
      new THREE.CapsuleGeometry(0.16, 0.22, 8, 12),
      this._mat.shirt
    );
    this.body.position.set(0, 0.60, 0);
    this.group.add(this.body);

    // Hips (pants)
    const hips = new THREE.Mesh(
      new THREE.CapsuleGeometry(0.14, 0.08, 6, 10),
      this._mat.pants
    );
    hips.position.set(0, 0.38, 0);
    this.group.add(hips);
  }

  _buildArms() {
    this.leftArmPivot = new THREE.Group();
    this.leftArmPivot.position.set(-0.22, 0.68, 0);
    this.rightArmPivot = new THREE.Group();
    this.rightArmPivot.position.set(0.22, 0.68, 0);

    for (const [pivot, side] of [[this.leftArmPivot, -1], [this.rightArmPivot, 1]]) {
      // Shoulder ball
      const shoulder = new THREE.Mesh(
        new THREE.SphereGeometry(0.055, 8, 6),
        this._mat.shirt
      );
      pivot.add(shoulder);

      // Upper arm
      const upper = new THREE.Mesh(
        new THREE.CapsuleGeometry(0.04, 0.14, 5, 8),
        this._mat.shirt
      );
      upper.position.set(0, -0.10, 0);
      pivot.add(upper);

      // Forearm (skin)
      const forearm = new THREE.Mesh(
        new THREE.CapsuleGeometry(0.035, 0.12, 5, 8),
        this._mat.skin
      );
      forearm.position.set(0, -0.22, 0);
      pivot.add(forearm);

      // Hand
      const hand = new THREE.Mesh(
        new THREE.SphereGeometry(0.035, 8, 6),
        this._mat.skin
      );
      hand.position.set(0, -0.30, 0);
      pivot.add(hand);

      this.group.add(pivot);
    }
  }

  _buildLegs() {
    this.leftLegPivot = new THREE.Group();
    this.leftLegPivot.position.set(-0.08, 0.32, 0);
    this.rightLegPivot = new THREE.Group();
    this.rightLegPivot.position.set(0.08, 0.32, 0);

    for (const [pivot] of [[this.leftLegPivot], [this.rightLegPivot]]) {
      // Thigh (pants)
      const thigh = new THREE.Mesh(
        new THREE.CapsuleGeometry(0.05, 0.14, 5, 8),
        this._mat.pants
      );
      thigh.position.set(0, -0.10, 0);
      pivot.add(thigh);

      // Shin (pants)
      const shin = new THREE.Mesh(
        new THREE.CapsuleGeometry(0.04, 0.12, 5, 8),
        this._mat.pants
      );
      shin.position.set(0, -0.22, 0);
      pivot.add(shin);

      // Shoe
      const shoe = new THREE.Mesh(
        new THREE.CapsuleGeometry(0.042, 0.04, 5, 8),
        this._mat.shoes
      );
      shoe.position.set(0, -0.30, 0.015);
      shoe.scale.set(1.0, 0.7, 1.3);
      pivot.add(shoe);

      this.group.add(pivot);
    }
  }

  _buildGroundRing() {
    const mat = new THREE.MeshBasicMaterial({
      color: '#a1a1aa',
      transparent: true,
      opacity: 0.2,
      side: THREE.DoubleSide,
    });
    const ring = new THREE.Mesh(new THREE.RingGeometry(0.18, 0.22, 32), mat);
    ring.rotation.x = -Math.PI / 2;
    ring.position.y = 0.005;
    this.group.add(ring);
  }

  // --- Animation interface (matches ChibiLobster API) ---

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

  moveTo(target) {
    this._target = target.clone();
    this.state = 'moving';
    this._walkElapsed = this._walkElapsed || 0;
  }

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
    } else {
      // Idle — subtle breathing
      const t = performance.now() / 1000;
      this.body.position.y = 0.60 + Math.sin(t * 1.5) * 0.008;
      this.head.position.y = 0.92 + Math.sin(t * 1.5) * 0.006;
      this.head.rotation.y = Math.sin(t * 0.4) * 0.04;

      // Reset limbs
      this.leftArmPivot.rotation.x = Math.sin(t * 0.8) * 0.03;
      this.rightArmPivot.rotation.x = Math.sin(t * 0.8 + Math.PI) * 0.03;
      this.leftLegPivot.rotation.x = 0;
      this.rightLegPivot.rotation.x = 0;
      this.group.rotation.z = 0;
      this.group.position.y = 0;
    }
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

    this.group.rotation.y += Math.sign(angleDiff) * Math.min(Math.abs(angleDiff), this._turnSpeed * delta);

    const facingFactor = Math.max(0, 1 - Math.abs(angleDiff) / Math.PI);
    const speed = this._moveSpeed * facingFactor;
    pos.x += Math.sin(this.group.rotation.y) * speed * delta;
    pos.z += Math.cos(this.group.rotation.y) * speed * delta;
  }

  _tickWalkCycle(delta, blend) {
    const isRunning = this.state === 'run';
    this._walkElapsed += delta;
    const t = this._walkElapsed;
    const speed = isRunning ? 9.0 : 5.5;
    const phase = (t * speed) % (Math.PI * 2);

    const legSwing = (isRunning ? 0.6 : 0.35) * blend;
    const armSwing = (isRunning ? 0.5 : 0.25) * blend;

    // Legs
    this.leftLegPivot.rotation.x = Math.sin(phase) * legSwing;
    this.rightLegPivot.rotation.x = Math.sin(phase + Math.PI) * legSwing;

    // Arms swing opposite to legs
    this.leftArmPivot.rotation.x = Math.sin(phase + Math.PI) * armSwing;
    this.rightArmPivot.rotation.x = Math.sin(phase) * armSwing;

    // Body bob
    this.group.position.y = Math.max(0, Math.sin(phase * 2)) * (isRunning ? 0.04 : 0.015) * blend;

    // Slight sway
    this.group.rotation.z = Math.sin(phase) * 0.025 * blend;

    // Head bob
    this.head.rotation.y = Math.sin(phase * 0.5) * 0.03 * blend;
  }

  // Stub for accessory compat
  equip() { return false; }
  unequip() { return false; }

  dispose() {
    this.group.traverse(child => {
      if (child.geometry) child.geometry.dispose();
    });
    for (const m of Object.values(this._mat)) m.dispose();
  }
}
