// Clawnads Character Viewer — Accessory System
// Slot-based accessories built from Three.js primitives

import * as THREE from 'three';
import { ChibiLobster } from './lobster.js';

export const AccessorySlot = {
  HEAD: 'head',
  FACE: 'face',
  BACK: 'back',
  LEFT_CLAW: 'left-claw',
  RIGHT_CLAW: 'right-claw'
};

// --- Sample accessory factories ---

function createTopHat() {
  const group = new THREE.Group();
  group.name = 'acc-top-hat';
  const mat = new THREE.MeshLambertMaterial({ color: '#1c1c1f' });

  // Brim
  const brim = new THREE.Mesh(
    new THREE.CylinderGeometry(0.10, 0.10, 0.015, 12),
    mat
  );
  group.add(brim);

  // Crown
  const crown = new THREE.Mesh(
    new THREE.CylinderGeometry(0.065, 0.07, 0.10, 10),
    mat
  );
  crown.position.y = 0.055;
  group.add(crown);

  // Band (Clawnads green)
  const band = new THREE.Mesh(
    new THREE.TorusGeometry(0.068, 0.008, 6, 12),
    new THREE.MeshLambertMaterial({ color: '#22c55e' })
  );
  band.position.y = 0.015;
  band.rotation.x = Math.PI / 2;
  group.add(band);

  return group;
}

function createMonocle() {
  const group = new THREE.Group();
  group.name = 'acc-monocle';

  // Gold ring
  const ring = new THREE.Mesh(
    new THREE.TorusGeometry(0.035, 0.004, 6, 16),
    new THREE.MeshLambertMaterial({ color: '#d4af37' })
  );
  group.add(ring);

  // Lens
  const lens = new THREE.Mesh(
    new THREE.CircleGeometry(0.033, 12),
    new THREE.MeshBasicMaterial({
      color: '#aaddff',
      transparent: true,
      opacity: 0.3,
      side: THREE.DoubleSide
    })
  );
  group.add(lens);

  // Chain
  const chainPoints = [
    new THREE.Vector3(0, -0.035, 0),
    new THREE.Vector3(0.02, -0.08, 0)
  ];
  const chain = new THREE.Line(
    new THREE.BufferGeometry().setFromPoints(chainPoints),
    new THREE.LineBasicMaterial({ color: '#d4af37' })
  );
  group.add(chain);

  // Offset to right eye position
  group.position.set(0.06, 0, 0);

  return group;
}

function createBriefcase() {
  const group = new THREE.Group();
  group.name = 'acc-briefcase';

  // Case body
  const body = new THREE.Mesh(
    new THREE.BoxGeometry(0.10, 0.07, 0.03),
    new THREE.MeshLambertMaterial({ color: '#8B4513' })
  );
  group.add(body);

  // Handle
  const handle = new THREE.Mesh(
    new THREE.TorusGeometry(0.025, 0.005, 4, 8, Math.PI),
    new THREE.MeshLambertMaterial({ color: '#5C3317' })
  );
  handle.position.y = 0.04;
  handle.rotation.z = Math.PI;
  group.add(handle);

  // Clasp
  const clasp = new THREE.Mesh(
    new THREE.BoxGeometry(0.015, 0.01, 0.035),
    new THREE.MeshLambertMaterial({ color: '#d4af37' })
  );
  group.add(clasp);

  return group;
}

// Registry of standard accessories (non-cape)
export const SAMPLE_ACCESSORIES = [
  { name: 'Top Hat', slot: AccessorySlot.HEAD, create: createTopHat },
  { name: 'Monocle', slot: AccessorySlot.FACE, create: createMonocle },
  { name: 'Briefcase', slot: AccessorySlot.RIGHT_CLAW, create: createBriefcase },
];

// Cape presets — used by viewer's cape sub-panel
export const CAPE_PRESETS = [
  { name: 'Rust',     key: 'claude-rust',   emoji: '🧡' },
  { name: 'Orange',   key: 'claude-orange', emoji: '🟠' },
  { name: 'Dark',     key: 'claude-dark',   emoji: '⬛' },
  { name: 'Sand',     key: 'claude-sand',   emoji: '🤍' },
  { name: 'Royal',    key: 'royal',         emoji: '👑' },
  { name: 'Crimson',  key: 'crimson',       emoji: '❤️' },
  { name: 'Emerald',  key: 'emerald',       emoji: '💚' },
  { name: 'Midnight', key: 'midnight',      emoji: '🌙' },
];
