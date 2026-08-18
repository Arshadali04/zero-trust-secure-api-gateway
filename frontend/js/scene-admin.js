/**
 * scene-admin.js
 * Data-lattice: a 10 × 6 grid of nodes with connecting row lines.
 * Random nodes flash to simulate live audit-log entries.
 * Exported flashNode(row, col) lets admin.js trigger a flash programmatically.
 */

import * as THREE from 'https://cdn.jsdelivr.net/npm/three@0.128.0/build/three.module.js';
import { initScene } from './scene-core.js';

const COLS      = 10;
const ROWS      = 6;
const SPACING   = 1.2;
const NODE_R    = 0.06;

// Colour channels for #5b8cff
const BASE_R = 0x5b / 255;
const BASE_G = 0x8c / 255;
const BASE_B = 0xff / 255;

// Flash duration and brightness
const FLASH_DURATION = 0.55; // seconds
const FLASH_OPACITY  = 0.95;
const BASE_OPACITY   = 0.28;

/**
 * @param {HTMLCanvasElement} canvas
 * @returns {{ stop: function, flashNode: function(number, number): void }|null}
 */
export function initAdminScene(canvas) {
  const core = initScene(canvas, {
    bloom:          true,
    bloomStrength:  0.5,
    bloomRadius:    0.35,
    bloomThreshold: 0.2,
  });
  if (!core) return null;

  const { scene, camera, animate, stop: coreStop } = core;

  // Pull camera back so the full 10×6 grid is visible
  camera.position.z = 14;

  // ── Grid dimensions ───────────────────────────────────────────────────────
  const totalW  = (COLS - 1) * SPACING;   // 10.8
  const totalH  = (ROWS - 1) * SPACING;   // 6.0
  const originX = -totalW / 2;            // -5.4
  const originY = -totalH / 2;            // -3.0

  // ── Scene group (whole lattice rotates as one) ────────────────────────────
  const lattice = new THREE.Group();
  scene.add(lattice);

  // ── Node geometry (shared) ────────────────────────────────────────────────
  const nodeGeo = new THREE.SphereGeometry(NODE_R, 6, 6);

  /**
   * nodeMats[row][col] — individual material per node so each can flash
   * independently without affecting neighbours.
   */
  const nodeMats  = [];
  const nodeMeshes = []; // flat array [row * COLS + col]

  /** Per-node flash animation state. */
  const flashStates = [];

  for (let row = 0; row < ROWS; row++) {
    nodeMats.push([]);
    for (let col = 0; col < COLS; col++) {
      const x = originX + col * SPACING;
      const y = originY + row * SPACING;

      const mat = new THREE.MeshBasicMaterial({
        color:       0x5b8cff,
        transparent: true,
        opacity:     BASE_OPACITY,
      });
      nodeMats[row].push(mat);

      const mesh = new THREE.Mesh(nodeGeo, mat);
      mesh.position.set(x, y, 0);
      lattice.add(mesh);
      nodeMeshes.push(mesh);

      flashStates.push({ active: false, t: 0 });
    }
  }

  // ── Horizontal row lines ──────────────────────────────────────────────────
  const lineMat = new THREE.LineBasicMaterial({
    color:       0x5b8cff,
    transparent: true,
    opacity:     0.08,
  });

  for (let row = 0; row < ROWS; row++) {
    const y = originY + row * SPACING;
    const pts = [
      new THREE.Vector3(originX,            y, 0),
      new THREE.Vector3(originX + totalW,   y, 0),
    ];
    const geo  = new THREE.BufferGeometry().setFromPoints(pts);
    lattice.add(new THREE.Line(geo, lineMat));
  }

  // ── Auto-flash timer ──────────────────────────────────────────────────────
  let autoFlashCountdown = 0.8 + Math.random() * 1.4; // 0.8–2.2 s initially

  // ── Public: flash a specific node ────────────────────────────────────────
  /**
   * @param {number} row  0-based row index (0 = bottom)
   * @param {number} col  0-based column index
   */
  function flashNode(row, col) {
    const r   = Math.max(0, Math.min(ROWS - 1, row));
    const c   = Math.max(0, Math.min(COLS - 1, col));
    const idx = r * COLS + c;
    flashStates[idx].active = true;
    flashStates[idx].t      = 0;
  }

  // ── Animation ─────────────────────────────────────────────────────────────
  animate((elapsed, delta) => {
    // Lattice rotates slowly around Y
    lattice.rotation.y += 0.0005;

    // Y-wave: node y-offset = sin(col * 0.5 + time * 0.3) * 0.15
    for (let row = 0; row < ROWS; row++) {
      for (let col = 0; col < COLS; col++) {
        const idx   = row * COLS + col;
        const mesh  = nodeMeshes[idx];
        const baseY = originY + row * SPACING;
        mesh.position.y = baseY + Math.sin(col * 0.5 + elapsed * 0.3) * 0.15;
      }
    }

    // Flash animation — triangle envelope
    for (let i = 0; i < flashStates.length; i++) {
      const fs = flashStates[i];
      if (!fs.active) continue;

      fs.t += delta / FLASH_DURATION;
      if (fs.t >= 1.0) {
        fs.t      = 0;
        fs.active = false;
        const row = Math.floor(i / COLS);
        const col = i % COLS;
        nodeMats[row][col].opacity = BASE_OPACITY;
        nodeMats[row][col].color.setRGB(BASE_R, BASE_G, BASE_B);
      } else {
        // Ramp up to peak then back down
        const env  = fs.t < 0.4 ? fs.t / 0.4 : (1 - fs.t) / 0.6;
        const op   = BASE_OPACITY + (FLASH_OPACITY - BASE_OPACITY) * env;
        const row  = Math.floor(i / COLS);
        const col  = i % COLS;
        nodeMats[row][col].opacity = op;
        // Shift colour toward near-white on peak
        const r = BASE_R + (1.0  - BASE_R) * env * 0.6;
        const g = BASE_G + (0.95 - BASE_G) * env * 0.6;
        const b = BASE_B;
        nodeMats[row][col].color.setRGB(r, g, b);
      }
    }

    // Auto-flash: pick a random node every ~1.5 s
    autoFlashCountdown -= delta;
    if (autoFlashCountdown <= 0) {
      flashNode(
        Math.floor(Math.random() * ROWS),
        Math.floor(Math.random() * COLS)
      );
      autoFlashCountdown = 1.0 + Math.random() * 1.0; // 1–2 s
    }
  });

  return { stop: coreStop, flashNode };
}
