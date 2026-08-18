/**
 * scene-attacklab.js
 * Volumetric threat field: particles drift inward; blocked ones flash red and
 * arc outward; allowed ones streak blue toward the center.
 */

import * as THREE from 'https://cdn.jsdelivr.net/npm/three@0.128.0/build/three.module.js';
import { initScene } from './scene-core.js';

// Particle count — balanced for 60fps on a 2019 laptop
const N = 500;

// Colour constants (pre-normalized for BufferAttribute)
const COL_BLUE = [0x5b / 255, 0x8c / 255, 0xff / 255]; // #5b8cff
const COL_RED  = [0xff / 255, 0x5d / 255, 0x5d / 255]; // #ff5d5d
const COL_WHT  = [0xf0 / 255, 0xf4 / 255, 0xff / 255]; // #f0f4ff (allowed)

// Respawn radius band
const R_SPAWN_MIN = 6.5;
const R_SPAWN_MAX = 8.0;

/** Sample a point on the surface of a sphere with the given radius. */
function sphereSurface(r) {
  const phi   = Math.acos(2 * Math.random() - 1);
  const theta = Math.random() * Math.PI * 2;
  return [
    r * Math.sin(phi) * Math.cos(theta),
    r * Math.sin(phi) * Math.sin(theta),
    r * Math.cos(phi),
  ];
}

/**
 * @param {HTMLCanvasElement} canvas
 * @returns {{
 *   stop:         function(): void,
 *   spawnBlock:   function(): void,
 *   spawnAllow:   function(): void,
 *   setRunning:   function(boolean): void,
 *   setRiskLevel: function(number): void,
 * }|null}
 */
export function initAttackScene(canvas) {
  const core = initScene(canvas, {
    bloom:          true,
    bloomStrength:  1.5,
    bloomRadius:    0.6,
    bloomThreshold: 0.05,
  });
  if (!core) return null;

  const { scene, animate, stop: coreStop, bloomPass } = core;

  // ── Internal state ────────────────────────────────────────────────────────
  let running   = false;
  let riskLevel = 0; // 0 – 1

  // ── Particle buffers ──────────────────────────────────────────────────────
  const positions = new Float32Array(N * 3);
  const colors    = new Float32Array(N * 3);

  /**
   * Per-particle state:
   *   type:    'ambient' | 'blocked' | 'allowed'
   *   t:       normalised animation progress (0–1) for non-ambient states
   *   arcDir:  [x,y,z] unit vector used by blocked particles to arc outward
   */
  const pState = Array.from({ length: N }, () => ({
    type:   'ambient',
    t:      0,
    arcDir: [0, 0, 0],
  }));

  // Initialise all particles spread across the spawn sphere
  for (let i = 0; i < N; i++) {
    const r   = R_SPAWN_MIN + Math.random() * (R_SPAWN_MAX - R_SPAWN_MIN);
    const [x, y, z] = sphereSurface(r);
    positions[i * 3]     = x;
    positions[i * 3 + 1] = y;
    positions[i * 3 + 2] = z;
    colors[i * 3]     = COL_BLUE[0];
    colors[i * 3 + 1] = COL_BLUE[1];
    colors[i * 3 + 2] = COL_BLUE[2];
  }

  const geo = new THREE.BufferGeometry();
  geo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
  geo.setAttribute('color',    new THREE.BufferAttribute(colors,    3));

  const mat = new THREE.PointsMaterial({
    size:            0.09,
    vertexColors:    true,
    transparent:     true,
    opacity:         0.85,
    sizeAttenuation: true,
  });

  const points = new THREE.Points(geo, mat);
  scene.add(points);

  // ── Helpers ───────────────────────────────────────────────────────────────

  /** Reset particle i to a random ambient position. */
  function respawnAmbient(i) {
    const r = R_SPAWN_MIN + Math.random() * (R_SPAWN_MAX - R_SPAWN_MIN);
    const [x, y, z] = sphereSurface(r);
    positions[i * 3]     = x;
    positions[i * 3 + 1] = y;
    positions[i * 3 + 2] = z;
    colors[i * 3]     = COL_BLUE[0];
    colors[i * 3 + 1] = COL_BLUE[1];
    colors[i * 3 + 2] = COL_BLUE[2];
    pState[i].type = 'ambient';
    pState[i].t    = 0;
  }

  // ── Animation ─────────────────────────────────────────────────────────────
  animate((_elapsed, delta) => {
    // Base inward drift speed — faster when running and riskLevel is high
    const baseSpeed = (running ? 0.018 : 0.007) * (1 + riskLevel * 2);

    for (let i = 0; i < N; i++) {
      const xi = positions[i * 3];
      const yi = positions[i * 3 + 1];
      const zi = positions[i * 3 + 2];
      const r  = Math.sqrt(xi * xi + yi * yi + zi * zi);
      const st = pState[i];

      if (st.type === 'blocked') {
        // Arc outward for ~1.2 s, brighten then fade
        st.t += delta / 1.2;
        if (st.t >= 1.0) {
          respawnAmbient(i);
        } else {
          // Move along pre-computed arc direction
          const outSpeed = 0.045 * (1 - st.t * 0.6); // decelerate
          positions[i * 3]     += st.arcDir[0] * outSpeed;
          positions[i * 3 + 1] += st.arcDir[1] * outSpeed;
          positions[i * 3 + 2] += st.arcDir[2] * outSpeed;

          // Colour: bright red → fading
          const intensity = 1.0 - st.t * 0.55;
          colors[i * 3]     = COL_RED[0] * intensity + (1 - intensity) * 0.1;
          colors[i * 3 + 1] = COL_RED[1] * intensity * 0.4;
          colors[i * 3 + 2] = COL_RED[2] * intensity * 0.4;
        }

      } else if (st.type === 'allowed') {
        // Rush inward quickly, flash white-blue
        st.t += delta / 0.6;
        if (r < 0.4 || st.t >= 1.0) {
          respawnAmbient(i);
        } else {
          const rushSpeed = 0.08;
          if (r > 0.001) {
            positions[i * 3]     -= (xi / r) * rushSpeed;
            positions[i * 3 + 1] -= (yi / r) * rushSpeed;
            positions[i * 3 + 2] -= (zi / r) * rushSpeed;
          }
          const fade = 1.0 - st.t;
          colors[i * 3]     = COL_WHT[0] * fade + COL_BLUE[0] * (1 - fade);
          colors[i * 3 + 1] = COL_WHT[1] * fade + COL_BLUE[1] * (1 - fade);
          colors[i * 3 + 2] = COL_WHT[2] * fade + COL_BLUE[2] * (1 - fade);
        }

      } else {
        // Ambient — drift inward; respawn when too close
        if (r < 0.45) {
          respawnAmbient(i);
        } else {
          positions[i * 3]     -= (xi / r) * baseSpeed;
          positions[i * 3 + 1] -= (yi / r) * baseSpeed;
          positions[i * 3 + 2] -= (zi / r) * baseSpeed;
        }
      }
    }

    geo.attributes.position.needsUpdate = true;
    geo.attributes.color.needsUpdate    = true;
  });

  // ── Public API ────────────────────────────────────────────────────────────

  /**
   * Flash 3-6 ambient particles near the edge as blocked (red + arc outward).
   */
  function spawnBlock() {
    const count  = 3 + Math.floor(Math.random() * 4); // 3–6
    let spawned  = 0;

    for (let i = 0; i < N && spawned < count; i++) {
      if (pState[i].type !== 'ambient') continue;

      const xi = positions[i * 3];
      const yi = positions[i * 3 + 1];
      const zi = positions[i * 3 + 2];
      const r  = Math.sqrt(xi * xi + yi * yi + zi * zi);

      if (r < 4.0) continue; // only particles near the outer shell

      pState[i].type = 'blocked';
      pState[i].t    = 0;

      // Arc direction: mostly outward with a random tangential kick
      const nx = xi / r + (Math.random() - 0.5) * 0.5;
      const ny = yi / r + (Math.random() - 0.5) * 0.5;
      const nz = zi / r + (Math.random() - 0.5) * 0.5;
      const nl = Math.sqrt(nx * nx + ny * ny + nz * nz) || 1;
      pState[i].arcDir = [nx / nl, ny / nl, nz / nl];

      colors[i * 3]     = COL_RED[0];
      colors[i * 3 + 1] = COL_RED[1];
      colors[i * 3 + 2] = COL_RED[2];
      spawned++;
    }
  }

  /**
   * Send 1-2 blue particles rushing inward (allowed request visualisation).
   */
  function spawnAllow() {
    const count = 1 + Math.floor(Math.random() * 2); // 1–2
    let spawned = 0;

    for (let i = 0; i < N && spawned < count; i++) {
      if (pState[i].type !== 'ambient') continue;

      pState[i].type = 'allowed';
      pState[i].t    = 0;

      colors[i * 3]     = COL_WHT[0];
      colors[i * 3 + 1] = COL_WHT[1];
      colors[i * 3 + 2] = COL_WHT[2];
      spawned++;
    }
  }

  /**
   * Toggle high-activity mode (faster drift, more visual noise).
   * @param {boolean} active
   */
  function setRunning(active) {
    running = !!active;
  }

  /**
   * @param {number} level  0 (calm) – 1 (critical); affects speed & bloom.
   */
  function setRiskLevel(level) {
    riskLevel = Math.max(0, Math.min(1, level));
    if (bloomPass) {
      // 1.5 (idle) → 3.5 (max threat)
      bloomPass.strength = 1.5 + riskLevel * 2.0;
    }
  }

  return { stop: coreStop, spawnBlock, spawnAllow, setRunning, setRiskLevel };
}
