/**
 * scene-dashboard.js
 * Interactive node graph: identity hub at center, edges to security services.
 * Edges pulse on API activity; call pulseEdge(index) from dashboard UI code.
 */

import * as THREE from 'https://cdn.jsdelivr.net/npm/three@0.128.0/build/three.module.js';
import { initScene } from './scene-core.js';

/**
 * Node definitions (index 0 = center hub).
 * Edge i connects node[0] → node[i+1].
 */
const NODE_DEFS = [
  { label: 'YOU',        color: 0x5b8cff, pos: [ 0.0,  0.0,  0.0], isCenter: true  },
  { label: 'Risk Engine',color: 0xffb636, pos: [-3.0,  1.5, -1.0], isCenter: false },
  { label: 'WAF',        color: 0xff5d5d, pos: [ 3.0,  1.0, -1.0], isCenter: false },
  { label: 'Proxy',      color: 0x2dd4a0, pos: [ 0.0, -3.0, -1.0], isCenter: false },
  { label: 'Attack Lab', color: 0xff5d5d, pos: [-2.5, -1.5,  0.0], isCenter: false },
];

const EDGE_BASE_OPACITY = 0.15;
const EDGE_PEAK_OPACITY = 0.60;
const PULSE_DURATION    = 0.8; // seconds

/**
 * @param {HTMLCanvasElement} canvas
 * @returns {{ stop: function, pulseEdge: function(number): void }|null}
 */
export function initDashboardScene(canvas) {
  const core = initScene(canvas, {
    bloom:          true,
    bloomStrength:  0.7,
    bloomRadius:    0.4,
    bloomThreshold: 0.15,
  });
  if (!core) return null;

  const { scene, animate, stop: coreStop } = core;

  // ── Shared node sphere geometry ──────────────────────────────────────────
  const nodeGeo  = new THREE.SphereGeometry(0.12, 12, 12);
  const glowGeo  = new THREE.SphereGeometry(0.28, 10, 10);

  // ── Build nodes + glow halos ─────────────────────────────────────────────
  const group      = new THREE.Group();
  const nodeMeshes = [];
  const baseY      = []; // store original Y for oscillation

  NODE_DEFS.forEach(({ color, pos, isCenter }) => {
    const mat  = new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.95 });
    const mesh = new THREE.Mesh(nodeGeo, mat);
    mesh.position.set(...pos);
    group.add(mesh);
    nodeMeshes.push(mesh);
    baseY.push(pos[1]);

    if (!isCenter) {
      const glowMat  = new THREE.MeshBasicMaterial({
        color,
        transparent: true,
        opacity:     0.10,
      });
      const glowMesh = new THREE.Mesh(glowGeo, glowMat);
      glowMesh.position.set(...pos);
      group.add(glowMesh);
    }
  });

  // ── Edges: center → each outer node ─────────────────────────────────────
  const edges       = [];
  const edgeStates  = [];

  for (let i = 1; i < NODE_DEFS.length; i++) {
    const start = new THREE.Vector3(...NODE_DEFS[0].pos);
    const end   = new THREE.Vector3(...NODE_DEFS[i].pos);
    const geo   = new THREE.BufferGeometry().setFromPoints([start, end]);
    const mat   = new THREE.LineBasicMaterial({
      color:       0xffffff,
      transparent: true,
      opacity:     EDGE_BASE_OPACITY,
    });
    const line  = new THREE.Line(geo, mat);
    group.add(line);
    edges.push(line);
    edgeStates.push({ pulsing: false, t: 0 });
  }

  scene.add(group);

  // ── 200 ambient background points ───────────────────────────────────────
  (() => {
    const count = 200;
    const pos   = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
      pos[i * 3]     = (Math.random() - 0.5) * 30;
      pos[i * 3 + 1] = (Math.random() - 0.5) * 30;
      pos[i * 3 + 2] = (Math.random() - 0.5) * 30 - 5;
    }
    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    const mat = new THREE.PointsMaterial({
      color:           0x5b8cff,
      size:            0.03,
      transparent:     true,
      opacity:         0.18,
      sizeAttenuation: true,
    });
    scene.add(new THREE.Points(geo, mat));
  })();

  // ── Auto-pulse timer ─────────────────────────────────────────────────────
  let autoPulseCountdown = 2 + Math.random() * 2;

  // ── Public: trigger edge pulse from outside ──────────────────────────────
  /**
   * @param {number} edgeIndex  0 = Risk Engine edge, 1 = WAF, 2 = Proxy, 3 = Attack Lab
   */
  function pulseEdge(edgeIndex) {
    const idx = Math.max(0, Math.min(edges.length - 1, edgeIndex));
    edgeStates[idx].pulsing = true;
    edgeStates[idx].t       = 0;
  }

  // ── Animation ─────────────────────────────────────────────────────────────
  animate((elapsed, delta) => {
    // Whole group slowly rotates
    group.rotation.y += 0.0004;

    // Outer nodes: gentle Y oscillation
    for (let i = 1; i < nodeMeshes.length; i++) {
      nodeMeshes[i].position.y = baseY[i] + Math.sin(elapsed * 0.8 + i * 1.4) * 0.12;
    }

    // Edge pulse updates
    edgeStates.forEach((state, i) => {
      if (!state.pulsing) return;
      state.t += delta / PULSE_DURATION;
      if (state.t >= 1.0) {
        state.t       = 0;
        state.pulsing = false;
        edges[i].material.opacity = EDGE_BASE_OPACITY;
      } else {
        // Triangle envelope: ramp up then down
        const progress = state.t < 0.5 ? state.t * 2 : (1 - state.t) * 2;
        edges[i].material.opacity =
          EDGE_BASE_OPACITY + (EDGE_PEAK_OPACITY - EDGE_BASE_OPACITY) * progress;
      }
    });

    // Auto-pulse: randomly pick an edge every 2-4 seconds
    autoPulseCountdown -= delta;
    if (autoPulseCountdown <= 0) {
      pulseEdge(Math.floor(Math.random() * edges.length));
      autoPulseCountdown = 2 + Math.random() * 2;
    }
  });

  return { stop: coreStop, pulseEdge };
}
