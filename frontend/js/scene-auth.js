/**
 * scene-auth.js
 * Rotating wireframe icosahedron "core" + inner glow sphere.
 * Used by: login, register, forgot-password, reset-password, stepup pages.
 */

import * as THREE from 'https://cdn.jsdelivr.net/npm/three@0.128.0/build/three.module.js';
import { initScene } from './scene-core.js';

/**
 * @param {HTMLCanvasElement} canvas
 * @returns {{ stop: function }|null}
 */
export function initAuthScene(canvas) {
  const core = initScene(canvas, {
    bloom:          true,
    bloomStrength:  1.0,
    bloomRadius:    0.5,
    bloomThreshold: 0.1,
  });
  if (!core) return null;

  const { scene, animate, stop: coreStop } = core;

  // ── 1. Inner wireframe icosahedron ──────────────────────────────────────
  const innerIcoMesh = (() => {
    const geo = new THREE.IcosahedronGeometry(2.5, 1);
    const mat = new THREE.MeshBasicMaterial({
      color:       0x5b8cff,
      wireframe:   true,
      transparent: true,
      opacity:     0.2,
    });
    const mesh = new THREE.Mesh(geo, mat);
    scene.add(mesh);
    return mesh;
  })();

  // ── 2. Identity core — inner glow sphere ────────────────────────────────
  const glowSphere = (() => {
    const geo = new THREE.SphereGeometry(0.4, 16, 16);
    const mat = new THREE.MeshBasicMaterial({
      color:       0x5b8cff,
      transparent: true,
      opacity:     0.9,
    });
    const mesh = new THREE.Mesh(geo, mat);
    scene.add(mesh);
    return mesh;
  })();

  // ── 3. Outer cage — subtle second icosahedron ────────────────────────────
  const outerIcoMesh = (() => {
    const geo = new THREE.IcosahedronGeometry(3.0, 1);
    const mat = new THREE.MeshBasicMaterial({
      color:       0x5b8cff,
      wireframe:   true,
      transparent: true,
      opacity:     0.06,
    });
    const mesh = new THREE.Mesh(geo, mat);
    scene.add(mesh);
    return mesh;
  })();

  // ── 4. Three orbital rings at different tilt angles ─────────────────────
  const ringDefs = [
    { rx: 0,              rz: 0,            opacity: 0.15 },
    { rx: Math.PI / 6,    rz: 0,            opacity: 0.10 }, // 30°
    { rx: -Math.PI / 4,   rz: Math.PI / 8,  opacity: 0.07 }, // -45°
  ];

  const rings = ringDefs.map(({ rx, rz, opacity }) => {
    const geo  = new THREE.TorusGeometry(2.0, 0.018, 6, 72);
    const mat  = new THREE.MeshBasicMaterial({
      color:       0x5b8cff,
      transparent: true,
      opacity,
    });
    const mesh = new THREE.Mesh(geo, mat);
    mesh.rotation.x = rx;
    mesh.rotation.z = rz;
    scene.add(mesh);
    return mesh;
  });

  // ── 5. 120 sparse floating stars ─────────────────────────────────────────
  (() => {
    const count = 120;
    const pos   = new Float32Array(count * 3);
    for (let i = 0; i < count; i++) {
      pos[i * 3]     = (Math.random() - 0.5) * 26;
      pos[i * 3 + 1] = (Math.random() - 0.5) * 26;
      pos[i * 3 + 2] = (Math.random() - 0.5) * 26 - 4; // bias behind scene
    }
    const geo = new THREE.BufferGeometry();
    geo.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    const mat = new THREE.PointsMaterial({
      color:          0xffffff,
      size:           0.04,
      transparent:    true,
      opacity:        0.3,
      sizeAttenuation: true,
    });
    scene.add(new THREE.Points(geo, mat));
  })();

  // ── Animation ─────────────────────────────────────────────────────────────
  animate((elapsed) => {
    // Inner icosahedron — steady rotation
    innerIcoMesh.rotation.y += 0.003;
    innerIcoMesh.rotation.z += 0.002;

    // Outer cage — counter-rotate slowly
    outerIcoMesh.rotation.y -= 0.001;

    // Rings — each on a distinct axis
    rings[0].rotation.z += 0.004;
    rings[1].rotation.y += 0.003;
    rings[2].rotation.x += 0.002;
    rings[2].rotation.z += 0.001;

    // Glow sphere — sinusoidal pulse (bloom amplifies it)
    const scale = 1.0 + Math.sin(elapsed * 2.0) * 0.05;
    glowSphere.scale.setScalar(scale);
  });

  return { stop: coreStop };
}
