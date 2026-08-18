/**
 * scene-profile.js
 * Concentric data rings and floating orbiting points — suggests identity
 * and layered access control.  Used by profile.html and api-keys.html.
 */

import * as THREE from 'https://cdn.jsdelivr.net/npm/three@0.128.0/build/three.module.js';
import { initScene } from './scene-core.js';

const TWO_PI = Math.PI * 2;

/**
 * @param {HTMLCanvasElement} canvas
 * @returns {{ stop: function }|null}
 */
export function initProfileScene(canvas) {
  const core = initScene(canvas, {
    bloom:          true,
    bloomStrength:  0.6,
    bloomRadius:    0.4,
    bloomThreshold: 0.12,
  });
  if (!core) return null;

  const { scene, animate, stop: coreStop } = core;

  // ── Three concentric torus rings ──────────────────────────────────────────
  const ringDefs = [
    { radius: 2.2, tube: 0.022, rx: Math.PI * 0.12,  ry: 0,           opacity: 0.20, speedY: 0.004 },
    { radius: 3.1, tube: 0.016, rx: -Math.PI * 0.25, ry: Math.PI/5,   opacity: 0.13, speedX: 0.003 },
    { radius: 4.0, tube: 0.012, rx: Math.PI * 0.40,  ry: -Math.PI/8,  opacity: 0.08, speedZ: 0.002 },
  ];

  const rings = ringDefs.map(def => {
    const geo  = new THREE.TorusGeometry(def.radius, def.tube, 6, 80);
    const mat  = new THREE.MeshBasicMaterial({
      color:       0x5b8cff,
      transparent: true,
      opacity:     def.opacity,
    });
    const mesh = new THREE.Mesh(geo, mat);
    mesh.rotation.x = def.rx;
    mesh.rotation.y = def.ry;
    scene.add(mesh);
    return { mesh, ...def };
  });

  // ── Central wireframe icosahedron ─────────────────────────────────────────
  const coreIco = (() => {
    const geo  = new THREE.IcosahedronGeometry(0.8, 1);
    const mat  = new THREE.MeshBasicMaterial({
      color:       0x5b8cff,
      wireframe:   true,
      transparent: true,
      opacity:     0.40,
    });
    const mesh = new THREE.Mesh(geo, mat);
    scene.add(mesh);
    return mesh;
  })();

  // ── 40 floating data points orbiting on randomised elliptical paths ───────
  const ORBIT_COUNT = 40;

  const orbitData = Array.from({ length: ORBIT_COUNT }, () => ({
    radius:   1.4 + Math.random() * 2.8,        // semi-major
    radiusB:  0.3 + Math.random() * 0.6,        // semi-minor (thickness)
    phase:    Math.random() * TWO_PI,
    speed:    0.3 + Math.random() * 0.5,        // rad/s
    tiltX:    (Math.random() - 0.5) * Math.PI,
    tiltY:    (Math.random() - 0.5) * Math.PI,
    tiltZ:    (Math.random() - 0.5) * Math.PI,
  }));

  const dotPositions = new Float32Array(ORBIT_COUNT * 3);

  const dotGeo = new THREE.BufferGeometry();
  dotGeo.setAttribute('position', new THREE.BufferAttribute(dotPositions, 3));

  const dotMat = new THREE.PointsMaterial({
    color:           0x5b8cff,
    size:            0.06,
    transparent:     true,
    opacity:         0.55,
    sizeAttenuation: true,
  });

  scene.add(new THREE.Points(dotGeo, dotMat));

  // ── Animation ─────────────────────────────────────────────────────────────
  // Reusable scratch vectors
  const v3 = new THREE.Vector3();
  const m4 = new THREE.Matrix4();

  animate((elapsed) => {
    // Rings — each rotates on its own primary axis
    rings[0].mesh.rotation.y += rings[0].speedY || 0.004;
    rings[1].mesh.rotation.x += rings[1].speedX || 0.003;
    rings[2].mesh.rotation.z += rings[2].speedZ || 0.002;
    rings[2].mesh.rotation.y += 0.001;

    // Central icosahedron — slow dual-axis spin
    coreIco.rotation.y += 0.004;
    coreIco.rotation.z += 0.002;

    // Orbiting data points
    for (let i = 0; i < ORBIT_COUNT; i++) {
      const od    = orbitData[i];
      const angle = elapsed * od.speed + od.phase;

      // Elliptical orbit in local XZ plane, then tilt with rotation matrix
      v3.set(
        Math.cos(angle) * od.radius,
        Math.sin(angle) * od.radiusB,
        Math.sin(angle) * od.radius * 0.4
      );

      m4.makeRotationX(od.tiltX);
      v3.applyMatrix4(m4);
      m4.makeRotationY(od.tiltY);
      v3.applyMatrix4(m4);
      m4.makeRotationZ(od.tiltZ);
      v3.applyMatrix4(m4);

      dotPositions[i * 3]     = v3.x;
      dotPositions[i * 3 + 1] = v3.y;
      dotPositions[i * 3 + 2] = v3.z;
    }
    dotGeo.attributes.position.needsUpdate = true;
  });

  return { stop: coreStop };
}
