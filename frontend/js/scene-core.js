/**
 * scene-core.js
 * Foundation module — renderer, camera, clock, post-processing, mouse parallax.
 * Every page-specific scene imports and calls initScene().
 */

import * as THREE from 'https://cdn.jsdelivr.net/npm/three@0.128.0/build/three.module.js';
import { EffectComposer } from 'https://cdn.jsdelivr.net/npm/three@0.128.0/examples/jsm/postprocessing/EffectComposer.js';
import { RenderPass } from 'https://cdn.jsdelivr.net/npm/three@0.128.0/examples/jsm/postprocessing/RenderPass.js';
import { UnrealBloomPass } from 'https://cdn.jsdelivr.net/npm/three@0.128.0/examples/jsm/postprocessing/UnrealBloomPass.js';

/**
 * @param {HTMLCanvasElement} canvas
 * @param {object}  opts
 * @param {boolean} [opts.bloom=false]
 * @param {number}  [opts.bloomStrength=0.8]
 * @param {number}  [opts.bloomRadius=0.4]
 * @param {number}  [opts.bloomThreshold=0.1]
 * @returns {object|null}  null when WebGL is unavailable
 */
export function initScene(canvas, opts = {}) {
  if (!canvas) return null;

  // ── WebGL capability check ───────────────────────────────────────────────
  let hasWebGL = false;
  try {
    const probe = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    hasWebGL = !!probe;
  } catch (_) {}

  if (!hasWebGL) {
    canvas.style.display = 'none';
    return null;
  }

  const {
    bloom          = false,
    bloomStrength  = 0.8,
    bloomRadius    = 0.4,
    bloomThreshold = 0.1,
  } = opts;

  // ── Renderer ─────────────────────────────────────────────────────────────
  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({
      canvas,
      antialias: true,
      alpha:     true,
      powerPreference: 'default',
    });
  } catch (_) {
    canvas.style.display = 'none';
    return null;
  }

  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.setSize(window.innerWidth, window.innerHeight);
  renderer.setClearColor(0x000000, 0); // transparent background

  // ── Scene ────────────────────────────────────────────────────────────────
  const scene = new THREE.Scene();

  // ── Camera ───────────────────────────────────────────────────────────────
  const camera = new THREE.PerspectiveCamera(
    50,
    window.innerWidth / window.innerHeight,
    0.1,
    200
  );
  camera.position.z = 10;

  // ── Clock ────────────────────────────────────────────────────────────────
  const clock = new THREE.Clock();

  // ── Post-processing ──────────────────────────────────────────────────────
  let composer  = null;
  let bloomPass = null;

  if (bloom) {
    composer = new EffectComposer(renderer);
    composer.addPass(new RenderPass(scene, camera));

    bloomPass = new UnrealBloomPass(
      new THREE.Vector2(window.innerWidth, window.innerHeight),
      bloomStrength,
      bloomRadius,
      bloomThreshold
    );
    composer.addPass(bloomPass);
  }

  // ── Mouse parallax ───────────────────────────────────────────────────────
  // mouseNX / mouseNY are normalised to [-1, 1]
  let mouseNX    = 0;
  let mouseNY    = 0;
  let currentRotY = 0; // radians, lerp target for camera.rotation.y
  let currentRotX = 0; // radians, lerp target for camera.rotation.x

  // Horizontal max ≈ 3.4°, vertical max ≈ 1.7°  (both under the 4° ceiling)
  const SENS_H = 0.06; // radians at full horizontal deflection
  const SENS_V = 0.03; // radians at full vertical deflection
  const LERP   = 0.04; // lerp speed per frame

  const _onMouseMove = (e) => {
    mouseNX =  (e.clientX / window.innerWidth  - 0.5) * 2;
    mouseNY = -(e.clientY / window.innerHeight - 0.5) * 2;
  };
  window.addEventListener('mousemove', _onMouseMove);

  // ── Resize ───────────────────────────────────────────────────────────────
  const _onResize = () => {
    const w = window.innerWidth;
    const h = window.innerHeight;
    renderer.setSize(w, h);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
    if (composer) composer.setSize(w, h);
  };
  window.addEventListener('resize', _onResize);

  // ── Animation loop ───────────────────────────────────────────────────────
  let rafId    = null;
  let prevTime = 0;

  /**
   * Start the render loop.
   * @param {function(elapsed: number, delta: number): void} callback
   */
  function animate(callback) {
    const loop = () => {
      rafId = requestAnimationFrame(loop);

      const elapsed = clock.getElapsedTime();
      const delta   = elapsed - prevTime;
      prevTime       = elapsed;

      // Smooth mouse parallax — lerp toward (mouseNX*SENS_H, mouseNY*SENS_V)
      currentRotY += (mouseNX * SENS_H - currentRotY) * LERP;
      currentRotX += (mouseNY * SENS_V - currentRotX) * LERP;
      camera.rotation.y = currentRotY;
      camera.rotation.x = currentRotX;

      if (callback) callback(elapsed, delta);

      if (composer) {
        composer.render();
      } else {
        renderer.render(scene, camera);
      }
    };
    loop();
  }

  /** Force-update viewport (call after programmatic canvas resize). */
  function resize() { _onResize(); }

  /** Cancel the animation frame and detach all event listeners. */
  function stop() {
    if (rafId !== null) {
      cancelAnimationFrame(rafId);
      rafId = null;
    }
    window.removeEventListener('mousemove', _onMouseMove);
    window.removeEventListener('resize',    _onResize);
    renderer.dispose();
  }

  return { renderer, scene, camera, clock, composer, bloomPass, resize, animate, stop, THREE };
}
