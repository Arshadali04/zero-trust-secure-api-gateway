"""
gateway/detection/ml_anomaly.py
-------------------------------
ML-powered anomaly detection using scikit-learn's IsolationForest.

Why IsolationForest:
  * Works well on small, unlabelled datasets (no attack samples needed)
  * Efficiently isolates outliers in request-behaviour feature space
  * Cheap to refit — suitable for live per-user scoring on a demo gateway

Design (kept explainable for a final-year project):
  * Per-user sliding window of recent request feature vectors (in-memory)
  * Once enough history accumulates, fit/refit an IsolationForest per user
  * Score each new request; flag it if it falls below the anomaly threshold
  * Graceful fallback: if scikit-learn is unavailable, returns None (no crash)

Feature vector per authenticated request:
  [requests_per_minute, failed_auth_per_minute, log1p(body_bytes), hour_of_day]
"""

import hashlib
import hmac
import logging
import math
import os
import re
from collections import OrderedDict, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC
from threading import Lock

logger = logging.getLogger(__name__)

# scikit-learn is optional — fall back to rule-based detection if missing
try:
    import joblib
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except Exception:  # pragma: no cover
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn unavailable — ML anomaly detection disabled.")

# ── Model persistence ─────────────────────────────────────────────────────────
# Per-user models are saved to disk so they survive restarts.  Directory is
# created on first save.  Model files are named by user ID: user_<id>.pkl
#
# GATEWAY_MODEL_DIR overrides the location. Tests set it to a tmp dir so a test
# run cannot read, overwrite or delete the real models under data/models.
_MODEL_DIR = os.environ.get("GATEWAY_MODEL_DIR") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data", "models",
)

# Only `user_<digits>.pkl` is ever accepted. os.listdir cannot return a path
# separator, so traversal is not reachable today, but the models directory is
# also the one place this process deserialises attacker-influenceable bytes, so
# the filename contract is made explicit rather than assumed.
_MODEL_FILENAME_RE = re.compile(r"^user_(\d+)\.pkl$")

# ── Configuration ─────────────────────────────────────────────────────────────
MIN_SAMPLES = 30          # observations required before the first fit
MAX_SAMPLES = 300         # cap per-user history (keeps refits cheap)
REFIT_EVERY = 10          # refit model after this many new observations
CONTAMINATION = 0.08      # expected anomaly fraction (sklearn default 0.10)
# decision_function() below this → flagged.
#
# Was -0.45, which no observation could ever reach, so the ML detector was dead
# code in production. sklearn's decision_function is score_samples - offset_,
# and with contamination=0.08 offset_ is fitted to the 8th percentile of the
# training scores. That puts 0.0 at the model's own normal/anomalous boundary:
# positive is more normal than the 92nd-percentile training point, negative is
# less. A shallow 50-tree forest keeps score_samples in a narrow band, so even a
# wildly out-of-distribution vector lands near -0.15, never -0.45. Both
# TestIsolationForest tests asserted a flag and got None for this reason.
#
# -0.05 is deliberately just inside the model's own boundary: strict enough that
# a borderline point does not raise a 0.62-risk event, loose enough to be
# reachable. contamination already caps expected flags near 8% of traffic.
ANOMALY_THRESHOLD = -0.05
RISK_BASE = 0.62          # baseline risk score for an ML flag
RISK_CAP = 0.95

# Upper bound on how many distinct users this process keeps state for.
#
# MAX_SAMPLES bounds each user's history, but nothing bounded the number of
# users: _history, _models and _since_refit were plain (default)dicts that only
# ever grew. Each tracked user costs a 300-entry deque of 4 floats plus a
# fitted 50-tree IsolationForest, so a long-lived worker serving a large user
# base climbed steadily and never gave memory back — and load_persisted_models()
# made it worse by loading *every* model on disk at startup, so the floor rose
# with each restart. Least-recently-scored users are now evicted; the only cost
# of eviction is that a returning user re-accumulates MIN_SAMPLES observations
# before ML scoring resumes, and their persisted model is still on disk.
MAX_TRACKED_USERS = 500

# ── In-memory state (per worker process) ──────────────────────────────────────
# _history is an OrderedDict used as an LRU: most-recently-scored user last.
# It is NOT a defaultdict — use _touch_user() to create an entry, so every
# insertion goes through the eviction check.
_history: "OrderedDict[int, deque]" = OrderedDict()
_models: dict[int, object] = {}
_since_refit: dict[int, int] = defaultdict(int)
_lock = Lock()


def _touch_user(user_id: int) -> deque:
    """Mark *user_id* as most-recently-used and return its history deque.

    Caller MUST already hold ``_lock``. Creates the deque on first use and
    evicts the least-recently-scored users once MAX_TRACKED_USERS is exceeded.
    """
    hist = _history.get(user_id)
    if hist is None:
        hist = deque(maxlen=MAX_SAMPLES)
        _history[user_id] = hist
    else:
        _history.move_to_end(user_id)

    while len(_history) > MAX_TRACKED_USERS:
        evicted, _ = _history.popitem(last=False)
        _models.pop(evicted, None)
        _since_refit.pop(evicted, None)
        logger.debug(
            "ML: evicted user=%s from in-memory state (tracking cap %d reached)",
            evicted, MAX_TRACKED_USERS,
        )
    return hist


def _feature_vector(rpm: float, failed_auth: float, body_bytes: int, hour: int) -> list[float]:
    return [
        float(rpm),
        float(failed_auth),
        math.log1p(float(body_bytes or 0)),
        float(hour),
    ]


def reset_user(user_id: int) -> None:
    """Drop all stored history/models for a user (useful for tests)."""
    with _lock:
        _history.pop(user_id, None)
        _models.pop(user_id, None)
        _since_refit.pop(user_id, None)


def is_ml_ready(user_id: int) -> bool:
    """True when this user has a fitted model (history exceeded MIN_SAMPLES)."""
    with _lock:
        return user_id in _models


def model_size(user_id: int) -> int:
    """Number of feature vectors retained for this user."""
    with _lock:
        return len(_history.get(user_id, ()))


# Single background worker for model fitting. A 50-tree IsolationForest fit
# plus a joblib.dump used to run *inside* `with _lock`, reached synchronously
# from logging.py::_track_behavior, which is awaited during the response. That
# blocked the whole event loop — not just the triggering request — for the
# duration of a CPU-bound fit and a disk write, every REFIT_EVERY requests per
# user. One worker is deliberate: fits are serialised so several active users
# cannot saturate the CPU.
_fit_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="ml-fit")
_fit_inflight: set[int] = set()


def _fit(user_id: int) -> None:
    """Refit the IsolationForest on the user's current history.

    IMPORTANT: this function acquires ``_lock`` itself and must therefore never
    be called while the caller already holds it (``threading.Lock`` is not
    reentrant). The expensive work — ``model.fit`` and ``joblib.dump`` — happens
    with the lock released, so concurrent scoring is not stalled by a refit.
    """
    with _lock:
        data = list(_history.get(user_id, ()))
    if len(data) < MIN_SAMPLES:
        with _lock:
            _models.pop(user_id, None)
        return
    try:
        model = IsolationForest(
            n_estimators=50,
            max_samples="auto",
            contamination=CONTAMINATION,
            random_state=42,
        )
        model.fit(data)                      # CPU-bound, lock released
    except Exception as exc:  # pragma: no cover
        logger.warning("IsolationForest fit failed for user=%s: %s", user_id, exc)
        with _lock:
            _models.pop(user_id, None)
        return
    with _lock:
        _models[user_id] = model
        _since_refit[user_id] = 0
    _persist_model(user_id, model)           # disk I/O, lock released


def _schedule_fit(user_id: int) -> None:
    """Queue a refit on the background worker; never blocks the caller.

    Call this from the request path instead of ``_fit``. Duplicate submissions
    for the same user are collapsed so a burst of traffic cannot queue hundreds
    of redundant fits. The consequence is that the very first model for a user
    becomes available a moment later than before, so ``record`` returns None for
    a few extra requests — an acceptable trade for not stalling the event loop.
    """
    if user_id in _fit_inflight:
        return
    _fit_inflight.add(user_id)

    def _run():
        try:
            _fit(user_id)
        finally:
            _fit_inflight.discard(user_id)

    try:
        _fit_executor.submit(_run)
    except RuntimeError:  # interpreter shutting down
        _fit_inflight.discard(user_id)


def _model_signature(payload: bytes) -> str:
    """HMAC-SHA256 of a serialised model, keyed with the app secret."""
    from gateway.config import settings
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"), payload, hashlib.sha256
    ).hexdigest()


def _persist_model(user_id: int, model) -> None:
    """Save a fitted model to disk alongside an HMAC signature.

    The signature is what makes load_persisted_models() safe — see the comment
    there. Written signature-last is deliberate: a crash between the two writes
    leaves an unsigned model that is refused on load, which is the safe
    direction to fail.
    """
    if not SKLEARN_AVAILABLE:
        return
    try:
        os.makedirs(_MODEL_DIR, exist_ok=True)
        path = os.path.join(_MODEL_DIR, f"user_{int(user_id)}.pkl")
        joblib.dump(model, path)
        with open(path, "rb") as fh:
            digest = _model_signature(fh.read())
        with open(path + ".sig", "w", encoding="utf-8") as fh:
            fh.write(digest)
    except Exception as exc:
        logger.debug("Model persist failed for user=%s: %s", user_id, exc)


def load_persisted_models() -> int:
    """Load previously persisted models from disk on startup.

    Call this once at application startup. Returns number of models loaded.

    SECURITY: joblib.load is pickle.load, which executes arbitrary code during
    deserialisation. This function used to load every `user_*.pkl` in
    data/models unconditionally, which turned "can write one file under data/"
    into "runs code as the gateway process on next restart" — and data/ is a
    mounted volume in docker-compose, so on a stock deployment the host side of
    that mount is a normal writable directory. Nothing else in the request path
    needs a file-write primitive for that to matter; a stray backup script or a
    loose container permission is enough.

    Each model is now accepted only if a sidecar `.sig` file matches an
    HMAC-SHA256 of the pickle bytes under SECRET_KEY. An unsigned or mismatched
    model is refused and logged at ERROR — losing a behavioural baseline costs a
    user MIN_SAMPLES requests of ML coverage, which is a trivial price next to
    executing an attacker's payload. Rotating SECRET_KEY invalidates every
    stored model by design; they simply refit.
    """
    if not SKLEARN_AVAILABLE or not os.path.isdir(_MODEL_DIR):
        return 0
    loaded = 0
    refused = 0
    for fname in sorted(os.listdir(_MODEL_DIR)):
        match = _MODEL_FILENAME_RE.match(fname)
        if not match:
            continue
        if loaded >= MAX_TRACKED_USERS:
            logger.warning(
                "ML: stopped loading persisted models at the %d-user cap; the "
                "remainder will be refitted on demand", MAX_TRACKED_USERS,
            )
            break
        path = os.path.join(_MODEL_DIR, fname)
        sig_path = path + ".sig"
        try:
            with open(path, "rb") as fh:
                payload = fh.read()
            try:
                with open(sig_path, encoding="utf-8") as fh:
                    stored_sig = fh.read().strip()
            except FileNotFoundError:
                refused += 1
                logger.error(
                    "ML: REFUSED unsigned model %s (no %s). Not deserialising — "
                    "an unsigned pickle in this directory is treated as hostile. "
                    "Delete it, or let it be refitted from live traffic.",
                    fname, os.path.basename(sig_path),
                )
                continue
            if not hmac.compare_digest(stored_sig, _model_signature(payload)):
                refused += 1
                logger.error(
                    "ML: REFUSED model %s — HMAC mismatch. Either the file was "
                    "tampered with, or SECRET_KEY was rotated since it was "
                    "written. Not deserialising.", fname,
                )
                continue

            uid = int(match.group(1))
            model = joblib.load(path)
            with _lock:
                _touch_user(uid)
                _models[uid] = model
            loaded += 1
        except Exception as exc:
            logger.warning("ML: failed to load model %s: %s", fname, exc)
    if loaded:
        logger.info("ML: loaded %d persisted user models from %s", loaded, _MODEL_DIR)
    if refused:
        logger.error(
            "ML: refused %d model file(s) in %s for failing integrity checks",
            refused, _MODEL_DIR,
        )
    return loaded


def score_user(user_id: int, rpm: float, failed_auth: float, body_bytes: int = 0,
               hour: int | None = None) -> dict | None:
    """
    Feed one observation into the per-user model and return an anomaly dict if
    the point is an ML-flagged outlier, else None.

    Returns:
      {"threat_type": "ml_anomaly",
       "risk_score": float,
       "reason": "isolation_score=-0.71 samples=120"}
    """
    if not SKLEARN_AVAILABLE:
        return None

    from datetime import datetime

    # UTC, not local: datetime.now() made the 4th feature depend on the
    # machine timezone, so a persisted model scored differently after a
    # host move and models were not portable between environments.
    hour = hour if hour is not None else datetime.now(UTC).hour
    vec = _feature_vector(rpm, failed_auth, body_bytes, hour)

    with _lock:
        hist = _touch_user(user_id)
        hist.append(vec)
        _since_refit[user_id] += 1

        # Refit periodically once enough samples exist. Scheduled, not inline:
        # see _schedule_fit. _since_refit is zeroed by the worker once the fit
        # lands, so the counter keeps climbing until then and the in-flight
        # guard prevents a resubmission storm.
        if _since_refit[user_id] >= REFIT_EVERY:
            _schedule_fit(user_id)

        model = _models.get(user_id)
        if model is None and len(hist) >= MIN_SAMPLES:
            _schedule_fit(user_id)

        if model is None:
            return None  # not enough history yet

        try:
            score = float(model.decision_function([vec])[0])
        except Exception as exc:  # pragma: no cover
            logger.warning("ML scoring failed for user=%s: %s", user_id, exc)
            return None

    if score >= ANOMALY_THRESHOLD:
        return None  # normal behaviour

    # Anomaly → risk climbs as the point gets more isolated
    risk = min(RISK_CAP, RISK_BASE + (ANOMALY_THRESHOLD - score) * 0.35)
    reason = (
        f"isolation_score={score:.2f} "
        f"rpm={rpm:.1f} samples={len(_history.get(user_id, ()))}"
    )
    logger.warning(
        "ML anomaly: user=%s %s (risk=%.2f)", user_id, reason, risk,
    )
    return {
        "threat_type": "ml_anomaly",
        "risk_score": round(risk, 3),
        "reason": reason,
    }


# ── Test helper ───────────────────────────────────────────────────────────────
def fit_synthetic_for_test(user_id: int, n: int = 60, seed: int = 7) -> None:
    """
    Populate a user's history with synthetic 'normal' traffic so a model can
    be fitted deterministically. Used by unit tests.
    """
    import random

    rng = random.Random(seed)
    with _lock:
        # _touch_user rather than a bare assignment, so the synthetic user is
        # registered in the LRU like any other and the eviction cap still holds.
        hist = _touch_user(user_id)
        hist.clear()
        for _ in range(n):
            rpm = rng.uniform(1, 8)
            fails = rng.uniform(0, 2)
            body = rng.uniform(50, 1200)
            hour = rng.randint(8, 22)
            hist.append(_feature_vector(rpm, fails, body, hour))
    # Outside the `with` block: _fit now takes _lock itself, and
    # threading.Lock is not reentrant. Called synchronously (not scheduled) so
    # tests can assert on the model immediately after this returns.
    _fit(user_id)
