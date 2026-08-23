"""
gateway/detection/context_validation.py
----------------------------------------
Impossible-travel detection and login-context validation.

On login, the gateway compares the login IP to the IP of the previous login and
asks whether the implied journey is physically possible in the elapsed time.

TWO MODES, AND THE DIFFERENCE IS DELIBERATE AND VISIBLE
-------------------------------------------------------
1. GeoIP mode (accurate). If a MaxMind GeoLite2-City database is present and a
   reader library is importable, both IPs are resolved to coordinates, the
   great-circle distance is computed, and the login is flagged when the implied
   travel speed exceeds what any commercial flight could achieve. This is the
   mode `data/geoip/.gitkeep` was written for.

2. Degraded mode (`rapid_ip_change`). Without GeoIP there is no way to know
   where an IP is, so no honest claim about travel can be made. Rather than
   guess, this module falls back to a narrower claim it *can* support — two
   logins from different public networks within RAPID_CHANGE_WINDOW — reports it
   under `method="rapid_ip_change"` at a lower risk score, and logs once at
   WARNING so a degraded detector is never mistaken for a working one.

WHAT THIS REPLACES, AND WHY IT HAD TO GO
----------------------------------------
The previous implementation scored the *arithmetic difference between the first
two octets* of the two addresses and called the result a geographic distance:

    diff  = abs(a[0] - b[0]) / 255.0
    diff += abs(a[1] - b[1]) / (255.0 * 4)

IP address numbering is not geographic, so that number carried no information
about the real world. Two worked examples, both from the shipped thresholds:

  * 1.2.3.4 -> 2.3.4.5 scored 0.005 and was NOT flagged. Those /8s belong to
    APNIC and RIPE respectively — plausibly Australia to France, roughly
    16,000 km, which is the single clearest impossible-travel case there is.
  * 45.x -> 194.x scored 0.584 and WAS flagged, over the 0.4 threshold. Both
    ranges are heavily used in Europe, so this routinely fired on a user who
    merely changed ISP or moved between mobile and home broadband.

So the detector was close to anti-correlated with the thing it claimed to
measure, and a false positive was not free: the caller feeds it into
`elevate_account_risk(..., 0.25)`, which pushes a user toward step-up MFA and
eventually a one-hour account freeze. Flagging nothing is strictly better than
flagging the wrong user, which is why degraded mode is narrow on purpose.

ENABLING ACCURATE MODE
----------------------
    pip install geoip2==4.8.0
    # download GeoLite2-City.mmdb (free, requires a MaxMind account) into:
    #   data/geoip/GeoLite2-City.mmdb
Override the path with GATEWAY_GEOIP_DB. Nothing else changes; the module
detects the database at first use and upgrades itself.

On detection a SecurityEvent is written with threat_type='impossible_travel'.
"""

import ipaddress
import logging
import math
import os
from datetime import datetime, timedelta, UTC
from threading import Lock

logger = logging.getLogger(__name__)

# ── GeoIP configuration ───────────────────────────────────────────────────────
_GEOIP_DB_PATH = os.environ.get("GATEWAY_GEOIP_DB") or os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "data", "geoip", "GeoLite2-City.mmdb",
)

# Fastest plausible door-to-door average for a real journey, in km/h.
# Commercial cruise is ~900 km/h; the allowance above that absorbs tailwinds and
# the fact that `elapsed` is measured from the previous *login*, not from
# departure. Anything faster than this is not travel.
MAX_PLAUSIBLE_KMH = 1000.0

# Below this, no speed is implausible enough to be worth an event — it is the
# same metro area and GeoIP city coordinates are only accurate to a few tens of
# km anyway, so short "journeys" are mostly geolocation error.
MIN_DISTANCE_KM = 300.0

# Degraded mode only: two logins from different public networks inside this
# window. Deliberately tight. A wider window turns an ordinary WiFi-to-cellular
# handover into a security event, and mobile users change public IP constantly.
RAPID_CHANGE_WINDOW = timedelta(minutes=5)

# Beyond this, any journey on Earth is possible, so there is nothing to detect.
MAX_TRAVEL_WINDOW = timedelta(hours=24)

_geoip_reader = None
_geoip_state = "unloaded"   # unloaded | ready | unavailable
_geoip_lock = Lock()
_degraded_warned = False


def _get_geoip_reader():
    """Return an open GeoIP reader, or None. Result is cached after first call.

    Import and file check happen once. A missing database is the normal case for
    a fresh clone, so it is reported at INFO rather than as an error.
    """
    global _geoip_reader, _geoip_state
    if _geoip_state != "unloaded":
        return _geoip_reader
    with _geoip_lock:
        if _geoip_state != "unloaded":
            return _geoip_reader
        if not os.path.isfile(_GEOIP_DB_PATH):
            _geoip_state = "unavailable"
            logger.info(
                "GeoIP database not found at %s — impossible-travel detection "
                "runs in degraded mode. See data/geoip/.gitkeep to enable it.",
                _GEOIP_DB_PATH,
            )
            return None
        try:
            import geoip2.database
            _geoip_reader = geoip2.database.Reader(_GEOIP_DB_PATH)
            _geoip_state = "ready"
            logger.info("GeoIP database loaded from %s", _GEOIP_DB_PATH)
        except ImportError:
            _geoip_state = "unavailable"
            logger.warning(
                "GeoIP database exists at %s but the geoip2 package is not "
                "installed — running in degraded mode. `pip install geoip2` to "
                "enable accurate impossible-travel detection.",
                _GEOIP_DB_PATH,
            )
        except Exception as exc:
            _geoip_state = "unavailable"
            logger.error(
                "GeoIP database at %s could not be opened (%s: %s) — degraded "
                "mode. The file may be truncated or not a MaxMind DB.",
                _GEOIP_DB_PATH, type(exc).__name__, exc,
            )
    return _geoip_reader


def _is_private(ip: str) -> bool:
    """True for anything with no meaningful public location.

    Uses the stdlib `ipaddress` module rather than string prefixes. The old
    prefix tuple missed carrier-grade NAT (100.64.0.0/10), link-local
    (169.254.0.0/16), every IPv6 private range beyond a literal '::1', and the
    reserved blocks — so a login from a CGNAT mobile network was treated as a
    public address with a real location.

    The test is `not is_global`, not `is_private`. They are not complements:
    CPython's `_private_networks` does not contain 100.64.0.0/10, so
    `ipaddress.ip_address("100.64.0.1").is_private` is False (verified on 3.10)
    even though shared address space per RFC 6598 has no locatable position.
    `is_global` excludes it correctly, and covers private, loopback, link-local,
    reserved, multicast and unspecified for both IPv4 and IPv6 in one predicate.
    This matters in practice: mobile carriers use CGNAT heavily, so treating
    those as public would resolve the carrier's egress point and could produce a
    travel flag for a user who never left their sofa.
    """
    if not ip or ip == "unknown":
        return True
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return True   # not an address we can reason about → do not flag
    # `is_multicast` is checked separately because CPython reports multicast as
    # global (it is globally routable in the addressing sense). A multicast
    # address is meaningless as the *source* of a login, and get_client_ip reads
    # X-Forwarded-For, which the client controls — so this is reachable input.
    return (not addr.is_global) or addr.is_multicast


def _coordinates(ip: str) -> tuple[float, float] | None:
    """(latitude, longitude) for *ip*, or None if it cannot be located."""
    reader = _get_geoip_reader()
    if reader is None:
        return None
    try:
        resp = reader.city(ip)
    except Exception:
        # AddressNotFoundError is routine — GeoLite2 does not cover every
        # address. DEBUG, because at WARNING this would be very noisy.
        logger.debug("GeoIP lookup miss for %s", ip)
        return None
    lat, lon = resp.location.latitude, resp.location.longitude
    if lat is None or lon is None:
        return None
    return float(lat), float(lon)


def _haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    """Great-circle distance in kilometres between two (lat, lon) pairs."""
    radius = 6371.0088
    lat1, lon1 = math.radians(a[0]), math.radians(a[1])
    lat2, lon2 = math.radians(b[0]), math.radians(b[1])
    dlat, dlon = lat2 - lat1, lon2 - lon1
    h = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return 2 * radius * math.asin(math.sqrt(min(1.0, h)))


def _elapsed_since(last_login) -> timedelta | None:
    """Time since *last_login*, or None if it cannot be interpreted."""
    if last_login is None:
        return None
    try:
        if isinstance(last_login, str):
            last_login = datetime.fromisoformat(last_login.replace("Z", "+00:00"))
        if last_login.tzinfo is None:
            # SQLite hands back naive datetimes; the app writes UTC.
            last_login = last_login.replace(tzinfo=UTC)
        return datetime.now(UTC) - last_login
    except Exception as exc:
        # Previously `except Exception: return None`, which silently disabled the
        # whole check for that login. Unparseable timestamps mean the detector is
        # blind, and that is worth knowing about.
        logger.warning(
            "Could not interpret previous login timestamp %r (%s: %s) — "
            "impossible-travel check skipped for this login",
            last_login, type(exc).__name__, exc,
        )
        return None


async def check_impossible_travel(
    user_id: int,
    current_ip: str,
    db,
    previous_login=None,
) -> dict | None:
    """Flag a login whose implied journey from the previous login is impossible.

    Returns None when the login is plausible, unmeasurable, or the detector is
    blind. On a flag, returns a dict with:
        threat_type, last_ip, current_ip, risk_score, method, detail,
        distance_km (float or None), distance (kept for backwards compatibility)
    """
    from sqlalchemy import select
    from gateway.db.models import User

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        return None

    last_ip = getattr(user, "last_login_ip", None)
    # Prefer the caller-supplied previous_login. The login route must overwrite
    # user.last_login as part of signing the user in, and SQLAlchemy's identity
    # map would otherwise hand back the *new* timestamp, making `elapsed` always
    # ~0 so the suppression windows below could never apply.
    last_login = previous_login if previous_login is not None else getattr(user, "last_login", None)

    if not last_ip or not current_ip:
        return None            # first login — nothing to compare against
    if last_ip == current_ip:
        return None            # did not move
    if _is_private(current_ip) or _is_private(last_ip):
        return None            # no meaningful location for at least one endpoint

    elapsed = _elapsed_since(last_login)
    if elapsed is None or elapsed < timedelta(0):
        return None
    if elapsed > MAX_TRAVEL_WINDOW:
        return None            # a day is long enough to reach anywhere

    hours = max(elapsed.total_seconds() / 3600.0, 1.0 / 3600.0)  # floor at 1s

    # ── Accurate mode ─────────────────────────────────────────────────────────
    here, there = _coordinates(current_ip), _coordinates(last_ip)
    if here and there:
        distance_km = _haversine_km(there, here)
        implied_kmh = distance_km / hours
        if distance_km < MIN_DISTANCE_KM or implied_kmh <= MAX_PLAUSIBLE_KMH:
            return None

        # Risk scales with how far past plausible the implied speed is: 1x over
        # the limit starts at the base, 3x or more saturates.
        overage = min((implied_kmh / MAX_PLAUSIBLE_KMH - 1.0) / 2.0, 1.0)
        risk = round(min(0.60 + 0.35 * overage, 0.95), 3)
        detail = (
            f"{distance_km:.0f}km in {elapsed.total_seconds() / 60:.0f}min "
            f"=> {implied_kmh:.0f}km/h (max plausible {MAX_PLAUSIBLE_KMH:.0f})"
        )
        logger.warning(
            "IMPOSSIBLE TRAVEL (geoip): user_id=%s %s -> %s %s",
            user_id, last_ip, current_ip, detail,
        )
        return {
            "threat_type": "impossible_travel",
            "method": "geoip",
            "last_ip": last_ip,
            "current_ip": current_ip,
            "distance_km": round(distance_km, 1),
            "distance": round(distance_km, 1),
            "detail": detail,
            "risk_score": risk,
        }

    # ── Degraded mode ─────────────────────────────────────────────────────────
    # No coordinates for at least one address. Make only the claim that is
    # actually supportable: two different public networks, very close together
    # in time. This is not a travel measurement and is not labelled as one.
    global _degraded_warned
    if not _degraded_warned:
        _degraded_warned = True
        logger.warning(
            "Impossible-travel detection is running in DEGRADED mode (no GeoIP "
            "coordinates for %s / %s). Only rapid public-IP changes within %s "
            "are reported, at reduced risk. Install geoip2 and GeoLite2-City.mmdb "
            "for real detection — see data/geoip/.gitkeep",
            last_ip, current_ip, RAPID_CHANGE_WINDOW,
        )

    if elapsed > RAPID_CHANGE_WINDOW:
        return None

    detail = (
        f"login from a different public network {elapsed.total_seconds():.0f}s "
        f"after the previous one; distance unknown (no GeoIP data)"
    )
    logger.warning(
        "RAPID IP CHANGE: user_id=%s %s -> %s (%s)",
        user_id, last_ip, current_ip, detail,
    )
    return {
        "threat_type": "impossible_travel",
        "method": "rapid_ip_change",
        "last_ip": last_ip,
        "current_ip": current_ip,
        "distance_km": None,
        # Backwards compatibility: callers that format `distance` as a float
        # still work. 0.0 rather than a fabricated number, because in this mode
        # the distance is genuinely unknown.
        "distance": 0.0,
        "detail": detail,
        "risk_score": 0.45,
    }
