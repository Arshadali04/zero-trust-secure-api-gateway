"""
gateway/routes/analytics.py
-----------------------------
Analytics endpoints for admin security dashboards.

Provides aggregated, time-bucketed statistics for charts:
  GET /admin/analytics/threat-timeline   — per-hour threat counts (last N hours)
  GET /admin/analytics/top-ips           — ranked attacker IPs with stats
  GET /admin/analytics/threat-breakdown  — counts by threat type (for donut chart)
  GET /admin/analytics/user-risk-dist    — risk score distribution across users
  GET /admin/analytics/summary           — single-object KPI summary for dashboard
"""

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.db.database import get_db
from gateway.db.models import AuditLog, BlockedIP, SecurityEvent, User
from gateway.dependencies import require_admin_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin/analytics", tags=["Analytics"])


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _bucket_hour(dt: datetime) -> str:
    """Format a datetime as 'HH:00' label for chart X-axis."""
    return dt.strftime("%H:00")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/threat-timeline")
async def threat_timeline(
    hours: int = Query(24, ge=1, le=168, description="Number of hours to look back"),
    _admin=Depends(require_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Return per-hour bucketed threat counts for the last N hours.

    Response shape:
      {
        "labels": ["00:00", "01:00", ...],
        "series": {
          "sql_injection": [0, 2, 0, ...],
          "xss": [1, 0, 0, ...],
          ...
        },
        "total": 42
      }
    """
    cutoff = _utcnow() - timedelta(hours=hours)

    # Fetch all security events in the window
    result = await db.execute(
        select(SecurityEvent.threat_type, SecurityEvent.timestamp)
        .where(SecurityEvent.timestamp >= cutoff)
        .order_by(SecurityEvent.timestamp.asc())
    )
    rows = result.all()

    # Build hour buckets
    now = _utcnow()
    buckets: list[datetime] = []
    for h in range(hours - 1, -1, -1):
        bucket_start = (now - timedelta(hours=h)).replace(minute=0, second=0, microsecond=0)
        buckets.append(bucket_start)

    labels = [_bucket_hour(b) for b in buckets]

    # Collect all threat types present
    all_types: set[str] = set()
    for threat_type, _ in rows:
        all_types.add(threat_type)

    # Zero-fill series
    series: dict[str, list[int]] = {t: [0] * len(buckets) for t in sorted(all_types)}

    for threat_type, ts in rows:
        if ts is None:
            continue
        # Normalise timezone-naive timestamps to UTC
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        # Find which bucket this event falls into
        for i, bucket in enumerate(buckets):
            bucket_end = bucket + timedelta(hours=1)
            if bucket <= ts < bucket_end:
                if threat_type in series:
                    series[threat_type][i] += 1
                break

    total = sum(sum(v) for v in series.values())

    return {
        "labels": labels,
        "series": series,
        "total": total,
        "hours": hours,
    }


@router.get("/top-ips")
async def top_ips(
    limit: int = Query(15, ge=1, le=50),
    hours: int = Query(24, ge=1, le=168),
    _admin=Depends(require_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Return top attacking IPs with aggregated statistics.

    Response shape:
      [
        {
          "ip": "1.2.3.4",
          "total_events": 42,
          "threat_types": ["sql_injection", "xss"],
          "max_risk_score": 0.95,
          "last_seen": "2026-09-30T03:00:00Z",
          "is_blocked": true
        },
        ...
      ]
    """
    cutoff = _utcnow() - timedelta(hours=hours)

    # Aggregate per-IP stats from security_events
    agg_result = await db.execute(
        select(
            SecurityEvent.ip_address,
            func.count(SecurityEvent.id).label("total_events"),
            func.max(SecurityEvent.risk_score).label("max_risk_score"),
            func.max(SecurityEvent.timestamp).label("last_seen"),
        )
        .where(SecurityEvent.timestamp >= cutoff)
        .group_by(SecurityEvent.ip_address)
        .order_by(func.count(SecurityEvent.id).desc())
        .limit(limit)
    )
    ip_rows = agg_result.all()

    if not ip_rows:
        return []

    # Collect threat types per IP
    ip_list = [row.ip_address for row in ip_rows]
    types_result = await db.execute(
        select(SecurityEvent.ip_address, SecurityEvent.threat_type)
        .where(
            SecurityEvent.ip_address.in_(ip_list),
            SecurityEvent.timestamp >= cutoff,
        )
        .distinct()
    )
    ip_types: dict[str, set[str]] = {}
    for ip, ttype in types_result.all():
        ip_types.setdefault(ip, set()).add(ttype)

    # Check which IPs are currently blocked
    blocked_result = await db.execute(
        select(BlockedIP.ip_address).where(BlockedIP.ip_address.in_(ip_list))
    )
    blocked_ips = {row[0] for row in blocked_result.all()}

    output = []
    for row in ip_rows:
        last_seen = row.last_seen
        if last_seen and last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        output.append({
            "ip": row.ip_address,
            "total_events": row.total_events,
            "threat_types": sorted(ip_types.get(row.ip_address, set())),
            "max_risk_score": round(float(row.max_risk_score or 0), 3),
            "last_seen": last_seen.isoformat() if last_seen else None,
            "is_blocked": row.ip_address in blocked_ips,
        })

    return output


@router.get("/threat-breakdown")
async def threat_breakdown(
    hours: int = Query(24, ge=1, le=168),
    _admin=Depends(require_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Return threat type counts for a donut/pie chart.

    Response shape:
      [
        {"threat_type": "sql_injection", "label": "SQL Injection", "count": 18, "color": "#ff5d5d"},
        ...
      ]
    """
    from gateway.middleware.waf import THREAT_LABELS

    cutoff = _utcnow() - timedelta(hours=hours)

    result = await db.execute(
        select(SecurityEvent.threat_type, func.count(SecurityEvent.id).label("cnt"))
        .where(SecurityEvent.timestamp >= cutoff)
        .group_by(SecurityEvent.threat_type)
        .order_by(func.count(SecurityEvent.id).desc())
    )
    rows = result.all()

    # Color palette for threat types (deterministic)
    _COLORS = {
        "sql_injection": "#ff5d5d",
        "xss": "#ffb636",
        "path_traversal": "#ff8c42",
        "command_injection": "#e040fb",
        "ssrf": "#ff6b9d",
        "xxe": "#ff4081",
        "ldap_injection": "#7c4dff",
        "prototype_pollution": "#40c4ff",
        "failed_login": "#5b8cff",
        "ml_anomaly": "#2dd4a0",
        "high_risk_request": "#ff7043",
        "impossible_travel": "#26c6da",
        "rapid_ip_change": "#ec407a",
    }

    return [
        {
            "threat_type": row.threat_type,
            "label": THREAT_LABELS.get(row.threat_type, row.threat_type.replace("_", " ").title()),
            "count": row.cnt,
            "color": _COLORS.get(row.threat_type, "#8899aa"),
        }
        for row in rows
    ]


@router.get("/user-risk-dist")
async def user_risk_distribution(
    _admin=Depends(require_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Return distribution of user risk scores across risk tiers.

    Response shape:
      {
        "low": 34,       # risk_score < 0.3
        "medium": 8,     # 0.3 <= risk_score < 0.55
        "high": 3,       # 0.55 <= risk_score < 0.85
        "critical": 1,   # risk_score >= 0.85
        "total": 46
      }
    """
    result = await db.execute(
        select(User.risk_score).where(User.is_active == True)  # noqa: E712
    )
    scores = [float(row[0] or 0) for row in result.all()]

    dist = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for s in scores:
        if s >= 0.85:
            dist["critical"] += 1
        elif s >= 0.55:
            dist["high"] += 1
        elif s >= 0.30:
            dist["medium"] += 1
        else:
            dist["low"] += 1

    dist["total"] = len(scores)
    return dist


@router.get("/summary")
async def analytics_summary(
    _admin=Depends(require_admin_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Single-call KPI summary for the admin dashboard header cards.

    Response shape:
      {
        "threats_24h": 42,
        "blocked_ips": 7,
        "active_users": 46,
        "high_risk_users": 4,
        "waf_blocks_24h": 18,
        "top_threat_type": "sql_injection",
        "avg_risk_score": 0.12
      }
    """
    now = _utcnow()
    cutoff_24h = now - timedelta(hours=24)

    # Threats in last 24h
    r1 = await db.execute(
        select(func.count(SecurityEvent.id))
        .where(SecurityEvent.timestamp >= cutoff_24h)
    )
    threats_24h = r1.scalar() or 0

    # WAF blocks in last 24h (status='blocked')
    r2 = await db.execute(
        select(func.count(SecurityEvent.id))
        .where(SecurityEvent.timestamp >= cutoff_24h, SecurityEvent.status == "blocked")
    )
    waf_blocks_24h = r2.scalar() or 0

    # Currently blocked IPs
    r3 = await db.execute(select(func.count(BlockedIP.id)))
    blocked_ips = r3.scalar() or 0

    # Active users
    r4 = await db.execute(
        select(func.count(User.id)).where(User.is_active == True)  # noqa: E712
    )
    active_users = r4.scalar() or 0

    # High/critical risk users
    r5 = await db.execute(
        select(func.count(User.id))
        .where(User.is_active == True, User.risk_score >= 0.55)  # noqa: E712
    )
    high_risk_users = r5.scalar() or 0

    # Average risk score
    r6 = await db.execute(
        select(func.avg(User.risk_score)).where(User.is_active == True)  # noqa: E712
    )
    avg_risk_raw = r6.scalar()
    avg_risk_score = round(float(avg_risk_raw or 0), 3)

    # Top threat type in last 24h
    r7 = await db.execute(
        select(SecurityEvent.threat_type, func.count(SecurityEvent.id).label("cnt"))
        .where(SecurityEvent.timestamp >= cutoff_24h)
        .group_by(SecurityEvent.threat_type)
        .order_by(func.count(SecurityEvent.id).desc())
        .limit(1)
    )
    top_row = r7.first()
    top_threat_type = top_row[0] if top_row else None

    # Recent audit requests (last 1h)
    r8 = await db.execute(
        select(func.count(AuditLog.id))
        .where(AuditLog.timestamp >= (now - timedelta(hours=1)))
    )
    requests_1h = r8.scalar() or 0

    return {
        "threats_24h": threats_24h,
        "waf_blocks_24h": waf_blocks_24h,
        "blocked_ips": blocked_ips,
        "active_users": active_users,
        "high_risk_users": high_risk_users,
        "avg_risk_score": avg_risk_score,
        "top_threat_type": top_threat_type,
        "requests_1h": requests_1h,
    }
