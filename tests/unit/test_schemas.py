"""
tests/unit/test_schemas.py
--------------------------
Unit tests for schema field serializers in gateway/db/schemas.py.
"""

from datetime import datetime, timezone

from gateway.db.schemas import ApiKeyResponse, AuditLogResponse, SecurityEventResponse, ServiceResponse, UserResponse


def test_schema_datetime_serializers():
    now_naive = datetime(2026, 1, 1, 12, 0, 0)
    now_aware = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

    # AuditLogResponse serializer
    a1 = AuditLogResponse(
        id=1,
        user_id=1,
        action="login",
        method="POST",
        resource="/auth/login",
        ip_address="127.0.0.1",
        user_agent="Mozilla",
        status_code=200,
        timestamp=now_naive,
        details=None,
    )
    assert a1.model_dump()["timestamp"] == now_aware.isoformat()
    a2 = AuditLogResponse(
        id=2,
        user_id=1,
        action="login",
        method="POST",
        resource="/auth/login",
        ip_address="127.0.0.1",
        user_agent="Mozilla",
        status_code=200,
        timestamp=now_aware,
        details=None,
    )
    assert a2.model_dump()["timestamp"] == now_aware.isoformat()

    # SecurityEventResponse serializer
    s1 = SecurityEventResponse(
        id=1,
        timestamp=now_naive,
        threat_type="sqli",
        ip_address="127.0.0.1",
        endpoint="/",
        payload="test",
        risk_score=0.9,
        status="blocked",
    )
    assert s1.model_dump()["timestamp"] == now_aware.isoformat()

    # ServiceResponse serializer
    srv1 = ServiceResponse(
        id=1,
        name="svc",
        slug="svc",
        upstream_url="http://example.com",
        is_active=True,
        created_at=now_naive,
        owner_user_id=1,
    )
    assert srv1.model_dump()["created_at"] == now_aware.isoformat()

    # UserResponse serializer
    u1 = UserResponse(
        id=1,
        email="u@test.com",
        username="testuser",
        role="user",
        is_active=True,
        mfa_enabled=False,
        created_at=now_naive,
        last_login=None,
        account_frozen_until=now_aware,
    )
    u_dump = u1.model_dump()
    assert u_dump["created_at"] == now_aware.isoformat()
    assert u_dump["last_login"] is None
    assert u_dump["account_frozen_until"] == now_aware.isoformat()

    # ApiKeyResponse serializer
    k1 = ApiKeyResponse(
        id=1,
        name="k",
        key_prefix="ztg_abc",
        scopes=["read"],
        is_active=True,
        created_at=now_naive,
        expires_at=None,
        revoked_at=now_aware,
        last_used_at=None,
    )
    k_dump = k1.model_dump()
    assert k_dump["created_at"] == now_aware.isoformat()
    assert k_dump["expires_at"] is None
    assert k_dump["revoked_at"] == now_aware.isoformat()
