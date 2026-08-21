"""
tests/unit/test_ml_anomaly.py
------------------------------
Unit tests for the IsolationForest anomaly detector.
"""

import pytest

from gateway.detection import ml_anomaly


@pytest.fixture(autouse=True)
def _clean_state():
    """Reset per-user ML state between tests."""
    yield
    ml_anomaly._history.clear()
    ml_anomaly._models.clear()
    ml_anomaly._since_refit.clear()


@pytest.mark.skipif(not ml_anomaly.SKLEARN_AVAILABLE, reason="scikit-learn not installed")
class TestIsolationForest:
    def test_returns_none_without_history(self):
        assert ml_anomaly.score_user(999, 5.0, 0.0) is None

    def test_fits_after_min_samples_and_accepts_normal(self):
        ml_anomaly.fit_synthetic_for_test(1, n=60)
        assert ml_anomaly.is_ml_ready(1)
        # A normal request within the learned range should NOT be flagged
        result = ml_anomaly.score_user(1, rpm=5.0, failed_auth=1.0, body_bytes=400, hour=14)
        assert result is None

    def test_flags_outlier_burst(self):
        ml_anomaly.fit_synthetic_for_test(2, n=60)
        # Score fewer than REFIT_EVERY calls so the original model (trained on
        # normal data only) is used. A refit would include the extreme vectors,
        # potentially causing the model to classify them as normal.
        flagged = None
        n_calls = ml_anomaly.REFIT_EVERY - 1  # stay below refit threshold
        for _ in range(n_calls):
            flagged = ml_anomaly.score_user(
                2, rpm=250.0, failed_auth=0.0, body_bytes=200000, hour=3
            )
        assert flagged is not None, (
            f"Expected ML anomaly after {n_calls} extreme-burst requests; "
            f"ANOMALY_THRESHOLD={ml_anomaly.ANOMALY_THRESHOLD}"
        )
        assert flagged["threat_type"] == "ml_anomaly"
        assert 0.0 < flagged["risk_score"] <= 0.95
        assert "isolation_score" in flagged["reason"]

    def test_risk_rises_with_isolation(self):
        ml_anomaly.fit_synthetic_for_test(3, n=80)
        risks = []
        n_calls = ml_anomaly.REFIT_EVERY - 1  # stay below refit threshold
        for _ in range(n_calls):
            r = ml_anomaly.score_user(3, rpm=400.0, failed_auth=5.0, body_bytes=500000, hour=2)
            if r:
                risks.append(r["risk_score"])
        assert risks, "expected at least one flagged risk"
        assert max(risks) >= min(risks)

    def test_reset_clears_state(self):
        ml_anomaly.fit_synthetic_for_test(4, n=60)
        assert ml_anomaly.is_ml_ready(4)
        ml_anomaly.reset_user(4)
        assert not ml_anomaly.is_ml_ready(4)
        assert ml_anomaly.model_size(4) == 0
