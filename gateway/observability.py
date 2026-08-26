"""
gateway/observability.py
-------------------------
OpenTelemetry + Prometheus instrumentation setup.

Configures distributed tracing and metrics collection for the gateway.
Traces flow through: Request → Middleware → Route → Proxy → Upstream,
giving full visibility into latency and error sources.

Disabled gracefully if opentelemetry packages are unavailable.
"""

import logging
import os

logger = logging.getLogger(__name__)

_TRACING_ENABLED = False


def setup_telemetry(app):
    """Wire OpenTelemetry tracing + Prometheus metrics into the FastAPI app."""
    global _TRACING_ENABLED

    if os.environ.get("OTEL_DISABLED", "").lower() in ("1", "true"):
        logger.info("OpenTelemetry disabled via OTEL_DISABLED env var.")
        return

    try:
        from opentelemetry import trace
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

        from gateway.config import APP_VERSION

        resource = Resource.create({
            "service.name": "zero-trust-gateway",
            "service.version": APP_VERSION,
            "deployment.environment": os.environ.get("ENVIRONMENT", "development"),
        })

        provider = TracerProvider(resource=resource)

        # Export to console in dev; replace with OTLP exporter in production
        if os.environ.get("ENVIRONMENT", "development") == "development":
            exporter = ConsoleSpanExporter()
        else:
            try:
                from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
                exporter = OTLPSpanExporter()
            except ImportError:
                exporter = ConsoleSpanExporter()

        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)

        FastAPIInstrumentor.instrument_app(app)
        _TRACING_ENABLED = True
        logger.info("OpenTelemetry tracing enabled (service.name=zero-trust-gateway)")

    except ImportError as e:
        logger.info("OpenTelemetry not available (%s) — tracing disabled.", e)
    except Exception as e:
        logger.warning("OpenTelemetry setup failed: %s — tracing disabled.", e)


def setup_prometheus(app):
    """Add Prometheus metrics endpoint at /metrics."""
    try:
        from prometheus_client import make_asgi_app

        # NOTE: a `gateway_requests_total` Counter and a
        # `gateway_request_duration_seconds` Histogram used to be constructed
        # here and returned to the caller. `main.py` calls
        # `setup_prometheus(app)` and discards the return value, so nothing ever
        # held a reference to increment them — but constructing a collector
        # registers it in the default Prometheus registry, so /metrics exported
        # both series pinned at zero forever. A dashboard or alert built on
        # `rate(gateway_requests_total[5m])` would have read a flat 0 through a
        # live flood and looked healthy. An absent metric fails loudly when you
        # query it; a metric that is always 0 does not. Removed rather than
        # wired up because the ASGI-level request instrumentation belongs in
        # `middleware/logging.py`, which already measures duration per request.
        metrics_app = make_asgi_app()
        app.mount("/metrics", metrics_app)
        logger.info("Prometheus metrics endpoint enabled at /metrics")

    except ImportError:
        logger.info("prometheus_client not available — metrics disabled.")
