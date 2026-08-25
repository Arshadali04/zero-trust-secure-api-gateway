"""
simulate_attack.py
------------------
Demonstrates the Zero Trust Gateway's adaptive risk scoring and WAF.

Sends two phases of traffic:
  Phase 1 — Repeated requests from a suspicious scanner UA with an invalid token.
            Behavior risk rises as request volume increases.
            Once blocked, moves to Phase 2.

  Phase 2 — SQL injection payloads in URL/body/headers.
            WAF detects and blocks them instantly.

Run the gateway first:
    python run.py

Then in another terminal:
    python scripts/simulate_attack.py
"""

import urllib.request
import urllib.error
import time

# ── Configuration ────────────────────────────────────────────────────────────
BASE_URL = "http://127.0.0.1:8000"
TARGET_ENDPOINT = "/auth/me"
PHASE1_REQUESTS = 130      # enough to push behavior risk past the 0.80 block threshold
DELAY_BETWEEN_REQUESTS = 0.05  # seconds — lets the sliding-window counter work correctly
CONCURRENCY = 1             # sequential to show score progression clearly

# Phase 1 headers: suspicious scanner UA + invalid token → max auth + pattern risk
SCANNER_HEADERS = {
    "User-Agent": "sqlmap/1.5.8#dev (http://sqlmap.org)",
    "Authorization": "Bearer INVALID_SIMULATED_TOKEN_123456",
}

# Phase 2: SQL injection payloads to demonstrate WAF
SQLI_PAYLOADS = [
    {"url_param": "id=1' UNION SELECT username,password FROM users--"},
    {"body": '{"query": "SELECT * FROM users WHERE id=1; DROP TABLE users;--"}'},
    {"header": {"Referer": "http://evil.com/?search=1 OR 1=1"}},
    {"header": {"User-Agent": "Mozilla/5.0 sqlmap/1.5"}},
    {"url_param": "q='; DELETE FROM users WHERE 1=1--"},
]


def _make_request(url, headers=None):
    """Send a GET request and return (status_code, risk_score, risk_action, extra)."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return (
                resp.status,
                resp.headers.get("X-Risk-Score", "-"),
                resp.headers.get("X-Risk-Action", "-"),
                resp.headers.get("X-WAF-Blocked", ""),
                resp.read().decode(errors="replace")[:200],
            )
    except urllib.error.HTTPError as e:
        # The headers live on the underlying response object
        resp_headers = e.headers
        return (
            e.code,
            resp_headers.get("X-Risk-Score", "-") if resp_headers else "-",
            resp_headers.get("X-Risk-Action", "-") if resp_headers else "-",
            resp_headers.get("X-WAF-Blocked", "") if resp_headers else "",
            e.read().decode(errors="replace")[:200],
        )
    except Exception as e:
        return (0, "-", "-", "", str(e))


def _action_label(action):
    colors = {"allow": "\033[92m", "monitor": "\033[93m", "challenge": "\033[93m", "block": "\033[91m"}
    reset = "\033[0m"
    return f"{colors.get(action, '')}{action.upper()}{reset}"


# ── Phase 1: Brute-force / scanner traffic ───────────────────────────────────

def phase1():
    print("=" * 62)
    print("  PHASE 1 — ADAPTIVE RISK SCORING (scanner traffic)")
    print("=" * 62)
    print(f"  Target : {BASE_URL}{TARGET_ENDPOINT}")
    print("  UA     : sqlmap/1.5.8#dev")
    print("  Token  : INVALID (max auth risk)")
    print(f"  Requests: {PHASE1_REQUESTS}  |  Delay: {DELAY_BETWEEN_REQUESTS}s between each")
    print("-" * 62)

    blocked_count = 0
    score_history = []

    for i in range(1, PHASE1_REQUESTS + 1):
        status, score, action, waf, body = _make_request(
            f"{BASE_URL}{TARGET_ENDPOINT}",
            headers=SCANNER_HEADERS,
        )

        score_history.append(score)

        # Only print key transitions to keep output readable
        if action == "block" and (i == 1 or score_history[-2] != score_history[-1]):
            print(f"  [{i:>4}] Status {status} | Risk {score} | {_action_label(action)}  ← BLOCKED")
            blocked_count += 1
        elif i <= 5 or i % 20 == 0 or i == PHASE1_REQUESTS:
            print(f"  [{i:>4}] Status {status} | Risk {score} | {_action_label(action)}")
            if action == "block":
                blocked_count += 1

        time.sleep(DELAY_BETWEEN_REQUESTS)

    print("-" * 62)
    print(f"  Phase 1 complete.  Blocked: {blocked_count}/{PHASE1_REQUESTS}")
    print()
    return blocked_count


# ── Phase 2: SQL injection / WAF ─────────────────────────────────────────────

def phase2():
    print("=" * 62)
    print("  PHASE 2 — WAF DETECTION (SQL injection payloads)")
    print("=" * 62)

    passed_user = SCANNER_HEADERS.get("Authorization", "none")

    for i, payload in enumerate(SQLI_PAYLOADS, 1):
        # Build the request URL and headers for this payload
        if "url_param" in payload:
            url = f"{BASE_URL}{TARGET_ENDPOINT}?{payload['url_param']}"
            headers = {"Authorization": passed_user, "User-Agent": "Mozilla/5.0"}
        elif "header" in payload:
            url = f"{BASE_URL}{TARGET_ENDPOINT}"
            headers = {**SCANNER_HEADERS, **payload["header"]}
        else:
            url = f"{BASE_URL}{TARGET_ENDPOINT}"
            headers = {"Authorization": passed_user, "User-Agent": "Mozilla/5.0"}

        status, score, action, waf_blocked, body = _make_request(url, headers)

        threat = waf_blocked if waf_blocked else "none"
        # The WAF returns 403, not 400 (gateway/middleware/waf.py). This line
        # tested `status == 400`, so the "BLOCKED" label could never render and
        # every genuinely blocked request printed as "Status 403" — the script
        # silently under-reported the thing it exists to demonstrate.
        label = "BLOCKED" if status == 403 and waf_blocked else f"Status {status}"
        print(f"  [{i}] {label:20s} | Threat: {threat:20s} | Score: {score}")

        # Show WAF detail for blocked requests
        if waf_blocked:
            try:
                import json
                detail = json.loads(body).get("threat_type", "?")
                print(f"       └─ WAF blocked: {detail}")
            except Exception as exc:
                # The gateway said it blocked this but the body isn't the JSON
                # shape we expect. Say so instead of printing nothing — a silent
                # gap here reads as "no detail available" when it actually means
                # the response contract changed.
                print(f"       └─ WAF blocked, but could not parse detail "
                      f"({type(exc).__name__}: {exc}); raw={body[:120]!r}")

    print("-" * 62)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print()
    print("\033[1;31m╔══════════════════════════════════════════════════════════════╗\033[0m")
    print("\033[1;31m║   ZERO TRUST GATEWAY — ATTACK SIMULATION                    ║\033[0m")
    print("\033[1;31m╚══════════════════════════════════════════════════════════════╝\033[0m")
    print()
    print("  Make sure the gateway is running:  python run.py")
    print()

    start = time.time()

    # Phase 1
    phase1()

    # Phase 2
    phase2()

    elapsed = time.time() - start
    print(f"  Total time: {elapsed:.1f}s")
    print()
    print("  Next steps:")
    print("   → Open http://127.0.0.1:8000/frontend/admin.html")
    print("   → Check Audit Logs for 'blocked' events")
    print("   → Check Security Events for 'sql_injection' detections")
    print()


if __name__ == "__main__":
    main()
