import urllib.request
import urllib.error
import time
import concurrent.futures

# URL to target for the simulation
TARGET_URL = "http://127.0.0.1:8000/auth/me"

# Headers that will increase Pattern Risk score
HEADERS = {
    "User-Agent": "sqlmap/1.5.8#dev (http://sqlmap.org)",
    "Authorization": "Bearer INVALID_SIMULATED_TOKEN_123456"
}

# Number of requests to trigger Behavior Risk (>120 requests/min for 0.9 score)
NUM_REQUESTS = 130
CONCURRENCY = 10

def fetch(i):
    req = urllib.request.Request(TARGET_URL, headers=HEADERS)
    try:
        with urllib.request.urlopen(req) as response:
            # Usually we won't hit this block because we get 401/403
            status = response.status
            risk_score = response.headers.get("X-Risk-Score", "N/A")
            risk_action = response.headers.get("X-Risk-Action", "N/A")
            print(f"[-] Request {i}: Status {status} | Risk Score: {risk_score} | Action: {risk_action}")
            return False
    except urllib.error.HTTPError as e:
        status = e.code
        risk_score = e.headers.get("X-Risk-Score", "N/A")
        risk_action = e.headers.get("X-Risk-Action", "N/A")
        
        if status == 403 and risk_action == "block":
            print(f"[!] Request {i}: BLOCKED! (Status 403) | Risk Score: {risk_score}")
            return True # Blocked successfully
        else:
            print(f"[-] Request {i}: Status {status} | Risk Score: {risk_score} | Action: {risk_action}")
            return False
    except Exception as e:
        print(f"Request {i} failed: {e}")
        return False

def main():
    print("=====================================================")
    print("🔴 ZERO TRUST GATEWAY - ADAPTIVE RISK SIMULATOR 🔴")
    print("=====================================================")
    print(f"Target: {TARGET_URL}")
    print("Simulating high-frequency malicious scanner traffic...")
    print("Sending 130 requests to rapidly increase behavior & pattern risk.\n")
    
    blocked_count = 0
    start_time = time.time()
    
    # Use ThreadPoolExecutor to run requests concurrently without external dependencies
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures = {executor.submit(fetch, i): i for i in range(1, NUM_REQUESTS + 1)}
        for future in concurrent.futures.as_completed(futures):
            is_blocked = future.result()
            if is_blocked:
                blocked_count += 1

    elapsed = time.time() - start_time
    print("\n=====================================================")
    print(f"Simulation Complete in {elapsed:.2f} seconds.")
    print(f"Total Requests Sent: {NUM_REQUESTS}")
    print(f"Requests Blocked by Risk Engine: {blocked_count}")
    print("=====================================================")
    print("\nNext Step:")
    print("Go to your Dashboard or Admin Panel to view the 'Critical' Risk Score")
    print("and the 'high_risk_request' events in your Audit Logs!")

if __name__ == "__main__":
    main()
