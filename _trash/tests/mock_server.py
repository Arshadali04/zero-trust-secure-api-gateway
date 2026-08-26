import http.server
import socketserver
import json
import logging

PORT = 8001

class MockMicroserviceHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    def do_GET(self):
        # Read the headers injected by the Zero Trust Gateway
        user_email = self.headers.get("X-Gateway-User", "Unknown")
        req_id = self.headers.get("X-Request-ID", "Unknown")
        
        # Prepare the response payload
        response_data = {
            "message": "Hello from the backend microservice!",
            "status": "success",
            "metadata": {
                "authenticated_user": user_email,
                "request_id": req_id,
                "note": "This data was protected by the API Gateway"
            }
        }
        
        # Send HTTP 200 OK
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        
        # Send JSON body
        self.wfile.write(json.dumps(response_data, indent=2).encode('utf-8'))
        
        print(f"Served mock data to gateway for user: {user_email}")

def run():
    print("==================================================")
    print("🛡️  MOCK BACKEND MICROSERVICE (Protected Resource)")
    print(f"Running on http://127.0.0.1:{PORT}")
    print("This server does not handle auth. It relies completely")
    print("on the Zero Trust API Gateway to filter traffic.")
    print("==================================================")
    
    class ReusableTCPServer(socketserver.TCPServer):
        allow_reuse_address = True
        
    try:
        with ReusableTCPServer(("127.0.0.1", PORT), MockMicroserviceHandler) as httpd:
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\nShutting down mock server.")
    except Exception as e:
        print(f"\n[ERROR] Failed to start mock server: {e}")
        print(f"Is port {PORT} already in use?")
        sys.exit(1)

if __name__ == "__main__":
    import sys
    run()
