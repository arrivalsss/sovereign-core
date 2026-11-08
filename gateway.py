import http.server
import hmac
import secrets

GATEWAY_AUTH_TOKEN = secrets.token_hex(32)
print(f"[AUTH] Gateway Token: {GATEWAY_AUTH_TOKEN}")

class SecureGatewayHandler(http.server.BaseHTTPRequestHandler):
    timeout = 10

    def do_POST(self):
        auth_header = self.headers.get("Authorization", "")
        expected_header = f"Bearer {GATEWAY_AUTH_TOKEN}"
        
        if not hmac.compare_digest(auth_header.encode(), expected_header.encode()):
            self.send_error(403, "Forbidden: Unauthorized access to local gateway")
            return

        content_type = self.headers.get("Content-Type", "")
        if not content_type.startswith("application/json"):
            self.send_error(415, "Unsupported Media Type: Must be application/json")
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            self.send_error(400, "Bad Request: Invalid Content-Length")
            return

        if content_length <= 0 or content_length > 1024 * 1024:
            self.send_error(413, "Payload Too Large or Empty")
            return

        body = self.rfile.read(content_length)
        
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "authorized"}')

if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 8080), SecureGatewayHandler)
    print("[SERVER] Running on 127.0.0.1:8080")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
