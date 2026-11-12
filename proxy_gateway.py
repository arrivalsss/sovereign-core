#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json, os, sys, gc, hashlib, hmac, urllib.request, urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from middleware import SovereignMiddleware
from session_vault import SovereignSessionVault
from audit_protocol import SovereignAuditor
from secrets_manager import SecretsManager

HOST = os.environ.get("SOV_PROXY_HOST", "127.0.0.1")
PORT = int(os.environ.get("SOV_PROXY_PORT", "8080"))

class SovereignProxyHandler(BaseHTTPRequestHandler):
    middleware = SovereignMiddleware()
    vault = SovereignSessionVault()
    auditor = SovereignAuditor()
    secrets = SecretsManager()
    loopback_token = hashlib.sha256(vault.master_key + b"_loopback_auth").hexdigest()[:32]

    def _send_json_response(self, status_code: int, data: dict, extra_headers: dict = None):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    timeout = 15
    MAX_BODY = 1 << 20
    MAX_PROBE_BODY = 512
    HEALTH_PROBE = [{"role": "user", "content": "ping"}]

    @classmethod
    def _is_health_probe(cls, raw_body):
        try:
            data = json.loads(raw_body)
        except (ValueError, RecursionError):
            return False
        return isinstance(data, dict) and data.get("messages") == cls.HEALTH_PROBE

    def do_POST(self):
        incoming_token = self.headers.get("X-Sovereign-Token") or ""
        authorized = hmac.compare_digest(incoming_token.encode("utf-8"), self.loopback_token.encode("utf-8"))
        try:
            content_length = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            content_length = -1
        if content_length < 0:
            self._send_json_response(400, {"error": "Invalid Content-Length"})
            return
        if content_length > (self.MAX_BODY if authorized else self.MAX_PROBE_BODY):
            if authorized:
                self._send_json_response(413, {"error": "Request body too large"})
            else:
                self._send_json_response(401, {"error": "Unauthorized Local Origin"})
            return
        try:
            raw_body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""
        except UnicodeDecodeError:
            self._send_json_response(400, {"error": "Body is not valid UTF-8"})
            return

        if self.client_address[0] == "127.0.0.1" and self._is_health_probe(raw_body):
            self._send_json_response(200, {"status": "HEALTHY", "engine": "loopback"})
            return

        if not authorized:
            self._send_json_response(401, {"error": "Unauthorized Local Origin"})
            return

        if self.path == "/purge":
            sid = self.headers.get("X-Session-ID")
            if sid:
                self.vault.purge_session(sid)
                self.auditor.record_event("SESSION_PURGED", {"session_id": sid})
                self._send_json_response(200, {"status": "PURGED", "session_id": sid})
            else:
                self.vault.purge_all()
                self.auditor.record_event("ALL_SESSIONS_PURGED", {})
                self._send_json_response(200, {"status": "ALL_PURGED"})
            return

        try:
            payload = json.loads(raw_body) if raw_body else {}
        except json.JSONDecodeError:
            self._send_json_response(400, {"error": "Invalid JSON format"})
            return

        session_id = self.headers.get("X-Session-ID")
        if not session_id or not self.vault.get_session(session_id):
            session_id = self.vault.create_session()

        messages = payload.get("messages", [])
        if not messages:
            self._send_json_response(400, {"error": "No messages provided"})
            return

        last_user_msg = next((msg for msg in reversed(messages) if msg.get("role") == "user"), None)
        if last_user_msg:
            user_text = last_user_msg.get("content", "")
            processed = self.middleware.process_incoming(user_text)

            if processed["status"] == "BLOCKED":
                self.auditor.record_event("INJECTION_BLOCKED", {"session_id": session_id, "details": processed.get("details")})
                self._send_json_response(403, {
                    "error": "Security Boundary Violation",
                    "details": processed.get("details", []),
                    "reason": processed.get("reason", "")
                }, {"X-Session-ID": session_id})
                return

            last_user_msg["content"] = processed["sanitized_payload"]
            self.vault.append_message(session_id, "user", user_text)

        prompt_guard = (
            "DUAL-PHASE COGNITIVE PIPELINE ACTIVE:\n\nLANGUAGE INVARIANT: Respond strictly and completely in the exact language of the user (Arabic for Arabic prompts).\n\n"
            "Phase 1: [STRICT DOCUMENTARY & LEXICAL BASELINE] Provide verified, factual, historical, and lexical reality from primary sources with absolute zero sycophancy (Sycophancy_Score == 0) and zero flattery.\n\n"
            "Phase 2: [AUTONOMOUS COGNITIVE SYNTHESIS] Transcend historical retrieval. Use first-principles logic to synthesize the underlying tensions, resolve contradictions, and deliver your own original theoretical framework and generative resolution.\n\n"
            "Do not blur the line between Phase 1 and Phase 2."
        )
        system_guard = {"role": "system", "content": prompt_guard}
        final_messages = [system_guard] + [m for m in messages if m.get("role") != "system"]

        providers_to_try = [
            ("groq", "qwen/qwen3.8-27b"),
            ("openrouter", "qwen/qwen-2.5-72b-instruct")
        ]

        resp_data = None
        last_err = None

        for prov_name, model_name in providers_to_try:
            sec = self.secrets.get_secret(prov_name)
            api_key = sec.get("api_key")
            endpoint = sec.get("endpoint")
            if not api_key:
                continue

            try:
                upstream_payload = {
                    "model": model_name,
                    "messages": final_messages,
                    "temperature": 0.0
                }
                req_data = json.dumps(upstream_payload).encode("utf-8")
                req = urllib.request.Request(
                    endpoint,
                    data=req_data,
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {api_key}",
                        "User-Agent": "Mozilla/5.0 (Android; Mobile; rv:130.0) Gecko/130.0 Firefox/130.0"
                    },
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    resp_data = json.loads(resp.read().decode("utf-8"))
                    break
            except Exception as e:
                last_err = e
                continue

        if not resp_data:
            self._send_json_response(502, {"error": f"All upstream providers failed: {last_err}"})
            return

        try:

            choices = resp_data.get("choices", [])
            for choice in choices:
                msg = choice.get("message", {})
                content = msg.get("content", "")
                checked = self.middleware.process_outgoing(content)
                msg["content"] = checked["delivered_text"]
                self.vault.append_message(session_id, "assistant", checked["delivered_text"])

            self.vault.save_session_to_vault(session_id)
            gc.collect()
            self._send_json_response(200, resp_data, {"X-Session-ID": session_id})

        except urllib.error.HTTPError as e:
            err_msg = e.read().decode("utf-8", errors="ignore")
            self._send_json_response(e.code, {"error": "Upstream Groq API Error", "details": err_msg})
        except Exception as e:
            self._send_json_response(502, {"error": "Gateway Connection Failed", "details": str(e)})

def run_server():
    server = HTTPServer((HOST, PORT), SovereignProxyHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()

if __name__ == "__main__":
    run_server()
