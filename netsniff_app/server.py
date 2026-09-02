from __future__ import annotations

import argparse
import json
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .analyzer import Analyzer
from .websocket import websocket_handshake


ROOT = Path(__file__).resolve().parent.parent
RULES_PATH = ROOT / "rules.yaml"
STATIC_DIR = ROOT / "static"

class ApiHandler(BaseHTTPRequestHandler):
    analyzer: Analyzer

    def log_message(self, format: str, *args: Any) -> None:
        return

    def send_json(self, data: Any, status: int = 200) -> None:
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/":
            return self.serve_file(STATIC_DIR / "index.html", "text/html")
        if path.startswith("/static/"):
            name = path.replace("/static/", "", 1)
            content_type = "text/css" if name.endswith(".css") else "application/javascript"
            return self.serve_file(STATIC_DIR / name, content_type)
        if path == "/ws":
            return self.handle_websocket()
        if path == "/events":
            return self.stream_events()
        query = parse_qs(parsed.query)
        limit = int(query.get("limit", ["1000"])[0])
        routes = {
            "/packets": "packets",
            "/sessions": "sessions",
            "/alerts": "alerts",
            "/dns": "dns_queries",
            "/http": "http_requests",
            "/tls": "tls_metadata",
            "/rules": "detection_rules",
        }
        if path in routes:
            return self.send_json(self.analyzer.query(routes[path], limit))
        if path == "/statistics":
            return self.send_json(self.analyzer.get_full_stats())
        if path == "/capture/status":
            return self.send_json(self.analyzer.status())
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        if path == "/capture/start":
            self.analyzer.start(
                interface=body.get("interface") or None,
                bpf_filter=body.get("bpf_filter", ""),
            )
            return self.send_json(self.analyzer.status())
        if path == "/capture/stop":
            self.analyzer.stop()
            return self.send_json(self.analyzer.status())
        if path == "/rules":
            if not body.get("id"):
                return self.send_json({"error": "rule id is required"}, 400)
            self.analyzer.save_rule(body)
            return self.send_json(body, 201)
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_DELETE(self) -> None:
        if urlparse(self.path).path in ("/clear", "/packets", "/alerts"):
            self.analyzer.clear_all()
            return self.send_json({"deleted": True})
        self.send_error(HTTPStatus.NOT_FOUND)

    def serve_file(self, path: Path, content_type: str) -> None:
        if not path.exists():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        body = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_websocket(self) -> None:
        if not websocket_handshake(self):
            self.send_error(HTTPStatus.BAD_REQUEST)
            return
        self.analyzer.add_ws_client(self.wfile)
        try:
            while True:
                data = self.rfile.read(2)
                if not data:
                    break
        except Exception:
            pass
        finally:
            self.analyzer.remove_ws_client(self.wfile)

    def stream_events(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        last_id = 0
        while True:
            with self.analyzer.event_lock:
                events = [event for event in self.analyzer.events if event["id"] > last_id]
            for event in events:
                last_id = event["id"]
                payload = f"event: {event['kind']}\ndata: {json.dumps(event['payload'])}\n\n".encode("utf-8")
                try:
                    self.wfile.write(payload)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    return
            time.sleep(0.5)


def run_server(host: str, port: int, autostart: bool = False) -> None:
    analyzer = Analyzer(RULES_PATH)
    ApiHandler.analyzer = analyzer
    if autostart:
        analyzer.start()
    server = ThreadingHTTPServer((host, port), ApiHandler)
    print(f"NetSniff IDS running at http://{host}:{port}")
    print("Install Npcap and run this terminal as Administrator for live packet capture.")
    print("Use Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        analyzer.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description="NetSniff live protocol analyzer and lightweight IDS")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--autostart", action="store_true")
    args = parser.parse_args()
    run_server(args.host, args.port, autostart=args.autostart)
