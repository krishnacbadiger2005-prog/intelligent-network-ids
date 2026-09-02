from __future__ import annotations

import base64
import hashlib
import struct
from http.server import BaseHTTPRequestHandler


def websocket_handshake(handler: BaseHTTPRequestHandler) -> bool:
    key = handler.headers.get("Sec-WebSocket-Key")
    if not key:
        return False
    guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    accept_val = base64.b64encode(hashlib.sha1((key.strip() + guid).encode("utf-8")).digest()).decode("utf-8")
    handler.send_response(101, "Switching Protocols")
    handler.send_header("Upgrade", "websocket")
    handler.send_header("Connection", "Upgrade")
    handler.send_header("Sec-WebSocket-Accept", accept_val)
    handler.end_headers()
    return True


def make_ws_frame(text: str) -> bytes:
    payload = text.encode("utf-8")
    length = len(payload)
    if length <= 125:
        header = bytes([0x81, length])
    elif length <= 65535:
        header = bytes([0x81, 126]) + struct.pack("!H", length)
    else:
        header = bytes([0x81, 127]) + struct.pack("!Q", length)
    return header + payload
