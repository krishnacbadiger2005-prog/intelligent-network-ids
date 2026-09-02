from __future__ import annotations

import hashlib
from typing import Any

from .models import Packet
from .utils import entropy


def parse_http(payload: str) -> dict[str, Any]:
    lines = payload.splitlines()
    result = {"method": "", "uri": "", "host": "", "user_agent": "", "status_code": 0, "content_length": 0, "mime_type": ""}
    if not lines:
        return result
    first = lines[0].split()
    if first and first[0].startswith("HTTP/"):
        result["status_code"] = int(first[1]) if len(first) > 1 and first[1].isdigit() else 0
    elif len(first) >= 2:
        result["method"], result["uri"] = first[0], first[1]
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "host":
            result["host"] = value
        elif key == "user-agent":
            result["user_agent"] = value
        elif key == "content-length" and value.isdigit():
            result["content_length"] = int(value)
        elif key == "content-type":
            result["mime_type"] = value
    return result


def parse_dns_payload(payload: str, packet: Packet) -> dict[str, Any]:
    query = payload.strip() or packet.info.replace("DNS query ", "")
    return {
        "query_name": query,
        "query_type": "A",
        "response": "",
        "ttl": 300,
        "resolver": packet.dst_ip,
        "record_type": "A",
        "entropy": round(entropy(query.split(".")[0]), 3),
    }


def parse_tls_client_hello(payload: str, packet: Packet) -> dict[str, Any]:
    sni = payload.replace("TLS ClientHello SNI=", "").strip() or packet.info.replace("TLS ClientHello SNI=", "")
    cipher_suites = ["4865", "4866", "4867", "49195"]
    extensions = ["server_name", "supported_groups", "signature_algorithms", "alpn"]
    ja3_src = f"771,{ '-'.join(cipher_suites) },0-11-10-35,23-29-24,0"
    return {
        "tls_version": "TLS 1.2/1.3 ClientHello",
        "sni": sni,
        "cipher_suites": cipher_suites,
        "extensions": extensions,
        "ja3": hashlib.md5(ja3_src.encode("utf-8")).hexdigest(),
    }
