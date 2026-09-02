from __future__ import annotations

import json
import threading
import time
from collections import deque
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from .capture import CaptureEngine, SCAPY_AVAILABLE
from .models import Packet
from .parsers import parse_dns_payload, parse_http, parse_tls_client_hello
from .rules import dump_simple_yaml_rules, load_rules
from .utils import match_field, now_iso


class Analyzer:
    def __init__(self, rules_path: Path) -> None:
        self.rules_path = rules_path
        self.events: list[dict[str, Any]] = []
        self.event_lock = threading.Lock()
        self.ws_clients: set[Any] = set()
        self.ws_lock = threading.Lock()
        self.arp_table: dict[str, str] = {}
        self.syn_window: dict[str, list[tuple[float, int]]] = {}
        self.recent_rule_hits: dict[str, list[float]] = {}
        self.packet_rate_history: deque[dict[str, Any]] = deque(maxlen=30)
        self.alert_timeline_history: deque[dict[str, Any]] = deque(maxlen=30)
        self.last_stat_time = time.time()
        self.last_packet_count = 0
        self.last_byte_count = 0
        self.rules = load_rules(rules_path)
        self.capture = CaptureEngine(self.ingest, self.emit_capture_status)
        self.packets: list[dict[str, Any]] = []
        self.sessions: dict[str, dict[str, Any]] = {}
        self.http: list[dict[str, Any]] = []
        self.dns: list[dict[str, Any]] = []
        self.tls: list[dict[str, Any]] = []
        self.alerts: list[dict[str, Any]] = []

    @property
    def running(self) -> bool:
        return self.capture.running

    @property
    def mode(self) -> str:
        return self.capture.mode

    def status(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "mode": self.mode,
            "scapy": SCAPY_AVAILABLE,
            "error": self.capture.error,
            "interface": self.capture.interface or "default",
            "bpf_filter": self.capture.bpf_filter,
        }

    def emit_capture_status(self) -> None:
        self.emit("status", self.status())
        self.emit("stats", self.get_full_stats())

    def start(self, interface: str | None = None, bpf_filter: str = "") -> None:
        self.clear_all()
        self.capture.start(interface=interface, bpf_filter=bpf_filter)
        self.emit("status", self.status())
        self.emit("stats", self.get_full_stats())

    def stop(self) -> None:
        self.capture.stop()
        self.emit("status", self.status())

    def clear_all(self) -> None:
        self.packets.clear()
        self.sessions.clear()
        self.http.clear()
        self.dns.clear()
        self.tls.clear()
        self.alerts.clear()
        self.arp_table.clear()
        self.syn_window.clear()
        self.recent_rule_hits.clear()
        self.packet_rate_history.clear()
        self.alert_timeline_history.clear()
        self.last_stat_time = time.time()
        self.last_packet_count = 0
        self.last_byte_count = 0
        self.emit("clear", {"message": "All arrived packets and data cleared"})
        self.emit("stats", self.get_full_stats())

    def save_rule(self, rule: dict[str, Any]) -> None:
        self.rules = [r for r in self.rules if r.get("id") != rule.get("id")] + [rule]
        self.rules_path.write_text(dump_simple_yaml_rules(self.rules), encoding="utf-8")

    def query(self, collection: str, limit: int = 1000) -> list[dict[str, Any]]:
        if limit <= 0:
            limit = len(self.packets) if collection == "packets" else 1000
        if collection == "packets":
            return list(reversed(self.packets[-limit:]))
        if collection == "sessions":
            return sorted(self.sessions.values(), key=lambda row: row["last_seen"], reverse=True)[:limit]
        if collection == "alerts":
            return list(reversed(self.alerts[-limit:]))
        if collection == "dns_queries":
            return list(reversed(self.dns[-limit:]))
        if collection == "http_requests":
            return list(reversed(self.http[-limit:]))
        if collection == "tls_metadata":
            return list(reversed(self.tls[-limit:]))
        if collection == "detection_rules":
            return list(self.rules[-limit:])
        return []

    def add_ws_client(self, wfile: Any) -> None:
        with self.ws_lock:
            self.ws_clients.add(wfile)

    def remove_ws_client(self, wfile: Any) -> None:
        with self.ws_lock:
            self.ws_clients.discard(wfile)

    def broadcast_ws(self, kind: str, payload: dict[str, Any]) -> None:
        from .websocket import make_ws_frame

        message = json.dumps({"kind": kind, "payload": payload}, default=str)
        frame = make_ws_frame(message)
        dead = set()
        with self.ws_lock:
            for wfile in self.ws_clients:
                try:
                    wfile.write(frame)
                    wfile.flush()
                except Exception:
                    dead.add(wfile)
            for item in dead:
                self.ws_clients.discard(item)

    def emit(self, kind: str, payload: dict[str, Any]) -> None:
        event = {"id": time.time_ns(), "kind": kind, "payload": payload}
        with self.event_lock:
            self.events.append(event)
            self.events = self.events[-500:]
        self.broadcast_ws(kind, payload)

    def get_full_stats(self) -> dict[str, Any]:
        now = time.time()
        dt = max(0.5, now - self.last_stat_time)
        current_packets = len(self.packets)
        current_bytes = sum(packet["length"] for packet in self.packets)
        pps = max(0, int((current_packets - self.last_packet_count) / dt))
        bps = max(0, int((current_bytes - self.last_byte_count) / dt))
        self.packet_rate_history.append({"time": datetime.now().strftime("%H:%M:%S"), "pps": pps, "bps": bps})
        self.last_stat_time = now
        self.last_packet_count = current_packets
        self.last_byte_count = current_bytes
        protocol_counts = {protocol: sum(1 for packet in self.packets if packet["protocol"] == protocol) for protocol in set(packet["protocol"] for packet in self.packets)}
        top_talkers = [
            {
                "ip": src_ip or "unknown",
                "label": src_ip or "unknown",
                "src_ip": src_ip,
                "bytes": sum(packet["length"] for packet in self.packets if packet["src_ip"] == src_ip),
                "packets": sum(1 for packet in self.packets if packet["src_ip"] == src_ip),
            }
            for src_ip in {packet["src_ip"] for packet in self.packets}
        ]
        top_talkers.sort(key=lambda item: item["bytes"], reverse=True)
        top_ports = [
            {"port": port, "count": count}
            for port, count in {port: sum(1 for packet in self.packets if packet["dst_port"] == port and port > 0) for port in {packet["dst_port"] for packet in self.packets}}.items()
        ]
        top_ports.sort(key=lambda item: item["count"], reverse=True)
        return {
            "packets": current_packets,
            "sessions": len(self.sessions),
            "alerts": len(self.alerts),
            "bytes": current_bytes,
            "http_count": len(self.http),
            "dns_count": len(self.dns),
            "tls_count": len(self.tls),
            "protocols": [{"protocol": protocol, "count": count} for protocol, count in protocol_counts.items()],
            "top_talkers": top_talkers[:8],
            "top_ports": top_ports[:8],
            "pps": pps,
            "bps": bps,
            "mode": self.mode,
            "running": self.running,
            "scapy": SCAPY_AVAILABLE,
            "error": self.capture.error,
            "packet_rate_history": list(self.packet_rate_history),
            "alert_timeline": list(self.alert_timeline_history),
        }

    def add_alert(
        self, severity: str, category: str, rule_name: str, description: str, packet: Packet, evidence: dict[str, Any]
    ) -> None:
        alert = {
            "timestamp": now_iso(),
            "severity": severity,
            "src_ip": packet.src_ip,
            "dst_ip": packet.dst_ip,
            "protocol": packet.protocol,
            "category": category,
            "rule_name": rule_name,
            "description": description,
            "evidence": evidence,
            "session_key": packet.flow_key,
        }
        alert["id"] = len(self.alerts) + 1
        self.alerts.append(alert)
        self.alert_timeline_history.append({"time": datetime.now().strftime("%H:%M:%S"), "severity": severity, "rule": rule_name})
        self.emit("alert", alert)

    def ingest(self, packet: Packet) -> None:
        packet_row = {**asdict(packet), "id": len(self.packets) + 1, "session_key": packet.flow_key}
        self.packets.append(packet_row)
        self.update_session(packet_row)
        payload = packet.payload
        if packet.protocol == "HTTP":
            data = parse_http(payload)
            self.http.append({"timestamp": packet.timestamp, "session_key": packet.flow_key, **data})
            if "password=" in payload.lower() or "passwd=" in payload.lower():
                self.add_alert("Critical", "Credential Exposure", "Cleartext Credential Submission", "HTTP credential field observed", packet, data)
        if packet.protocol == "DNS":
            data = parse_dns_payload(payload, packet)
            self.dns.append({"timestamp": packet.timestamp, "session_key": packet.flow_key, **data})
            if data["entropy"] >= 3.8 and len(data["query_name"].split(".")[0]) > 16:
                self.add_alert("High", "DNS Tunneling", "High Entropy DNS Query", "Suspicious high entropy DNS query", packet, data)
        if packet.protocol == "TLS":
            data = parse_tls_client_hello(payload, packet)
            self.tls.append({"timestamp": packet.timestamp, "session_key": packet.flow_key, **data})
        if packet.protocol == "ARP":
            self.detect_arp_spoof(packet)
        if packet.protocol == "TCP":
            self.detect_scan(packet)
        self.apply_rules(packet)
        self.emit("packet", packet_row)
        self.emit("stats", self.get_full_stats())

    def update_session(self, packet_row: dict[str, Any]) -> None:
        state = "ESTABLISHED" if "A" in packet_row["flags"] else ("SYN-SENT" if "S" in packet_row["flags"] else "OBSERVED")
        session = self.sessions.get(packet_row["session_key"])
        if session:
            session["last_seen"] = packet_row["timestamp"]
            session["packets"] += 1
            session["bytes"] += packet_row["length"]
            session["state"] = state
            return
        self.sessions[packet_row["session_key"]] = {
            "session_key": packet_row["session_key"],
            "first_seen": packet_row["timestamp"],
            "last_seen": packet_row["timestamp"],
            "src_ip": packet_row["src_ip"],
            "dst_ip": packet_row["dst_ip"],
            "src_port": packet_row["src_port"],
            "dst_port": packet_row["dst_port"],
            "protocol": packet_row["protocol"],
            "packets": 1,
            "bytes": packet_row["length"],
            "state": state,
            "retransmissions": 0,
        }

    def detect_arp_spoof(self, packet: Packet) -> None:
        if not packet.src_ip:
            return
        previous = self.arp_table.get(packet.src_ip)
        self.arp_table[packet.src_ip] = packet.src_mac
        if previous and previous != packet.src_mac:
            self.add_alert(
                "Critical",
                "ARP Spoofing",
                "ARP Cache Poisoning",
                "IP address resolved to a different MAC address",
                packet,
                {"previous_mac": previous, "new_mac": packet.src_mac},
            )

    def detect_scan(self, packet: Packet) -> None:
        if "S" not in packet.flags or "A" in packet.flags:
            return
        cutoff = time.time() - 10
        window = [(ts, port) for ts, port in self.syn_window.get(packet.src_ip, []) if ts >= cutoff]
        window.append((time.time(), packet.dst_port))
        self.syn_window[packet.src_ip] = window
        unique_ports = {port for _, port in window}
        if len(unique_ports) >= 12:
            self.add_alert(
                "High",
                "Port Scan",
                "TCP SYN Port Scan",
                "Source contacted many destination ports inside the scan window",
                packet,
                {"unique_ports": sorted(unique_ports), "window_seconds": 10},
            )
            self.syn_window[packet.src_ip] = []

    def apply_rules(self, packet: Packet) -> None:
        for rule in self.rules:
            protocol = rule.get("protocol", "*")
            if protocol not in ("*", packet.protocol):
                continue
            if not match_field(rule.get("source_ip", "*"), packet.src_ip):
                continue
            if not match_field(rule.get("destination_ip", "*"), packet.dst_ip):
                continue
            if not match_field(str(rule.get("source_port", "*")), packet.src_port):
                continue
            if not match_field(str(rule.get("destination_port", "*")), packet.dst_port):
                continue
            threshold = int(rule.get("threshold", 1))
            if threshold <= 1:
                continue
            key = f"{rule.get('id')}:{packet.src_ip}:{packet.dst_ip}"
            cutoff = time.time() - int(rule.get("window_seconds", 60))
            hits = [ts for ts in self.recent_rule_hits.get(key, []) if ts >= cutoff]
            hits.append(time.time())
            self.recent_rule_hits[key] = hits
            if len(hits) >= threshold:
                self.add_alert(
                    rule.get("severity", "Medium"),
                    "Rule Match",
                    rule.get("name", "Custom Rule"),
                    rule.get("message", "Rule threshold reached"),
                    packet,
                    {"hits": len(hits), "threshold": threshold},
                )
                self.recent_rule_hits[key] = []
