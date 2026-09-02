from __future__ import annotations

import threading
import time
from typing import Any, Callable

from .models import Packet
from .utils import now_iso, random_mac

try:
    import scapy.all as scapy

    SCAPY_AVAILABLE = True
except ImportError:
    scapy = None
    SCAPY_AVAILABLE = False


PacketCallback = Callable[[Packet], None]
StatusCallback = Callable[[], None]


class CaptureEngine:
    def __init__(self, callback: PacketCallback, status_callback: StatusCallback | None = None) -> None:
        self.callback = callback
        self.status_callback = status_callback
        self.running = False
        self.mode = "live"
        self.interface: str | None = None
        self.bpf_filter = ""
        self.thread: threading.Thread | None = None
        self.error = ""

    def start(self, interface: str | None = None, bpf_filter: str = "") -> None:
        self.stop()
        self.running = True
        self.error = ""
        self.mode = "live"
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.thread = threading.Thread(target=self._run_live, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.running = False

    def _run_live(self) -> None:
        if not SCAPY_AVAILABLE:
            self.error = "Scapy is not installed. Install it with: py -3.13 -m pip install scapy"
            self.running = False
            self._notify_status()
            return
        try:
            scapy.sniff(
                iface=self.interface,
                filter=self.bpf_filter or None,
                prn=self._handle_scapy_packet,
                store=False,
                stop_filter=lambda _: not self.running,
            )
        except Exception as exc:
            self.error = f"Live capture failed. Install Npcap, run terminal as Administrator, and retry. Details: {exc}"
            self.running = False
            self._notify_status()

    def _notify_status(self) -> None:
        if self.status_callback:
            self.status_callback()

    def _handle_scapy_packet(self, raw_packet: Any) -> None:
        if not self.running:
            return
        packet = scapy_to_packet(raw_packet)
        if packet:
            self.callback(packet)


def scapy_to_packet(raw_packet: Any) -> Packet | None:
    if not SCAPY_AVAILABLE:
        return None
    try:
        from scapy.all import ARP, DNS, DNSQR, Ether, IP, IPv6, Raw, TCP, UDP

        src_mac = raw_packet[Ether].src if raw_packet.haslayer(Ether) else random_mac()
        dst_mac = raw_packet[Ether].dst if raw_packet.haslayer(Ether) else random_mac()
        src_ip = ""
        dst_ip = ""
        ttl = 64
        if raw_packet.haslayer(IP):
            src_ip = raw_packet[IP].src
            dst_ip = raw_packet[IP].dst
            ttl = raw_packet[IP].ttl
        elif raw_packet.haslayer(IPv6):
            src_ip = raw_packet[IPv6].src
            dst_ip = raw_packet[IPv6].dst
        elif raw_packet.haslayer(ARP):
            src_ip = raw_packet[ARP].psrc
            dst_ip = raw_packet[ARP].pdst

        src_port = 0
        dst_port = 0
        flags = ""
        seq = 0
        ack = 0
        window = 0
        if raw_packet.haslayer(TCP):
            src_port = int(raw_packet[TCP].sport)
            dst_port = int(raw_packet[TCP].dport)
            flags = str(raw_packet[TCP].flags)
            seq = int(raw_packet[TCP].seq)
            ack = int(raw_packet[TCP].ack)
            window = int(raw_packet[TCP].window)
        elif raw_packet.haslayer(UDP):
            src_port = int(raw_packet[UDP].sport)
            dst_port = int(raw_packet[UDP].dport)

        payload = ""
        if raw_packet.haslayer(Raw):
            payload = raw_packet[Raw].load.decode("utf-8", errors="ignore")

        protocol = "IP"
        info = f"IP {src_ip} -> {dst_ip}"
        if raw_packet.haslayer(DNS) or raw_packet.haslayer(DNSQR):
            protocol = "DNS"
            qname = ""
            if raw_packet.haslayer(DNSQR):
                qname = raw_packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            payload = qname or payload
            info = f"DNS query {qname}" if qname else "DNS"
        elif raw_packet.haslayer(ARP):
            protocol = "ARP"
            info = f"ARP {src_ip} -> {dst_ip}"
        elif raw_packet.haslayer(TCP) and payload.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HTTP/")):
            protocol = "HTTP"
            info = payload.splitlines()[0][:90] if payload else "HTTP"
        elif raw_packet.haslayer(TCP) and (src_port == 443 or dst_port == 443):
            protocol = "TLS"
            info = f"TLS traffic {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        elif raw_packet.haslayer(TCP):
            protocol = "TCP"
            info = f"TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port} [{flags}]"
        elif raw_packet.haslayer(UDP):
            protocol = "UDP"
            info = f"UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

        return Packet(
            timestamp=now_iso(),
            src_mac=src_mac,
            dst_mac=dst_mac,
            src_ip=src_ip or "0.0.0.0",
            dst_ip=dst_ip or "0.0.0.0",
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            length=len(raw_packet),
            ttl=ttl,
            flags=flags,
            seq=seq,
            ack=ack,
            window=window,
            payload=payload,
            info=info,
        )
    except Exception:
        return None


