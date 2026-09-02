from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Packet:
    timestamp: str
    src_mac: str
    dst_mac: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    length: int
    ttl: int
    flags: str = ""
    seq: int = 0
    ack: int = 0
    window: int = 0
    payload: str = ""
    info: str = ""

    @property
    def flow_key(self) -> str:
        left = (self.src_ip, self.src_port)
        right = (self.dst_ip, self.dst_port)
        a, b = sorted([left, right])
        return f"{a[0]}:{a[1]}-{b[0]}:{b[1]}-{self.protocol}"
