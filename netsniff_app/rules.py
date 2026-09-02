from __future__ import annotations

from pathlib import Path
from typing import Any


DEFAULT_RULES = [
    {
        "id": "DNS-ENTROPY-001",
        "name": "High Entropy DNS Query",
        "protocol": "DNS",
        "source_ip": "*",
        "destination_ip": "*",
        "source_port": "*",
        "destination_port": "*",
        "threshold": 1,
        "window_seconds": 30,
        "severity": "High",
        "message": "Possible DNS tunneling or generated domain name",
    },
    {
        "id": "HTTP-CRED-001",
        "name": "Cleartext Credential Submission",
        "protocol": "HTTP",
        "source_ip": "*",
        "destination_ip": "*",
        "source_port": "*",
        "destination_port": "*",
        "threshold": 1,
        "window_seconds": 30,
        "severity": "Critical",
        "message": "HTTP payload contains password-like data",
    },
    {
        "id": "TCP-SYNSCAN-001",
        "name": "TCP SYN Port Scan",
        "protocol": "TCP",
        "source_ip": "*",
        "destination_ip": "*",
        "source_port": "*",
        "destination_port": "*",
        "threshold": 12,
        "window_seconds": 10,
        "severity": "High",
        "message": "One source contacted many destination ports quickly",
    },
]


def load_rules(path: Path) -> list[dict[str, Any]]:
    if path.exists():
        rules = load_simple_yaml_rules(path.read_text(encoding="utf-8"))
        if rules:
            return rules
    path.write_text(dump_simple_yaml_rules(DEFAULT_RULES), encoding="utf-8")
    return [dict(rule) for rule in DEFAULT_RULES]


def load_simple_yaml_rules(text: str) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            if current:
                rules.append(current)
            current = {}
            line = line[1:].strip()
            if not line:
                continue
        if ":" in line and current is not None:
            key, value = line.split(":", 1)
            value = value.strip().strip('"').strip("'")
            current[key.strip()] = int(value) if value.isdigit() else value
    if current:
        rules.append(current)
    return rules


def dump_simple_yaml_rules(rules: list[dict[str, Any]]) -> str:
    ordered_keys = [
        "id",
        "name",
        "protocol",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "threshold",
        "window_seconds",
        "severity",
        "message",
    ]
    lines = ["# NetSniff detection rules"]
    for rule in rules:
        lines.append("-")
        for key in ordered_keys:
            if key not in rule:
                continue
            value = rule[key]
            if isinstance(value, str):
                lines.append(f'  {key}: "{value.replace(chr(34), chr(92) + chr(34))}"')
            else:
                lines.append(f"  {key}: {value}")
    lines.append("")
    return "\n".join(lines)
