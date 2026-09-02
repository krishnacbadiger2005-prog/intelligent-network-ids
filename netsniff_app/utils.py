from __future__ import annotations

import math
import random
from datetime import datetime, timezone


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def entropy(value: str) -> float:
    if not value:
        return 0.0
    return -sum((value.count(c) / len(value)) * math.log2(value.count(c) / len(value)) for c in set(value))


def random_mac() -> str:
    return ":".join(f"{random.randint(0, 255):02x}" for _ in range(6))


def match_field(pattern: object, value: object) -> bool:
    if pattern in (None, "", "*"):
        return True
    return str(pattern) == str(value)
