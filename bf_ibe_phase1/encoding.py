"""Small serialization helpers for the demo implementation."""

from __future__ import annotations

import base64


def b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


def int_to_b64(value: int) -> str:
    if value < 0:
        raise ValueError("cannot encode negative integers")
    length = max(1, (value.bit_length() + 7) // 8)
    return b64encode(value.to_bytes(length, "big"))


def int_from_b64(value: str) -> int:
    return int.from_bytes(b64decode(value), "big")
