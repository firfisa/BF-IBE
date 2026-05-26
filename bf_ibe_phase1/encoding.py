"""序列化工具。

密文、曲线点、私钥这些二进制数据通常不能直接放进 JSON，所以演示代码
统一用 URL-safe base64 转成字符串。toy 实现里的“点/标量”是整数，也通过
int <-> bytes <-> base64 存储。
"""

from __future__ import annotations

import base64


def b64encode(data: bytes) -> str:
    """bytes -> 可放进 JSON 的 ASCII 字符串。"""
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64decode(value: str) -> bytes:
    """base64 字符串 -> bytes。"""
    return base64.urlsafe_b64decode(value.encode("ascii"))


def int_to_b64(value: int) -> str:
    """整数标量 -> base64。"""
    if value < 0:
        raise ValueError("cannot encode negative integers")
    length = max(1, (value.bit_length() + 7) // 8)
    return b64encode(value.to_bytes(length, "big"))


def int_from_b64(value: str) -> int:
    """base64 -> 整数标量。"""
    return int.from_bytes(b64decode(value), "big")
