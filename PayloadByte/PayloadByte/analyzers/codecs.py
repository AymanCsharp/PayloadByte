import base64
import binascii
from typing import List, Dict, Any, Tuple

from ..utils import printable_ratio


def try_b64_decode(candidate: bytes) -> bytes | None:
    try:
        compact = b"".join(candidate.split())
        if len(compact) % 4 != 0:
            compact += b"=" * ((4 - len(compact) % 4) % 4)
        decoded = base64.b64decode(compact, validate=True)
        return decoded
    except Exception:
        return None


def try_hex_decode(candidate: bytes) -> bytes | None:
    try:
        decoded = binascii.unhexlify(candidate)
        return decoded
    except Exception:
        return None


def single_byte_xor(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def scan_xor_single_byte(
    data: bytes,
    window_size: int = 1024,
    max_keys: int = 256,
    printable_threshold: float = 0.85,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    max_windows = min(64, max(1, len(data) // max(1, window_size)))
    for w in range(max_windows):
        start = w * window_size
        block = data[start : start + window_size]
        if not block:
            break
        keys_to_try = range(max_keys)
        for k in keys_to_try:
            x = single_byte_xor(block, k)
            pr = printable_ratio(x)
            if pr >= printable_threshold:
                findings.append({
                    "offset": start,
                    "size": len(block),
                    "key": k,
                    "printable_ratio": pr,
                    "preview": x[:128].decode(errors="replace"),
                })
    return findings
