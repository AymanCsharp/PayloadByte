import math
import os
from typing import Iterator, Tuple

PRINTABLE_BYTES = set(range(32, 127)) | {9, 10, 13}


def read_file_bytes(path: str, max_bytes: int | None = None) -> bytes:
    with open(path, "rb") as f:
        data = f.read() if max_bytes is None else f.read(max_bytes)
    return data


def iter_chunks(data: bytes, size: int) -> Iterator[Tuple[int, bytes]]:
    for offset in range(0, len(data), size):
        yield offset, data[offset : offset + size]


def shannon_entropy(block: bytes) -> float:
    if not block:
        return 0.0
    frequency = [0] * 256
    for b in block:
        frequency[b] += 1
    entropy = 0.0
    length = len(block)
    for count in frequency:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for b in data if b in PRINTABLE_BYTES)
    return printable / len(data)


def detect_magic(data: bytes) -> str | None:
    if data.startswith(b"MZ"):
        return "PE/COFF (MZ)"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP"
    if data.startswith(b"%PDF"):
        return "PDF"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\fa\xcf", b"\xcf\xfa\xed\xfe"):
        return "Mach-O"
    return None