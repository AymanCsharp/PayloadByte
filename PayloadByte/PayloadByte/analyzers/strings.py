import re
from dataclasses import dataclass
from typing import List, Dict, Any

ASCII_RE = re.compile(rb"[\x20-\x7E]{4,}")
UTF16LE_RE = re.compile(rb"(?:[\x20-\x7E]\x00){4,}")
BASE64_CANDIDATE_RE = re.compile(rb"(?i)\b[A-Z0-9+/]{24,}={0,2}\b")
HEX_CANDIDATE_RE = re.compile(rb"\b(?:[0-9a-fA-F]{2}){8,}\b")

URL_RE = re.compile(rb"(?i)\bhttps?://[\w\-\.\:/%\?&=#]+")
DOMAIN_RE = re.compile(rb"\b[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}\b")
IPV4_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")

SUSPICIOUS_KEYWORDS = [
    b"cmd.exe", b"powershell", b"wscript", b"cscript", b"/bin/sh", b"bash",
    b"curl", b"wget", b"nc ", b"netcat", b"eval(", b"exec(", b"subprocess",
    b"VirtualAlloc", b"WriteProcessMemory", b"CreateRemoteThread", b"LoadLibrary",
    b"GetProcAddress", b"Crypt", b"Base64", b"XOR", b"shellcode",
]


def extract_ascii_strings(data: bytes, min_len: int = 4) -> List[bytes]:
    if min_len < 4:
        pattern = re.compile(rb"[\x20-\x7E]{%d,}" % min_len)
        return pattern.findall(data)
    return ASCII_RE.findall(data)


def extract_utf16le_strings(data: bytes, min_len: int = 4) -> List[bytes]:
    if min_len != 4:
        pattern = re.compile(rb"(?:[\x20-\x7E]\x00){%d,}" % min_len)
        return pattern.findall(data)
    return UTF16LE_RE.findall(data)


def find_candidates(data: bytes) -> Dict[str, List[bytes]]:
    return {
        "base64": BASE64_CANDIDATE_RE.findall(data),
        "hex": HEX_CANDIDATE_RE.findall(data),
        "urls": URL_RE.findall(data),
        "domains": DOMAIN_RE.findall(data),
        "ipv4": IPV4_RE.findall(data),
        "suspicious_keywords": [kw for kw in SUSPICIOUS_KEYWORDS if kw in data],
    }