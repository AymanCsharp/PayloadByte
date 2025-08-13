from typing import Dict, Any

from ..utils import detect_magic


def compute_indicators(data: bytes, strings_info: Dict[str, Any]) -> Dict[str, Any]:
    score = 0.0
    indicators: Dict[str, Any] = {}

    magic = detect_magic(data)
    if magic:
        indicators["file_magic"] = magic
        if magic in ("PE/COFF (MZ)", "ELF"):
            score += 0.5  

    num_urls = len(strings_info.get("urls", []))
    num_ips = len(strings_info.get("ipv4", []))
    num_domains = len(strings_info.get("domains", []))
    num_keywords = len(strings_info.get("suspicious_keywords", []))

    if num_urls:
        indicators["urls"] = [u.decode(errors="replace") for u in strings_info["urls"][:20]]
        score += min(1.0, num_urls * 0.05)
    if num_domains:
        indicators["domains"] = [d.decode(errors="replace") for d in strings_info["domains"][:20]]
        score += min(0.5, num_domains * 0.02)
    if num_ips:
        indicators["ipv4"] = [ip.decode(errors="replace") for ip in strings_info["ipv4"][:20]]
        score += min(0.5, num_ips * 0.05)
    if num_keywords:
        indicators["suspicious_keywords"] = [k.decode(errors="replace") for k in strings_info["suspicious_keywords"]]
        score += min(1.0, num_keywords * 0.2)

    indicators["num_base64_candidates"] = len(strings_info.get("base64", []))
    indicators["num_hex_candidates"] = len(strings_info.get("hex", []))

    return {"score": round(score, 3), "indicators": indicators}
