import json
from typing import Dict, Any


def build_report(
    file_path: str,
    size: int,
    entropy: Dict[str, Any],
    strings_summary: Dict[str, Any],
    decoded_payloads: Dict[str, Any],
    xor_findings: list,
    indicators: Dict[str, Any],
) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "file": file_path,
        "size": size,
        "entropy": entropy,
        "strings": {
            "num_ascii": strings_summary.get("num_ascii", 0),
            "num_utf16le": strings_summary.get("num_utf16le", 0),
            "samples": strings_summary.get("samples", []),
            "url_count": len(strings_summary.get("urls", [])),
            "domain_count": len(strings_summary.get("domains", [])),
            "ipv4_count": len(strings_summary.get("ipv4", [])),
        },
        "decoded": decoded_payloads,
        "xor_findings": xor_findings[:5],
        "indicators": indicators,
    }
    avg_entropy = entropy.get("avg_entropy", 0.0)
    max_entropy = entropy.get("max_entropy", 0.0)
    ent_score = 0.0
    if max_entropy >= 7.5:
        ent_score += 0.7
    if avg_entropy >= 7.0:
        ent_score += 0.5
    overall = min(10.0, 3.0 * indicators.get("score", 0.0) + ent_score)
    report["overall_score"] = round(overall, 3)
    return report


def to_text_summary(report: Dict[str, Any]) -> str:
    lines = []
    lines.append(f"File: {report['file']} ({report['size']} bytes)")
    lines.append(f"Entropy avg={report['entropy']['avg_entropy']:.3f} max={report['entropy']['max_entropy']:.3f} window={report['entropy']['window_size']}")
    lines.append(f"Strings: ascii={report['strings']['num_ascii']} utf16le={report['strings']['num_utf16le']} urls={report['strings']['url_count']} domains={report['strings']['domain_count']} ipv4={report['strings']['ipv4_count']}")
    if report.get("decoded", {}).get("base64", []):
        lines.append(f"Decoded Base64: {len(report['decoded']['base64'])} candidates")
    if report.get("decoded", {}).get("hex", []):
        lines.append(f"Decoded Hex: {len(report['decoded']['hex'])} candidates")
    if report.get("xor_findings"):
        lines.append(f"XOR findings: {len(report['xor_findings'])} (showing up to 5)")
    ind = report.get("indicators", {})
    lines.append(f"Indicators score={ind.get('score', 0.0)} details={list(ind.get('indicators', {}).keys())}")
    lines.append(f"Overall score: {report['overall_score']}/10.0")
    return "\n".join(lines)


def to_json(report: Dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2)
