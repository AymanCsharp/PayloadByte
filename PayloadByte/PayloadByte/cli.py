import argparse
import os
from typing import Dict, Any

from .utils import read_file_bytes
from .analyzers.entropy import scan_entropy
from .analyzers.strings import (
    extract_ascii_strings,
    extract_utf16le_strings,
    find_candidates,
)
from .analyzers.codecs import (
    try_b64_decode,
    try_hex_decode,
    scan_xor_single_byte,
)
from .analyzers.patterns import compute_indicators
from .report import build_report, to_text_summary, to_json


def _analyze(file_path: str, args: argparse.Namespace) -> Dict[str, Any]:
    data = read_file_bytes(file_path, max_bytes=args.max_bytes)

    entropy_info = scan_entropy(
        data,
        window_size=args.window_size,
        high_threshold=args.high_entropy_threshold,
    )

    ascii_strings = extract_ascii_strings(data, min_len=args.min_string_len)
    utf16le_strings = extract_utf16le_strings(data, min_len=args.min_string_len)
    samples = [s.decode(errors="replace") for s in ascii_strings[:20]]

    candidates = find_candidates(data)

    decoded: Dict[str, Any] = {"base64": [], "hex": []}
    for cand in candidates["base64"][:50]:
        dec = try_b64_decode(cand)
        if dec:
            decoded["base64"].append({
                "candidate_preview": cand[:64].decode(errors="replace"),
                "decoded_preview": dec[:128].decode(errors="replace"),
                "size": len(dec),
            })
    for cand in candidates["hex"][:50]:
        dec = try_hex_decode(cand)
        if dec:
            decoded["hex"].append({
                "candidate_preview": cand[:64].decode(errors="replace"),
                "decoded_preview": dec[:128].decode(errors="replace"),
                "size": len(dec),
            })

    xor_findings = []
    if args.xor_scan:
        xor_findings = scan_xor_single_byte(
            data,
            window_size=args.window_size,
            max_keys=args.max_xor_keys,
            printable_threshold=args.xor_printable_ratio,
        )

    strings_summary = {
        "num_ascii": len(ascii_strings),
        "num_utf16le": len(utf16le_strings),
        "samples": samples,
        "urls": candidates.get("urls", []),
        "domains": candidates.get("domains", []),
        "ipv4": candidates.get("ipv4", []),
    }
    indicators = compute_indicators(data, candidates)

    report = build_report(
        file_path=file_path,
        size=len(data),
        entropy=entropy_info,
        strings_summary=strings_summary,
        decoded_payloads=decoded,
        xor_findings=xor_findings,
        indicators=indicators,
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "PayloadByte"
        )
    )
    parser.add_argument("--file", required=True, help="Path to the payload file for analysis")
    parser.add_argument("--output", help="Path to the JSON file to save the report")
    parser.add_argument("--min-string-len", type=int, default=4, help="Minimum string length")
    parser.add_argument("--window-size", type=int, default=1024, help="Entropy window size")
    parser.add_argument("--high-entropy-threshold", type=float, default=7.2, help="High entropy threshold")
    parser.add_argument("--xor-scan", action="store_true", help="Try single-byte XOR on segments")
    parser.add_argument("--max-xor-keys", type=int, default=256, help="Maximum number of XOR keys to try (0..N-1)")
    parser.add_argument("--xor-printable-ratio", type=float, default=0.85, help="Acceptable printable ratio to consider XOR result suspicious")
    parser.add_argument("--max-bytes", type=int, help="Maximum number of bytes to read from the file for analysis")

    args = parser.parse_args(argv)

    file_path = args.file
    if not os.path.exists(file_path):
        print(f"[!] The File Cant Found: {file_path}")
        return 2

    try:
        report = _analyze(file_path, args)
    except Exception as exc:
        print(f"[!] There Are Erorr: {exc}")
        return 1

    print(to_text_summary(report))

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(to_json(report))
            print(f"\n[+]The report has been saved JSON: {args.output}")
        except Exception as exc:
            print(f"[!] Failed To Save report: {exc}")
            return 1

    return 0
