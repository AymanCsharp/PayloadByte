from dataclasses import dataclass
from typing import List, Dict, Any

from ..utils import iter_chunks, shannon_entropy


@dataclass
class EntropyRegion:
    offset: int
    size: int
    entropy: float


def scan_entropy(data: bytes, window_size: int = 1024, high_threshold: float = 7.2) -> Dict[str, Any]:
    regions: List[EntropyRegion] = []
    entropies: List[float] = []
    for offset, block in iter_chunks(data, window_size):
        e = shannon_entropy(block)
        entropies.append(e)
        if e >= high_threshold and len(block) == window_size:
            regions.append(EntropyRegion(offset=offset, size=len(block), entropy=e))
    return {
        "window_size": window_size,
        "high_threshold": high_threshold,
        "avg_entropy": sum(entropies) / max(1, len(entropies)),
        "max_entropy": max(entropies) if entropies else 0.0,
        "regions": [r.__dict__ for r in regions],
    }