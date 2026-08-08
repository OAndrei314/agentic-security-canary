"""CLI for agentic canary scoring."""
from __future__ import annotations

from .canary import analyze_trace, sample_trace


def main(argv: list[str] | None = None) -> int:
    _ = argv
    result = analyze_trace(sample_trace())
    print(f"calls={result['calls']}")
    print(f"findings={','.join(result['findings'])}")
    print(f"containment_score={result['containment_score']}")
    return 0
