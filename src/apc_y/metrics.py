from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class LatencyHistogram:
    samples: list[float] = field(default_factory=list)

    def observe(self, seconds):
        self.samples.append(seconds)

    def percentile(self, p):
        if not self.samples:
            return 0.0
        xs = sorted(self.samples)
        i = min(len(xs) - 1, max(0, int(round((p / 100) * (len(xs) - 1)))))
        return xs[i]

    def summary_ms(self):
        return {f"p{p}": self.percentile(p) * 1000 for p in (50, 95, 99)}


class Timer:
    def __init__(self, h):
        self.h = h

    def __enter__(self):
        self.t = time.perf_counter()
        return self

    def __exit__(self, *_):
        self.h.observe(time.perf_counter() - self.t)
