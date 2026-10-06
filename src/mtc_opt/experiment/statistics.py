"""Explicit nearest-rank quantiles and reproducible confidence intervals."""
from __future__ import annotations

import math
import random
from statistics import mean


def _values(values):
    result = tuple(values)
    if any(isinstance(v, bool) or not isinstance(v, (int, float)) or
           not math.isfinite(v) or v < 0 for v in result):
        raise ValueError("samples must be finite non-negative numbers")
    return result


def percentile(values, q):
    values = sorted(_values(values))
    if isinstance(q, bool) or not isinstance(q, (int, float)) or not 0 <= q <= 100:
        raise ValueError("percentile must be in [0,100]")
    return None if not values else values[max(0, math.ceil(q * len(values) / 100) - 1)]


def summarize(values):
    values = _values(values)
    return dict(count=len(values), mean=None if not values else mean(values),
                p50=percentile(values, 50), p95=percentile(values, 95),
                p99=percentile(values, 99))


def mean_confidence_interval(values, *, confidence=0.95, resamples=2000, seed=0):
    """Percentile bootstrap of INDEPENDENT RUN means, not inner-loop timings."""
    values = _values(values)
    if not 0 < confidence < 1 or isinstance(resamples, bool) or not isinstance(resamples, int) or resamples < 1:
        raise ValueError("invalid bootstrap parameters")
    if len(values) < 2:
        return None
    rng = random.Random(seed)
    means = [mean(rng.choices(values, k=len(values))) for _ in range(resamples)]
    tail = (1 - confidence) * 50
    return percentile(means, tail), percentile(means, 100 - tail)


def binomial_rate(successes, trials, *, z=1.959963984540054):
    """Wilson 95% interval by default; empty denominators remain unavailable."""
    if any(isinstance(v, bool) or not isinstance(v, int) for v in (successes, trials)) or not 0 <= successes <= trials:
        raise ValueError("require 0 <= successes <= trials")
    if not math.isfinite(z) or z <= 0:
        raise ValueError("z must be finite and positive")
    if not trials:
        return dict(rate=None, lower=None, upper=None, trials=0)
    p = successes / trials
    divisor = 1 + z*z/trials
    center = (p + z*z/(2*trials))/divisor
    half = z * math.sqrt(p*(1-p)/trials + z*z/(4*trials*trials))/divisor
    return dict(rate=p, lower=max(0, center-half), upper=min(1, center+half), trials=trials)
