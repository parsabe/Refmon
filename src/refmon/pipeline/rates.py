"""Rate detectors behind four methods: mass change, lateral fan-out, exfil volume, responses.

`CountedRates` compares counts with fixed thresholds from `policy.rates` (the fallback without
weights). `StatRates` is the C11.6 version: a Poisson tail test for bursts, CUSUM for the exfil
volume and a Poisson test on repeated response anomalies per client, with exponential moving
average baselines that are frozen while an incident is open. Every number comes from the policy.

v1.1 (A49): the Poisson and repeat tests run over two windows, the short `rates.window` and the
hour-scale `rates.long_window`, each with its own baseline; either one can raise the signal. The
counted fallback keeps its single window.
"""

from __future__ import annotations

import math
from collections import deque

from ..calculus.stats import Cusum, Ema, poisson_tail, z_score
from ..policy import Policy


class _Window:
    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self.items: deque[tuple[float, object, float]] = deque()

    def add(self, ts: float, item: object = None, amount: float = 1.0) -> None:
        self.items.append((ts, item, amount))
        while self.items and self.items[0][0] < ts - self.seconds:
            self.items.popleft()

    def distinct(self) -> int:
        return len({i for _, i, _ in self.items})

    def total(self) -> float:
        return sum(a for _, _, a in self.items)


class CountedRates:
    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self._windows: dict[tuple[str, str], _Window] = {}

    def _win(self, kind: str, key: str) -> _Window:
        return self._windows.setdefault((kind, key), _Window(self.policy.rates.window))

    def mass_change(self, root: str, role: str, ts: float, fp: str | None) -> bool:
        w = self._win("mass", root)
        w.add(ts, fp)
        return w.distinct() >= self.policy.rates.mass_change_files

    def lateral(self, root: str, role: str, ts: float, host_fp: str | None) -> bool:
        w = self._win("lateral", root)
        w.add(ts, host_fp)
        return w.distinct() >= self.policy.rates.lateral_hosts

    def exfil(self, root: str, role: str, ts: float, nbytes: float) -> bool:
        w = self._win("exfil", root)
        w.add(ts, None, nbytes)
        limit = self.policy.rates.exfil_bytes_by_role.get(role, self.policy.rates.exfil_bytes)
        return w.total() >= limit

    def response(self, client: str, role: str, ts: float, nbytes: float) -> tuple[bool, bool]:
        """(this response is anomalous, anomalies to this client are repeated)."""
        if nbytes < self.policy.rates.response_anomaly_bytes:
            return False, False
        w = self._win("response", client)
        w.add(ts, None, nbytes)
        return True, len(w.items) >= self.policy.rates.response_repeat


class StatRates:
    """Statistical rate tests (CLAUDE.md C11.6)."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy
        self._windows: dict[tuple[str, str, str], _Window] = {}
        self._baselines: dict[tuple[str, str, str], Ema] = {}
        self._buckets: dict[tuple[str, str, str], tuple[int, set]] = {}
        self._cusum: dict[str, Cusum] = {}
        self._volume: dict[str, tuple[int, float]] = {}
        self._volume_mean: dict[str, Ema] = {}
        self._incident: dict[str, float] = {}  # process-tree root -> last time it was open

    def forget(self, now: float) -> None:
        """v1.5 (A62): windows and drift statistics of process trees silent for longer than the
        hour-scale window hold nothing a test could still use."""
        horizon = now - self.policy.rates.long_window
        for key in [k for k, w in self._windows.items() if not w.items or w.items[-1][0] < horizon]:
            del self._windows[key]
        seconds = dict(self._scopes())
        for key in [k for k, (b, _) in self._buckets.items()
                    if (b + 1) * seconds[k[2]] < horizon]:  # fmt: skip
            del self._buckets[key]
        for root in [r for r, (b, _) in self._volume.items()
                     if b * self.policy.rates.window < horizon]:  # fmt: skip
            del self._volume[root]
            self._cusum.pop(root, None)

    # -- incidents freeze the baselines -----------------------------------------------------------

    def mark_incident(self, root: str, is_open: bool, ts: float | None = None) -> None:
        if is_open:
            self._incident[root] = ts if ts is not None else self._incident.get(root, 0.0)
        else:
            self._incident.pop(root, None)
        if ts is not None:
            # v1.5 (A61): an incident whose process tree has been silent for the hour-scale window
            # is over. Until v1.4 it stayed open until that tree produced an allowed story, which a
            # contained tree never does, so one block froze every baseline for good.
            horizon = ts - self.policy.rates.long_window
            for r in [r for r, last in self._incident.items() if last < horizon]:
                del self._incident[r]
        for ema in [*self._baselines.values(), *self._volume_mean.values()]:
            ema.frozen = bool(self._incident)

    # -- helpers ----------------------------------------------------------------------------------

    def _scopes(self) -> tuple[tuple[str, float], ...]:
        r = self.policy.rates
        return (("short", r.window), ("long", r.long_window))

    def _win(self, kind: str, key: str, scope: str = "short") -> _Window:
        seconds = dict(self._scopes())[scope]
        return self._windows.setdefault((kind, key, scope), _Window(seconds))

    def _rate_for(self, kind: str, role: str, scope: str = "short") -> Ema:
        key = (kind, role, scope)
        if key not in self._baselines:
            m = self.policy.math
            table, default = (
                (m.baseline_rate, m.baseline_rate_default)
                if scope == "short"
                else (m.baseline_rate_long, m.baseline_rate_long_default)
            )
            lam = table.get(f"{kind}:{role}", table.get(kind, default))
            self._baselines[key] = Ema(lam, m.ema_beta, frozen=bool(self._incident))
        return self._baselines[key]

    def _learn_buckets(
        self, kind: str, root: str, role: str, ts: float, item, scope: str = "short"
    ) -> None:
        """Tumbling windows feed the moving average of the burst baseline."""
        bucket = math.floor(ts / dict(self._scopes())[scope])
        old = self._buckets.get((kind, root, scope))
        if old is not None and old[0] != bucket:
            self._rate_for(kind, role, scope).update(len(old[1]))
            old = None
        items = old[1] if old else set()
        items.add(item)
        self._buckets[(kind, root, scope)] = (bucket, items)

    def _burst(self, kind: str, root: str, role: str, ts: float, item) -> bool:
        hit = False
        for scope, _seconds in self._scopes():
            w = self._win(kind, root, scope)
            w.add(ts, item)
            self._learn_buckets(kind, root, role, ts, item, scope)
            lam = self._rate_for(kind, role, scope).value
            hit = hit or poisson_tail(w.distinct(), lam) < self.policy.math.poisson_alpha
        return hit

    # -- the four detectors -----------------------------------------------------------------------

    def mass_change(self, root: str, role: str, ts: float, fp: str | None) -> bool:
        return self._burst("mass_change", root, role, ts, fp)

    def lateral(self, root: str, role: str, ts: float, host_fp: str | None) -> bool:
        return self._burst("lateral", root, role, ts, host_fp)

    def exfil(self, root: str, role: str, ts: float, nbytes: float) -> bool:
        """CUSUM on the z-score of the bytes sent per window, against the role's baseline."""
        m = self.policy.math
        mean0, sigma = m.baseline_bytes.get(role, m.baseline_bytes_default)
        mean = self._volume_mean.setdefault(role, Ema(mean0, m.ema_beta, bool(self._incident)))
        cusum = self._cusum.setdefault(root, Cusum(m.cusum.k, m.cusum.h))
        bucket = math.floor(ts / self.policy.rates.window)
        prev_bucket, total = self._volume.get(root, (bucket, 0.0))
        if prev_bucket != bucket:  # the previous window is closed: it enters the statistic
            cusum.update(z_score(total, mean.value, sigma))
            mean.update(total)
            total = 0.0
        total += nbytes
        self._volume[root] = (bucket, total)
        return cusum.peek(z_score(total, mean.value, sigma)) > cusum.h

    def response(self, client: str, role: str, ts: float, nbytes: float) -> tuple[bool, bool]:
        """(this response is anomalous, anomalies to this client are repeated at Poisson level)."""
        if nbytes < self.policy.rates.response_anomaly_bytes:
            return False, False
        repeated = False
        for scope, _seconds in self._scopes():
            w = self._win("response", client, scope)
            w.add(ts, None, nbytes)
            lam = self._rate_for("response_anomaly", role, scope).value
            count = len(w.items)
            repeated = repeated or (
                count > 1 and poisson_tail(count, lam) < self.policy.math.poisson_alpha
            )
        return True, repeated
