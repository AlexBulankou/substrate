# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""SLO-knee throughput post-processor over runner.py's stats.jsonl.

runner.py emits one JSONL entry per named gRPC op per run, with a
``measurements`` map carrying p50/p95/p99/requests_per_s (latencies in ms).
A *ladder* is several such runs at the same ``tag`` and ascending concurrent
user counts. Given a target op (e.g. "ResumeActor") and a latency SLO (1s /
5s), this reports the **SLO-knee**: the highest user-count rung whose target-op
p95 still met the SLO, plus that rung's throughput (requests_per_s). That is
the sustainable-load number the concurrency sweep exists to find.

Pure stdlib, offline-testable against synthetic JSONL fixtures (no cluster).
Additive to the benchmarking tree: reads the JSONL the working p50/p95/RPS
path already writes; never mutates a run.

User-count provenance (the #6595 seam), in precedence order:
  (b) the explicit top-level ``users`` field runner.py now stamps into each
      entry (preferred — unambiguous); falling back to
  (a) a ``_<N>_users`` substring parsed out of ``test_name`` (the naming
      convention the glutton ladder already follows, e.g.
      "glutton_baseline_10_users") when the explicit field is absent (older
      JSONL emitted before the stamp landed).
An entry that yields a user count by neither path is skipped with a note; it
cannot be placed on the ladder.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# Parse "_<N>_users" out of a test_name (fallback provenance path (a)).
_USERS_IN_NAME = re.compile(r"_(\d+)_users\b")


def parse_slo_ms(spec: str) -> float:
    """Parse an SLO latency spec into milliseconds.

    Accepts "1s", "5s", "500ms", "1500" (bare number => ms), "2.5s". Raises
    ValueError on anything else so a typo'd SLO fails loud rather than
    silently gating at a nonsense threshold.
    """
    s = spec.strip().lower()
    if not s:
        raise ValueError("empty SLO spec")
    if s.endswith("ms"):
        return float(s[:-2])
    if s.endswith("s"):
        return float(s[:-1]) * 1000.0
    # bare number: interpret as milliseconds
    return float(s)


def user_count_for_entry(entry: dict) -> int | None:
    """Resolve an entry's concurrent-user count: explicit field, then name.

    Precedence: the explicit top-level ``users`` field (option (b)); else a
    ``_<N>_users`` substring in ``test_name`` (option (a)); else None.
    """
    u = entry.get("users")
    if isinstance(u, bool):
        # bool is an int subclass in Python; a stray True/False is not a count.
        u = None
    if isinstance(u, int):
        return u
    if isinstance(u, str):
        try:
            return int(u)
        except ValueError:
            pass
    name = entry.get("test_name") or ""
    m = _USERS_IN_NAME.search(name)
    if m:
        return int(m.group(1))
    return None


def _measurement_float(measurements: dict, key: str) -> float | None:
    raw = measurements.get(key)
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


@dataclass
class Rung:
    """One ladder rung: the target op's measurement at a given user count."""

    users: int
    latency_ms: float
    requests_per_s: float
    meets_slo: bool


@dataclass
class SLOKneeResult:
    target_op: str
    slo_ms: float
    latency_field: str
    rungs: list[Rung] = field(default_factory=list)  # ascending by users
    knee_users: int | None = None
    knee_requests_per_s: float | None = None
    # True when the top rung still met the SLO: the real knee may be higher
    # than any rung we measured (extend the ladder to find it).
    saturated_beyond_range: bool = False
    # True when even the smallest rung failed the SLO: the knee (if any) is
    # below the range we measured.
    below_smallest_rung: bool = False
    skipped: list[str] = field(default_factory=list)  # human-readable notes


def _iter_jsonl(path: Path) -> Iterable[dict]:
    with open(path) as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                # Skip a malformed line rather than aborting the whole ladder;
                # a partial JSONL from a crashed run should still yield a knee
                # from its good rungs.
                continue
            if isinstance(obj, dict):
                yield obj


def find_slo_knee(
    entries: Iterable[dict],
    target_op: str,
    slo_ms: float,
    latency_field: str = "p95",
) -> SLOKneeResult:
    """Compute the SLO-knee for ``target_op`` across a flattened entry stream.

    ``target_op`` matches an entry's ``metric`` (e.g. "gRPC_ResumeActor") by
    case-insensitive substring, so callers pass "ResumeActor" without the
    "gRPC_" type prefix. Among rungs whose ``latency_field`` (default p95) is
    strictly below ``slo_ms``, the knee is the one with the MAX user count.

    When two entries land on the same user count for the target op (should not
    happen in a clean ladder), the more conservative — higher latency — one is
    kept so a spurious fast duplicate can't inflate the knee.
    """
    result = SLOKneeResult(
        target_op=target_op, slo_ms=slo_ms, latency_field=latency_field
    )
    needle = target_op.lower()
    # users -> Rung, keeping the most conservative rung per user count.
    by_users: dict[int, Rung] = {}
    for entry in entries:
        metric = entry.get("metric") or ""
        if needle not in metric.lower():
            continue
        users = user_count_for_entry(entry)
        if users is None:
            result.skipped.append(
                f"no user count for entry metric={metric!r} "
                f"test_name={entry.get('test_name')!r}"
            )
            continue
        measurements = entry.get("measurements") or {}
        latency = _measurement_float(measurements, latency_field)
        if latency is None:
            result.skipped.append(
                f"no {latency_field} for users={users} metric={metric!r}"
            )
            continue
        rps = _measurement_float(measurements, "requests_per_s")
        if rps is None:
            rps = 0.0
        rung = Rung(
            users=users,
            latency_ms=latency,
            requests_per_s=rps,
            meets_slo=latency < slo_ms,
        )
        prior = by_users.get(users)
        if prior is None or rung.latency_ms > prior.latency_ms:
            by_users[users] = rung

    result.rungs = [by_users[u] for u in sorted(by_users)]
    if not result.rungs:
        return result

    meeting = [r for r in result.rungs if r.meets_slo]
    if not meeting:
        result.below_smallest_rung = True
        return result

    knee = max(meeting, key=lambda r: r.users)
    result.knee_users = knee.users
    result.knee_requests_per_s = knee.requests_per_s
    result.saturated_beyond_range = knee.users == result.rungs[-1].users
    return result


def load_ladder(paths: Iterable[Path]) -> list[dict]:
    """Flatten all JSONL entries across the given ladder files."""
    entries: list[dict] = []
    for p in paths:
        entries.extend(_iter_jsonl(Path(p)))
    return entries


def format_result(result: SLOKneeResult) -> str:
    lines = [
        f"SLO-knee for op~={result.target_op!r} "
        f"@ {result.latency_field} < {result.slo_ms:g}ms",
        "  ladder (users -> {}ms, rps, meets):".format(result.latency_field),
    ]
    for r in result.rungs:
        mark = "OK " if r.meets_slo else "OVER"
        lines.append(
            f"    {r.users:>5}  {r.latency_ms:>10.2f}  "
            f"{r.requests_per_s:>10.2f}  [{mark}]"
        )
    if result.knee_users is None:
        if not result.rungs:
            lines.append("  knee: NONE (no matching rungs)")
        else:
            lines.append(
                "  knee: NONE — even the smallest rung "
                f"({result.rungs[0].users} users) exceeded the SLO"
            )
    else:
        note = ""
        if result.saturated_beyond_range:
            note = "  (saturated: top rung still met SLO, real knee may be higher)"
        lines.append(
            f"  knee: {result.knee_users} users @ "
            f"{result.knee_requests_per_s:.2f} req/s{note}"
        )
    for s in result.skipped:
        lines.append(f"  skipped: {s}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Report the SLO-knee (max sustainable load) for a target "
        "op across a ladder of runner.py stats.jsonl files."
    )
    parser.add_argument(
        "jsonl", nargs="+", type=Path,
        help="one or more stats.jsonl files forming the ladder",
    )
    parser.add_argument(
        "--op", required=True,
        help="target op, matched as a substring of the entry metric "
        "(e.g. ResumeActor)",
    )
    parser.add_argument(
        "--slo", required=True,
        help="latency SLO: '1s', '5s', '500ms', or bare ms",
    )
    parser.add_argument(
        "--latency-field", default="p95",
        help="which percentile to gate on (default: p95)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="emit the result as JSON instead of a text table",
    )
    args = parser.parse_args(argv)

    entries = load_ladder(args.jsonl)
    result = find_slo_knee(
        entries, args.op, parse_slo_ms(args.slo), args.latency_field
    )
    if args.json:
        payload = {
            "target_op": result.target_op,
            "slo_ms": result.slo_ms,
            "latency_field": result.latency_field,
            "knee_users": result.knee_users,
            "knee_requests_per_s": result.knee_requests_per_s,
            "saturated_beyond_range": result.saturated_beyond_range,
            "below_smallest_rung": result.below_smallest_rung,
            "rungs": [
                {
                    "users": r.users,
                    "latency_ms": r.latency_ms,
                    "requests_per_s": r.requests_per_s,
                    "meets_slo": r.meets_slo,
                }
                for r in result.rungs
            ],
            "skipped": result.skipped,
        }
        print(json.dumps(payload, indent=2))
    else:
        print(format_result(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
