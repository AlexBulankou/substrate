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

"""Offline unit tests for the SLO-knee post-processor.

Stdlib unittest (no pytest) so it runs with a bare `python3 -m unittest` in
the benchmarking image without adding a test dependency. Fixtures are
synthetic JSONL matching runner.py's stats_to_jsonl entry shape — no cluster,
no GCS.
"""

import json
import tempfile
import unittest
from pathlib import Path

import slo_knee


def _entry(op, users, p95_ms, rps, *, include_users=True, test_name=None):
    """Build one runner.py-shaped stats.jsonl entry."""
    e = {
        "timestamp": "2026-08-12T00:00:00Z",
        "tag": "deadbeef",
        "test_name": test_name if test_name is not None else f"ladder_{users}_users",
        "metric": f"gRPC_{op}",
        "measurements": {
            "p50": p95_ms / 2.0,
            "p95": p95_ms,
            "p99": p95_ms * 1.2,
            "requests_per_s": rps,
        },
    }
    if include_users:
        e["users"] = users
    return e


class TestParseSloMs(unittest.TestCase):
    def test_seconds(self):
        self.assertEqual(slo_knee.parse_slo_ms("1s"), 1000.0)
        self.assertEqual(slo_knee.parse_slo_ms("5s"), 5000.0)
        self.assertEqual(slo_knee.parse_slo_ms("2.5s"), 2500.0)

    def test_millis(self):
        self.assertEqual(slo_knee.parse_slo_ms("500ms"), 500.0)

    def test_bare_number_is_ms(self):
        self.assertEqual(slo_knee.parse_slo_ms("1500"), 1500.0)

    def test_bad_spec_raises(self):
        with self.assertRaises(ValueError):
            slo_knee.parse_slo_ms("")
        with self.assertRaises(ValueError):
            slo_knee.parse_slo_ms("fast")


class TestUserCountProvenance(unittest.TestCase):
    def test_prefers_explicit_field(self):
        # Explicit field wins even when the name would parse to something else.
        e = _entry("ResumeActor", 10, 100.0, 5.0, test_name="ladder_99_users")
        self.assertEqual(slo_knee.user_count_for_entry(e), 10)

    def test_falls_back_to_name_parse(self):
        e = _entry(
            "ResumeActor", 7, 100.0, 5.0,
            include_users=False, test_name="glutton_baseline_7_users",
        )
        self.assertEqual(slo_knee.user_count_for_entry(e), 7)

    def test_string_users_field_coerced(self):
        e = _entry("ResumeActor", 0, 100.0, 5.0, include_users=False)
        e["users"] = "12"
        self.assertEqual(slo_knee.user_count_for_entry(e), 12)

    def test_none_when_no_provenance(self):
        e = _entry(
            "ResumeActor", 0, 100.0, 5.0,
            include_users=False, test_name="no_count_here",
        )
        self.assertIsNone(slo_knee.user_count_for_entry(e))

    def test_bool_users_field_ignored(self):
        e = _entry(
            "ResumeActor", 0, 100.0, 5.0,
            include_users=False, test_name="ladder_3_users",
        )
        e["users"] = True  # bool is an int subclass; must not be read as 1
        self.assertEqual(slo_knee.user_count_for_entry(e), 3)


class TestFindSloKnee(unittest.TestCase):
    def _ladder(self):
        # p95 climbs with load; SLO=1s (1000ms) knee sits at 10 users.
        return [
            _entry("ResumeActor", 1, 200.0, 4.0),
            _entry("ResumeActor", 5, 600.0, 18.0),
            _entry("ResumeActor", 10, 950.0, 30.0),
            _entry("ResumeActor", 15, 1400.0, 33.0),
        ]

    def test_knee_in_middle(self):
        r = slo_knee.find_slo_knee(self._ladder(), "ResumeActor", 1000.0)
        self.assertEqual(r.knee_users, 10)
        self.assertAlmostEqual(r.knee_requests_per_s, 30.0)
        self.assertFalse(r.saturated_beyond_range)
        self.assertFalse(r.below_smallest_rung)
        self.assertEqual([rung.users for rung in r.rungs], [1, 5, 10, 15])

    def test_all_rungs_meet_slo_is_saturated(self):
        r = slo_knee.find_slo_knee(self._ladder(), "ResumeActor", 5000.0)
        self.assertEqual(r.knee_users, 15)  # top rung
        self.assertTrue(r.saturated_beyond_range)
        self.assertFalse(r.below_smallest_rung)

    def test_no_rung_meets_slo(self):
        r = slo_knee.find_slo_knee(self._ladder(), "ResumeActor", 100.0)
        self.assertIsNone(r.knee_users)
        self.assertIsNone(r.knee_requests_per_s)
        self.assertTrue(r.below_smallest_rung)
        self.assertFalse(r.saturated_beyond_range)

    def test_op_filter_isolates_target(self):
        # Two ops interleaved in the same stream; knee must reflect only the
        # target op's latencies, not the other's.
        entries = [
            _entry("ResumeActor", 1, 200.0, 4.0),
            _entry("SuspendActor", 1, 9000.0, 4.0),
            _entry("ResumeActor", 10, 900.0, 30.0),
            _entry("SuspendActor", 10, 9000.0, 30.0),
        ]
        r = slo_knee.find_slo_knee(entries, "ResumeActor", 1000.0)
        self.assertEqual(r.knee_users, 10)

    def test_substring_match_without_type_prefix(self):
        r = slo_knee.find_slo_knee(self._ladder(), "resume", 1000.0)
        self.assertEqual(r.knee_users, 10)  # case-insensitive substring

    def test_duplicate_user_count_keeps_conservative(self):
        # Two entries at 10 users: the slower one must decide SLO membership.
        entries = [
            _entry("ResumeActor", 1, 200.0, 4.0),
            _entry("ResumeActor", 10, 900.0, 30.0),
            _entry("ResumeActor", 10, 1200.0, 31.0),  # over SLO
        ]
        r = slo_knee.find_slo_knee(entries, "ResumeActor", 1000.0)
        # 10-user rung is now OVER (conservative), so knee falls back to 1.
        self.assertEqual(r.knee_users, 1)
        self.assertEqual(len(r.rungs), 2)

    def test_empty_stream(self):
        r = slo_knee.find_slo_knee([], "ResumeActor", 1000.0)
        self.assertIsNone(r.knee_users)
        self.assertEqual(r.rungs, [])
        self.assertFalse(r.below_smallest_rung)

    def test_missing_latency_field_skips_rung(self):
        e = _entry("ResumeActor", 5, 600.0, 18.0)
        del e["measurements"]["p95"]
        r = slo_knee.find_slo_knee([e], "ResumeActor", 1000.0)
        self.assertEqual(r.rungs, [])
        self.assertTrue(any("no p95" in s for s in r.skipped))

    def test_no_user_count_entry_skipped(self):
        e = _entry(
            "ResumeActor", 0, 600.0, 18.0,
            include_users=False, test_name="unlabeled",
        )
        r = slo_knee.find_slo_knee([e], "ResumeActor", 1000.0)
        self.assertEqual(r.rungs, [])
        self.assertTrue(any("no user count" in s for s in r.skipped))

    def test_latency_field_override(self):
        # Gate on p50 instead of p95: p50 = p95/2, so the 15-user rung
        # (p95=1400 -> p50=700) now meets a 1000ms SLO.
        r = slo_knee.find_slo_knee(
            self._ladder(), "ResumeActor", 1000.0, latency_field="p50"
        )
        self.assertEqual(r.knee_users, 15)
        self.assertTrue(r.saturated_beyond_range)


class TestLadderFromFiles(unittest.TestCase):
    def test_load_and_knee_from_jsonl_files(self):
        rungs = [
            _entry("ResumeActor", 1, 200.0, 4.0),
            _entry("ResumeActor", 5, 600.0, 18.0),
            _entry("ResumeActor", 10, 950.0, 30.0),
            _entry("ResumeActor", 15, 1400.0, 33.0),
        ]
        with tempfile.TemporaryDirectory() as d:
            paths = []
            for rung in rungs:
                p = Path(d) / f"run_{rung['users']}.jsonl"
                # One file per rung, each carrying the single target-op entry.
                p.write_text(json.dumps(rung) + "\n")
                paths.append(p)
            entries = slo_knee.load_ladder(paths)
            r = slo_knee.find_slo_knee(entries, "ResumeActor", 1000.0)
        self.assertEqual(r.knee_users, 10)
        self.assertAlmostEqual(r.knee_requests_per_s, 30.0)

    def test_malformed_line_skipped_not_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "run.jsonl"
            good = json.dumps(_entry("ResumeActor", 10, 900.0, 30.0))
            p.write_text(good + "\n" + "{not json\n" + "\n")
            entries = slo_knee.load_ladder([p])
            r = slo_knee.find_slo_knee(entries, "ResumeActor", 1000.0)
        self.assertEqual(r.knee_users, 10)


class TestMainCli(unittest.TestCase):
    def test_json_output_smoke(self):
        import contextlib
        import io

        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "run.jsonl"
            p.write_text(
                json.dumps(_entry("ResumeActor", 10, 900.0, 30.0)) + "\n"
            )
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = slo_knee.main(
                    [str(p), "--op", "ResumeActor", "--slo", "1s", "--json"]
                )
        self.assertEqual(rc, 0)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["knee_users"], 10)
        self.assertEqual(payload["slo_ms"], 1000.0)


if __name__ == "__main__":
    unittest.main()
