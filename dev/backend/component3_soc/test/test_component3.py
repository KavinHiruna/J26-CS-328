"""
Tests for Component 3. Run from the dev folder:

    python -m unittest discover -s backend/component3_soc/test -v

Uses only Python's built-in unittest, so nothing extra has to be installed.
The tests do NOT trust the code under test: expected numbers are written out by hand (plain arithmetic) or
recomputed in a different way (eigenvector of the survey matrix, a second live-versus-batch route).
"""
import json
import sys
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))      # the dev folder (contains backend/)
from backend.component3_soc import calibrate, config, factors, pipeline, scoring, service, soc_logic  # noqa: E402

ATTACKS = ["Backdoor", "DDoS_HTTP", "DDoS_ICMP", "DDoS_TCP", "DDoS_UDP", "Fingerprinting", "MITM", "Password",
           "Port_Scanning", "Ransomware", "SQL_injection", "Uploading", "Vulnerability_scanner", "XSS"]


class TestScoring(unittest.TestCase):
    """The formula, checked against numbers worked out by hand."""

    def test_hand_calculated_cases(self):
        # (severity, confidence, asset, frequency) -> score worked out on paper with the survey weights
        cases = [((5, 1.0, 5, 5), 100.0),            # everything at maximum
                 ((1, 0.0, 1, 1), 0.0),              # everything at minimum
                 ((3, 0.5, 3, 2), 47.58),            # 100 x (0.3154x0.5 + 0.1718x0.5 + 0.4158x0.5 + 0.0970x0.25)
                 ((2, 0.75, 4, 3), 56.81),
                 ((5, 0.9, 5, 4), 95.86)]
        for inputs, expected in cases:
            with self.subTest(inputs=inputs):
                self.assertAlmostEqual(scoring.risk_score(*inputs), expected, places=2)

    def test_rejects_bad_input(self):
        bad = [(None, .5, 3, 2), (3, 1.5, 3, 2), (3, .5, 0, 2), (3, .5, 3, 6), ("high", .5, 3, 2),
               (True, .5, 3, 2), (3, float("nan"), 3, 2), (6, .5, 3, 2), (3, -0.1, 3, 2)]
        for inputs in bad:
            with self.subTest(inputs=inputs):
                with self.assertRaises(ValueError):
                    scoring.risk_score(*inputs)

    def test_level_boundaries(self):
        for score, level in [(100, "Critical"), (90, "Critical"), (89.99, "High"), (70, "High"), (69.99, "Medium"),
                             (40, "Medium"), (39.99, "Low"), (0, "Low")]:
            with self.subTest(score=score):
                self.assertEqual(scoring.priority_level(score), level)
        with self.assertRaises(ValueError):
            scoring.priority_level(100.5)

    def test_more_risk_never_lowers_score(self):
        base = scoring.risk_score(3, .5, 3, 3)
        self.assertGreater(scoring.risk_score(4, .5, 3, 3), base)
        self.assertGreater(scoring.risk_score(3, .6, 3, 3), base)
        self.assertGreater(scoring.risk_score(3, .5, 4, 3), base)
        self.assertGreater(scoring.risk_score(3, .5, 3, 4), base)

    def test_contributions_add_up_to_the_score(self):
        parts = scoring.contributions(4, .8, 5, 3)
        self.assertAlmostEqual(sum(parts.values()), scoring.risk_score(4, .8, 5, 3), places=1)

    def test_advice(self):
        self.assertIn("Investigate the alert immediately", scoring.recommend("Critical", "Ransomware"))
        self.assertTrue(any("encryption" in step for step in scoring.recommend("High", "Ransomware")))
        with self.assertRaises(ValueError):
            scoring.recommend("Urgent", "XSS")


class TestWeights(unittest.TestCase):
    def test_weights_sum_to_one(self):
        self.assertAlmostEqual(sum(config.WEIGHTS.values()), 1.0, places=4)

    def test_weights_match_survey_eigenvector(self):
        """Recompute the AHP weights from the survey's group matrix (principal eigenvector) and compare."""
        matrix = pd.read_csv(config.GROUP_MATRIX_FILE, index_col=0).to_numpy(float)
        values, vectors = np.linalg.eig(matrix)
        top = np.argmax(values.real)
        weights = np.abs(vectors[:, top].real)
        weights = weights / weights.sum()
        for name, computed in zip(["severity", "confidence", "asset", "frequency"], weights):
            with self.subTest(factor=name):
                self.assertAlmostEqual(config.WEIGHTS[name], computed, delta=0.001)
        ci = (values.real.max() - 4) / 3
        self.assertLess(ci / 0.90, 0.10)                 # consistency ratio below Saaty's 0.10 limit


class TestFactors(unittest.TestCase):
    def test_every_attack_has_a_severity_between_1_and_5(self):
        for attack in ATTACKS:
            with self.subTest(attack=attack):
                self.assertTrue(1 <= factors.get_severity(attack) <= 5)

    def test_known_severities(self):
        # published CAPEC levels mapped Very Low..Very High -> 1..5, or the survey-2 median
        expected = {"Fingerprinting": 1, "Port_Scanning": 2, "DDoS_TCP": 3, "Password": 4, "XSS": 5, "Ransomware": 5,
                    "Backdoor": 5, "SQL_injection": 4}
        for attack, value in expected.items():
            with self.subTest(attack=attack):
                self.assertEqual(factors.get_severity(attack), value)

    def test_unknown_attack_is_rejected(self):
        with self.assertRaises(ValueError):
            factors.get_severity("Not_An_Attack")

    def test_asset_lookup(self):
        self.assertEqual(factors.get_asset("192.168.0.128")[0], "OT-001")
        self.assertEqual(factors.get_asset("192.168.0.128")[2], 5.0)
        asset_id, _, crit, status = factors.get_asset("10.9.9.9")
        self.assertEqual(asset_id, config.FALLBACK_ASSET_ID)
        self.assertTrue(status.startswith("fallback"))

    def test_log_frequency(self):
        self.assertEqual(factors.log_frequency(1), 1.0)
        self.assertEqual(factors.log_frequency(0), 1.0)
        self.assertEqual(factors.log_frequency(500), 5.0)
        self.assertEqual(factors.log_frequency(5000), 5.0)
        self.assertAlmostEqual(factors.log_frequency(10), 1 + 4 * 1 / np.log10(500), places=2)

    def test_window_counts_by_hand(self):
        alerts = pd.DataFrame({"flow_id": range(7), "dst_ip": ["A"] * 4 + ["B"] * 2 + ["A"],
                               "predicted_type": ["X"] * 4 + ["X"] * 2 + ["Y"],
                               "event_time": [0, 10, 20, 100, 5, 6, np.nan]})
        counts = factors.window_counts(alerts)
        # A/X at 0,10,20,100: 1, 2, 3 (0 to 20 are within 60 s) and 1 (the one at 100 is 80 s after 20)
        self.assertEqual(list(counts[:4]), [1, 2, 3, 1])
        self.assertEqual(list(counts[4:6]), [1, 2])      # B/X at 5 and 6
        self.assertTrue(np.isnan(counts[6]))             # no timestamp: left empty, fallback used instead
        self.assertEqual(factors.capture_counts(alerts)[0], 4)

    def test_live_counter_matches_by_hand(self):
        counter = factors.WindowCounter()
        got = [counter.add("A", "X", t) for t in [0, 10, 20, 100]]
        self.assertEqual(got, [1, 2, 3, 1])
        counter.reset()
        self.assertEqual(counter.add("A", "X", 0), 1)


class TestCalibration(unittest.TestCase):
    def test_calibration_makes_confidence_honest(self):
        alerts = pipeline.load_alerts()
        calibrated = calibrate.calibrate(alerts)
        correct = (alerts["predicted_type"] == alerts["true_type"]).to_numpy(float)
        before = calibrate.ece(alerts["confidence_raw"].to_numpy(float), correct)
        after = calibrate.ece(calibrated, correct)
        self.assertGreater(before, 0.05)                 # raw: over-confident
        self.assertLess(after, 0.01)                     # calibrated: honest
        self.assertTrue(((calibrated >= 0) & (calibrated <= 1)).all())


class TestPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw, cls.queue = pipeline.run(save=False)

    def test_counts(self):
        self.assertEqual(len(self.raw), 31560)
        self.assertEqual(len(self.queue), 26699)                       # 4,861 flows predicted Normal are dropped
        self.assertFalse((self.queue["predicted_type"] == "Normal").any())

    def test_level_counts_match_the_verified_run(self):
        counts = self.queue["priority"].value_counts().to_dict()
        self.assertEqual(counts.get("Critical", 0), 3642)
        self.assertEqual(counts.get("High", 0), 16066)
        self.assertEqual(counts.get("Medium", 0), 6991)
        self.assertEqual(counts.get("Low", 0), 0)

    def test_no_missing_values_and_sorted(self):
        core = self.queue.drop(columns=["window_count"])               # empty by design when no timestamp
        self.assertFalse(core.isna().any().any())
        self.assertTrue(self.queue["risk_score"].is_monotonic_decreasing)

    def test_every_score_is_recomputed_identically(self):
        again = [scoring.risk_score(r.attack_severity, r.detection_confidence, r.asset_criticality, r.attack_frequency)
                 for r in self.queue.itertuples()]
        self.assertEqual(list(self.queue["risk_score"]), again)
        self.assertEqual(list(self.queue["priority"]), [scoring.priority_level(s) for s in self.queue["risk_score"]])

    def test_fallbacks_are_flagged(self):
        fallback = self.queue[self.queue["frequency_basis"].str.startswith("fallback")]
        self.assertEqual(sorted(fallback["predicted_type"].unique()), ["DDoS_UDP", "MITM"])   # the two without timestamps
        self.assertAlmostEqual(len(fallback) / len(self.queue), 0.12, delta=0.005)
        unmapped = self.queue[self.queue["asset_status"].str.startswith("fallback")]
        self.assertAlmostEqual(len(unmapped) / len(self.queue), 0.193, delta=0.005)

    def test_ransomware_on_the_control_endpoint_ranks_at_the_top(self):
        top = self.queue.head(50)
        self.assertTrue((top["asset_id"] == "OT-001").all())
        self.assertTrue((self.queue["risk_score"].iloc[0] >= 94))

    def test_detector_accuracy_is_unchanged(self):
        self.assertAlmostEqual((self.raw["predicted_type"] == self.raw["true_type"]).mean(), 0.9065, places=3)

    def test_what_if_agrees_with_the_pipeline(self):
        row = self.queue[self.queue["asset_id"] == "OT-001"].iloc[0]
        by_ip, _ = factors.registry()
        ip = [k for k, v in by_ip.items() if v == "OT-001"][0]
        count = int(round(10 ** ((row["attack_frequency"] - 1) / 4 * np.log10(500))))
        result = soc_logic.what_if(row["predicted_type"], row["detection_confidence"], ip, count)
        self.assertAlmostEqual(result["score"], row["risk_score"], delta=0.1)


class TestService(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        patcher = mock.patch.object(service, "LIVE_FILE", Path(self.tmp.name) / "live.jsonl")
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)
        service.reset()

    def message(self, **change):
        base = {"flow_id": 1, "src_ip": "192.168.0.170", "dst_ip": "192.168.0.128", "predicted_type": "Ransomware",
                "confidence": 0.97, "event_time": 1000.0}
        base.update(change)
        return base

    def test_scores_an_alert_by_hand(self):
        result = service.score_alert(self.message())
        # By hand: 100 x (0.3154 x 1 + 0.1718 x 0.97 + 0.4158 x 1 + 0.0970 x 0) = 31.54 + 16.66 + 41.58 = 89.78
        # (severity 5, confidence 0.97, control endpoint 5, a single alert = frequency 1.0)
        self.assertAlmostEqual(result["risk_score"], 89.78, places=2)
        self.assertEqual(result["priority"], "High")                  # 89.78 is just below the Critical cut-off of 90
        self.assertEqual(result["asset_id"], "OT-001")

    def test_repeats_raise_the_frequency(self):
        first = service.score_alert(self.message(event_time=1000.0))
        second = service.score_alert(self.message(flow_id=2, event_time=1010.0))
        self.assertEqual(second["frequency_count"], 2)
        self.assertGreater(second["risk_score"], first["risk_score"])
        far_later = service.score_alert(self.message(flow_id=3, event_time=5000.0))
        self.assertEqual(far_later["frequency_count"], 1)              # the window has moved on

    def test_normal_is_dropped_and_bad_messages_rejected(self):
        self.assertIsNone(service.score_alert(self.message(predicted_type="Normal")))
        for bad in [{"src_ip": "a"}, self.message(predicted_type="Alien"), self.message(confidence=1.7),
                    self.message(confidence="high")]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    service.score_alert(bad)

    def test_no_timestamp_is_flagged_fallback(self):
        message = self.message()
        del message["event_time"]
        result = service.score_alert(message)
        self.assertTrue(result["frequency_basis"].startswith("fallback"))

    def test_live_equals_batch_for_alerts_with_timestamps(self):
        raw = pipeline.load_alerts()
        raw["confidence"] = calibrate.calibrate(raw)
        _, queue = pipeline.run(save=False)
        timed = raw[(raw["predicted_type"] != "Normal") & raw["event_time"].notna()].sort_values(["event_time", "flow_id"])
        live = {}
        for r in timed.itertuples():
            out = service.score_alert({"flow_id": r.flow_id, "src_ip": r.src_ip, "dst_ip": r.dst_ip,
                                       "predicted_type": r.predicted_type, "confidence": r.confidence,
                                       "event_time": r.event_time})
            live[r.flow_id] = out["risk_score"]
        batch = queue.set_index("flow_id").loc[list(live)]["risk_score"].to_numpy()
        self.assertEqual(len(live), 23499)
        self.assertTrue((batch == np.array(list(live.values()))).all())

    def test_http_interface(self):
        server = service.make_server("127.0.0.1", 0)                   # port 0 = any free port
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)

        def call(path, payload=None):
            data = json.dumps(payload).encode() if payload is not None else None
            request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data)
            try:
                with urllib.request.urlopen(request, timeout=5) as reply:
                    return reply.status, json.loads(reply.read())
            except urllib.error.HTTPError as error:
                return error.code, json.loads(error.read())

        status, body = call("/alert", self.message())
        self.assertEqual((status, body["status"], body["priority"]), (200, "scored", "High"))
        self.assertEqual(call("/alert", self.message(predicted_type="Normal"))[1]["status"], "benign, dropped")
        status, body = call("/alert", self.message(confidence=9))
        self.assertEqual((status, body["status"]), (400, "rejected"))
        status, health = call("/health")
        self.assertEqual((health["received"], health["scored"], health["rejected"]), (3, 1, 1))     # 3 messages received: 1 scored, 1 benign, 1 rejected
        self.assertEqual(len(call("/alerts?limit=5")[1]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
