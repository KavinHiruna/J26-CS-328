"""
Tests for grouping alerts into incidents (incidents.py) and the export for Component 4 (export_incident.py).
Run from the dev folder:

    python -m unittest discover -s backend/component3_soc/test -v

Expected counts on the current data: 5,331 timed + 310 untimed = 5,641 incidents from 26,699 alerts.
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))      # the dev folder (contains backend/)
from backend.component3_soc import config, export_incident, incidents, pipeline, soc_logic  # noqa: E402

SCHEMA_KEYS = ["incident_id", "seed_ip", "time_window", "time_basis", "flagged_assets", "attack_type", "alert_count",
               "alert_ids", "priority", "risk_score", "reason", "recommendations"]


def small_alerts(rows):
    """Hand-made queue + alert table. rows = (flow_id, src_ip, dst_ip, type, event_time or None, risk_score)."""
    queue = pd.DataFrame([{"alert_id": f"FLOW-{f}", "flow_id": f, "src_ip": s, "dst_ip": d, "predicted_type": t,
                           "risk_score": r, "priority": "High", "asset_id": "OT-001",
                           "asset_status": "mapped from registry IP", "attack_severity": 5.0,
                           "detection_confidence": 1.0, "asset_criticality": 5.0, "attack_frequency": 1.0,
                           "recommendations": "step a | step b"} for f, s, d, t, _, r in rows])
    alerts = pd.DataFrame({"flow_id": [r[0] for r in rows],
                           "event_time": [np.nan if r[4] is None else r[4] for r in rows]})
    return queue, alerts


class TestGroupingByHand(unittest.TestCase):
    def test_gap_of_59_s_stays_and_61_s_splits(self):
        # times 0, 59, 118 (gaps 59) then 179 (gap 61) -> two incidents: [0, 59, 118] and [179]
        queue, alerts = small_alerts([(1, "A", "B", "X", 0.0, 80), (2, "A", "B", "X", 59.0, 80),
                                      (3, "A", "B", "X", 118.0, 80), (4, "A", "B", "X", 179.0, 80)])
        got = incidents.group_alerts(queue, alerts)
        self.assertEqual([list(ids) for ids in got["alert_ids"]], [["FLOW-1", "FLOW-2", "FLOW-3"], ["FLOW-4"]])
        self.assertEqual((got.loc[0, "start"], got.loc[0, "end"]), (0.0, 118.0))

    def test_gap_equal_to_the_window_stays(self):
        queue, alerts = small_alerts([(1, "A", "B", "X", 0.0, 80), (2, "A", "B", "X", float(config.WINDOW_SECONDS), 80)])
        self.assertEqual(len(incidents.group_alerts(queue, alerts)), 1)          # "at most" WINDOW_SECONDS

    def test_different_src_dst_or_type_never_merge(self):
        queue, alerts = small_alerts([(1, "A", "B", "X", 0.0, 80), (2, "C", "B", "X", 1.0, 80),     # other src
                                      (3, "A", "D", "X", 2.0, 80), (4, "A", "B", "Y", 3.0, 80),     # other dst, type
                                      (5, "A", "B", "X", None, 80), (6, "C", "B", "X", None, 80)])  # untimed too
        got = incidents.group_alerts(queue, alerts)
        self.assertEqual(len(got), 6)
        self.assertTrue((got["alert_count"] == 1).all())

    def test_untimed_alerts_form_one_capture_wide_group(self):
        queue, alerts = small_alerts([(1, "A", "B", "X", None, 70), (2, "A", "B", "X", None, 90),
                                      (3, "A", "B", "X", 0.0, 80)])
        got = incidents.group_alerts(queue, alerts)
        self.assertEqual(list(got["untimed"]), [False, True])                     # untimed groups get the last IDs
        untimed = incidents.build_incident(got.iloc[1])
        self.assertEqual(untimed["alert_ids"], ["FLOW-1", "FLOW-2"])
        self.assertIsNone(untimed["time_window"])
        self.assertEqual(untimed["time_basis"], "no timestamp (capture-wide group)")
        self.assertEqual(untimed["risk_score"], 90)                               # the highest alert decides
        self.assertEqual(incidents.build_incident(got.iloc[0])["time_basis"], "timestamps")


class TestIncidentsOnRealData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alerts = pipeline.load_alerts()
        _, cls.queue = pipeline.run(save=False)                          # fresh queue, not a file left on disk
        cls.incidents = incidents.group_alerts(cls.queue, cls.alerts)

    def test_counts(self):
        self.assertEqual(len(self.incidents), 5641)
        self.assertEqual(int((~self.incidents["untimed"]).sum()), 5331)
        self.assertEqual(int(self.incidents["untimed"].sum()), 310)
        self.assertEqual(int(self.incidents["alert_count"].sum()), 26699)
        self.assertEqual(self.incidents["priority"].value_counts().get("Critical", 0), 11)   # verified run

    def test_every_alert_in_exactly_one_incident(self):
        ids = [a for group in self.incidents["alert_ids"] for a in group]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(ids), set(self.queue["alert_id"]))
        counts = self.incidents["alert_ids"].map(len)
        self.assertTrue((counts == self.incidents["alert_count"]).all())

    def test_incident_score_is_the_max_alert_score(self):
        score = self.queue.set_index("alert_id")["risk_score"]
        for _, row in self.incidents.iterrows():
            group_max = score.loc[row["alert_ids"]].max()
            self.assertEqual(row["risk_score"], group_max, row["incident_id"])
            got = incidents.build_incident(row)
            # each reason value is rounded to 2 decimals, so the sum may be off by 0.01; round() removes float noise
            self.assertLessEqual(round(abs(sum(got["reason"].values()) - got["risk_score"]), 6), 0.01)

    def test_build_incident_schema_survives_json(self):
        for _, row in pd.concat([self.incidents.head(3), self.incidents.tail(3)]).iterrows():   # timed and untimed
            got = incidents.build_incident(row)
            self.assertEqual(list(got), SCHEMA_KEYS)
            self.assertEqual(json.loads(json.dumps(got)), got)
            self.assertEqual(got["alert_count"], len(got["alert_ids"]))

    def test_fallback_asset_stays_marked(self):
        row = self.incidents[self.incidents["asset_id"] == config.FALLBACK_ASSET_ID].iloc[0]
        asset = incidents.build_incident(row)["flagged_assets"][0]
        self.assertEqual(asset["asset_status"], "fallback (destination not in registry)")

    def test_ids_are_identical_when_run_twice(self):
        shuffled = self.queue.sample(frac=1, random_state=7)                      # input order must not matter
        again = incidents.group_alerts(shuffled, self.alerts)
        self.assertEqual(list(again["incident_id"]), list(self.incidents["incident_id"]))
        self.assertEqual(list(again["alert_ids"]), list(self.incidents["alert_ids"]))

    def test_export_command_line(self):
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(soc_logic, "load_queue", return_value=self.queue):
            self.assertEqual(export_incident.main(["--top", "3", "--priority", "Critical", "--out", folder]), 0)
            files = sorted(Path(folder).glob("*.json"))
            self.assertEqual(len(files), 3)
            for path in files:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(list(loaded), SCHEMA_KEYS)
                self.assertEqual(loaded["priority"], "Critical")
            self.assertEqual(export_incident.main(["--incident", "INC-999999", "--out", folder]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
