"""
Tests for the evidence scripts: they must reproduce the numbers the presentation quotes.
Run from the dev folder:   python -m unittest discover -s backend/component3_soc/test -v
"""
import contextlib
import io
import sys
import unittest
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))      # the dev folder (contains backend/)
from backend.component3_soc import config, factors, pipeline  # noqa: E402
from backend.component3_soc.analysis import (ahp_survey, evidence_check, expert_validation, parameter_register, sensitivity,  # noqa: E402
                                              survey2_values, window_evidence)


def quiet(function, *args):
    """Run a script's main() without printing its report."""
    with contextlib.redirect_stdout(io.StringIO()):
        return function(*args)


class TestSurveys(unittest.TestCase):
    def test_ahp_survey_reproduces_the_weights(self):
        df = pd.read_csv(config.SURVEY1_FILE)
        self.assertEqual(len(df), 15)
        per_person, group, weights, cr = ahp_survey.analyse(df)
        self.assertLess(cr, 0.10)
        self.assertAlmostEqual(cr, 0.031, places=3)
        for key, w in zip(ahp_survey.KEYS, weights):
            self.assertAlmostEqual(config.WEIGHTS[key], w, delta=0.001)

    def test_survey_files_contain_no_free_text_comments(self):
        columns = pd.read_csv(config.SURVEY1_FILE).columns
        self.assertFalse(any(c.strip().startswith("9.") for c in columns))

    def test_survey2_matches_the_evidence_tables(self):
        self.assertEqual(len(pd.read_csv(config.SURVEY2_FILE)), 10)
        self.assertTrue(quiet(survey2_values.main)["ok"])


class TestDataEvidence(unittest.TestCase):
    def test_window_evidence(self):
        result = quiet(window_evidence.main)
        self.assertAlmostEqual(result["share_le_60"], 0.974, places=3)     # 97.4% of gaps <= 60 s
        self.assertAlmostEqual(result["p99_count"], 467, delta=1)          # 99th percentile of 60 s counts
        self.assertLessEqual(result["p99_count"], config.WINDOW_CAP)

    def test_sensitivity(self):
        table = quiet(sensitivity.main)["table"].set_index("change")
        for name in [n for n in table.index if n.startswith("weight of")]:   # +-20% on one weight barely moves the queue
            with self.subTest(name=name):
                self.assertGreater(table.loc[name, "spearman_with_chosen"], 0.98)
                self.assertEqual(table.loc[name, "top1000_kept_%"], 100.0)
        self.assertEqual(table.loc["level cut-offs 85/65/40", "spearman_with_chosen"], 1.0)   # cut-offs never reorder


class TestConfigMatchesEvidence(unittest.TestCase):
    """The scoring code uses the numbers in config.py; the evidence files must say the same."""

    def test_every_number_matches_its_evidence_file(self):
        for what, in_config, in_file, ok in evidence_check.compare():
            with self.subTest(item=what):
                self.assertTrue(ok, f"{what}: config.py has {in_config!r}, evidence file has {in_file!r}")

    def test_scoring_code_does_not_read_evidence_files(self):
        source = (Path(config.HERE) / "factors.py").read_text(encoding="utf-8")
        self.assertNotIn("read_csv", source)
        self.assertEqual(factors.get_severity("SQL_injection"), config.SEVERITY["SQL_injection"])
        self.assertEqual(factors.get_asset("192.168.0.128")[2], config.ROLE_CRITICALITY["control_endpoint"])


class TestExpertValidation(unittest.TestCase):
    def test_sheets_are_complete_and_valid(self):
        key = pd.read_csv(config.EXPERT_KEY_FILE)
        _, queue = pipeline.run(save=False)
        self.assertEqual(len(key), 100)
        self.assertTrue(key["flow_id"].is_unique)
        self.assertTrue(set(key["flow_id"]) <= set(queue["flow_id"]))
        sheets = sorted(config.EXPERT_DIR.glob("*.xlsx"))
        self.assertEqual(len(sheets), 2)
        for path in sheets:
            ratings = pd.read_excel(path, sheet_name="Alerts").filter(like="Rating").iloc[:, 0]
            self.assertEqual(len(ratings), 100)
            self.assertTrue(ratings.isin(["Critical", "High", "Medium", "Low"]).all(), path.name)

    def test_agreement_numbers(self):
        result = quiet(expert_validation.evaluate)
        methods = result["methods"]["spearman_with_raters_mean"]
        self.assertAlmostEqual(methods["Risk score (AHP weights)"], 0.700, delta=0.005)
        self.assertGreater(methods["Risk score (AHP weights)"], methods["Severity only"] + 0.3)
        self.assertAlmostEqual(result["between_raters"][0], 0.41, delta=0.01)    # the raters agree only weakly


class TestRegister(unittest.TestCase):
    def test_register_matches_the_code(self):
        table = parameter_register.rows().set_index("parameter")
        for key, name in [("severity", "Severity"), ("confidence", "Confidence"), ("asset", "Asset criticality"),
                          ("frequency", "Frequency")]:
            self.assertEqual(float(table.loc[f"Weight: {name}", "value"]), config.WEIGHTS[key])
        self.assertEqual(table.loc["Frequency window", "value"], f"{config.WINDOW_SECONDS} s")
        self.assertEqual(int(table.loc["Frequency cap", "value"]), config.WINDOW_CAP)
        for level, cut in config.LEVEL_CUTOFFS.items():
            self.assertEqual(table.loc[f"Level cut-off: {level}", "value"], f">= {cut}")
        self.assertFalse(table["source"].isna().any() if "source" in table else table["where_in_code"].isna().any())
        self.assertGreaterEqual(len(table), 25)


if __name__ == "__main__":
    unittest.main(verbosity=2)
