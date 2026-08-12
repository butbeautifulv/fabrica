"""ASPM SSVC-lite + offline CISA KEV mapping."""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_aspm():
    path = ROOT / "scripts" / "dojo-render-aspm-report.py"
    spec = importlib.util.spec_from_file_location("dojo_render_aspm_report", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["dojo_render_aspm_report"] = mod
    # Ensure scripts/ is on path for lib.kev_catalog before exec
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    spec.loader.exec_module(mod)
    return mod


asp = _load_aspm()


class TestKevAspmSsvc(unittest.TestCase):
    def test_medium_in_kev_is_act(self) -> None:
        f = asp.normalize_finding(
            {
                "title": "Medium CVE-2021-44228 in lib",
                "severity": "Medium",
                "cve": "CVE-2021-44228",
            }
        )
        catalog = frozenset({"CVE-2021-44228"})
        f = asp.apply_kev_flags([f], catalog)[0]
        self.assertTrue(f["in_kev"])
        self.assertEqual(asp.ssvc_lite(f), "Act")

    def test_critical_without_kev_stays_act(self) -> None:
        f = asp.normalize_finding({"title": "Crit", "severity": "Critical"})
        f = asp.apply_kev_flags([f], frozenset({"CVE-2021-44228"}))[0]
        self.assertFalse(f["in_kev"])
        self.assertEqual(asp.ssvc_lite(f), "Act")

    def test_high_without_kev_is_attend(self) -> None:
        f = asp.normalize_finding({"title": "High", "severity": "High"})
        f = asp.apply_kev_flags([f], frozenset())[0]
        self.assertEqual(asp.ssvc_lite(f), "Attend")

    def test_missing_catalog_no_crash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            missing = Path(td) / "nope.json"
            cat = asp.load_kev_catalog_optional(missing)
            self.assertIsNone(cat)
            f = asp.normalize_finding(
                {"title": "CVE-2021-44228", "severity": "Medium", "cve": "CVE-2021-44228"}
            )
            f2 = asp.apply_kev_flags([f], cat)[0]
            self.assertFalse(f2["in_kev"])
            self.assertEqual(asp.ssvc_lite(f2), "Track*")

    def test_risk_score_boosts_kev(self) -> None:
        base = asp.normalize_finding({"title": "x", "severity": "Medium"})
        kev = dict(base)
        kev["cve_ids"] = ["CVE-2021-44228"]
        kev = asp.apply_kev_flags([kev], frozenset({"CVE-2021-44228"}))[0]
        kev["ssvc_action"] = asp.ssvc_lite(kev)
        base["ssvc_action"] = asp.ssvc_lite(base)
        self.assertGreater(asp.risk_score(kev), asp.risk_score(base))

    def test_vulnerability_ids_list(self) -> None:
        f = asp.normalize_finding(
            {
                "title": "dep",
                "severity": "Low",
                "vulnerability_ids": [{"vulnerability_id": "CVE-2022-22965"}],
            }
        )
        self.assertEqual(f["cve_ids"], ["CVE-2022-22965"])


if __name__ == "__main__":
    unittest.main()
