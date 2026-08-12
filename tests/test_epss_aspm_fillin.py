"""ASPM EPSS offline fill-in (dojo-first)."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_aspm():
    path = ROOT / "scripts" / "dojo-render-aspm-report.py"
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    spec = importlib.util.spec_from_file_location("dojo_render_aspm_report", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["dojo_render_aspm_report"] = mod
    spec.loader.exec_module(mod)
    return mod


asp = _load_aspm()


class TestEpssAspmFillin(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = {
            "CVE-2021-44228": {"epss": 0.97, "percentile": 0.99},
            "CVE-2022-22965": {"epss": 0.55, "percentile": 0.94},
        }

    def test_fill_when_dojo_missing(self) -> None:
        f = asp.normalize_finding(
            {"title": "x CVE-2021-44228", "severity": "Medium", "cve": "CVE-2021-44228"}
        )
        self.assertIsNone(f["epss_score"])
        out = asp.apply_epss_fillin([f], self.catalog, prefer="dojo")[0]
        self.assertAlmostEqual(out["epss_score"], 0.97)
        self.assertEqual(out["epss_source"], "catalog")
        self.assertEqual(asp.ssvc_lite(out), "Attend")  # Medium + EPSS bump

    def test_dojo_wins_by_default(self) -> None:
        f = asp.normalize_finding(
            {
                "title": "x CVE-2021-44228",
                "severity": "Low",
                "cve": "CVE-2021-44228",
                "epss_score": 0.1,
            }
        )
        out = asp.apply_epss_fillin([f], self.catalog, prefer="dojo")[0]
        self.assertAlmostEqual(out["epss_score"], 0.1)
        self.assertEqual(out["epss_source"], "dojo")
        self.assertAlmostEqual(out["epss_percentile"], 0.99)

    def test_prefer_catalog(self) -> None:
        f = asp.normalize_finding(
            {
                "title": "x CVE-2021-44228",
                "severity": "Low",
                "cve": "CVE-2021-44228",
                "epss_score": 0.1,
            }
        )
        out = asp.apply_epss_fillin([f], self.catalog, prefer="catalog")[0]
        self.assertAlmostEqual(out["epss_score"], 0.97)
        self.assertEqual(out["epss_source"], "catalog")

    def test_missing_catalog_no_crash(self) -> None:
        f = asp.normalize_finding({"title": "CVE-2021-44228", "severity": "High"})
        out = asp.apply_epss_fillin([f], None, prefer="dojo")[0]
        self.assertIsNone(out.get("epss_score"))


if __name__ == "__main__":
    unittest.main()
