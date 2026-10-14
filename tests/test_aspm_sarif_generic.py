"""SARIF → DefectDojo Generic Findings (KEV/EPSS fields)."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def _load():
    """Import aspm-export.py (hyphenated module name)."""
    path = ROOT / "scripts" / "aspm-export.py"
    spec = importlib.util.spec_from_file_location("aspm_export", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


aspm = _load()


class TestSarifToGeneric(unittest.TestCase):
    def test_maps_epss_and_kev(self) -> None:
        sarif = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "CVE-2024-23334",
                            "level": "error",
                            "message": {"text": "aiohttp path traversal CVE-2024-23334"},
                            "properties": {
                                "security-severity": 7.5,
                                "epss": 0.76875,
                                "epssPercentile": 0.99503,
                                "epssCve": "CVE-2024-23334",
                                "cisaKev": True,
                                "cisaKevCves": ["CVE-2024-23334"],
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "requirements.txt"},
                                        "region": {"startLine": 12},
                                    }
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "osa.sarif"
            src.write_text(json.dumps(sarif), encoding="utf-8")
            out = aspm.sarif_to_generic(src)
            self.assertTrue(out.name.endswith(".generic.json"))
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(len(payload["findings"]), 1)
            f = payload["findings"][0]
            self.assertEqual(f["vulnerability_ids"], ["CVE-2024-23334"])
            self.assertNotIn("cve", f)
            self.assertEqual(f["epss_score"], 0.76875)
            self.assertEqual(f["epss_percentile"], 0.99503)
            self.assertTrue(f["known_exploited"])
            self.assertIn("cisa-kev", f["tags"])
            self.assertIn("epss", f["tags"])
            self.assertEqual(f["severity"], "High")
            self.assertEqual(f["file_path"], "requirements.txt")
            self.assertEqual(f["line"], 12)

    def test_epss_without_kev(self) -> None:
        result = {
            "ruleId": "CVE-2021-44228",
            "level": "error",
            "message": {"text": "log4j"},
            "properties": {"epss": 0.97, "epssPercentile": 0.99},
        }
        f = aspm.sarif_result_to_generic_finding(result)
        self.assertEqual(f["epss_score"], 0.97)
        self.assertNotIn("known_exploited", f)
        self.assertEqual(f["tags"], ["epss"])


if __name__ == "__main__":
    unittest.main()
