"""Tests for kev-enrich-sarif.py."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    path = ROOT / "scripts" / "kev-enrich-sarif.py"
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    spec = importlib.util.spec_from_file_location("kev_enrich_sarif", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["kev_enrich_sarif"] = mod
    spec.loader.exec_module(mod)
    return mod


mod = _load()


class TestKevEnrichSarif(unittest.TestCase):
    def test_enrich_sets_property(self) -> None:
        doc = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "CVE-2021-44228",
                            "message": {"text": "log4shell"},
                            "level": "error",
                        },
                        {
                            "ruleId": "CVE-1999-0001",
                            "message": {"text": "old"},
                            "level": "warning",
                        },
                    ]
                }
            ]
        }
        catalog = frozenset({"CVE-2021-44228"})
        out, hits = mod.enrich_sarif(doc, catalog)
        self.assertEqual(len(hits), 1)
        r0 = out["runs"][0]["results"][0]
        self.assertTrue(r0["properties"]["cisaKev"])
        self.assertEqual(r0["properties"]["cisaKevCves"], ["CVE-2021-44228"])
        self.assertNotIn("properties", out["runs"][0]["results"][1])

    def test_cli_writes_hits(self) -> None:
        sarif = {
            "runs": [
                {
                    "results": [
                        {"ruleId": "CVE-2021-44228", "message": {"text": "x"}},
                    ]
                }
            ]
        }
        catalog = {
            "source": "t",
            "catalogVersion": "t",
            "dateReleased": "",
            "count": 1,
            "cveIDs": ["CVE-2021-44228"],
        }
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            sarif_path = td_path / "osa.sarif"
            cat_path = td_path / "kev.json"
            hits_path = td_path / "kev-hits.json"
            out_path = td_path / "osa-out.sarif"
            sarif_path.write_text(json.dumps(sarif), encoding="utf-8")
            cat_path.write_text(json.dumps(catalog), encoding="utf-8")
            rc = mod.main(
                [
                    "--in",
                    str(sarif_path),
                    "--out",
                    str(out_path),
                    "--catalog",
                    str(cat_path),
                    "--hits",
                    str(hits_path),
                ]
            )
            self.assertEqual(rc, 0)
            summary = json.loads(hits_path.read_text(encoding="utf-8"))
            self.assertEqual(summary["count"], 1)
            enriched = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertTrue(enriched["runs"][0]["results"][0]["properties"]["cisaKev"])


if __name__ == "__main__":
    unittest.main()
