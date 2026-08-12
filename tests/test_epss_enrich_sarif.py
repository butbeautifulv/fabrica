"""Tests for epss-enrich-sarif.py."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    path = ROOT / "scripts" / "epss-enrich-sarif.py"
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    spec = importlib.util.spec_from_file_location("epss_enrich_sarif", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["epss_enrich_sarif"] = mod
    spec.loader.exec_module(mod)
    return mod


mod = _load()


class TestEpssEnrichSarif(unittest.TestCase):
    def test_enrich_sets_properties(self) -> None:
        doc = {
            "runs": [
                {
                    "results": [
                        {"ruleId": "CVE-2021-44228", "message": {"text": "x"}, "level": "error"},
                        {"ruleId": "CVE-1999-0001", "message": {"text": "y"}, "level": "note"},
                    ]
                }
            ]
        }
        catalog = {
            "CVE-2021-44228": {"epss": 0.97, "percentile": 0.99},
        }
        out, hits = mod.enrich_sarif(doc, catalog)
        self.assertEqual(len(hits), 1)
        props = out["runs"][0]["results"][0]["properties"]
        self.assertAlmostEqual(props["epss"], 0.97)
        self.assertAlmostEqual(props["epssPercentile"], 0.99)

    def test_cli(self) -> None:
        import gzip

        sarif = {
            "runs": [{"results": [{"ruleId": "CVE-2021-44228", "message": {"text": "x"}}]}]
        }
        payload = {
            "source": "t",
            "model": "t",
            "scoreDate": "2026-08-11",
            "sparseMin": 0.1,
            "count": 1,
            "scores": {"CVE-2021-44228": {"epss": 0.97, "percentile": 0.99}},
        }
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            sarif_path = td_path / "osa.sarif"
            cat_path = td_path / "epss.json.gz"
            hits_path = td_path / "epss-hits.json"
            out_path = td_path / "out.sarif"
            sarif_path.write_text(json.dumps(sarif), encoding="utf-8")
            cat_path.write_bytes(gzip.compress(json.dumps(payload).encode()))
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
            self.assertEqual(json.loads(hits_path.read_text())["count"], 1)


if __name__ == "__main__":
    unittest.main()
