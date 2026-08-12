"""Unit tests for offline EPSS catalog helpers."""
from __future__ import annotations

import gzip
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from lib.epss_catalog import (  # noqa: E402
    load_epss,
    lookup,
    parse_epss_csv,
    refresh,
)


class TestEpssCatalog(unittest.TestCase):
    def test_parse_sparse_min(self) -> None:
        csv_text = (
            "#model_version:v2026.06.15,score_date:2026-08-11T12:00:00Z\n"
            "cve,epss,percentile\n"
            "CVE-2021-44228,0.97000,0.99000\n"
            "CVE-1999-0001,0.03351,0.87558\n"
        )
        meta, scores = parse_epss_csv(csv_text, sparse_min=0.1)
        self.assertEqual(meta["model"], "v2026.06.15")
        self.assertEqual(meta["scoreDate"], "2026-08-11")
        self.assertIn("CVE-2021-44228", scores)
        self.assertNotIn("CVE-1999-0001", scores)
        self.assertAlmostEqual(scores["CVE-2021-44228"]["epss"], 0.97)

    def test_load_fixture(self) -> None:
        path = ROOT / "tests" / "fixtures" / "epss_sparse_fixture.json.gz"
        catalog = load_epss(path)
        hit = lookup("cve-2021-44228", catalog)
        self.assertIsNotNone(hit)
        assert hit is not None
        self.assertGreaterEqual(hit["epss"], 0.9)

    def test_refresh_from_local_csv(self) -> None:
        csv_text = (
            "#model_version:v2026.06.15,score_date:2026-08-11T12:00:00Z\n"
            "cve,epss,percentile\n"
            "CVE-2021-44228,0.97000,0.99000\n"
            "CVE-2022-22965,0.05000,0.50000\n"
        )
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            csv_path = td_path / "epss.csv"
            csv_path.write_text(csv_text, encoding="utf-8")
            out_gz = td_path / "epss_scores.min.json.gz"
            out_meta = td_path / "epss_meta.json"
            refresh(out=out_gz, meta_out=out_meta, csv_path=csv_path, sparse_min=0.1)
            catalog = load_epss(out_gz)
            self.assertIn("CVE-2021-44228", catalog)
            self.assertNotIn("CVE-2022-22965", catalog)
            meta = json.loads(out_meta.read_text(encoding="utf-8"))
            self.assertEqual(meta["count"], 1)
            self.assertEqual(meta["sparseMin"], 0.1)
            # gzip is valid
            json.loads(gzip.decompress(out_gz.read_bytes()))


if __name__ == "__main__":
    unittest.main()
