"""Unit tests for offline CISA KEV catalog helpers."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from lib.kev_catalog import (  # noqa: E402
    extract_cves,
    in_kev,
    load_kev,
    min_catalog_from_cisa,
    normalize_cve,
)


class TestKevCatalog(unittest.TestCase):
    def test_normalize_upper(self) -> None:
        self.assertEqual(normalize_cve("cve-2021-44228"), "CVE-2021-44228")

    def test_extract_cves_unique_order(self) -> None:
        text = "See cve-2021-44228 and CVE-2021-45046; again CVE-2021-44228"
        self.assertEqual(
            extract_cves(text, "CVE-2022-22965"),
            ["CVE-2021-44228", "CVE-2021-45046", "CVE-2022-22965"],
        )

    def test_load_and_lookup_fixture(self) -> None:
        payload = {
            "source": "test",
            "catalogVersion": "test",
            "dateReleased": "2026-01-01",
            "count": 2,
            "cveIDs": ["CVE-2021-44228", "cve-2023-34362"],
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "kev.min.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            catalog = load_kev(path)
            self.assertTrue(in_kev("CVE-2021-44228", catalog))
            self.assertTrue(in_kev("cve-2023-34362", catalog))
            self.assertFalse(in_kev("CVE-1999-0001", catalog))

    def test_min_catalog_from_cisa(self) -> None:
        doc = {
            "catalogVersion": "2026.08.11",
            "dateReleased": "2026-08-11T00:00:00Z",
            "vulnerabilities": [
                {"cveID": "CVE-2021-44228"},
                {"cveID": "cve-2021-44228"},
                {"cveID": "CVE-2022-22965"},
            ],
        }
        out = min_catalog_from_cisa(doc)
        self.assertEqual(out["count"], 2)
        self.assertEqual(out["cveIDs"], ["CVE-2021-44228", "CVE-2022-22965"])

    def test_committed_catalog_has_log4shell(self) -> None:
        path = ROOT / "config" / "kev" / "cisa-kev.min.json"
        if not path.is_file():
            self.skipTest("committed KEV catalog missing")
        catalog = load_kev(path)
        self.assertTrue(in_kev("CVE-2021-44228", catalog))
        self.assertGreaterEqual(len(catalog), 1000)


if __name__ == "__main__":
    unittest.main()
