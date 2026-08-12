"""gate-check FIRST EPSS warn / block paths."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    path = ROOT / "scripts" / "gate-check.py"
    spec = importlib.util.spec_from_file_location("gate_check_mod", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["gate_check_mod"] = mod
    spec.loader.exec_module(mod)
    return mod


gc = _load()


class TestGateEpss(unittest.TestCase):
    def _sarif(self, epss: float | None) -> dict:
        result: dict = {"ruleId": "CVE-2021-44228", "level": "error"}
        if epss is not None:
            result["properties"] = {"epss": epss, "epssPercentile": 0.99}
        return {"runs": [{"results": [result]}]}

    def test_warn_when_block_false(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "x.sarif"
            path.write_text(json.dumps(self._sarif(0.97)), encoding="utf-8")
            ok, msg = gc.evaluate_epss(
                path, {"block_on_high_epss": False, "warn_epss_threshold": 0.5}
            )
            self.assertTrue(ok)
            self.assertIn("WARN", msg)

    def test_block_when_flag_true(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "x.sarif"
            path.write_text(json.dumps(self._sarif(0.97)), encoding="utf-8")
            ok, msg = gc.evaluate_epss(
                path, {"block_on_high_epss": True, "warn_epss_threshold": 0.5}
            )
            self.assertFalse(ok)
            self.assertIn("EPSS>=0.5", msg)

    def test_below_threshold_ok(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "x.sarif"
            path.write_text(json.dumps(self._sarif(0.2)), encoding="utf-8")
            ok, msg = gc.evaluate_epss(
                path, {"block_on_high_epss": True, "warn_epss_threshold": 0.5}
            )
            self.assertTrue(ok)
            self.assertEqual(msg, "epss=0")

    def test_zero_hits_ok(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "x.sarif"
            path.write_text(json.dumps(self._sarif(None)), encoding="utf-8")
            ok, msg = gc.evaluate_epss(
                path, {"block_on_high_epss": True, "warn_epss_threshold": 0.5}
            )
            self.assertTrue(ok)
            self.assertEqual(msg, "epss=0")


if __name__ == "__main__":
    unittest.main()
