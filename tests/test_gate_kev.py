"""gate-check CISA KEV warn / block paths."""
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


class TestGateKev(unittest.TestCase):
    def _sarif(self, kev: bool) -> dict:
        result: dict = {"ruleId": "CVE-2021-44228", "level": "error"}
        if kev:
            result["properties"] = {"cisaKev": True}
        return {"runs": [{"results": [result]}]}

    def test_warn_when_block_false(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "x.sarif"
            path.write_text(json.dumps(self._sarif(True)), encoding="utf-8")
            ok, msg = gc.evaluate_kev(path, {"block_on_kev": False})
            self.assertTrue(ok)
            self.assertIn("WARN", msg)

    def test_block_when_flag_true(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "x.sarif"
            path.write_text(json.dumps(self._sarif(True)), encoding="utf-8")
            ok, msg = gc.evaluate_kev(path, {"block_on_kev": True})
            self.assertFalse(ok)
            self.assertIn("CISA KEV hits", msg)

    def test_zero_hits_ok(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "x.sarif"
            path.write_text(json.dumps(self._sarif(False)), encoding="utf-8")
            ok, msg = gc.evaluate_kev(path, {"block_on_kev": True})
            self.assertTrue(ok)
            self.assertEqual(msg, "kev=0")


if __name__ == "__main__":
    unittest.main()
