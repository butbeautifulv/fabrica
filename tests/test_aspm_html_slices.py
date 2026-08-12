"""ASPM --write-slices / --only-slice / manifest."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "aspm-slices-fixture.json"
SCRIPT = ROOT / "scripts" / "dojo-render-aspm-report.py"
VENV_PY = ROOT / ".venv-aspm-report" / "bin" / "python"


def _load():
    spec = importlib.util.spec_from_file_location("dojo_render_aspm_mod", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["dojo_render_aspm_mod"] = mod
    spec.loader.exec_module(mod)
    return mod


mod = _load()


def _python() -> str:
    if VENV_PY.is_file():
        return str(VENV_PY)
    return sys.executable


def _has_jinja() -> bool:
    try:
        subprocess.run(
            [_python(), "-c", "import jinja2"],
            check=True,
            capture_output=True,
        )
        return True
    except (subprocess.CalledProcessError, OSError):
        return False


@unittest.skipUnless(_has_jinja(), "jinja2 required for HTML render")
class TestAspmHtmlSlices(unittest.TestCase):
    def test_write_slices_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "aspm-report-slices_fixture_service.html"
            proc = subprocess.run(
                [
                    _python(),
                    str(SCRIPT),
                    "--from-json",
                    str(FIXTURE),
                    "--out",
                    str(out),
                    "--write-slices",
                    "--kev-catalog",
                    str(ROOT / "config" / "kev" / "cisa-kev.min.json"),
                    "--epss-catalog",
                    str(ROOT / "config" / "epss" / "epss_scores.min.json.gz"),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            self.assertTrue(out.is_file())
            sast = mod.slice_out_path(out, "sast-semgrep")
            dast = mod.slice_out_path(out, "dast-zap")
            self.assertTrue(sast.is_file())
            self.assertTrue(dast.is_file())
            self.assertFalse(mod.slice_out_path(out, "secrets").is_file())
            sast_html = sast.read_text(encoding="utf-8")
            self.assertIn("UNIQUE_SLICE_SAST", sast_html)
            self.assertNotIn("UNIQUE_SLICE_DAST", sast_html)
            self.assertIn("Slice: sast-semgrep", sast_html)
            dast_html = dast.read_text(encoding="utf-8")
            self.assertIn("UNIQUE_SLICE_DAST", dast_html)
            self.assertNotIn("UNIQUE_SLICE_SAST", dast_html)
            man = mod.slices_manifest_path(out)
            self.assertTrue(man.is_file())
            doc = json.loads(man.read_text(encoding="utf-8"))
            self.assertEqual(doc["full"], out.name)
            layers = {s["layer"] for s in doc["slices"]}
            self.assertEqual(layers, {"sast-semgrep", "dast-zap"})

    def test_only_slice(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "dast-only.html"
            proc = subprocess.run(
                [
                    _python(),
                    str(SCRIPT),
                    "--from-json",
                    str(FIXTURE),
                    "--out",
                    str(out),
                    "--only-slice",
                    "dast-zap",
                    "--kev-catalog",
                    str(ROOT / "config" / "kev" / "cisa-kev.min.json"),
                    "--epss-catalog",
                    str(ROOT / "config" / "epss" / "epss_scores.min.json.gz"),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            self.assertTrue(out.is_file())
            html = out.read_text(encoding="utf-8")
            self.assertIn("UNIQUE_SLICE_DAST", html)
            self.assertNotIn("UNIQUE_SLICE_SAST", html)
            self.assertIn("Slice: dast-zap", html)
            # no sibling full/slices when only-slice
            self.assertEqual(list(Path(td).glob("*.html")), [out])

    def test_only_slice_missing_layer(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "missing.html"
            proc = subprocess.run(
                [
                    _python(),
                    str(SCRIPT),
                    "--from-json",
                    str(FIXTURE),
                    "--out",
                    str(out),
                    "--only-slice",
                    "secrets",
                    "--kev-catalog",
                    str(ROOT / "config" / "kev" / "cisa-kev.min.json"),
                    "--epss-catalog",
                    str(ROOT / "config" / "epss" / "epss_scores.min.json.gz"),
                ],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("--only-slice", proc.stderr + proc.stdout)


if __name__ == "__main__":
    unittest.main()
