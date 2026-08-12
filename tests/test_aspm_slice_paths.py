"""ASPM slice path helper + template context fields (no jinja required)."""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    path = ROOT / "scripts" / "dojo-render-aspm-report.py"
    spec = importlib.util.spec_from_file_location("dojo_render_aspm_mod", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["dojo_render_aspm_mod"] = mod
    spec.loader.exec_module(mod)
    return mod


mod = _load()


class TestAspmSlicePaths(unittest.TestCase):
    def test_slice_out_path(self) -> None:
        out = Path("/tmp/reports/aspm-report-svc.html")
        self.assertEqual(
            mod.slice_out_path(out, "sast-semgrep"),
            Path("/tmp/reports/aspm-report-svc.sast-semgrep.html"),
        )

    def test_slices_manifest_path(self) -> None:
        out = Path("reports/aspm-report-hwa_service.html")
        self.assertEqual(
            mod.slices_manifest_path(out),
            Path("reports/aspm-report-hwa_service.slices.json"),
        )

    def test_context_slice_label(self) -> None:
        bundle = {
            "product": {"name": "svc"},
            "engagement": {"name": "CI/CD"},
            "source": "fixture",
        }
        findings = [
            {
                "title": "x",
                "severity": "High",
                "test_title": "sast-semgrep",
                "active": True,
                "age_days": 1,
            }
        ]
        analysis = mod.analyze_findings(findings, coverage_only_titles=["sast-semgrep"])
        ctx = mod.build_template_context(
            bundle,
            analysis,
            public_url="",
            include_mitigated=False,
            include_false_positive=False,
            slice_label="sast-semgrep",
        )
        self.assertEqual(ctx["slice_label"], "sast-semgrep")
        self.assertIn("(slice: sast-semgrep)", ctx["report_title"])
        self.assertIn("slice=sast-semgrep", ctx["filters_note"])
        self.assertEqual([r["test_title"] for r in analysis["coverage"]], ["sast-semgrep"])

    def test_context_full_has_no_slice(self) -> None:
        bundle = {
            "product": {"name": "svc"},
            "engagement": {"name": "CI/CD"},
            "source": "fixture",
        }
        analysis = mod.analyze_findings([])
        ctx = mod.build_template_context(
            bundle,
            analysis,
            public_url="",
            include_mitigated=False,
            include_false_positive=False,
        )
        self.assertIsNone(ctx["slice_label"])
        self.assertNotIn("slice=", ctx["filters_note"])
        self.assertNotIn("(slice:", ctx["report_title"])


if __name__ == "__main__":
    unittest.main()
