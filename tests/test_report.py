from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "storage-analyzer" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from build_report import render_report
from test_policy import analysis_for


class ReportTests(unittest.TestCase):
    def test_report_keeps_sections_and_escapes_embedded_script_data(self) -> None:
        analysis = analysis_for(Path("/tmp/home"))
        analysis["summary"]["overview"] = "</script><script>alert(1)</script>"
        template = "<script>const D=__REPORT_DATA__;const C=__DELETE_CONFIG__;</script>"
        rendered = render_report(analysis, template)
        self.assertEqual(rendered.count("</script>"), 1)
        self.assertIn("\\u003c/script\\u003e", rendered)
        self.assertIn("const C=null", rendered)

    def test_real_template_keeps_reading_order_and_contains_no_legacy_request(self) -> None:
        analysis = analysis_for(Path("/tmp/home"))
        analysis["summary"]["overview"] = "</script><script>alert(1)</script>"
        template = (ROOT / "storage-analyzer" / "assets" / "report_template.html").read_text(
            encoding="utf-8"
        )
        rendered = render_report(analysis, template)
        self.assertNotIn("data-paths", rendered)
        self.assertNotIn("authorizedPaths", rendered)
        self.assertNotIn("postAction", rendered)
        self.assertIn("本次操作历史", rendered)
        self.assertEqual(rendered.count("</script>"), 1)
        self.assertIn("\\u003c/script\\u003e", rendered)
        mount = rendered.split("function mount()", 1)[1]
        calls = [
            "+ topFive(REPORT.top5)",
            '+ listBlock("执行建议"',
            '+ findingsSection("可自动清理',
            '+ findingsSection("需你参与',
            '+ findingsSection("谨慎清理',
            '+ listBlock("长期优化建议"',
        ]
        positions = [mount.find(value) for value in calls]
        self.assertNotIn(-1, positions)
        self.assertEqual(positions, sorted(positions))

    def test_mobile_system_metadata_can_shrink_inside_the_overview(self) -> None:
        template = (ROOT / "storage-analyzer" / "assets" / "report_template.html").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            ".system-grid > div { min-width: 0; overflow-wrap: anywhere; }",
            template,
        )


if __name__ == "__main__":
    unittest.main()
