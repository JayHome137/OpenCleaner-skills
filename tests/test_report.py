from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "open-cleaner" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import build_report as report_module
from build_report import render_report
from test_policy import analysis_for


class ReportTests(unittest.TestCase):
    def test_windows_static_report_entry_is_disabled(self) -> None:
        with patch("build_report.sys.platform", "win32"):
            with self.assertRaisesRegex(report_module.ContractError, "仅支持 macOS"):
                report_module.build_report("unused.json", "unused.html")

    def test_report_keeps_sections_and_escapes_embedded_script_data(self) -> None:
        analysis = analysis_for(Path("/tmp/home"))
        analysis["summary"]["overview"] = "</script><script>alert(1)</script>"
        template = "<script>const D=__REPORT_DATA__;const S=__DECISION_DATA__;const C=__DELETE_CONFIG__;</script>"
        rendered = render_report(analysis, template)
        self.assertEqual(rendered.count("</script>"), 1)
        self.assertIn("\\u003c/script\\u003e", rendered)
        self.assertIn("const S=", rendered)
        self.assertIn("const C=null", rendered)

    def test_report_rejects_template_without_decision_placeholder(self) -> None:
        analysis = analysis_for(Path("/tmp/home"))
        with self.assertRaisesRegex(report_module.ContractError, "DECISION_DATA"):
            render_report(analysis, "<script>const D=__REPORT_DATA__;const C=__DELETE_CONFIG__;</script>")

    def test_real_template_keeps_reading_order_and_contains_no_legacy_request(self) -> None:
        analysis = analysis_for(Path("/tmp/home"))
        analysis["summary"]["overview"] = "</script><script>alert(1)</script>"
        template = (ROOT / "open-cleaner" / "assets" / "report_template.html").read_text(
            encoding="utf-8"
        )
        rendered = render_report(analysis, template)
        self.assertNotIn("data-paths", rendered)
        self.assertNotIn("authorizedPaths", rendered)
        self.assertNotIn("postAction", rendered)
        self.assertIn("const SESSION = null", rendered)
        # The static artifact carries no action IDs or operation controls. The
        # controlled session shell remains in the template source but is never
        # populated when SESSION is null.
        self.assertNotIn('data-mode="trash"', rendered)
        self.assertNotIn('data-mode="reviewed_trash"', rendered)
        self.assertNotIn('class="action-panel"', rendered)
        self.assertIn("const DECISION =", rendered)
        self.assertIn('class="action-select"', template)
        self.assertNotIn("CSS.escape", template)
        self.assertIn('["owner_active", "runtime_unknown"]', template)
        self.assertIn('class="block findings-section"', template)
        self.assertIn('class="action-button secondary section-toggle section-expand"', template)
        self.assertIn('class="action-button secondary section-toggle section-collapse"', template)
        self.assertIn('class="disposal-verdict ${h(verdict.tone)}"', template)
        self.assertIn('class="finding-status ${h(verdict.tone)}"', template)
        self.assertIn('class="finding-path-preview"', template)
        self.assertIn("绿色 · 可删除候选", template)
        self.assertIn("橙色 · 人工决定", template)
        self.assertIn("红色 · 不能直接删除", template)
        self.assertIn("静态只读副本", template)
        self.assertIn('class="action-button ${h(mode)}"', template)
        self.assertIn('if (SESSION) return `<section class="interactive-details"', template)
        self.assertIn('detail("归属应用 / 工具"', template)
        self.assertIn('detail("主要作用"', template)
        self.assertIn('detail("判断依据"', template)
        self.assertIn("function setSectionExpanded(section, expanded)", template)
        self.assertIn("updateSectionButtons(section)", template)
        self.assertIn("本次操作历史", rendered)
        self.assertEqual(rendered.count("</script>"), 1)
        self.assertIn("\\u003c/script\\u003e", rendered)
        mount = rendered.split("function mount()", 1)[1]
        calls = [
            ".innerHTML = decisionSection()",
            "+ sessionSection()",
            "+ interactiveDetails",
            "+ overview(REPORT.system || {}, summary)",
            "+ topFive(REPORT.top5)",
            '+ listBlock("执行建议"',
            "+ staticDetails",
            '+ listBlock("长期优化建议"',
        ]
        positions = [mount.find(value) for value in calls]
        self.assertNotIn(-1, positions)
        self.assertEqual(positions, sorted(positions))

    def test_mobile_system_metadata_can_shrink_inside_the_overview(self) -> None:
        template = (ROOT / "open-cleaner" / "assets" / "report_template.html").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            ".system-grid > div { min-width: 0; overflow-wrap: anywhere; }",
            template,
        )
        self.assertIn(
            ".table-frame { width: 100%; min-width: 0; max-width: 100%; overflow: auto; contain: inline-size; clip-path: inset(0); }",
            template,
        )
        self.assertIn("table { min-width: 0; table-layout: fixed; }", template)
        self.assertIn("th:nth-child(6), td:nth-child(6)", template)
        self.assertIn(".permission-note", template)
        self.assertIn("overflow-wrap: anywhere;", template)


if __name__ == "__main__":
    unittest.main()
