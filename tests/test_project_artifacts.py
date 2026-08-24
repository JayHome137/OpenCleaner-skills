from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "open-cleaner" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from policy import PolicyError, SafetyPolicy
from project_artifacts import (
    ProjectArtifactError,
    discover_artifact_paths,
    inspect_project_artifact,
    project_search_roots,
)
from project_stage import augment_with_project_artifacts
from rules import canonical_path
from test_policy import analysis_for


class ProjectArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="open-cleaner-project-")
        self.home = Path(self.temp.name) / "home"
        self.projects = self.home / "Projects"
        self.projects.mkdir(parents=True)
        self.environment = {
            "HOME": str(self.home),
            "OPEN_CLEANER_PROJECT_ROOTS": str(self.projects),
            "OPEN_CLEANER_PROJECT_IDLE_SECONDS": "1800",
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_swift_project(self, name: str = "Example") -> tuple[Path, Path]:
        project = self.projects / name
        target = project / ".build"
        target.mkdir(parents=True)
        (project / "Package.swift").write_text("// swift-tools-version: 5.9\n", encoding="utf-8")
        artifact = target / "artifact.bin"
        artifact.write_bytes(b"generated")
        old = time.time() - 3600
        os.utime(artifact, (old, old))
        os.utime(target, (old, old))
        return project, target

    def inspect(self, target: Path, **overrides):
        return inspect_project_artifact(
            str(target),
            str(self.home),
            self.environment,
            now_ns=int(time.time_ns()),
            open_file_checker=overrides.get("open_file_checker", lambda _path: False),
        )

    def test_idle_manifest_backed_artifact_is_eligible(self) -> None:
        project, target = self.make_swift_project()
        result = self.inspect(target)
        self.assertEqual(result["project_root"], canonical_path(str(project)))
        self.assertEqual(result["artifact_kind"], ".build")

    def test_default_search_roots_cover_common_project_locations(self) -> None:
        expected = (
            "Desktop",
            "Documents",
            "Downloads",
            "Developer",
            "Projects",
            "Code",
            "plugins",
            "Sites",
        )
        for name in expected:
            (self.home / name).mkdir(exist_ok=True)
        worktrees = self.home / ".codex" / "worktrees"
        worktrees.mkdir(parents=True)
        go_sources = self.home / "go" / "src"
        go_sources.mkdir(parents=True)
        roots = set(project_search_roots(str(self.home), {"HOME": str(self.home)}))
        self.assertEqual(
            roots,
            {canonical_path(str(self.home / name)) for name in expected}
            | {canonical_path(str(worktrees)), canonical_path(str(go_sources))},
        )

    def test_recent_or_open_artifact_is_rejected(self) -> None:
        _project, target = self.make_swift_project()
        now = time.time()
        os.utime(target / "artifact.bin", (now, now))
        with self.assertRaises(ProjectArtifactError) as recent:
            self.inspect(target)
        self.assertEqual(recent.exception.code, "project_not_idle")

        old = now - 3600
        os.utime(target / "artifact.bin", (old, old))
        with self.assertRaises(ProjectArtifactError) as opened:
            self.inspect(target, open_file_checker=lambda _path: True)
        self.assertEqual(opened.exception.code, "project_artifact_active")

        with self.assertRaises(ProjectArtifactError) as unknown:
            self.inspect(target, open_file_checker=lambda _path: None)
        self.assertEqual(unknown.exception.code, "project_activity_unknown")

    def test_build_with_archives_is_rejected(self) -> None:
        project = self.projects / "XcodeProject"
        target = project / "build"
        (target / "Archives").mkdir(parents=True)
        (project / "project.yml").write_text("name: Example\n", encoding="utf-8")
        old = time.time() - 3600
        os.utime(target / "Archives", (old, old))
        os.utime(target, (old, old))
        with self.assertRaises(ProjectArtifactError) as raised:
            self.inspect(target)
        self.assertEqual(raised.exception.code, "protected_build_output")

    def test_git_project_requires_ignored_untracked_artifact(self) -> None:
        project, target = self.make_swift_project("GitProject")
        subprocess.run(["git", "init", "-q", str(project)], check=True)
        with self.assertRaises(ProjectArtifactError) as unignored:
            self.inspect(target)
        self.assertEqual(unignored.exception.code, "not_git_ignored")

        (project / ".gitignore").write_text(".build/\n", encoding="utf-8")
        self.assertEqual(self.inspect(target)["project_root"], canonical_path(str(project)))

    def test_discovery_and_policy_authorization_share_the_same_boundary(self) -> None:
        _project, target = self.make_swift_project()
        self.assertIn(
            canonical_path(str(target)),
            set(discover_artifact_paths(str(self.home), self.environment)),
        )
        policy = SafetyPolicy(
            home=str(self.home),
            platform="darwin",
            environment=self.environment,
        )
        action = policy.authorize(str(target), "reviewed_trash", "yellow")
        self.assertEqual(action["rule_id"], "reviewed.project-artifact")
        self.assertEqual(action["project"]["artifact_kind"], ".build")

        (target / "new.bin").write_bytes(b"active")
        with self.assertRaises(PolicyError) as raised:
            policy.revalidate(action)
        self.assertEqual(raised.exception.code, "project_not_idle")

    def test_stage_augmentation_is_transactional_and_contract_validated(self) -> None:
        project, target = self.make_swift_project("StageProject")
        source = analysis_for(self.home)
        metadata = {
            "project_root": canonical_path(str(project)),
            "artifact_kind": ".build",
            "idle_seconds": 1800,
            "latest_mtime_ns": int(target.stat().st_mtime_ns),
        }
        with patch("project_stage.discover_artifact_paths", return_value=[str(target)]), patch(
            "project_stage._size_kb", return_value=100 * 1024
        ), patch("project_stage.inspect_project_artifact", return_value=metadata):
            result = augment_with_project_artifacts(
                source, environment=self.environment, min_kb=0
            )

        self.assertNotIn("analysis_origin", source)
        self.assertEqual(result["analysis_origin"], "project-stage")
        self.assertEqual(result["project_stage"]["actionable"], 1)
        self.assertEqual(result["yellow"][-1]["stage_status"]["state"], "ready")

    def test_invalid_idle_configuration_fails_before_mutating_analysis(self) -> None:
        source = analysis_for(self.home)
        environment = {**self.environment, "OPEN_CLEANER_PROJECT_IDLE_SECONDS": "invalid"}
        with self.assertRaises(ProjectArtifactError) as raised:
            augment_with_project_artifacts(source, environment=environment, min_kb=0)
        self.assertEqual(raised.exception.code, "invalid_idle_window")
        self.assertNotIn("analysis_origin", source)

        too_short = {**self.environment, "OPEN_CLEANER_PROJECT_IDLE_SECONDS": "0"}
        with self.assertRaises(ProjectArtifactError) as raised:
            augment_with_project_artifacts(source, environment=too_short, min_kb=0)
        self.assertEqual(raised.exception.code, "invalid_idle_window")
        self.assertNotIn("analysis_origin", source)


if __name__ == "__main__":
    unittest.main()
