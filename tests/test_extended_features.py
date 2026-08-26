from __future__ import annotations

import json
import os
import plistlib
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "open-cleaner" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from browse import browse_directory
from installers import inspect_installer, sanitize_source
from ownership import resolve_ownership
from policy import PolicyError, SafetyPolicy, build_action_plan
from project_artifacts import inspect_project_artifact
from runtime import RuntimeInspector
from scan import ScanEngine, ScanTarget
from settings import SettingsError, SettingsStore
from server import ServerContext
from test_policy import analysis_for, test_catalog
from test_server import running


class ExtendedFeatureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="open-cleaner-extended-")
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.state = self.root / "state"
        self.environment = {"HOME": str(self.home)}
        self.catalog = test_catalog(self.home)
        self.store = SettingsStore(
            str(self.home), self.environment, state_dir=self.state, volume_root=self.root / "Volumes"
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def guarded_policy(self, **kwargs) -> SafetyPolicy:
        inspector = RuntimeInspector(
            "darwin",
            checker=lambda _pattern: False,
            tool_checker=lambda _tool: True,
            open_file_checker=kwargs.pop("open_file_checker", lambda _path: False),
        )
        return SafetyPolicy(
            home=str(self.home),
            platform="darwin",
            environment=self.environment,
            settings_store=self.store,
            runtime_inspector=inspector,
            catalog=self.catalog,
            **kwargs,
        )

    def commit_project(self, project: Path) -> None:
        subprocess.run(["git", "-C", str(project), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(project), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "checkpoint"],
            check=True,
        )
    def test_settings_are_private_atomic_and_protection_blocks_policy(self) -> None:
        cache = self.home / "Library" / "Developer" / "Xcode" / "DerivedData" / "example"
        cache.mkdir(parents=True)
        settings = self.store.load()
        settings["protected_paths"] = [str(cache)]
        saved = self.store.save(settings)
        self.assertEqual(saved["protected_paths"], [str(cache.resolve())])
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.state / "settings.json").stat().st_mode), 0o600)
        with self.assertRaises(PolicyError) as raised:
            self.guarded_policy().authorize(str(cache), "trash", "green")
        self.assertEqual(raised.exception.code, "user_protected")

    def test_settings_reject_symlink_and_out_of_scope_root(self) -> None:
        real = self.home / "real"
        real.mkdir()
        link = self.home / "link"
        link.symlink_to(real, target_is_directory=True)
        settings = self.store.load()
        settings["scan_roots"] = [str(link)]
        with self.assertRaises(SettingsError) as raised:
            self.store.save(settings)
        self.assertEqual(raised.exception.code, "symlink_denied")
        outside = self.root / "outside"
        outside.mkdir()
        settings["scan_roots"] = [str(outside)]
        with self.assertRaises(SettingsError) as raised:
            self.store.save(settings)
        self.assertEqual(raised.exception.code, "setting_out_of_scope")

    def test_browser_enters_registered_roots_and_supports_filters(self) -> None:
        folder = self.home / "Folder"
        folder.mkdir()
        (folder / "large.bin").write_bytes(b"x" * 2048)
        (folder / "small.bin").write_bytes(b"x")
        result = browse_directory(
            self.store,
            str(folder),
            search="large",
            sort="size",
            min_size_bytes=1024,
        )
        self.assertEqual([item["name"] for item in result["items"]], ["large.bin"])
        outside = self.root / "outside"
        outside.mkdir()
        with self.assertRaises(SettingsError) as raised:
            browse_directory(self.store, str(outside))
        self.assertEqual(raised.exception.code, "browse_out_of_scope")

    def test_custom_scan_root_participates_without_granting_policy_access(self) -> None:
        custom = self.home / "Archive"
        custom.mkdir()
        payload = custom / "payload.bin"
        payload.write_bytes(b"data")
        engine = ScanEngine("darwin")
        with patch.object(engine, "_size_macos", return_value=100 * 1024):
            groups, coverage = engine.scan_targets([ScanTarget("custom_roots", str(custom))])
        self.assertEqual(groups["custom_roots"][0]["path"], str(payload))
        self.assertEqual(coverage["completed_roots"], 1)
        with self.assertRaises(PolicyError) as raised:
            self.guarded_policy().authorize(str(payload), "trash", "green")
        self.assertEqual(raised.exception.code, "no_matching_rule")

    def test_installer_and_app_ownership_metadata_are_concrete(self) -> None:
        self.assertEqual(
            sanitize_source("https://downloads.example.test/file.dmg?signature=secret"),
            "https://downloads.example.test",
        )
        applications = self.home / "Applications"
        app = applications / "Example.app"
        info = app / "Contents" / "Info.plist"
        info.parent.mkdir(parents=True)
        with info.open("wb") as handle:
            plistlib.dump({"CFBundleIdentifier": "com.example.app", "CFBundleDisplayName": "Example"}, handle)
        package = self.home / "Downloads" / "Example.dmg"
        package.parent.mkdir()
        package.write_bytes(b"installer")
        installer = inspect_installer(str(package), app_roots=[str(applications)])
        self.assertEqual(installer["format"], "DMG")
        self.assertEqual(installer["installed_state"], "可能已安装")
        owner = resolve_ownership(
            str(self.home / "Library" / "Containers" / "com.example.app"),
            str(self.home),
            apps=[{"bundle_id": "com.example.app", "display_name": "Example", "path": str(app)}],
            launch_agents=[
                {"label": "Example Login", "program": str(app), "kind": "login"},
                {"label": "com.example.app.helper", "program": str(app), "kind": "background"},
            ],
        )
        self.assertEqual(owner["bundle_id"], "com.example.app")
        self.assertIn("沙盒容器", owner["relationships"])
        self.assertEqual(owner["login_items"], ["Example Login"])
        self.assertEqual(owner["background_processes"], ["com.example.app.helper"])

    def test_sqlite_open_files_and_shared_apps_fail_closed(self) -> None:
        cache = self.home / "TestTrash" / "database"
        cache.mkdir(parents=True)
        (cache / "state.db").write_bytes(b"db")
        (cache / "state.db-wal").write_bytes(b"wal")
        with self.assertRaises(PolicyError) as raised:
            self.guarded_policy().authorize(str(cache), "trash", "green")
        self.assertEqual(raised.exception.code, "sqlite_live_set")
        (cache / "state.db-wal").unlink()
        with self.assertRaises(PolicyError) as raised:
            self.guarded_policy(open_file_checker=lambda _path: True).authorize(str(cache), "trash", "green")
        self.assertEqual(raised.exception.code, "open_files")
        shared = {
            "bundle_id": "com.example.app", "display_name": "Example", "app_paths": ["/Applications/A.app", "/Applications/B.app"],
            "relationships": ["缓存"], "login_items": [], "background_processes": [], "shared_bundle_id": True, "multiple_versions": True,
        }
        with patch("policy.resolve_ownership", return_value=shared):
            with self.assertRaises(PolicyError) as raised:
                self.guarded_policy().authorize(str(cache), "trash", "green")
        self.assertEqual(raised.exception.code, "shared_app_identity")

    def test_project_artifacts_cover_node_rust_go_maven_and_gradle(self) -> None:
        projects = self.home / "Projects"
        node = projects / "Node"
        modules = node / "node_modules"
        modules.mkdir(parents=True)
        (node / "package.json").write_text("{}", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(node)], check=True)
        (node / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
        self.commit_project(node)
        environment = {**self.environment, "OPEN_CLEANER_PROJECT_ROOTS": str(projects)}
        old = time.time() - 3600
        os.utime(modules, (old, old))
        with self.assertRaisesRegex(Exception, "锁文件"):
            inspect_project_artifact(str(modules), str(self.home), environment, open_file_checker=lambda _path: False)
        (node / "package-lock.json").write_text("{}", encoding="utf-8")
        subprocess.run(["git", "-C", str(node), "add", "package-lock.json"], check=True)
        subprocess.run(
            ["git", "-C", str(node), "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "lock"],
            check=True,
        )
        result = inspect_project_artifact(str(modules), str(self.home), environment, open_file_checker=lambda _path: False)
        self.assertEqual(result["build_system"], "node")
        cases = (
            ("Rust", "Cargo.toml", "target", "rust", {"Cargo.lock": ""}),
            ("Go", "go.mod", "bin", "go", {}),
            ("Maven", "pom.xml", "target", "maven", {}),
            ("Gradle", "build.gradle.kts", "out", "gradle", {}),
        )
        for name, marker, artifact_name, expected, extras in cases:
            with self.subTest(build_system=expected):
                project = projects / name
                artifact = project / artifact_name
                artifact.mkdir(parents=True)
                (project / marker).write_text("manifest", encoding="utf-8")
                for filename, content in extras.items():
                    (project / filename).write_text(content, encoding="utf-8")
                subprocess.run(["git", "init", "-q", str(project)], check=True)
                (project / ".gitignore").write_text(f"{artifact_name}/\n", encoding="utf-8")
                self.commit_project(project)
                os.utime(artifact, (old, old))
                value = inspect_project_artifact(
                    str(artifact), str(self.home), environment, open_file_checker=lambda _path: False
                )
                self.assertEqual(value["build_system"], expected)

    def test_report_contains_all_extended_interactions(self) -> None:
        template = (ROOT / "open-cleaner" / "assets" / "report_template.html").read_text(encoding="utf-8")
        for marker in (
            "目录浏览与保护", "browser-search", "browser-sort", "browser-min-size",
            "保护所选路径", "安装包专项视图", "App 归属解析", "protect-value",
        ):
            self.assertIn(marker, template)

    def test_server_exposes_token_guarded_browse_and_settings_api(self) -> None:
        folder = self.home / "Folder"
        folder.mkdir()
        (folder / "item.txt").write_text("data", encoding="utf-8")
        policy = self.guarded_policy()
        analysis = analysis_for(self.home)
        plan = build_action_plan(
            analysis,
            home=str(self.home),
            platform="darwin",
            environment=self.environment,
            purpose="session",
            runtime_inspector=policy.runtime_inspector,
            settings_store=self.store,
        )
        context = ServerContext(
            analysis,
            "__REPORT_DATA____DELETE_CONFIG__",
            policy,
            plan,
            token="test-token",
            settings_store=self.store,
        )
        with running(context) as port:
            query = urllib.parse.urlencode({"path": str(folder), "sort": "name"})
            denied = urllib.request.Request(f"http://127.0.0.1:{port}/browse?{query}")
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(denied, timeout=3)
            self.assertEqual(raised.exception.code, 403)
            allowed = urllib.request.Request(
                f"http://127.0.0.1:{port}/browse?{query}",
                headers={"X-OpenCleaner-Token": "test-token"},
            )
            with urllib.request.urlopen(allowed, timeout=3) as response:
                value = json.loads(response.read())
            self.assertTrue(value["ok"])
            self.assertEqual(value["items"][0]["name"], "item.txt")


if __name__ == "__main__":
    unittest.main()
