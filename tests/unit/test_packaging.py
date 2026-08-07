from __future__ import annotations

import os
import subprocess
import unittest
from pathlib import Path
from xml.etree import ElementTree


ROOT = Path(__file__).parents[2]


class LinuxPackagingTests(unittest.TestCase):
    def test_shell_entrypoints_are_executable_and_parse(self) -> None:
        scripts = (
            ROOT / "packaging/build_appimage.sh",
            ROOT / "packaging/build_bundle.sh",
            ROOT / "packaging/collect_native_licenses.sh",
            ROOT / "packaging/build_deb.sh",
            ROOT / "packaging/build_rpm.sh",
            ROOT / "packaging/build_tarball.sh",
            ROOT / "packaging/stage_linux.sh",
            ROOT / "packaging/smoke_frozen_web.sh",
            ROOT / "packaging/linux/log-classification-pipeline",
            ROOT / "packaging/linux/AppRun",
        )
        for script in scripts:
            with self.subTest(script=script.name):
                self.assertTrue(os.access(script, os.X_OK))
                subprocess.run(["sh", "-n", script], check=True)

    def test_launcher_has_guided_setup_without_default_credentials(self) -> None:
        launcher = (
            ROOT / "packaging/linux/log-classification-pipeline"
        ).read_text(encoding="utf-8")
        self.assertIn("workspace init", launcher)
        self.assertIn("127.0.0.1:8080", launcher)
        self.assertNotIn("password=", launcher.casefold())
        self.assertNotIn("--password", launcher)

    def test_release_candidate_workflow_is_read_only_and_pinned(self) -> None:
        workflow = (ROOT / ".github/workflows/package-linux.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("contents: read", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("gh release", workflow)
        self.assertIn("SHA256SUMS", workflow)
        self.assertIn("bundle.spdx.json", workflow)
        self.assertNotIn("actions/checkout@v", workflow)
        self.assertNotIn("actions/upload-artifact@v", workflow)
        self.assertIn("appstreamcli validate --no-net", workflow)

    def test_bundle_explicitly_excludes_models_and_ml_runtimes(self) -> None:
        builder = (ROOT / "packaging/build_bundle.sh").read_text(encoding="utf-8")
        self.assertIn("--exclude-module readline", builder)
        self.assertIn("--exclude-module torch", builder)
        self.assertIn("--exclude-module transformers", builder)
        self.assertIn("doctor --require web", builder)

        native_licenses = (
            ROOT / "packaging/collect_native_licenses.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("%{SOURCERPM}", native_licenses)
        self.assertIn("sibling_packages", native_licenses)
        self.assertIn("%{LICENSE}", native_licenses)
        self.assertIn("cannot locate RPM license evidence", native_licenses)

    def test_appstream_identity_filename_and_homepage_are_consistent(self) -> None:
        metadata = ElementTree.parse(
            ROOT
            / "packaging/linux/io.github.rikimela1992.log-classification-pipeline.metainfo.xml"
        ).getroot()
        self.assertEqual(
            metadata.findtext("id"),
            "io.github.rikimela1992.log-classification-pipeline",
        )
        self.assertEqual(metadata.findtext("developer/name"), "Riccardo Melini")
        self.assertEqual(
            metadata.findtext("url"),
            "https://github.com/rikimela1992/log-classification-pipeline",
        )


if __name__ == "__main__":
    unittest.main()
