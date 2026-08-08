from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from log_classification_pipeline.cli import main

PASSWORD = "correct-horse-battery-staple"


class WorkspaceCliTests(unittest.TestCase):
    def run_cli(
        self,
        arguments: list[str],
        passwords: list[str],
    ) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch(
                "log_classification_pipeline.cli.getpass.getpass",
                side_effect=passwords,
            ),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            status = main(arguments)
        return status, stdout.getvalue(), stderr.getvalue()

    def test_models_catalog_is_available_without_loading_artifacts(self) -> None:
        status, output, errors = self.run_cli(["models"], [])

        self.assertEqual(status, 0, errors)
        catalog = json.loads(output)
        self.assertEqual(catalog["default_model"], "rules")
        self.assertEqual(catalog["items"][0]["id"], "rules")
        self.assertEqual(
            [item["id"] for item in catalog["items"]],
            [
                "rules",
                "english-deberta-v1",
                "multilingual-minilm-v1",
                "multilingual-mdeberta-v1",
                "multilingual-bge-m3-v1",
            ],
        )
        self.assertTrue(all(item["experimental"] for item in catalog["items"]))

    def test_doctor_reports_core_optional_features_and_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            database = Path(raw_directory) / "workspace.sqlite3"
            status, _, errors = self.run_cli(
                ["workspace", "init", str(database), "sample-org", "owner"],
                [PASSWORD, PASSWORD],
            )
            self.assertEqual(status, 0, errors)

            status, output, errors = self.run_cli(
                ["doctor", "--database", str(database)],
                [],
            )

        self.assertEqual(status, 0, errors)
        report = json.loads(output)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["maturity"], "alpha")
        self.assertEqual(report["python"]["status"], "supported")
        self.assertEqual(report["core"]["model_profiles"], 5)
        self.assertEqual(report["workspace"], {"checked": True, "status": "ok"})
        self.assertEqual(set(report["optional_features"]), {"ml", "ui", "web"})
        self.assertNotIn(str(database), output)

    def test_doctor_can_require_an_optional_feature(self) -> None:
        with mock.patch(
            "log_classification_pipeline.cli.importlib.util.find_spec",
            return_value=None,
        ):
            status, output, errors = self.run_cli(
                ["doctor", "--require", "web"],
                [],
            )

        self.assertEqual(status, 2)
        self.assertEqual(
            json.loads(output)["missing_required_features"],
            ["web"],
        )
        self.assertEqual(
            errors.strip(),
            "error: required optional feature(s) unavailable: web",
        )

    def test_initialize_classify_list_show_and_policy_flow(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            root = Path(raw_directory)
            database = root / "state" / "workspace.sqlite3"
            input_path = root / "synthetic.jsonl"
            input_path.write_text(
                '{"message":"Authentication failed"}\n',
                encoding="utf-8",
            )

            status, output, errors = self.run_cli(
                ["workspace", "init", str(database), "sample-org", "owner"],
                [PASSWORD, PASSWORD],
            )
            self.assertEqual(status, 0, errors)
            self.assertEqual(json.loads(output)["status"], "initialized")

            status, output, errors = self.run_cli(
                [
                    "workspace",
                    "classify",
                    str(database),
                    "sample-org",
                    "owner",
                    str(input_path),
                ],
                [PASSWORD],
            )
            self.assertEqual(status, 0, errors)
            classified = json.loads(output)
            self.assertEqual(classified["summary"]["input_records"], 1)

            status, output, errors = self.run_cli(
                [
                    "workspace",
                    "show",
                    str(database),
                    "sample-org",
                    "owner",
                    classified["job_id"],
                ],
                [PASSWORD],
            )
            self.assertEqual(status, 0, errors)
            job = json.loads(output)
            self.assertEqual(job["status"], "succeeded")
            self.assertEqual(job["results"][0]["subsystem"]["label"], "auth")

            status, output, errors = self.run_cli(
                [
                    "workspace",
                    "retention-set",
                    str(database),
                    "sample-org",
                    "owner",
                    "--raw-days",
                    "7",
                    "--result-days",
                    "30",
                    "--audit-days",
                    "180",
                ],
                [PASSWORD],
            )
            self.assertEqual(status, 0, errors)
            self.assertEqual(json.loads(output)["policy"]["raw_days"], 7)

            status, output, errors = self.run_cli(
                [
                    "workspace",
                    "jobs",
                    str(database),
                    "sample-org",
                    "owner",
                ],
                [PASSWORD],
            )
            self.assertEqual(status, 0, errors)
            self.assertEqual(len(json.loads(output)), 1)

        combined = output + errors
        self.assertNotIn(PASSWORD, combined)
        self.assertNotIn("Authentication failed", combined)

    def test_user_add_prompts_for_both_passwords_and_enforces_role(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            database = Path(raw_directory) / "workspace.sqlite3"
            status, _, errors = self.run_cli(
                ["workspace", "init", str(database), "sample-org", "owner"],
                [PASSWORD, PASSWORD],
            )
            self.assertEqual(status, 0, errors)

            status, output, errors = self.run_cli(
                [
                    "workspace",
                    "user-add",
                    str(database),
                    "sample-org",
                    "owner",
                    "reviewer",
                    "--role",
                    "viewer",
                ],
                [PASSWORD, "viewer-password-value", "viewer-password-value"],
            )
            self.assertEqual(status, 0, errors)
            self.assertEqual(json.loads(output)["role"], "viewer")

    def test_password_confirmation_failure_is_concise(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            database = Path(raw_directory) / "workspace.sqlite3"
            status, output, errors = self.run_cli(
                ["workspace", "init", str(database), "sample-org", "owner"],
                [PASSWORD, "different-password-value"],
            )
        self.assertEqual(status, 2)
        self.assertEqual(output, "")
        self.assertEqual(errors.strip(), "error: passwords do not match")

    def test_corrupt_database_error_is_concise(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            database = Path(raw_directory) / "corrupt.sqlite3"
            database.write_bytes(b"synthetic non-sqlite bytes")
            database.chmod(0o600)
            status, output, errors = self.run_cli(
                [
                    "workspace",
                    "jobs",
                    str(database),
                    "sample-org",
                    "owner",
                ],
                [PASSWORD],
            )
        self.assertEqual(status, 2)
        self.assertEqual(output, "")
        self.assertTrue(errors.startswith("error: "))
        self.assertNotIn("Traceback", errors)


if __name__ == "__main__":
    unittest.main()
