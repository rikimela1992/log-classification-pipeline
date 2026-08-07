"""Command-line entry point for validation, classification, evaluation, and UI."""

from __future__ import annotations

import argparse
import getpass
import importlib.util
import json
import sqlite3
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .adapters import RulesPredictor, ZeroShotConfig, ZeroShotPredictor
from .application import classify_file_into_workspace
from .batch import process_batch
from .evaluation import evaluate_records
from .jsonl import read_jsonl
from .model_artifact import create_artifact_manifest, verify_artifact_manifest
from .model_catalog import RULES_MODEL_NAME, registered_model_catalog
from .model_profiles import (
    ENGLISH_PROFILE_ID,
    MODEL_PROFILE_IDS,
)
from .workspace import RetentionPolicy, Role, Workspace


def _add_limits(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-input-bytes", type=int, default=1_000_000)
    parser.add_argument("--max-records", type=int, default=1_000)


def _add_adapter(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--adapter",
        choices=("rules", "zero-shot"),
        default="rules",
        help="rules is a wiring baseline; zero-shot requires the ml extra",
    )
    parser.add_argument(
        "--model-profile",
        choices=MODEL_PROFILE_IDS,
        default=ENGLISH_PROFILE_ID,
        help="versioned model/prompt profile used by the zero-shot adapter",
    )
    parser.add_argument(
        "--model-source",
        help="local model directory",
    )
    parser.add_argument(
        "--model-id",
        help="declared model id for a local model directory",
    )
    parser.add_argument(
        "--model-revision",
        help="declared revision for a local model directory",
    )
    parser.add_argument(
        "--model-manifest",
        type=Path,
        help="SHA-256 manifest for a local model directory",
    )
    parser.add_argument(
        "--allow-download",
        action="store_true",
        help="explicitly permit a pinned Hub download",
    )
    parser.add_argument("--confidence-threshold", type=float, default=0.60)
    parser.add_argument(
        "--subsystem-threshold",
        type=float,
        help="override the zero-shot subsystem abstention threshold",
    )
    parser.add_argument(
        "--severity-threshold",
        type=float,
        help="override the zero-shot severity abstention threshold",
    )


def _add_workspace_identity(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("database", type=Path)
    parser.add_argument("organization")
    parser.add_argument("username")


def _add_workspace_commands(subparsers: argparse._SubParsersAction) -> None:
    workspace = subparsers.add_parser(
        "workspace",
        help="manage a local authenticated classification workspace",
    )
    commands = workspace.add_subparsers(dest="workspace_command", required=True)

    initialize = commands.add_parser(
        "init",
        help="create the first local administrator",
    )
    initialize.add_argument("database", type=Path)
    initialize.add_argument("organization")
    initialize.add_argument("username")

    user_add = commands.add_parser("user-add", help="add a user to the workspace")
    _add_workspace_identity(user_add)
    user_add.add_argument("new_username")
    user_add.add_argument("--role", choices=tuple(Role), required=True)

    classify = commands.add_parser(
        "classify",
        help="classify a JSONL file and persist only a complete job",
    )
    _add_workspace_identity(classify)
    classify.add_argument("input", type=Path)
    classify.add_argument(
        "--store-raw",
        action="store_true",
        help="retain source bytes according to policy; disabled by default",
    )
    classify.add_argument("--batch-size", type=int, default=64)
    _add_limits(classify)
    _add_adapter(classify)

    jobs = commands.add_parser("jobs", help="list recent classification jobs")
    _add_workspace_identity(jobs)
    jobs.add_argument("--limit", type=int, default=50)

    show = commands.add_parser("show", help="export one job as JSON")
    _add_workspace_identity(show)
    show.add_argument("job_id")

    retention_show = commands.add_parser(
        "retention-show",
        help="show the organization's retention policy",
    )
    _add_workspace_identity(retention_show)

    retention_set = commands.add_parser(
        "retention-set",
        help="set retention periods; existing job expiries are unchanged",
    )
    _add_workspace_identity(retention_set)
    retention_set.add_argument("--raw-days", type=int, required=True)
    retention_set.add_argument("--result-days", type=int, required=True)
    retention_set.add_argument("--audit-days", type=int, required=True)

    purge = commands.add_parser("purge", help="purge data whose retention expired")
    _add_workspace_identity(purge)

    audit = commands.add_parser("audit", help="show privacy-minimal audit events")
    _add_workspace_identity(audit)
    audit.add_argument("--limit", type=int, default=100)


def _build_predictor(args: argparse.Namespace):
    if args.adapter == "rules":
        if (
            args.model_profile != ENGLISH_PROFILE_ID
            or args.model_source
            or args.model_id
            or args.model_revision
            or args.model_manifest
            or args.allow_download
            or args.subsystem_threshold is not None
            or args.severity_threshold is not None
        ):
            raise ValueError("model options require --adapter zero-shot")
        return RulesPredictor(
            confidence_threshold=args.confidence_threshold,
        )
    if args.model_source:
        source_path = Path(args.model_source)
        if not source_path.is_dir():
            raise ValueError("model-source must be an existing local directory")
        if not args.model_id or not args.model_revision:
            raise ValueError(
                "local model-source requires --model-id and --model-revision"
            )
        if args.allow_download:
            raise ValueError("--allow-download cannot be used with a local model")
        profile = ZeroShotConfig.from_profile(args.model_profile)
        if (
            args.model_id != profile.model_id
            or args.model_revision != profile.revision
        ):
            raise ValueError(
                "local model identity and revision must match --model-profile"
            )
        if args.model_manifest is None:
            raise ValueError("local model-source requires --model-manifest")
        verification = verify_artifact_manifest(
            source_path,
            args.model_manifest,
            args.model_profile,
        )
        source = source_path
        model_id = args.model_id
        revision = args.model_revision
        allow_download = False
        artifact_manifest = args.model_manifest
        artifact_sha256 = verification.tree_sha256
    else:
        if args.model_id or args.model_revision or args.model_manifest:
            raise ValueError(
                "--model-id, --model-revision, and --model-manifest require "
                "--model-source"
            )
        profile_config = ZeroShotConfig.from_profile(args.model_profile)
        source = profile_config.model_source
        model_id = profile_config.model_id
        revision = profile_config.revision
        allow_download = args.allow_download
        artifact_manifest = None
        artifact_sha256 = None
    return ZeroShotPredictor(
        ZeroShotConfig(
            model_source=source,
            model_id=model_id,
            revision=revision,
            allow_download=allow_download,
            confidence_threshold=args.confidence_threshold,
            profile_id=args.model_profile,
            subsystem_threshold=args.subsystem_threshold,
            severity_threshold=args.severity_threshold,
            artifact_manifest=artifact_manifest,
            artifact_sha256=artifact_sha256,
        )
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="log-classify")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "models",
        help="list model profiles without loading model artifacts",
    )

    doctor = subparsers.add_parser(
        "doctor",
        help="check the local runtime and optional feature availability",
    )
    doctor.add_argument(
        "--database",
        type=Path,
        help="also verify an existing workspace database",
    )
    doctor.add_argument(
        "--require",
        action="append",
        choices=("ml", "ui", "web"),
        default=[],
        dest="required_features",
        help="fail when an optional feature is unavailable; repeatable",
    )

    model_manifest = subparsers.add_parser(
        "model-manifest",
        help="create or verify a SHA-256 manifest for a local model",
    )
    manifest_commands = model_manifest.add_subparsers(
        dest="manifest_command",
        required=True,
    )
    manifest_create = manifest_commands.add_parser(
        "create",
        help="print a deterministic model manifest as JSON",
    )
    manifest_create.add_argument("model_directory", type=Path)
    manifest_create.add_argument(
        "--model-profile",
        choices=MODEL_PROFILE_IDS,
        default=ENGLISH_PROFILE_ID,
    )
    manifest_verify = manifest_commands.add_parser(
        "verify",
        help="verify a local model against a manifest",
    )
    manifest_verify.add_argument("model_directory", type=Path)
    manifest_verify.add_argument("manifest", type=Path)
    manifest_verify.add_argument(
        "--model-profile",
        choices=MODEL_PROFILE_IDS,
        default=ENGLISH_PROFILE_ID,
    )

    validate = subparsers.add_parser("validate", help="validate input JSONL")
    validate.add_argument("input", type=Path)
    _add_limits(validate)

    classify = subparsers.add_parser(
        "classify",
        help="classify JSONL into an atomically published output",
    )
    classify.add_argument("input", type=Path)
    classify.add_argument("output", type=Path)
    classify.add_argument("--overwrite", action="store_true")
    classify.add_argument("--batch-size", type=int, default=64)
    _add_limits(classify)
    _add_adapter(classify)

    evaluate = subparsers.add_parser(
        "evaluate",
        help="evaluate a labelled synthetic JSONL fixture",
    )
    evaluate.add_argument("input", type=Path)
    _add_limits(evaluate)
    _add_adapter(evaluate)

    ui = subparsers.add_parser("ui", help="launch the local Gradio interface")
    _add_adapter(ui)
    ui.add_argument("--port", type=int, default=7860)

    web = subparsers.add_parser(
        "web",
        help="launch the authenticated local web workspace",
    )
    web.add_argument("database", type=Path)
    web.add_argument("--port", type=int, default=8080)
    web.add_argument(
        "--enable-model-profile",
        action="append",
        choices=MODEL_PROFILE_IDS,
        default=[],
        help="add a lazy zero-shot profile to the web model selector; repeatable",
    )
    web.add_argument(
        "--queue-capacity",
        type=int,
        default=8,
        help="maximum admitted web jobs, including the running job",
    )
    web.add_argument(
        "--worker-batch-size",
        type=int,
        default=16,
        help="records per cancellable worker chunk",
    )
    web.add_argument(
        "--login-account-limit",
        type=int,
        default=5,
        help="failed logins per account within the login window",
    )
    web.add_argument(
        "--login-source-limit",
        type=int,
        default=20,
        help="failed logins per client source within the login window",
    )
    web.add_argument(
        "--login-window-seconds",
        type=int,
        default=60,
        help="in-process failed-login window in seconds",
    )
    _add_limits(web)
    _add_adapter(web)
    _add_workspace_commands(subparsers)
    return parser


def _emit(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _read_secret(prompt: str, *, confirm: bool = False) -> str:
    password = getpass.getpass(prompt)
    if confirm:
        repeated = getpass.getpass("Confirm password: ")
        if password != repeated:
            raise ValueError("passwords do not match")
    return password


def _workspace_login(args: argparse.Namespace, workspace: Workspace) -> str:
    token, _ = workspace.login(
        args.organization,
        args.username,
        _read_secret("Password: "),
    )
    return token


def _run_workspace(args: argparse.Namespace) -> None:
    workspace = Workspace(args.database)
    if args.workspace_command == "init":
        organization_id, user_id = workspace.bootstrap(
            args.organization,
            args.username,
            _read_secret("New administrator password: ", confirm=True),
        )
        _emit(
            {
                "administrator_id": user_id,
                "database": str(args.database),
                "organization_id": organization_id,
                "status": "initialized",
            }
        )
        return

    token = _workspace_login(args, workspace)
    try:
        if args.workspace_command == "user-add":
            user_id = workspace.create_user(
                token,
                args.new_username,
                _read_secret("New user password: ", confirm=True),
                args.role,
            )
            _emit({"role": args.role, "status": "created", "user_id": user_id})
            return
        if args.workspace_command == "classify":
            predictor = _build_predictor(args)
            summary, job_id = classify_file_into_workspace(
                args.input,
                predictor,
                workspace,
                token,
                store_raw=args.store_raw,
                batch_size=args.batch_size,
                max_input_bytes=args.max_input_bytes,
                max_records=args.max_records,
            )
            _emit({"job_id": job_id, "summary": summary})
            return
        if args.workspace_command == "jobs":
            _emit(workspace.list_jobs(token, limit=args.limit))
            return
        if args.workspace_command == "show":
            _emit(workspace.get_job(token, args.job_id))
            return
        if args.workspace_command == "retention-show":
            _emit(asdict(workspace.get_retention_policy(token)))
            return
        if args.workspace_command == "retention-set":
            policy = RetentionPolicy(
                raw_days=args.raw_days,
                result_days=args.result_days,
                audit_days=args.audit_days,
            )
            workspace.set_retention_policy(token, policy)
            _emit({"policy": asdict(policy), "status": "updated"})
            return
        if args.workspace_command == "purge":
            _emit(asdict(workspace.purge_expired(token)))
            return
        if args.workspace_command == "audit":
            _emit(workspace.list_audit_events(token, limit=args.limit))
            return
    finally:
        workspace.logout(token)
    raise AssertionError(f"unhandled workspace command: {args.workspace_command}")


def _run(args: argparse.Namespace) -> None:
    if args.command == "model-manifest":
        if args.manifest_command == "create":
            _emit(
                create_artifact_manifest(
                    args.model_directory,
                    args.model_profile,
                )
            )
            return
        verification = verify_artifact_manifest(
            args.model_directory,
            args.manifest,
            args.model_profile,
        )
        _emit({"status": "verified", **asdict(verification)})
        return

    if args.command == "models":
        _emit(
            {
                "default_model": RULES_MODEL_NAME,
                "items": registered_model_catalog(
                    (RULES_MODEL_NAME, *MODEL_PROFILE_IDS)
                ),
            }
        )
        return

    if args.command == "doctor":
        required_modules = {
            "ml": ("sentencepiece", "torch", "transformers"),
            "ui": ("gradio",),
            "web": ("fastapi", "jinja2", "multipart", "uvicorn"),
        }
        features = {
            feature: {
                "available": all(
                    importlib.util.find_spec(module) is not None
                    for module in modules
                ),
                "modules": list(modules),
            }
            for feature, modules in required_modules.items()
        }
        workspace_status: dict[str, Any] = {"checked": False}
        if args.database is not None:
            workspace = Workspace(args.database)
            workspace.initialize(create=False)
            workspace.verify()
            workspace_status = {"checked": True, "status": "ok"}
        report = {
            "core": {
                "model_profiles": len(MODEL_PROFILE_IDS) + 1,
                "status": "ok",
            },
            "maturity": "alpha",
            "optional_features": features,
            "python": {
                "status": "supported" if sys.version_info >= (3, 12) else "unsupported",
                "version": ".".join(str(part) for part in sys.version_info[:3]),
            },
            "status": "ok",
            "workspace": workspace_status,
        }
        missing = sorted(
            feature
            for feature in set(args.required_features)
            if not features[feature]["available"]
        )
        if missing:
            report["status"] = "missing_required_features"
            report["missing_required_features"] = missing
        _emit(report)
        if missing:
            raise RuntimeError(
                "required optional feature(s) unavailable: " + ", ".join(missing)
            )
        return

    if args.command == "validate":
        parsed = read_jsonl(
            args.input,
            max_input_bytes=args.max_input_bytes,
            max_records=args.max_records,
        )
        _emit(
            {
                "batch_id": parsed.batch_id,
                "blank_lines": parsed.blank_lines,
                "input_records": len(parsed.records),
                "valid": True,
            }
        )
        return

    if args.command == "workspace":
        _run_workspace(args)
        return

    if args.command == "web":
        try:
            import uvicorn

            from .web import WebSettings, create_app
        except ImportError as exc:
            raise RuntimeError(
                "the web workspace is optional; install "
                "'log-classification-pipeline[web]'"
            ) from exc
        if isinstance(args.port, bool) or not 1 <= args.port <= 65535:
            raise ValueError("port must be an integer between 1 and 65535")
        if args.adapter == "rules" and args.enable_model_profile:
            if (
                args.model_profile != ENGLISH_PROFILE_ID
                or args.model_source
                or args.model_id
                or args.model_revision
                or args.model_manifest
            ):
                raise ValueError(
                    "custom model options require --adapter zero-shot"
                )
            selected_predictor = RulesPredictor(
                confidence_threshold=args.confidence_threshold,
            )
        else:
            selected_predictor = _build_predictor(args)
        predictors = {
            "rules": RulesPredictor(
                confidence_threshold=args.confidence_threshold,
            )
        }
        if args.adapter == "zero-shot":
            predictors[args.model_profile] = selected_predictor
        else:
            predictors["rules"] = selected_predictor
        for profile_id in dict.fromkeys(args.enable_model_profile):
            if profile_id not in predictors:
                predictors[profile_id] = ZeroShotPredictor(
                    ZeroShotConfig.from_profile(
                        profile_id,
                        allow_download=args.allow_download,
                        confidence_threshold=args.confidence_threshold,
                        subsystem_threshold=args.subsystem_threshold,
                        severity_threshold=args.severity_threshold,
                    )
                )
        application = create_app(
            WebSettings(
                database_path=args.database,
                max_input_bytes=args.max_input_bytes,
                max_records=args.max_records,
                max_request_bytes=args.max_input_bytes + 262_144,
                max_admitted_jobs=args.queue_capacity,
                worker_batch_size=args.worker_batch_size,
                login_account_limit=args.login_account_limit,
                login_source_limit=args.login_source_limit,
                login_window_seconds=args.login_window_seconds,
            ),
            predictors,
        )
        uvicorn.run(
            application,
            host="127.0.0.1",
            port=args.port,
            access_log=False,
            proxy_headers=False,
        )
        return

    predictor = _build_predictor(args)
    if args.command == "classify":
        summary = process_batch(
            args.input,
            args.output,
            predictor,
            batch_size=args.batch_size,
            overwrite=args.overwrite,
            max_input_bytes=args.max_input_bytes,
            max_records=args.max_records,
        )
        _emit(asdict(summary))
        return
    if args.command == "evaluate":
        parsed = read_jsonl(
            args.input,
            max_input_bytes=args.max_input_bytes,
            max_records=args.max_records,
        )
        _emit(evaluate_records(parsed.records, predictor))
        return
    if args.command == "ui":
        from .ui import build_demo

        demo = build_demo(predictor)
        demo.queue(default_concurrency_limit=1).launch(
            server_name="127.0.0.1",
            server_port=args.port,
            share=False,
            inbrowser=False,
        )
        return
    raise AssertionError(f"unhandled command: {args.command}")


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and turn expected failures into a concise non-zero exit."""

    try:
        _run(_parser().parse_args(argv))
    except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
