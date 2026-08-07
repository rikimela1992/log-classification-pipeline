from __future__ import annotations

import asyncio
import io
import json
import re
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

try:
    import fastapi  # noqa: F401
except ModuleNotFoundError as exc:
    if exc.name != "fastapi":
        raise
    TestClient = None  # type: ignore[assignment,misc]
    WEB_AVAILABLE = False
else:
    from fastapi.testclient import TestClient

    from log_classification_pipeline.web import WebSettings, create_app
    from log_classification_pipeline.web.app import RequestSizeLimitMiddleware
    from log_classification_pipeline.web.i18n import (
        load_catalogs,
        negotiate_locale,
        translator,
    )

    WEB_AVAILABLE = True

from log_classification_pipeline.adapters import RulesPredictor
from log_classification_pipeline.adapters.zero_shot import ZeroShotPredictor
from log_classification_pipeline.cli import main
from log_classification_pipeline.model_profiles import MULTILINGUAL_PROFILE_ID
from log_classification_pipeline.workspace import Role, Workspace


PASSWORD = "correct-horse-battery-staple"


class TrackingPredictor:
    def __init__(self) -> None:
        self.calls = 0
        self.delegate = RulesPredictor()

    def __call__(self, records):
        self.calls += 1
        return self.delegate(records)


class MarkupPredictor:
    def __call__(self, records):
        predictions = RulesPredictor()(records)
        for prediction in predictions:
            prediction["model"]["id"] = "<script>alert('synthetic')</script>"
        return predictions


class ExplodingPredictor:
    def __call__(self, _records):
        raise TypeError("synthetic internal detail that must not escape")


@unittest.skipUnless(WEB_AVAILABLE, "web extra is not installed")
class WebApplicationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        root = Path(self.temporary_directory.name)
        self.database = root / "workspace.sqlite3"
        self.workspace = Workspace(self.database)
        self.workspace.bootstrap("sample-org", "owner", PASSWORD)
        admin_token, _ = self.workspace.login("sample-org", "owner", PASSWORD)
        self.workspace.create_user(
            admin_token,
            "analyst",
            "analyst-password-value",
            Role.ANALYST,
        )
        self.workspace.create_user(
            admin_token,
            "reviewer",
            "viewer-password-value",
            Role.VIEWER,
        )
        self.workspace.logout(admin_token)
        self.predictor = TrackingPredictor()
        self.app = create_app(
            WebSettings(
                self.database,
                allowed_hosts=("testserver",),
                max_input_bytes=1_000,
                max_records=10,
                max_request_bytes=4_096,
            ),
            {"rules": self.predictor},
        )
        self.client = TestClient(
            self.app,
            base_url="http://testserver",
            raise_server_exceptions=False,
        )

    def tearDown(self) -> None:
        self.client.close()
        self.temporary_directory.cleanup()

    def api_login(self, username: str, password: str) -> str:
        response = self.client.post(
            "/api/v1/sessions",
            json={
                "organization": "sample-org",
                "username": username,
                "password": password,
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()["access_token"]

    @staticmethod
    def bearer(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def ui_login(self, username: str = "owner", password: str = PASSWORD) -> None:
        login_page = self.client.get("/app/login")
        self.assertEqual(login_page.status_code, 200)
        csrf_cookie = self.client.cookies.get("lcp_login_csrf")
        self.assertIsNotNone(csrf_cookie)
        match = re.search(r'name="csrf" value="([^"]+)"', login_page.text)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), csrf_cookie)
        response = self.client.post(
            "/app/login",
            data={
                "organization": "sample-org",
                "username": username,
                "password": password,
                "csrf": csrf_cookie,
            },
            headers={
                "Origin": "http://testserver",
                "X-CSRF-Token": csrf_cookie,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303, response.text)
        self.assertIsNotNone(self.client.cookies.get("lcp_session"))

    def csrf_header(self) -> dict[str, str]:
        dashboard = self.client.get("/app")
        self.assertEqual(dashboard.status_code, 200, dashboard.text)
        match = re.search(r'<meta name="csrf-token" content="([^"]+)"', dashboard.text)
        self.assertIsNotNone(match)
        return {
            "Origin": "http://testserver",
            "X-CSRF-Token": match.group(1),
        }

    def test_security_headers_trusted_host_and_no_cors(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"maturity": "alpha", "status": "ok"})
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertIn("frame-ancestors 'none'", response.headers["content-security-policy"])
        self.assertEqual(response.headers["x-content-type-options"], "nosniff")
        self.assertEqual(response.headers["x-frame-options"], "DENY")
        self.assertNotIn("strict-transport-security", response.headers)
        self.assertNotIn("access-control-allow-origin", response.headers)

        hostile = self.client.get("/health", headers={"Host": "hostile.invalid"})
        self.assertEqual(hostile.status_code, 400)
        self.assertIn("x-content-type-options", hostile.headers)

    def test_catalogs_negotiate_language_and_fallback_without_api_drift(self) -> None:
        catalogs = load_catalogs()
        self.assertEqual(set(catalogs), {"en", "it", "fr", "es"})
        self.assertEqual(negotiate_locale(None, "fr-CA,fr;q=0.9,en;q=0.8"), "fr")
        self.assertEqual(negotiate_locale("it", "es"), "it")
        self.assertEqual(negotiate_locale(None, "de,*;q=0.5"), "en")
        self.assertEqual(
            negotiate_locale(None, "x" * 1025),
            "en",
        )
        self.assertIn("40", translator(catalogs, "es")("jobs.shown", count=40))

        page = self.client.get(
            "/app/login",
            headers={"Accept-Language": "it-IT,it;q=0.9"},
        )
        self.assertEqual(page.headers["content-language"], "it")
        self.assertIn("Accept-Language", page.headers["vary"])
        self.assertIn("Cookie", page.headers["vary"])
        self.assertIn('<html lang="it">', page.text)
        self.assertIn("Accedi", page.text)

        api = self.client.post(
            "/api/v1/sessions",
            headers={"Accept-Language": "it"},
            json={"organization": "x", "username": "x", "password": "x"},
        )
        self.assertEqual(api.status_code, 422)
        self.assertEqual(api.headers["content-type"], "application/problem+json")
        self.assertEqual(api.json()["code"], "invalid_request")

    def test_locale_cookie_change_is_csrf_protected_and_bounded(self) -> None:
        page = self.client.get("/app/login")
        csrf = self.client.cookies.get("lcp_login_csrf")
        self.assertIsNotNone(csrf)

        denied = self.client.post(
            "/app/locale",
            data={"locale": "fr", "target": "login"},
            headers={"Origin": "http://testserver"},
            follow_redirects=False,
        )
        self.assertEqual(denied.status_code, 403)

        changed = self.client.post(
            "/app/locale",
            data={"locale": "fr", "target": "outside"},
            headers={
                "Origin": "http://testserver",
                "X-CSRF-Token": csrf,
            },
            follow_redirects=False,
        )
        self.assertEqual(changed.status_code, 303)
        self.assertEqual(changed.headers["location"], "/app/login")
        locale_cookie = next(
            value
            for value in changed.headers.get_list("set-cookie")
            if "lcp_locale=" in value
        )
        self.assertIn("HttpOnly", locale_cookie)
        self.assertIn("SameSite=strict", locale_cookie)

        selected = self.client.get(
            "/app/login",
            headers={"Accept-Language": "es"},
        )
        self.assertEqual(selected.headers["content-language"], "fr")
        self.assertIn('<html lang="fr">', selected.text)

    def test_api_bearer_authentication_and_ambiguous_cookie_are_rejected(self) -> None:
        missing = self.client.get("/api/v1/jobs")
        self.assertEqual(missing.status_code, 401)
        self.assertEqual(missing.headers["www-authenticate"], "Bearer")

        token = self.api_login("owner", PASSWORD)
        me = self.client.get("/api/v1/me", headers=self.bearer(token))
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.json()["role"], "admin")

        self.client.cookies.set("lcp_session", "synthetic-cookie-value")
        ambiguous = self.client.get("/api/v1/me", headers=self.bearer(token))
        self.assertEqual(ambiguous.status_code, 400)
        self.assertEqual(ambiguous.json()["code"], "ambiguous_authentication")

    def test_api_logout_revokes_the_server_side_session(self) -> None:
        token = self.api_login("owner", PASSWORD)
        logged_out = self.client.delete(
            "/api/v1/session",
            headers=self.bearer(token),
        )
        self.assertEqual(logged_out.status_code, 204, logged_out.text)

        denied = self.client.get("/api/v1/me", headers=self.bearer(token))
        self.assertEqual(denied.status_code, 401)
        self.assertEqual(denied.json()["code"], "not_authenticated")

    def test_viewer_is_denied_before_predictor_and_analyst_can_classify(self) -> None:
        viewer_token = self.api_login("reviewer", "viewer-password-value")
        denied = self.client.post(
            "/api/v1/classifications",
            headers=self.bearer(viewer_token),
            json={"records": [{"message": "Authentication failed"}]},
        )
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(self.predictor.calls, 0)

        analyst_token = self.api_login("analyst", "analyst-password-value")
        created = self.client.post(
            "/api/v1/classifications",
            headers=self.bearer(analyst_token),
            json={"records": [{"message": "Authentication failed"}]},
        )
        self.assertEqual(created.status_code, 201, created.text)
        self.assertEqual(self.predictor.calls, 1)
        job_id = created.json()["job_id"]

        stored = self.client.get(
            f"/api/v1/jobs/{job_id}",
            headers=self.bearer(analyst_token),
        )
        self.assertEqual(stored.status_code, 200)
        self.assertEqual(stored.json()["input_records"], 1)
        self.assertEqual(stored.json()["output_records"], 1)
        self.assertNotIn("message", json.dumps(stored.json()["results"]))

        exported = self.client.get(
            f"/api/v1/jobs/{job_id}/export",
            headers=self.bearer(analyst_token),
        )
        self.assertEqual(exported.status_code, 200)
        self.assertEqual(exported.headers["content-type"], "application/x-ndjson")
        exported_record = json.loads(exported.text)
        self.assertNotIn("message", exported_record)
        self.assertNotIn("Authentication failed", exported.text)

        admin_denied = self.client.get(
            "/api/v1/admin/users",
            headers=self.bearer(analyst_token),
        )
        self.assertEqual(admin_denied.status_code, 403)

    def test_file_upload_is_bounded_and_ignores_hostile_filename(self) -> None:
        token = self.api_login("analyst", "analyst-password-value")
        accepted = self.client.post(
            "/api/v1/classifications/file",
            headers=self.bearer(token),
            data={"model": "rules"},
            files={
                "upload": (
                    "../../synthetic.jsonl",
                    b'{"message":"Backup completed"}\n',
                    "application/octet-stream",
                )
            },
        )
        self.assertEqual(accepted.status_code, 201, accepted.text)

        oversized = self.client.post(
            "/api/v1/classifications/file",
            headers=self.bearer(token),
            files={"upload": ("input.jsonl", b"x" * 1_001, "application/x-ndjson")},
        )
        self.assertEqual(oversized.status_code, 413, oversized.text)

    def test_unknown_model_is_sanitized_and_openapi_excludes_ui_routes(self) -> None:
        token = self.api_login("analyst", "analyst-password-value")
        rejected = self.client.post(
            "/api/v1/classifications",
            headers=self.bearer(token),
            json={
                "model": "not-configured",
                "records": [{"message": "Synthetic event"}],
            },
        )
        self.assertEqual(rejected.status_code, 422)
        self.assertEqual(rejected.json()["detail"], "Request is invalid.")
        self.assertNotIn("not-configured", rejected.text)

        schema = self.client.get("/api/v1/openapi.json")
        self.assertEqual(schema.status_code, 200, schema.text)
        paths = schema.json()["paths"]
        self.assertIn("/api/v1/classifications", paths)
        self.assertTrue(all(not path.startswith("/app") for path in paths))

    def test_database_failure_during_authentication_returns_sanitized_503(self) -> None:
        token = self.api_login("analyst", "analyst-password-value")
        self.database.write_bytes(b"synthetic non-sqlite bytes")

        response = self.client.get("/api/v1/jobs", headers=self.bearer(token))
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json()["code"], "workspace_unavailable")
        self.assertEqual(response.headers["retry-after"], "1")
        self.assertNotIn(str(self.database), response.text)
        self.assertNotIn("Traceback", response.text)

    def test_job_pagination_and_unavailable_export_are_explicit(self) -> None:
        token = self.api_login("owner", PASSWORD)
        for index in range(1, 4):
            self.workspace.store_completed_job(
                token,
                f"{index:064x}",
                1,
                [RulesPredictor()([{"message": "Backup completed"}])[0]],
            )

        first = self.client.get(
            "/api/v1/jobs?limit=2",
            headers=self.bearer(token),
        )
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(len(first.json()["items"]), 2)
        self.assertEqual(first.json()["next_offset"], 2)
        second = self.client.get(
            "/api/v1/jobs?limit=2&offset=2",
            headers=self.bearer(token),
        )
        self.assertEqual(len(second.json()["items"]), 1)
        self.assertIsNone(second.json()["next_offset"])

        pending_id = self.workspace.create_job(token, "f" * 64, 1)
        unavailable = self.client.get(
            f"/api/v1/jobs/{pending_id}/export",
            headers=self.bearer(token),
        )
        self.assertEqual(unavailable.status_code, 409)
        self.assertEqual(unavailable.json()["code"], "conflict")

    def test_ui_cookie_login_origin_csrf_and_classification_flow(self) -> None:
        page = self.client.get("/app/login")
        set_cookie = page.headers.get_list("set-cookie")
        login_cookie = next(item for item in set_cookie if "lcp_login_csrf=" in item)
        self.assertIn("HttpOnly", login_cookie)
        self.assertIn("SameSite=strict", login_cookie)
        self.assertNotIn("Secure", login_cookie)

        csrf = self.client.cookies.get("lcp_login_csrf")
        denied_origin = self.client.post(
            "/app/login",
            data={
                "organization": "sample-org",
                "username": "owner",
                "password": PASSWORD,
                "csrf": csrf,
            },
        )
        self.assertEqual(denied_origin.status_code, 403)

        self.ui_login()
        dashboard = self.client.get("/app")
        self.assertIn("Classification workspace", dashboard.text)
        self.assertNotIn(self.client.cookies.get("lcp_session"), dashboard.text)
        self.assertNotIn("retain raw", dashboard.text.casefold())

        missing_csrf = self.client.post(
            "/app/classify",
            headers={"Origin": "http://testserver"},
            files={"upload": ("input.jsonl", b'{"message":"Backup completed"}\n')},
        )
        self.assertEqual(missing_csrf.status_code, 403)
        calls_before = self.predictor.calls

        created = self.client.post(
            "/app/classify",
            headers=self.csrf_header(),
            data={"model": "rules"},
            files={"upload": ("input.jsonl", b'{"message":"Backup completed"}\n')},
            follow_redirects=False,
        )
        self.assertEqual(created.status_code, 303, created.text)
        self.assertEqual(self.predictor.calls, calls_before + 1)
        detail = self.client.get(created.headers["location"])
        self.assertEqual(detail.status_code, 200)
        self.assertIn("Completed classification", detail.text)
        self.assertNotIn("Backup completed", detail.text)

        logout = self.client.post(
            "/app/logout",
            headers=self.csrf_header(),
            follow_redirects=False,
        )
        self.assertEqual(logout.status_code, 303)
        self.assertIsNone(self.client.cookies.get("lcp_session"))
        redirected = self.client.get("/app", follow_redirects=False)
        self.assertEqual(redirected.status_code, 303)
        self.assertEqual(redirected.headers["location"], "/app/login")

    def test_ui_viewer_is_denied_before_upload_parsing_and_prediction(self) -> None:
        self.ui_login("reviewer", "viewer-password-value")
        calls_before = self.predictor.calls
        denied = self.client.post(
            "/app/classify",
            headers=self.csrf_header(),
            files={"upload": ("input.jsonl", b"not even json")},
        )
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(self.predictor.calls, calls_before)

    def test_template_autoescape_blocks_model_markup(self) -> None:
        markup_app = create_app(
            WebSettings(
                self.database,
                allowed_hosts=("testserver",),
                max_input_bytes=1_000,
                max_records=10,
                max_request_bytes=4_096,
            ),
            {"markup": MarkupPredictor()},
        )
        with TestClient(
            markup_app,
            base_url="http://testserver",
            raise_server_exceptions=False,
        ) as client:
            session = client.post(
                "/api/v1/sessions",
                json={
                    "organization": "sample-org",
                    "username": "analyst",
                    "password": "analyst-password-value",
                },
            )
            token = session.json()["access_token"]
            created = client.post(
                "/api/v1/classifications",
                headers=self.bearer(token),
                json={
                    "model": "markup",
                    "records": [{"message": "Backup completed"}],
                },
            )
            self.assertEqual(created.status_code, 201, created.text)
            client.cookies.set("lcp_session", token)
            detail = client.get(f'/app/jobs/{created.json()["job_id"]}')
            self.assertEqual(detail.status_code, 200, detail.text)
            self.assertNotIn("<script>alert", detail.text)
            self.assertIn("&lt;script&gt;alert", detail.text)

    def test_unexpected_predictor_error_is_a_sanitized_problem(self) -> None:
        failing_app = create_app(
            WebSettings(
                self.database,
                allowed_hosts=("testserver",),
                max_input_bytes=1_000,
                max_records=10,
                max_request_bytes=4_096,
            ),
            {"failing": ExplodingPredictor()},
        )
        with TestClient(
            failing_app,
            base_url="http://testserver",
            raise_server_exceptions=False,
        ) as client:
            session = client.post(
                "/api/v1/sessions",
                json={
                    "organization": "sample-org",
                    "username": "analyst",
                    "password": "analyst-password-value",
                },
            )
            token = session.json()["access_token"]
            response = client.post(
                "/api/v1/classifications",
                headers=self.bearer(token),
                json={
                    "model": "failing",
                    "records": [{"message": "Synthetic event"}],
                },
            )
            self.assertEqual(response.status_code, 500)
            self.assertEqual(response.headers["content-type"], "application/problem+json")
            self.assertEqual(response.json()["code"], "internal_error")
            self.assertEqual(response.headers["x-content-type-options"], "nosniff")
            self.assertNotIn("synthetic internal detail", response.text)
            self.assertNotIn("Traceback", response.text)

    def test_admin_user_retention_and_request_limit(self) -> None:
        token = self.api_login("owner", PASSWORD)
        created = self.client.post(
            "/api/v1/admin/users",
            headers=self.bearer(token),
            json={
                "username": "observer",
                "password": "observer-password-value",
                "role": "viewer",
            },
        )
        self.assertEqual(created.status_code, 201, created.text)
        users = self.client.get("/api/v1/admin/users", headers=self.bearer(token))
        self.assertEqual(users.status_code, 200)
        self.assertIn("observer", {item["username"] for item in users.json()["items"]})

        policy = self.client.put(
            "/api/v1/admin/retention",
            headers=self.bearer(token),
            json={"raw_days": 7, "result_days": 30, "audit_days": 180},
        )
        self.assertEqual(policy.status_code, 200)
        self.assertEqual(policy.json()["policy"]["raw_days"], 7)

        too_large = self.client.post(
            "/api/v1/sessions",
            content=b"x" * 4_097,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(too_large.status_code, 413)
        self.assertNotIn("Traceback", too_large.text)


    def test_streamed_request_limit_cannot_be_bypassed_without_content_length(self) -> None:
        sent = []
        incoming = iter(
            (
                {"type": "http.request", "body": b"a" * 4, "more_body": True},
                {"type": "http.request", "body": b"b" * 5, "more_body": False},
            )
        )

        async def receive():
            return next(incoming)

        async def send(message):
            sent.append(message)

        async def consume_body(_scope, wrapped_receive, wrapped_send):
            while True:
                message = await wrapped_receive()
                if not message.get("more_body", False):
                    break
            await wrapped_send(
                {"type": "http.response.start", "status": 204, "headers": []}
            )
            await wrapped_send({"type": "http.response.body", "body": b""})

        middleware = RequestSizeLimitMiddleware(consume_body, max_bytes=8)
        asyncio.run(
            middleware(
                {
                    "type": "http",
                    "method": "POST",
                    "path": "/synthetic",
                    "headers": [],
                },
                receive,
                send,
            )
        )
        start = next(message for message in sent if message["type"] == "http.response.start")
        self.assertEqual(start["status"], 413)

    def test_secure_cookie_profile_enables_secure_and_hsts(self) -> None:
        secure_app = create_app(
            WebSettings(
                self.database,
                allowed_hosts=("testserver",),
                cookie_secure=True,
            ),
            {"rules": RulesPredictor()},
        )
        with TestClient(
            secure_app,
            base_url="https://testserver",
            raise_server_exceptions=False,
        ) as client:
            response = client.get("/app/login")
            self.assertEqual(response.status_code, 200)
            self.assertIn("strict-transport-security", response.headers)
            login_cookie = next(
                item
                for item in response.headers.get_list("set-cookie")
                if "lcp_login_csrf=" in item
            )
            self.assertIn("Secure", login_cookie)

    def test_cli_web_binds_loopback_and_rejects_irrelevant_model_options(self) -> None:
        with mock.patch("uvicorn.run") as run:
            status = main(["web", str(self.database), "--port", "8091"])
        self.assertEqual(status, 0)
        run.assert_called_once()
        self.assertEqual(run.call_args.kwargs["host"], "127.0.0.1")
        self.assertEqual(run.call_args.kwargs["port"], 8091)
        self.assertFalse(run.call_args.kwargs["access_log"])
        self.assertFalse(run.call_args.kwargs["proxy_headers"])

        with (
            mock.patch("uvicorn.run") as rejected_run,
            redirect_stderr(io.StringIO()) as error_output,
        ):
            status = main(
                [
                    "web",
                    str(self.database),
                    "--model-source",
                    str(self.database.parent),
                ]
            )
        self.assertEqual(status, 2)
        rejected_run.assert_not_called()
        self.assertIn("model options require --adapter zero-shot", error_output.getvalue())

        with (
            mock.patch("uvicorn.run") as mismatch_run,
            redirect_stderr(io.StringIO()) as mismatch_error,
        ):
            status = main(
                [
                    "web",
                    str(self.database),
                    "--adapter",
                    "zero-shot",
                    "--model-source",
                    str(self.database.parent),
                    "--model-id",
                    "example/mismatch",
                    "--model-revision",
                    "mismatch",
                ]
            )
        self.assertEqual(status, 2)
        mismatch_run.assert_not_called()
        self.assertIn("must match --model-profile", mismatch_error.getvalue())

        with mock.patch("uvicorn.run") as profile_run:
            status = main(
                [
                    "web",
                    str(self.database),
                    "--enable-model-profile",
                    MULTILINGUAL_PROFILE_ID,
                ]
            )
        self.assertEqual(status, 0)
        configured_app = profile_run.call_args.args[0]
        self.assertEqual(
            set(configured_app.state.predictors),
            {"rules", MULTILINGUAL_PROFILE_ID},
        )
        configured = configured_app.state.predictors[MULTILINGUAL_PROFILE_ID]
        self.assertIsInstance(configured, ZeroShotPredictor)
        self.assertFalse(configured.loaded)


if __name__ == "__main__":
    unittest.main()
