# Copyright (c) 2026 Gaetano. All rights reserved.
# Licensed under MIT License. See LICENSE in the project root.
"""Deterministic tests for the full-spectrum QA engines (v2.0.0).

Every test builds its own fixture on disk or in memory: no network, no browser,
no Android SDK. The live layer is exercised against a loopback HTTP server.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from qa_agent.cli import (
    run_audit_apk,
    run_audit_db,
    run_audit_pwa,
    run_audit_rbac,
    run_gen_test_plan,
    run_load_test_command,
    run_test_cli,
)
from qa_agent.db_qa import audit_ddl, audit_sqlite, parse_ddl_tables
from qa_agent.desktop_cli_qa import (
    CliCase,
    CliRun,
    audit_desktop_source,
    check_cli_case,
    default_cli_cases,
    run_cli_audit,
)
from qa_agent.functional_qa import audit_rbac, audit_workflow, load_rbac_matrix
from qa_agent.mobile_qa import audit_pwa, audit_pwa_dir, inspect_apk, manifest_icon_sizes
from qa_agent.performance_qa import LoadConfig, LoadSample, evaluate_load, run_load_test
from qa_agent.test_management import (
    build_rtm,
    discover_tests,
    generate_test_plan,
    parse_junit,
    parse_junit_file,
)

MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.app" android:versionName="1.2.3" android:versionCode="42"
    android:debuggable="true" android:allowBackup="true" android:usesCleartextTraffic="true">
  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="30" />
  <uses-permission android:name="android.permission.READ_SMS" />
  <uses-permission android:name="android.permission.CAMERA" />
  <application>
    <activity android:name=".MainActivity" android:exported="true" />
  </application>
</manifest>
"""


def build_apk(path: Path, *, manifest: str = MANIFEST, signed: bool = False, dex: bool = True) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        if dex:
            archive.writestr("classes.dex", b"dex\n035")
        if signed:
            archive.writestr("META-INF/CERT.RSA", b"signature")
    return path


def test_apk_flags_permissions_and_debug_build(tmp_path: Path) -> None:
    report = inspect_apk(build_apk(tmp_path / "app.apk"))
    titles = {finding.title for finding in report.findings}
    assert report.package == "com.example.app"
    assert report.version_name == "1.2.3"
    assert report.target_sdk == 30
    assert "Dangerous permission requested" in titles
    assert "Debuggable release build" in titles
    assert "APK is not signed" in titles
    assert report.passed is False


def test_apk_signed_clean_build_passes(tmp_path: Path) -> None:
    manifest = MANIFEST.replace('android:debuggable="true" ', "").replace('android:allowBackup="true" ', "")
    manifest = manifest.replace('android:usesCleartextTraffic="true"', 'android:usesCleartextTraffic="false"')
    manifest = manifest.replace('android:targetSdkVersion="30"', 'android:targetSdkVersion="34"')
    manifest = manifest.replace('<uses-permission android:name="android.permission.READ_SMS" />', "")
    manifest = manifest.replace('android:exported="true"', 'android:exported="false"')
    report = inspect_apk(build_apk(tmp_path / "clean.apk", manifest=manifest, signed=True))
    assert report.passed is True
    assert report.permissions == ("android.permission.CAMERA",)


def test_apk_binary_manifest_and_missing_file(tmp_path: Path) -> None:
    binary = tmp_path / "binary.apk"
    with zipfile.ZipFile(binary, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00binary")
        archive.writestr("classes.dex", b"dex")
    report = inspect_apk(binary)
    assert report.manifest_binary is True
    assert any(f.category == "mobile-apk-binary-manifest" for f in report.findings)
    missing = inspect_apk(tmp_path / "nope.apk")
    assert missing.passed is False
    assert missing.findings[0].category == "mobile-apk-missing"


def pwa_manifest(**overrides):
    data = {
        "name": "QA Demo",
        "short_name": "QADemo",
        "start_url": "/",
        "display": "standalone",
        "icons": [{"sizes": "192x192"}, {"sizes": "512x512"}],
        "theme_color": "#101828",
        "background_color": "#ffffff",
    }
    data.update(overrides)
    return data


PWA_HTML = (
    '<html><head><meta name="viewport" content="width=device-width, initial-scale=1">'
    '<meta name="theme-color" content="#101828"><link rel="manifest" href="/manifest.webmanifest">'
    "</head><body><script>if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');</script></body></html>"
)
PWA_WORKER = "self.addEventListener('install', e => e.waitUntil(caches.open('v1')));\nself.addEventListener('fetch', e => e.respondWith(caches.match(e.request)));"


def test_pwa_installable_report() -> None:
    report = audit_pwa(PWA_HTML, pwa_manifest(), PWA_WORKER, url="https://example.com")
    assert report.installable is True
    assert report.passed is True
    assert report.service_worker is True


def test_pwa_flags_insecure_and_missing_pieces() -> None:
    report = audit_pwa("<html></html>", {}, "", url="http://example.com")
    categories = {finding.category for finding in report.findings}
    assert {"pwa-manifest", "pwa-link", "pwa-viewport", "pwa-service-worker", "pwa-https"} <= categories
    assert report.installable is False


def test_pwa_dir_and_icon_sizes(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text(PWA_HTML, encoding="utf-8")
    (tmp_path / "manifest.webmanifest").write_text(json.dumps(pwa_manifest()), encoding="utf-8")
    (tmp_path / "sw.js").write_text(PWA_WORKER, encoding="utf-8")
    report = audit_pwa_dir(tmp_path)
    assert report.passed is True
    assert manifest_icon_sizes(pwa_manifest()) == {"192x192", "512x512"}
    assert audit_pwa_dir(tmp_path / "missing").passed is False


MINI_CLI = """
import argparse, sys
parser = argparse.ArgumentParser(prog="mini")
parser.add_argument("--version", action="version", version="mini 1.0")
args = parser.parse_args()
print("ok")
"""


def write_cli(tmp_path: Path) -> list[str]:
    script = tmp_path / "mini.py"
    script.write_text(MINI_CLI, encoding="utf-8")
    return [sys.executable, str(script)]


def test_cli_audit_passes_a_healthy_command(tmp_path: Path) -> None:
    report = run_cli_audit(write_cli(tmp_path))
    assert report.passed is True
    assert {run.name for run in report.runs} == {"help", "unknown-flag", "version"}


def test_cli_case_checks_exit_text_and_json() -> None:
    run = CliRun("json", ("cmd",), 0, '{"ok": true}', "")
    assert check_cli_case(run, CliCase("json", json_keys=("ok",))) == []
    broken = check_cli_case(CliRun("json", ("cmd",), 0, "nope", ""), CliCase("json", json_keys=("ok",)))
    assert any(f.category == "desktop-cli-json" for f in broken)
    timeout = check_cli_case(CliRun("slow", ("cmd",), -1, "", "", timed_out=True), CliCase("slow"))
    assert timeout[0].category == "desktop-cli-timeout"
    secret = check_cli_case(CliRun("leak", ("cmd",), 0, 'password = "hunter2hunter2"', ""), CliCase("leak"))
    assert any(f.category == "desktop-cli-secret" for f in secret)


def test_cli_audit_reports_failed_exit(tmp_path: Path) -> None:
    report = run_cli_audit(write_cli(tmp_path), (CliCase("version", ("--version",), expect_exit=3),))
    assert report.passed is False
    assert report.findings[0].category == "desktop-cli-exit-code"


def test_desktop_ast_audit_finds_risky_calls(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import os, subprocess\nimport tkinter as tk\n"
        "def run(value):\n"
        "    eval(value)\n"
        "    os.system('ls')\n"
        "    subprocess.run(['ls'], shell=True)\n",
        encoding="utf-8",
    )
    report = audit_desktop_source(tmp_path)
    categories = {finding.category for finding in report.findings}
    assert "desktop-dynamic-code" in categories
    assert "desktop-shell" in categories
    assert "desktop-cli-timeout" in categories
    assert report.frameworks == ("Tkinter",)
    assert report.passed is False


def test_desktop_ast_audit_missing_path_and_syntax_error(tmp_path: Path) -> None:
    assert audit_desktop_source(tmp_path / "none").passed is False
    (tmp_path / "broken.py").write_text("def x(:\n", encoding="utf-8")
    report = audit_desktop_source(tmp_path)
    assert any(f.category == "desktop-parse" for f in report.findings)


RBAC_MATRIX = {
    "roles": ["admin", "user", "guest"],
    "permissions": {
        "admin": ["read", "write", "delete", "billing"],
        "user": ["read", "write", "delete"],
        "guest": ["read"],
    },
    "sensitive_permissions": ["delete", "billing"],
}


def test_rbac_flags_over_privilege() -> None:
    report = audit_rbac(RBAC_MATRIX)
    assert report.passed is False
    assert any(f.category == "rbac-over-privilege" for f in report.findings)


def test_rbac_clean_matrix_passes() -> None:
    matrix = {
        "roles": ["admin", "user"],
        "permissions": {"admin": ["read", "write", "delete"], "user": ["read"]},
        "sensitive_permissions": ["delete"],
        "privileged_roles": ["admin"],
    }
    report = audit_rbac(matrix)
    assert report.passed is True


def test_rbac_flags_empty_and_orphan_roles(tmp_path: Path) -> None:
    payload = {
        "roles": ["admin", "ghost"],
        "permissions": {"admin": ["read", "write", "delete", "delete"], "stray": ["write"]},
        "sensitive_permissions": ["delete"],
    }
    path = tmp_path / "matrix.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    report = audit_rbac(path)
    categories = {finding.category for finding in report.findings}
    assert {"rbac-role-gap", "rbac-orphan-role"} <= categories
    assert load_rbac_matrix(path)["roles"] == ["admin", "ghost"]


def test_rbac_rejects_broken_document(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"roles": []}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_rbac_matrix(path)


def test_workflow_flags_dead_end_and_unreachable() -> None:
    report = audit_workflow(
        {"cart": ["checkout"], "checkout": ["paid"], "paid": [], "orphan": ["cart"]},
        initial="cart",
        terminal=["paid"],
    )
    categories = {finding.category for finding in report.findings}
    assert "workflow-unreachable" in categories
    assert report.unreachable == ("orphan",)
    assert report.passed is True


def test_workflow_flags_unknown_target_and_self_loop() -> None:
    report = audit_workflow({"cart": ["cart", "nowhere"]}, initial="cart", terminal=["paid"])
    categories = {finding.category for finding in report.findings}
    assert "workflow-unknown-target" in categories
    assert "workflow-self-loop" in categories
    assert "workflow-terminal" in categories
    assert report.passed is False


def test_workflow_skips_orphan_island_without_transitions() -> None:
    report = audit_workflow({"start": ["done"], "done": []}, initial="start", terminal=["done"])
    assert report.passed is True
    assert report.unreachable == ()


def test_workflow_dead_end_blocks() -> None:
    report = audit_workflow({"start": ["middle"], "middle": []}, initial="start", terminal=["done"])
    assert "workflow-dead-end" in {finding.category for finding in report.findings}
    assert report.passed is False


def test_workflow_required_state_must_be_reachable() -> None:
    report = audit_workflow(
        {"start": ["done"], "done": []}, initial="start", terminal=["done"], required=["refund"]
    )
    assert any(f.category == "workflow-required" for f in report.findings)


def test_workflow_empty_graph_blocks() -> None:
    report = audit_workflow({}, initial="start")
    assert report.passed is False
    assert report.findings[0].category == "workflow-empty"


DDL = """
CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL);
CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    total REAL NOT NULL,
    created_at TEXT
);
"""


def test_ddl_parsing_extracts_keys_and_money() -> None:
    tables = {table.name: table for table in parse_ddl_tables(DDL)}
    assert tables["users"].primary_key == ("id",)
    assert tables["orders"].foreign_keys == (("user_id", "users", "id"),)
    assert tables["orders"].money_columns == ("total",)


def test_ddl_flags_float_money_and_missing_fk_index() -> None:
    report = audit_ddl(DDL, schema_version=3)
    categories = {finding.category for finding in report.findings}
    assert "db-money-float" in categories
    assert "db-fk-index" in categories
    assert report.passed is False


def test_ddl_clean_schema_passes() -> None:
    ddl = """
    CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL);
    CREATE TABLE orders (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        total_cents INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    """
    report = audit_ddl(ddl, schema_version=4)
    assert report.tables[1].money_columns == ("total_cents",)
    assert report.passed is True


def test_sqlite_audit_detects_orphans_and_float_money(tmp_path: Path) -> None:
    path = tmp_path / "shop.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT);
        CREATE TABLE orders (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), total REAL);
        CREATE TABLE notes (body TEXT);
        INSERT INTO users (id, email) VALUES (1, 'a@example.com');
        INSERT INTO orders (id, user_id, total) VALUES (1, 99, 10.129);
        """
    )
    connection.commit()
    connection.close()
    report = audit_sqlite(path)
    categories = {finding.category for finding in report.findings}
    assert "db-primary-key" in categories
    assert "db-foreign-key" in categories
    assert "db-money-float" in categories
    assert "db-schema-version" in categories
    assert report.passed is False


def test_sqlite_audit_clean_database_passes(tmp_path: Path) -> None:
    path = tmp_path / "clean.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        PRAGMA user_version = 7;
        CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL);
        CREATE TABLE orders (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id),
            total_cents INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX idx_orders_user ON orders(user_id);
        """
    )
    connection.commit()
    connection.close()
    report = audit_sqlite(path)
    assert report.schema_version == 7
    assert report.passed is True


def test_sqlite_audit_missing_file(tmp_path: Path) -> None:
    report = audit_sqlite(tmp_path / "nope.db")
    assert report.passed is False
    assert report.findings[0].category == "db-missing"


def sample(status: int, duration: float) -> LoadSample:
    return LoadSample(index=0, status=status, duration_ms=duration)


def test_evaluate_load_clean_run_passes() -> None:
    config = LoadConfig(url="https://example.com", requests=5, concurrency=2, sla_ms=500)
    report = evaluate_load([sample(200, 120), sample(200, 130), sample(200, 140)], config=config, duration_s=0.4)
    assert report.passed is True
    assert report.error_rate == 0.0
    assert report.latency is not None and report.latency.count == 3


def test_evaluate_load_flags_sla_and_errors() -> None:
    config = LoadConfig(url="https://example.com", requests=4, concurrency=2, sla_ms=100, max_error_rate=0.0)
    samples = [sample(200, 300), sample(500, 320), sample(0, 50), sample(404, 90)]
    report = evaluate_load(samples, config=config, duration_s=1.0)
    categories = {finding.category for finding in report.findings}
    assert "perf-latency-sla" in categories
    assert "perf-error-rate" in categories
    assert "perf-server-error" in categories
    assert report.passed is False


def test_evaluate_load_empty_samples_blocks() -> None:
    config = LoadConfig(url="https://example.com")
    report = evaluate_load([], config=config, duration_s=0.0)
    assert report.passed is False
    assert report.findings[0].category == "perf-no-samples"


def test_load_config_rejects_bad_input() -> None:
    with pytest.raises(ValueError):
        LoadConfig(url="ftp://example.com")
    with pytest.raises(ValueError):
        LoadConfig(url="https://example.com", requests=0)
    with pytest.raises(ValueError):
        LoadConfig(url="https://example.com", method="TRACE")
    config = LoadConfig(url="https://example.com", requests=5000, concurrency=500)
    assert config.bounded_requests == 2000
    assert config.bounded_concurrency == 64


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - http.server contract
        body = b"ok"
        self.send_response(200 if self.path != "/fail" else 500)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        return


@pytest.fixture()
def loopback():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()


def test_live_load_test_against_loopback(loopback: str) -> None:
    config = LoadConfig(url=loopback, requests=4, concurrency=2, sla_ms=5000)
    report = run_load_test(config)
    assert report.passed is True
    assert len(report.samples) == 4
    assert all(sample.status == 200 for sample in report.samples)


def test_live_load_test_preview(loopback: str) -> None:
    report = run_load_test(LoadConfig(url=loopback, requests=10, concurrency=5), preview=True)
    assert len(report.samples) == 1


PROJECT_TREE = {
    "tests/test_alpha.py": (
        "import pytest\n"
        "def test_one():\n    assert True\n"
        "async def test_two():\n    assert True\n"
        "class TestGroup:\n    def test_three(self):\n        assert True\n"
    ),
    "web/app.test.ts": "describe('x', () => { it('renders', () => {}); test('click', () => {}); });\n",
    "src/app.py": "def helper():\n    return 1\n",
}


def build_project(tmp_path: Path) -> Path:
    for relative, content in PROJECT_TREE.items():
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    return tmp_path


def test_discover_tests_counts_python_and_js(tmp_path: Path) -> None:
    inventory = discover_tests(build_project(tmp_path))
    assert inventory.count == 5
    assert inventory.by_language == {"python": 3, "javascript": 2}
    assert inventory.passed is True


def test_discover_tests_reports_syntax_error(tmp_path: Path) -> None:
    (tmp_path / "test_broken.py").write_text("def test_x(:\n", encoding="utf-8")
    inventory = discover_tests(tmp_path)
    assert inventory.count == 0
    assert any(f.category == "test-inventory-parse" for f in inventory.findings)
    assert inventory.passed is False


def test_discover_tests_missing_root(tmp_path: Path) -> None:
    inventory = discover_tests(tmp_path / "none")
    assert inventory.passed is False
    assert inventory.findings[0].category == "test-inventory-path"


def test_rtm_coverage_and_orphans() -> None:
    report = build_rtm(
        [
            {"id": "R1", "title": "login", "tests": ["test_login"]},
            {"id": "R2", "title": "checkout", "tests": ["test_missing"], "risk": 9},
            {"id": "R3", "title": "search"},
        ],
        ["test_login", "test_search", "test_extra"],
        min_coverage=0.9,
    )
    assert report.coverage == pytest.approx(1 / 3)
    assert report.uncovered == ("R2", "R3")
    assert report.orphan_tests == ("test_extra", "test_search")
    assert report.passed is False
    categories = {finding.category for finding in report.findings}
    assert {"rtm-broken-link", "rtm-uncovered", "rtm-orphan-test", "rtm-coverage"} <= categories


def test_rtm_full_coverage_passes() -> None:
    report = build_rtm(["R1", "R2"], ["test_a"], min_coverage=0.5)
    assert report.coverage == 0.0
    assert report.passed is False
    clean = build_rtm([{"id": "R1", "tests": ["test_a"]}], ["test_a"])
    assert clean.coverage == 1.0
    assert clean.passed is True


def test_generate_test_plan_orders_by_risk_and_priority() -> None:
    plan = generate_test_plan(
        [
            {"id": "TC-1", "title": "low", "risk": 1, "tests": ["a"]},
            {"id": "TC-2", "title": "critical", "risk": 9, "priority": "critical", "tests": ["b"]},
            {"id": "TC-3", "title": "high", "risk": 8, "tests": ["c"]},
        ],
        max_items=2,
    )
    assert [item["id"] for item in plan["items"]] == ["TC-2", "TC-3"]
    assert plan["deferred"] == 1
    assert plan["passed"] is True


def test_generate_test_plan_empty_and_bounded_gate() -> None:
    assert generate_test_plan([])["passed"] is False
    plan = generate_test_plan([{"id": "a", "risk": 1, "tests": ["x", "y"]}], max_items=1, coverage_floor=2.0)
    assert plan["passed"] is False
    assert plan["findings"][0]["category"] == "plan-coverage"


def test_parse_junit_failures_and_slowest() -> None:
    xml = (
        '<testsuites><testsuite tests="3" time="2.5">'
        '<testcase classname="a" name="fast" time="0.5"/>'
        '<testcase classname="a" name="slow" time="1.9"><failure/></testcase>'
        '<testcase classname="a" name="skip" time="0.1"><skipped/></testcase>'
        "</testsuite></testsuites>"
    )
    health = parse_junit(xml)
    assert health.tests == 3
    assert health.failures == 1
    assert health.skipped == 1
    assert health.slowest == ("a::slow", 1.9)
    assert health.passed is False


def test_parse_junit_clean_report_passes() -> None:
    health = parse_junit('<testsuite tests="1" time="0.2"><testcase classname="a" name="ok" time="0.2"/></testsuite>')
    assert health.passed is True


def test_parse_junit_malformed_and_empty() -> None:
    assert parse_junit("<testsuite").findings[0].category == "junit-parse"
    assert parse_junit("").findings[0].category == "junit-empty"
    zero = parse_junit("<testsuite/>")
    assert zero.passed is False
    assert zero.findings[0].category == "junit-zero-tests"


def test_parse_junit_high_skip_ratio() -> None:
    xml = '<testsuite tests="5">' + "".join(
        '<testcase classname="a" name="s{}"><skipped/></testcase>'.format(index) for index in range(4)
    ) + '<testcase classname="a" name="ok"/>' + "</testsuite>"
    health = parse_junit(xml)
    assert any(f.category == "junit-skips" for f in health.findings)


def test_parse_junit_file(tmp_path: Path) -> None:
    path = tmp_path / "junit.xml"
    path.write_text('<testsuite tests="1"><testcase name="ok"/></testsuite>', encoding="utf-8")
    assert parse_junit_file(path).tests == 1


# ---------------------------------------------------------------------------
# CLI wrappers
# ---------------------------------------------------------------------------


def test_cli_audit_apk_writes_artifacts(tmp_path: Path) -> None:
    summary = run_audit_apk(build_apk(tmp_path / "app.apk"), tmp_path / "out")
    assert summary["command"] == "audit-apk"
    assert summary["passed"] is False
    assert (tmp_path / "out" / "apk_audit.json").is_file()
    assert (tmp_path / "out" / "audit_report.html").is_file()


def test_cli_audit_pwa_writes_artifacts(tmp_path: Path) -> None:
    build = tmp_path / "pwa"
    build.mkdir()
    (build / "index.html").write_text(PWA_HTML, encoding="utf-8")
    (build / "manifest.webmanifest").write_text(json.dumps(pwa_manifest()), encoding="utf-8")
    (build / "sw.js").write_text(PWA_WORKER, encoding="utf-8")
    summary = run_audit_pwa(str(build), tmp_path / "out")
    assert summary["command"] == "audit-pwa"
    assert summary["passed"] is True
    assert (tmp_path / "out" / "pwa_audit.json").is_file()


def test_cli_test_cli_probes_command(tmp_path: Path) -> None:
    script = tmp_path / "mini.py"
    script.write_text(MINI_CLI, encoding="utf-8")
    summary = run_test_cli([sys.executable, str(script)], tmp_path / "out", version_args=("--version",))
    assert summary["command"] == "test-cli"
    assert summary["passed"] is True
    assert len(summary["runs"]) == 3
    assert (tmp_path / "out" / "cli_audit.json").is_file()


def test_cli_audit_rbac_and_db(tmp_path: Path) -> None:
    matrix = tmp_path / "matrix.json"
    matrix.write_text(json.dumps(RBAC_MATRIX), encoding="utf-8")
    rbac = run_audit_rbac(matrix, tmp_path / "rbac")
    assert rbac["command"] == "audit-rbac"
    assert rbac["passed"] is False
    ddl = tmp_path / "schema.sql"
    ddl.write_text(DDL, encoding="utf-8")
    db = run_audit_db(ddl, tmp_path / "db")
    assert db["command"] == "audit-db"
    assert db["passed"] is False
    with pytest.raises(ValueError):
        run_audit_db(tmp_path / "missing.db", tmp_path / "db2")


def test_cli_load_test_loopback(loopback: str, tmp_path: Path) -> None:
    summary = run_load_test_command(loopback, tmp_path / "load", requests=2, concurrency=1, sla_ms=5000)
    assert summary["command"] == "load-test"
    assert summary["passed"] is True
    assert (tmp_path / "load" / "load_test.json").is_file()


def test_cli_gen_test_plan(tmp_path: Path) -> None:
    root = build_project(tmp_path / "project")
    requirements = tmp_path / "requirements.json"
    requirements.write_text(
        json.dumps([{"id": "R1", "title": "alpha", "tests": ["test_one", "test_two"], "risk": 8}]),
        encoding="utf-8",
    )
    junit = tmp_path / "junit.xml"
    junit.write_text('<testsuite tests="1"><testcase name="test_one"/></testsuite>', encoding="utf-8")
    summary = run_gen_test_plan(
        root, tmp_path / "out", requirements_path=requirements, junit_path=junit, min_coverage=0.5
    )
    assert summary["command"] == "gen-test-plan"
    assert summary["inventory"]["count"] == 5
    assert summary["coverage"] == 1.0
    assert (tmp_path / "out" / "test_plan.json").is_file()
    assert (tmp_path / "out" / "test_plan.md").read_text(encoding="utf-8").startswith("# Risk-Based Test Plan")


def test_cli_gen_test_plan_without_requirements(tmp_path: Path) -> None:
    summary = run_gen_test_plan(build_project(tmp_path / "project"), tmp_path / "out", min_coverage=0.0)
    assert summary["plan"]["total"] >= 1
    assert summary["junit"] is None


def test_default_cli_cases_shape() -> None:
    cases = default_cli_cases(version_args=())
    assert [case.name for case in cases] == ["help", "unknown-flag"]
