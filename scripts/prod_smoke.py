#!/usr/bin/env python3
"""Production smoke: boot the app on Postgres, walk a case end to end.

This is the R16 production-profile proof. It does not use the test
doubles: it starts the real application (uvicorn, production
wiring) with ``DATABASE_URL`` pointing at a fresh, empty database
on the server ``DATABASE_URL`` names, then walks the seeded
structuring case (ALRT-2026-1001) over HTTP through the whole
lifecycle the blueprint exists for:

    intake -> screening (pinned snapshots) -> transaction ingest
    -> typology run -> investigation record -> analyst disposition
    (escalate to SAR) -> SAR draft + citation verification ->
    dual-control approval -> seal -> export -> offline verify

Every step asserts the state it must find; any mismatch is a
failed step and the script exits non-zero. The fresh database is
dropped afterwards, so the smoke is safe to re-run. It also
verifies the export package with the blueprint's own pure offline
verifier (``verify_export_package``) — the same check an examiner
runs without the server — and confirms a sealed case refuses
further mutation over HTTP.

Usage:
    DATABASE_URL=postgresql://postgres@127.0.0.1:5433/aml_parity \
        uv run python scripts/prod_smoke.py

Exit codes: 0 = every step passed; 1 = a step failed;
2 = DATABASE_URL unset (the smoke has nothing to run against).
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

import httpx  # noqa: E402
import psycopg  # noqa: E402

ALERT_ID = "ALRT-2026-1001"
ANALYST = "a.okafor"
APPROVER = "m.osei"
OFFICER = {"officer_id": "o.reyes", "officer_role": "l2_reviewer"}
CUSTOMER_SUBJECT = {
    "subject_ref": "customer:CUST-1001",
    "name": "Daniel Okafor",
    "role": "customer",
    "dob": "1985-03-04",
    "identifiers": ["PP-NG-2210"],
}

_failures: list[str] = []
_passed = 0


def step(name: str, fn) -> object:
    global _passed
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - a smoke reports, never hides
        _failures.append(f"{name}: {exc}")
        print(f"FAIL {name}: {exc}")
        return None
    _passed += 1
    print(f"pass {name}")
    return result


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _swap_dbname(url: str, dbname: str) -> str:
    return url.rsplit("/", 1)[0] + f"/{dbname}"


def main() -> int:
    base_url = os.environ.get("DATABASE_URL") or ""
    if not base_url:
        print("DATABASE_URL is not set — the smoke has no Postgres to run against.")
        return 2

    # The smoke talks only to localhost (the app) and the local
    # Postgres. Proxy variables from the surrounding environment
    # must not reroute — or, where malformed, crash — those calls,
    # so they are dropped for this process and the child server.
    for name in [n for n in os.environ if "proxy" in n.lower()]:
        del os.environ[name]

    smoke_db = f"aml_smoke_{uuid.uuid4().hex[:12]}"
    admin = psycopg.connect(base_url, autocommit=True)
    try:
        admin.execute(
            f'CREATE DATABASE "{smoke_db}" TEMPLATE template0 ENCODING \'UTF8\''
        )
    finally:
        admin.close()
    smoke_url = _swap_dbname(base_url, smoke_db)

    tmp = Path(tempfile.mkdtemp(prefix="aml-prod-smoke-"))
    # A fresh ephemeral port per run: a fixed port lets a leaked
    # server from an earlier run answer a later run's steps.
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = dict(os.environ)
    env.update(
        {
            "DATABASE_URL": smoke_url,
            "OBJECT_STORE_DIR": str(tmp / "evidence-objects"),
            "AML_MODEL_PROFILE": "offline",
            "LOG_LEVEL": "WARNING",
        }
    )
    server_log = tmp / "uvicorn.log"
    with server_log.open("wb") as log:
        server = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "aml_investigations.api:app",
                "--port",
                str(port),
            ],
            cwd=REPO_ROOT,
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
    base = f"http://127.0.0.1:{port}"
    client: httpx.Client | None = None
    try:
        client = httpx.Client(base_url=base, timeout=30.0)

        def wait_ready() -> None:
            deadline = time.time() + 60
            while time.time() < deadline:
                if server.poll() is not None:
                    raise AssertionError(
                        "server exited during boot; log tail: "
                        + server_log.read_text()[-800:]
                    )
                try:
                    if client.get("/health").status_code == 200:
                        return
                except httpx.HTTPError:
                    pass
                time.sleep(0.5)
            raise AssertionError("server did not become healthy in 60s")

        step("boot: app healthy on a fresh Postgres database", wait_ready)

        def readiness() -> None:
            r = client.get("/readiness")
            expect(r.status_code == 200, f"readiness {r.status_code}")
            body = r.json()
            expect(body["ready"] is True, f"not ready: {body}")
            expect(body["case_store"] is True, "case store not pinging")

        step("readiness: Postgres case store + object store ping", readiness)

        case_id = step(
            "intake: seeded structuring alert opens a case",
            lambda: _intake(client),
        )
        if case_id is None:
            return _finish(client, server, base_url, smoke_db)
        step(
            "transition: case moves to assembling",
            lambda: _transition(client, case_id, "assembling"),
        )
        step(
            "screening: reference snapshots ingest from the feed",
            lambda: _expect_status(
                client.post("/screening/snapshots/ingest-feed"), 201
            ),
        )
        step(
            "screening: case screened against pinned sanctions 2026.10.1",
            lambda: _screen(client, case_id),
        )
        step(
            "transactions: account stream ingests from the feed",
            lambda: _expect_status(
                client.post(f"/cases/{case_id}/transactions/ingest-feed"), 201
            ),
        )
        step(
            "typologies: reference rule pack registers",
            lambda: _expect_status(
                client.post("/typologies/rule-packs/register-feed"), 201
            ),
        )
        step(
            "typologies: run finds the planted structuring pattern",
            lambda: _typologies(client, case_id),
        )
        step(
            "transition: case moves to investigating",
            lambda: _transition(client, case_id, "investigating"),
        )
        record = step(
            "investigation: record assembles with cited findings",
            lambda: _investigate(client, case_id),
        )
        step(
            "transition: case moves to awaiting_analyst",
            lambda: _transition(client, case_id, "awaiting_analyst"),
        )
        step(
            "disposition: named analyst escalates to SAR",
            lambda: _dispose(client, case_id, record),
        )
        step(
            "sar: narrative drafts and every statement verifies",
            lambda: _draft(client, case_id),
        )
        step(
            "sar: citation verifier re-run stands verified",
            lambda: _verify(client, case_id),
        )
        step(
            "approval: a second person approves (dual control)",
            lambda: _approve(client, case_id),
        )
        step("seal: compliance officer seals the case file", lambda: _seal(client, case_id))
        package = step(
            "export: sealed case file exports as a package",
            lambda: _export(client, case_id),
        )
        step(
            "export: offline verifier accepts the package",
            lambda: _verify_export_offline(package),
        )
        step(
            "seal posture: a sealed case refuses mutation (409)",
            lambda: _sealed_mutation_refused(client, case_id),
        )
    finally:
        if client is not None:
            client.close()
        _stop_server(server)
    return _finish(None, None, base_url, smoke_db)


def _stop_server(server: subprocess.Popen) -> None:
    """Terminate, then kill, then prove the server is gone.

    A smoke that leaks its server poisons the next run (the leaked
    server keeps answering on its port from its own database), so
    shutdown is verified, not assumed.
    """
    if server.poll() is not None:
        return
    server.terminate()
    try:
        server.wait(timeout=10)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=10)
    if server.poll() is None:  # pragma: no cover - last-resort guard
        raise RuntimeError("smoke server did not stop")


def _finish(client, server, base_url: str, smoke_db: str) -> int:
    admin = psycopg.connect(base_url, autocommit=True)
    try:
        dropped = False
        for _attempt in range(3):
            admin.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity"
                " WHERE datname = %s AND pid <> pg_backend_pid()",
                (smoke_db,),
            )
            try:
                admin.execute(f'DROP DATABASE IF EXISTS "{smoke_db}"')
                dropped = True
                break
            except psycopg.errors.ObjectInUse:
                time.sleep(1)
        if not dropped:
            _failures.append(f"cleanup: smoke database {smoke_db} not dropped")
    finally:
        admin.close()
    total = _passed + len(_failures)
    print(f"SMOKE: {_passed}/{total} steps passed")
    if _failures:
        for failure in _failures:
            print(f"  failed: {failure}")
        return 1
    return 0


def _expect_status(response: httpx.Response, status: int) -> dict:
    expect(
        response.status_code == status,
        f"expected {status}, got {response.status_code}: {response.text[:300]}",
    )
    return response.json()


def _intake(client: httpx.Client) -> str:
    body = _expect_status(
        client.post("/alerts/intake", json={"alert_id": ALERT_ID}), 201
    )
    case_id = body["case_id"]
    expect(bool(case_id), "intake returned no case_id")
    case = _expect_status(client.get(f"/cases/{case_id}"), 200)
    expect(case["status"] == "opened", f"case status {case['status']}")
    return case_id


def _transition(client: httpx.Client, case_id: str, target: str) -> None:
    body = _expect_status(
        client.post(
            f"/cases/{case_id}/transitions",
            json={"target": target, "actor": "prod-smoke"},
        ),
        200,
    )
    expect(body["status"] == target, f"status {body['status']} != {target}")


def _screen(client: httpx.Client, case_id: str) -> None:
    body = _expect_status(
        client.post(
            f"/cases/{case_id}/screening",
            json={
                "pins": {"sanctions": "2026.10.1"},
                "actor": "prod-smoke",
                "subjects": [CUSTOMER_SUBJECT],
            },
        ),
        201,
    )
    pins = {p["list_kind"]: p["version"] for p in body["run"]["pins"]}
    expect(
        pins.get("sanctions") == "2026.10.1",
        f"screening pins {pins} do not pin sanctions 2026.10.1",
    )


def _typologies(client: httpx.Client, case_id: str) -> None:
    body = _expect_status(
        client.post(
            f"/cases/{case_id}/typologies/run",
            json={
                "pack_id": "harborline-typologies",
                "version": "2026.10.1",
                "actor": "prod-smoke",
            },
        ),
        201,
    )
    findings = body["findings"]
    expect(len(findings) >= 1, "typology run produced no findings")
    typologies = [f.get("typology_id") for f in findings]
    expect(
        "structuring" in typologies,
        f"no structuring finding among {typologies}",
    )


def _investigate(client: httpx.Client, case_id: str) -> dict:
    record = _expect_status(
        client.post(
            f"/cases/{case_id}/investigation/run", json={"actor": "prod-smoke"}
        ),
        201,
    )
    expect(bool(record["record_id"]), "record has no id")
    expect(
        len(record.get("findings", [])) >= 1, "record carries no findings"
    )
    return record


def _dispose(client: httpx.Client, case_id: str, record: dict | None) -> None:
    expect(record is not None, "no investigation record to cite")
    body = _expect_status(
        client.post(
            f"/cases/{case_id}/disposition",
            json={
                "analyst_id": ANALYST,
                "analyst_role": "analyst",
                "outcome": "escalate_sar",
                "rationale_codes": ["STRUCTURING_SUSPECTED"],
                "record_id": record["record_id"],
                "record_version": record["version"],
            },
        ),
        201,
    )
    expect(
        body["case_status"] == "sar_pending",
        f"case status {body['case_status']} != sar_pending",
    )


def _draft(client: httpx.Client, case_id: str) -> None:
    body = _expect_status(client.post(f"/cases/{case_id}/sar/draft", json={}), 201)
    expect(
        body["narrative"]["status"] == "verified",
        f"narrative status {body['narrative']['status']}",
    )
    expect(
        body["verification"]["all_verified"] is True,
        "not every narrative statement verified against its citation",
    )


def _verify(client: httpx.Client, case_id: str) -> None:
    body = _expect_status(client.post(f"/cases/{case_id}/sar/verify"), 201)
    expect(body["narrative_status"] == "verified", "verifier re-run not verified")
    expect(body["verification"]["all_verified"] is True, "statements unverified")


def _approve(client: httpx.Client, case_id: str) -> None:
    body = _expect_status(
        client.post(
            f"/cases/{case_id}/sar/approve",
            json={
                "approver_id": APPROVER,
                "approver_role": "senior_analyst",
                "outcome": "approved",
            },
        ),
        201,
    )
    expect(
        body["case_status"] == "filed_sar",
        f"case status {body['case_status']} != filed_sar",
    )


def _seal(client: httpx.Client, case_id: str) -> None:
    body = _expect_status(client.post(f"/cases/{case_id}/seal", json=OFFICER), 201)
    seal = body["seal"]
    expect(seal["operative"] is True, "seal is not operative")
    expect(len(seal["manifest"]["items"]) >= 1, "seal manifest certifies no items")


def _export(client: httpx.Client, case_id: str) -> dict:
    package = _expect_status(client.get(f"/cases/{case_id}/export"), 200)
    expect(
        package["format"] == "harborline-case-file-export/1",
        f"export format {package['format']}",
    )
    body = _expect_status(
        client.post("/cases/export/verify", json={"package": package}), 200
    )
    expect(body["verification"]["ok"] is True, "server-side export verify failed")
    return package


def _verify_export_offline(package: dict | None) -> None:
    expect(package is not None, "no export package to verify")
    from aml_investigations.sealing import verify_export_package

    result = verify_export_package(package)
    expect(result.ok is True, f"offline verify problems: {result.problems}")


def _sealed_mutation_refused(client: httpx.Client, case_id: str) -> None:
    import base64

    response = client.post(
        f"/cases/{case_id}/evidence",
        json={
            "kind": "analyst_note",
            "content_base64": base64.b64encode(b"late").decode("ascii"),
            "source_ref": "prod-smoke",
            "captured_by": "prod-smoke",
        },
    )
    expect(
        response.status_code == 409,
        f"sealed mutation returned {response.status_code}, expected 409",
    )


if __name__ == "__main__":
    raise SystemExit(main())
