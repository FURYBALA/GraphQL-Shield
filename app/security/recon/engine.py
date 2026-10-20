"""
Authorization Research Engine - orchestration
=============================================
Drives the full vertical slice:

    Discover Schema -> Generate Tests -> Run Tests -> Inspect Finding
                    -> Reproduce -> Export

Maintains in-memory run sessions (progress + cancellation) and reuses the
gateway, ownership inference, AST minimizer and exporters already in the repo.
"""

from __future__ import annotations

import asyncio
import datetime
import time
import uuid
from typing import Any, Dict, List, Optional

import httpx

from app.config import settings
from app.core.security import create_access_token

from app.security.recon import engine_exporters
from app.security.recon.executor import LiveExecutor
from app.security.recon.generator import load_fixture, generate_tests_from_discovery
from app.security.recon.introspection import discover_live
from app.security.recon.models import DiscoveryResult, Finding, RunState, TestExecution
from app.security.recon.reproducer import Reproducer, make_predicate


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def default_base_url() -> str:
    return getattr(settings, "ENGINE_BASE_URL", "http://127.0.0.1:8000")


class AuthorizationEngine:
    def __init__(self) -> None:
        self._sessions: Dict[str, RunState] = {}
        self._tasks: Dict[str, asyncio.Task] = {}

    # -- session lifecycle -------------------------------------------------
    def _new_session(self, base_url: str, concurrency: int) -> RunState:
        sid = uuid.uuid4().hex[:12]
        session = RunState(
            session_id=sid,
            status="pending",
            base_url=base_url,
            concurrency=concurrency,
            started_at=_utcnow(),
        )
        self._sessions[sid] = session
        return session

    async def start_run(
        self,
        base_url: Optional[str] = None,
        *,
        concurrency: int = 4,
        schema_file: Optional[str] = None,
        token: Optional[str] = None,
        client: Optional[httpx.AsyncClient] = None,
        categories: Optional[List[str]] = None,
        minimize: bool = True,
        reproduce: bool = True,
    ) -> RunState:
        session = self._new_session(base_url or default_base_url(), concurrency)
        task = asyncio.create_task(
            self._run(session, concurrency, schema_file, token, client, categories, minimize, reproduce)
        )
        self._tasks[session.session_id] = task
        return session

    async def run_now(
        self,
        base_url: Optional[str] = None,
        *,
        concurrency: int = 4,
        schema_file: Optional[str] = None,
        token: Optional[str] = None,
        client: Optional[httpx.AsyncClient] = None,
        categories: Optional[List[str]] = None,
        minimize: bool = True,
        reproduce: bool = True,
    ) -> RunState:
        session = self._new_session(base_url or default_base_url(), concurrency)
        await self._run(session, concurrency, schema_file, token, client, categories, minimize, reproduce)
        return session

    def get(self, session_id: str) -> Optional[RunState]:
        return self._sessions.get(session_id)

    def list_sessions(self) -> List[Dict[str, Any]]:
        return [
            {
                "session_id": s.session_id,
                "status": s.status,
                "total": s.total,
                "completed": s.completed,
                "findings": len(s.findings),
                "started_at": s.started_at,
                "finished_at": s.finished_at,
                "base_url": s.base_url,
            }
            for s in self._sessions.values()
        ]

    def get(self, session_id: str) -> Optional[RunState]:
        return self._sessions.get(session_id) or self._sessions.get(session_id.lower())

    def cancel(self, session_id: str) -> bool:
        session = self.get(session_id)
        if not session:
            return False
        session.cancel_requested = True
        session.status = "cancelling"
        task = self._tasks.get(session.session_id)
        if task and not task.done():
            task.cancel()
        return True

    # -- the run -----------------------------------------------------------
    async def _run(
        self,
        session: RunState,
        concurrency: int,
        schema_file: Optional[str],
        token: Optional[str],
        client: Optional[httpx.AsyncClient],
        categories: Optional[List[str]],
        minimize: bool,
        reproduce: bool,
    ) -> None:
        owns_client = client is None
        if owns_client:
            client = httpx.AsyncClient(timeout=httpx.Timeout(20.0))
        session.status = "running"
        start = time.perf_counter()
        try:
            fixture, _ = load_fixture()
            admin_id = fixture.admin_id() or 103
            discovery_token = token or create_access_token(user_id=admin_id, role="admin")

            try:
                discovery = await discover_live(
                    session.base_url, client, token=discovery_token, schema_file=schema_file
                )
            except Exception as exc:
                session.status = "failed"
                session.error = f"Schema reconnaissance failed: {exc}"
                session.finished_at = _utcnow()
                return
            session.discovery = discovery

            tests = generate_tests_from_discovery(discovery)
            if categories:
                wanted = {c.upper() for c in categories}
                tests = [t for t in tests if t.category.upper() in wanted]
            session.total = len(tests)

            executor = LiveExecutor(session.base_url, client=client, concurrency=concurrency)
            cancel_check = lambda: session.cancel_requested

            async def _one(test) -> TestExecution:
                result = await executor.execute(test, cancel_check=cancel_check)
                session.completed += 1
                session.current = test.test_id
                session.executions.append(result)
                return result

            results = await asyncio.gather(*[_one(t) for t in tests], return_exceptions=True)
            session.executions.sort(key=lambda e: e.test.test_id)

            findings: List[Finding] = []
            for result in results:
                if isinstance(result, TestExecution) and result.finding is not None:
                    findings.append(result.finding)

            if reproduce and not session.cancel_requested:
                reproducer = Reproducer(executor)
                by_id = {e.test.test_id: e for e in session.executions}
                for finding in findings:
                    if finding.fixture:
                        continue
                    execution = by_id.get(finding.test_id)
                    if execution is None:
                        continue
                    test = execution.test
                    try:
                        still = await reproducer.validate(test)
                        finding.reproducible = bool(still)
                        predicate = make_predicate(test, execution)
                        minimized, attempts, improved = await reproducer.minimize(
                            test, predicate, max_attempts=12 if minimize else 0
                        )
                        if improved and minimized:
                            finding.minimized_query = minimized
                        else:
                            finding.minimized_query = test.query
                        finding.repro_reexecuted = True
                    except Exception as exc:
                        finding.repro_reexecuted = False
                        finding.minimized_query = finding.minimized_query or test.query
                        print(f"[ENGINE] reproduction error for {finding.test_id}: {exc}")

            session.findings = findings
            duration_ms = round((time.perf_counter() - start) * 1000, 2)
            session.summary = self._summarize(session, discovery, duration_ms)
            if session.cancel_requested:
                session.status = "cancelled"
            else:
                session.status = "completed"
        except asyncio.CancelledError:
            session.status = "cancelled"
            session.summary = self._summarize(session, session.discovery, round((time.perf_counter() - start) * 1000, 2))
        except Exception as exc:
            session.status = "failed"
            session.error = f"{type(exc).__name__}: {exc}"
        finally:
            session.finished_at = _utcnow()
            if owns_client and client is not None:
                await client.aclose()

    def _summarize(self, session: RunState, discovery: Optional[DiscoveryResult], duration_ms: float) -> Dict[str, Any]:
        executions = session.executions
        passed = sum(1 for e in executions if e.status == "PASS")
        failed = sum(1 for e in executions if e.status == "FAIL")
        inconclusive = sum(1 for e in executions if e.status == "INCONCLUSIVE")
        confirmed = [f for f in session.findings if not f.fixture]
        false_positives = [f for f in session.findings if f.category == "ORACLE_FALSE_POSITIVE"]
        fixture_leaks = sum(1 for e in executions if e.insecure_leaked)
        covered = len({e.test.schema_path for e in executions})
        total_fields = len(discovery.fields) if discovery else 0
        coverage = round((covered / total_fields) * 100.0, 1) if total_fields else 0.0
        provenance: Dict[str, int] = {}
        for e in executions:
            provenance[e.test.provenance] = provenance.get(e.test.provenance, 0) + 1
        mean_latency = round(sum(e.duration_ms for e in executions) / len(executions), 2) if executions else 0.0
        return {
            "total_tests": len(executions),
            "passed": passed,
            "failed": failed,
            "inconclusive": inconclusive,
            "confirmed_vulnerabilities": len(confirmed),
            "false_positives": len(false_positives),
            "fixture_baseline_leaks": fixture_leaks,
            "schema_fields_discovered": total_fields,
            "schema_paths_tested": covered,
            "schema_path_coverage_pct": coverage,
            "mean_latency_ms": mean_latency,
            "duration_ms": duration_ms,
            "provenance": provenance,
        }

    # -- exports -----------------------------------------------------------
    def export_sarif(self, session_id: str) -> Dict[str, Any]:
        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        data = engine_exporters.export_sarif(session.executions)
        ok, errors = engine_exporters.validate_sarif(data)
        data["runs"][0]["properties"]["validation"] = {"valid": ok, "errors": errors}
        return data

    def export_junit(self, session_id: str) -> str:
        session = self.get(session_id)
        if not session:
            raise KeyError(session_id)
        return engine_exporters.export_junit(session.executions)


ENGINE = AuthorizationEngine()


async def run_engine_blocking(base_url: str, **kwargs) -> RunState:
    return await ENGINE.run_now(base_url, **kwargs)
