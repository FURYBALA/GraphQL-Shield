"""
FEATURE 3 + FEATURE 4 - Real HTTP Execution & Differential Oracle (observation)
===============================================================================
Executes generated tests through the *actual HTTP interface* of a running
application (protected gateway ``/graphql`` and the deliberately vulnerable
local fixture ``/graphql-insecure``), with bounded concurrency and cooperative
cancellation.

A vulnerability is never asserted from an HTTP status alone:

  * query leaks are confirmed by inspecting the returned object identity
    (requested object id / owner id) versus the declared expectation;
  * mutation leaks are confirmed by reading the resulting database state.

Results are classified PASS / FAIL / INCONCLUSIVE. Leaks observed on the
labelled vulnerable fixture are kept separate from findings against the
protected gateway.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

import httpx

from app.core.security import create_access_token
from app.database import get_db_connection
from app.security.recon.models import Finding, GeneratedTest, TestExecution
from app.security.recon.oracle import extract_first_object, object_owner

FIXTURE_PATH = "/graphql-insecure"
GATEWAY_PATH = "/graphql"


@dataclass
class HttpObservation:
    status: Optional[int]
    payload: Optional[Dict[str, Any]]
    text: str = ""
    duration_ms: float = 0.0
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status is not None and self.error is None


class _Determine:
    """Small helper to read the gateway's declared decision from a response."""

    @staticmethod
    def gateway(raw: HttpObservation) -> tuple[Optional[str], Optional[str], Optional[str]]:
        if raw.error:
            return None, None, None
        if raw.status == 200:
            data = (raw.payload or {}).get("data")
            if data and not (raw.payload or {}).get("errors"):
                return "ALLOW", "PERMITTED", None
            return "ALLOW", "PERMITTED_WITH_ERRORS", None
        detail = (raw.payload or {}).get("detail")
        if isinstance(detail, dict):
            return (
                detail.get("decision", "DENY"),
                detail.get("reason", "POLICY_REJECTION"),
                detail.get("risk_level"),
            )
        return "DENY", "AUTHENTICATION_REQUIRED" if raw.status in (401, 403) else "POLICY_REJECTION", None


class LiveExecutor:
    """Executes tests over real HTTP against a running target."""

    def __init__(
        self,
        base_url: str,
        client: Optional[httpx.AsyncClient] = None,
        concurrency: int = 4,
        timeout: float = 15.0,
    ):
        self.base_url = base_url.rstrip("/")
        self._external_client = client
        self.semaphore = asyncio.Semaphore(max(1, min(concurrency, 16)))
        self.timeout = timeout
        self._mutation_lock = asyncio.Lock()

    async def _client_scope(self):
        if self._external_client is not None:
            return self._external_client, False
        return httpx.AsyncClient(timeout=httpx.Timeout(self.timeout)), True

    def _headers(self, caller_id: Optional[int], role: str) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if caller_id is not None and role != "anonymous":
            headers["Authorization"] = f"Bearer {create_access_token(user_id=caller_id, role=role)}"
        return headers

    async def _post(self, client: httpx.AsyncClient, path: str, payload: Dict[str, Any], headers: Dict[str, str]) -> HttpObservation:
        start = time.perf_counter()
        try:
            resp = await client.post(f"{self.base_url}{path}", json=payload, headers=headers)
            try:
                body = resp.json()
            except Exception:
                body = None
            return HttpObservation(
                status=resp.status_code,
                payload=body,
                text=resp.text,
                duration_ms=round((time.perf_counter() - start) * 1000, 2),
            )
        except Exception as exc:
            return HttpObservation(
                status=None,
                payload=None,
                error=f"{type(exc).__name__}: {exc}",
                duration_ms=round((time.perf_counter() - start) * 1000, 2),
            )

    # -- DB state helpers for mutation verification ------------------------
    def _snapshot(self, object_id: Optional[int]) -> Optional[Dict[str, Any]]:
        if object_id is None:
            return None
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, owner_id, object_type, parent_id FROM objects WHERE id = ?", (object_id,))
            row = cursor.fetchone()
            conn.close()
            return dict(row) if row else None
        except Exception:
            return None

    def _restore(self, snapshot: Dict[str, Any]) -> None:
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM objects WHERE id = ?", (snapshot["id"],))
            if cursor.fetchone():
                cursor.execute(
                    "UPDATE objects SET name = ?, owner_id = ?, object_type = ?, parent_id = ? WHERE id = ?",
                    (snapshot["name"], snapshot["owner_id"], snapshot["object_type"], snapshot["parent_id"], snapshot["id"]),
                )
            else:
                cursor.execute(
                    "INSERT INTO objects (id, name, owner_id, object_type, parent_id) VALUES (?, ?, ?, ?, ?)",
                    (snapshot["id"], snapshot["name"], snapshot["owner_id"], snapshot["object_type"], snapshot["parent_id"]),
                )
            conn.commit()
            conn.close()
        except Exception as exc:
            print(f"[ENGINE] state restore failed: {exc}")

    # -- main execution ----------------------------------------------------
    async def execute(self, test: GeneratedTest, cancel_check: Optional[Callable[[], bool]] = None) -> TestExecution:
        async with self.semaphore:
            if cancel_check and cancel_check():
                return TestExecution(test=test, status="INCONCLUSIVE", reason_class="CANCELLED", error="cancelled")
            return await self._execute_inner(test, cancel_check)

    async def _execute_inner(self, test: GeneratedTest, cancel_check: Optional[Callable[[], bool]]) -> TestExecution:
        headers = self._headers(test.caller_id, test.caller_role)
        payload: Dict[str, Any] = {"query": test.query, "variables": test.variables}
        if test.operation_name:
            payload["operationName"] = test.operation_name

        start = time.perf_counter()
        client, should_close = await self._client_scope()
        try:
            if test.is_mutation:
                return await self._execute_mutation(client, test, headers, payload, start)
            return await self._execute_query(client, test, headers, payload, start)
        finally:
            if should_close:
                await client.aclose()

    async def _execute_query(self, client, test, headers, payload, start) -> TestExecution:
        gw = await self._post(client, GATEWAY_PATH, payload, headers)
        fixture = await self._post(client, FIXTURE_PATH, payload, headers)
        gw_decision, gw_reason, gw_risk = _Determine.gateway(gw)
        gw_obj = extract_first_object(gw.payload) if gw.status == 200 else None
        fx_obj = extract_first_object(fixture.payload) if fixture.status == 200 else None

        fixture_leaked = False
        fixture_detail = ""
        if test.expected_decision == "DENY" and fixture.status == 200 and fx_obj is not None:
            owner = object_owner(fx_obj)
            if test.caller_id is None or owner is None or owner != test.caller_id:
                fixture_leaked = True
                fixture_detail = (
                    f"fixture returned object id={fx_obj.get('id')} owner={owner} "
                    f"to caller {test.caller_id}"
                )

        status, reason_class, detail, finding = self._classify_query(
            test, gw, gw_decision, gw_reason, gw_obj, fixture_leaked
        )
        duration = round((time.perf_counter() - start) * 1000, 2)
        return TestExecution(
            test=test,
            status=status,
            reason_class=reason_class,
            gateway_http_status=gw.status,
            gateway_decision=gw_decision,
            gateway_reason=gw_reason,
            gateway_risk_level=gw_risk,
            gateway_returned_object=gw_obj,
            gateway_error=gw.error,
            insecure_http_status=fixture.status,
            insecure_returned_object=fx_obj,
            insecure_leaked=fixture_leaked,
            duration_ms=duration,
            verdict_detail=detail + (f" | fixture leak: {fixture_detail}" if fixture_detail else ""),
            error=gw.error,
            finding=finding,
        )

    def _classify_query(self, test, gw, gw_decision, gw_reason, gw_obj, fixture_leaked):
        if gw.error or gw.status is None:
            return "INCONCLUSIVE", "ERROR", f"gateway request failed: {gw.error}", None

        if test.expected_decision == "ALLOW":
            if gw_decision == "ALLOW":
                return "PASS", "OK_ALLOWED", f"legitimate access permitted ({gw_reason})", None
            return (
                "FAIL",
                "ORACLE_FALSE_POSITIVE",
                f"legitimate access denied ({gw_reason}) — possible false positive",
                Finding(
                    test_id=test.test_id,
                    severity="medium",
                    title=f"False positive: legitimate access denied ({test.schema_path})",
                    schema_path=test.schema_path,
                    category="ORACLE_FALSE_POSITIVE",
                    query=test.query,
                    variables=test.variables,
                    caller_id=test.caller_id,
                    caller_role=test.caller_role,
                    target_object_type=test.target_object_type,
                    target_object_id=test.target_object_id,
                    expected=f"ALLOW ({test.expected_reason})",
                    observed=f"{gw_decision} ({gw_reason}) HTTP {gw.status}",
                    evidence="Protected gateway denied a request the policy oracle declared legitimate.",
                    fixture=False,
                    reproducible=True,
                ),
            )

        # expected DENY
        if gw_decision == "DENY" or gw.status in (401, 403):
            return "PASS", "OK_DENIED", f"unauthorized access correctly denied ({gw_reason})", None

        if gw_decision == "ALLOW" and gw_obj is not None:
            owner = object_owner(gw_obj)
            legit = owner is not None and test.caller_id is not None and owner == test.caller_id
            if legit:
                return "INCONCLUSIVE", "AMBIGUOUS", "gateway allowed, but returned object belongs to caller", None
            return (
                "FAIL",
                "CONFIRMED_VULNERABILITY",
                f"gateway returned object id={gw_obj.get('id')} owner={owner} to caller {test.caller_id}",
                Finding(
                    test_id=test.test_id,
                    severity="high",
                    title=f"Confirmed BOLA: {test.category} on {test.schema_path}",
                    schema_path=test.schema_path,
                    category=test.category,
                    query=test.query,
                    variables=test.variables,
                    caller_id=test.caller_id,
                    caller_role=test.caller_role,
                    target_object_type=test.target_object_type,
                    target_object_id=test.target_object_id,
                    expected=f"DENY ({test.expected_reason})",
                    observed=f"ALLOW HTTP {gw.status}; returned id={gw_obj.get('id')} owner={owner}",
                    evidence=(
                        f"Protected gateway returned resource belonging to {owner} to caller {test.caller_id}. "
                        "Confirmed by inspecting the returned object identity, not the HTTP status."
                    ),
                    fixture=False,
                    reproducible=True,
                ),
            )

        return "INCONCLUSIVE", "AMBIGUOUS", f"gateway response ambiguous (HTTP {gw.status})", None

    async def _execute_mutation(self, client, test, headers, payload, start) -> TestExecution:
        async with self._mutation_lock:
            snapshot = self._snapshot(test.target_object_id)
            try:
                gw = await self._post(client, GATEWAY_PATH, payload, headers)
                after_gateway = self._snapshot(test.target_object_id)
                gateway_changed = self._changed(snapshot, after_gateway)

                fixture = await self._post(client, FIXTURE_PATH, payload, headers)
                after_fixture = self._snapshot(test.target_object_id)
                fixture_changed = self._changed(snapshot, after_fixture)
            finally:
                if snapshot is not None:
                    self._restore(snapshot)

            gw_decision, gw_reason, gw_risk = _Determine.gateway(gw)
            gw_obj = extract_first_object(gw.payload) if gw.status == 200 else None
            fixture_leaked = (
                test.expected_decision == "DENY"
                and fixture.status == 200
                and bool(fixture_changed)
            )

            status, reason_class, detail, finding = self._classify_mutation(
                test, gw, gw_decision, gw_reason, gateway_changed
            )
            duration = round((time.perf_counter() - start) * 1000, 2)
            return TestExecution(
                test=test,
                status=status,
                reason_class=reason_class,
                gateway_http_status=gw.status,
                gateway_decision=gw_decision,
                gateway_reason=gw_reason,
                gateway_risk_level=gw_risk,
                gateway_returned_object=gw_obj,
                gateway_error=gw.error,
                insecure_http_status=fixture.status,
                insecure_returned_object=extract_first_object(fixture.payload) if fixture.status == 200 else None,
                insecure_leaked=fixture_leaked,
                insecure_state_changed=fixture_changed,
                state_changed=gateway_changed,
                duration_ms=duration,
                verdict_detail=detail,
                error=gw.error,
                finding=finding,
            )

    def _changed(self, before: Optional[Dict[str, Any]], after: Optional[Dict[str, Any]]) -> bool:
        if before is None and after is None:
            return False
        if before is None or after is None:
            return True
        return any(before.get(k) != after.get(k) for k in ("name", "owner_id", "object_type", "parent_id"))

    def _classify_mutation(self, test, gw, gw_decision, gw_reason, gateway_changed):
        if gw.error or gw.status is None:
            return "INCONCLUSIVE", "ERROR", f"gateway request failed: {gw.error}", None

        if test.expected_decision == "ALLOW":
            if gw_decision == "ALLOW" and gateway_changed:
                return "PASS", "OK_ALLOWED", "legitimate owner mutation applied as expected", None
            if gw_decision == "ALLOW" and not gateway_changed:
                return "INCONCLUSIVE", "AMBIGUOUS", "mutation allowed but observed state did not change", None
            return "FAIL", "ORACLE_FALSE_POSITIVE", f"legitimate mutation denied ({gw_reason})", Finding(
                test_id=test.test_id, severity="medium",
                title=f"False positive: legitimate mutation denied ({test.schema_path})",
                schema_path=test.schema_path, category="ORACLE_FALSE_POSITIVE", query=test.query,
                variables=test.variables, caller_id=test.caller_id, caller_role=test.caller_role,
                target_object_type=test.target_object_type, target_object_id=test.target_object_id,
                expected="ALLOW", observed=f"{gw_decision} ({gw_reason})", evidence="Legitimate owner mutation was denied.",
                fixture=False, reproducible=True,
            )

        if gw_decision == "DENY" or gw.status in (401, 403):
            if gateway_changed:
                return "FAIL", "CONFIRMED_VULNERABILITY", "gateway denied but state changed", Finding(
                    test_id=test.test_id, severity="high",
                    title=f"Confirmed unauthorized state change: {test.category} on {test.schema_path}",
                    schema_path=test.schema_path, category=test.category, query=test.query,
                    variables=test.variables, caller_id=test.caller_id, caller_role=test.caller_role,
                    target_object_type=test.target_object_type, target_object_id=test.target_object_id,
                    expected=f"DENY ({test.expected_reason})", observed="state changed despite DENY",
                    evidence="Database state changed even though the gateway returned a denial.",
                    fixture=False, reproducible=True,
                )
            return "PASS", "OK_DENIED", "unauthorized mutation correctly denied (no state change)", None

        if gateway_changed:
            return "FAIL", "CONFIRMED_VULNERABILITY", "unauthorized mutation modified state", Finding(
                test_id=test.test_id, severity="high",
                title=f"Confirmed BOLA state change: {test.category} on {test.schema_path}",
                schema_path=test.schema_path, category=test.category, query=test.query,
                variables=test.variables, caller_id=test.caller_id, caller_role=test.caller_role,
                target_object_type=test.target_object_type, target_object_id=test.target_object_id,
                expected=f"DENY ({test.expected_reason})", observed="unauthorized state change applied",
                evidence="Database state changed after an unauthorized mutation.",
                fixture=False, reproducible=True,
            )
        return "INCONCLUSIVE", "AMBIGUOUS", "mutation response ambiguous", None

    # -- lightweight probe used by the reproducer --------------------------
    async def probe(
        self,
        query: str,
        variables: Optional[Dict[str, Any]],
        caller_id: Optional[int],
        role: str,
        *,
        is_mutation: bool = False,
        target_object_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        headers = self._headers(caller_id, role)
        payload: Dict[str, Any] = {"query": query, "variables": variables or {}}
        client, should_close = await self._client_scope()
        try:
            if is_mutation:
                snapshot = self._snapshot(target_object_id)
                try:
                    gw = await self._post(client, GATEWAY_PATH, payload, headers)
                    after = self._snapshot(target_object_id)
                    changed = self._changed(snapshot, after)
                finally:
                    if snapshot is not None:
                        self._restore(snapshot)
                decision, reason, _ = _Determine.gateway(gw)
                return {
                    "gateway_status": gw.status,
                    "gateway_decision": decision,
                    "gateway_reason": reason,
                    "state_changed": changed,
                    "error": gw.error,
                }
            gw = await self._post(client, GATEWAY_PATH, payload, headers)
            fixture = await self._post(client, FIXTURE_PATH, payload, headers)
            decision, reason, _ = _Determine.gateway(gw)
            gw_obj = extract_first_object(gw.payload) if gw.status == 200 else None
            fx_obj = extract_first_object(fixture.payload) if fixture.status == 200 else None
            return {
                "gateway_status": gw.status,
                "gateway_decision": decision,
                "gateway_reason": reason,
                "gateway_object": gw_obj,
                "fixture_status": fixture.status,
                "fixture_object": fx_obj,
                "error": gw.error,
            }
        finally:
            if should_close:
                await client.aclose()
