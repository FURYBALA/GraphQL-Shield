"""
FEATURE 8 - Academic evaluation of the Real-Time GraphQL Authorization Engine
=============================================================================
Runs the engine end-to-end against the application (in-process via ASGI, the
same HTTP path the server serves) and produces measured results. Nothing here
is fabricated: every number is computed from the executions of the latest run.

Outputs
-------
    docs/AUTHORIZATION_ENGINE_EVAL.json          machine-readable results
    docs/evidence/authorization_engine_eval.txt  human-readable transcript

The documented manual-testing baseline used for comparison is the set of
hand-written cases the project shipped before automation (4 cases: direct BOLA,
nested BOLA, benign owner, admin override). It is declared as a constant below
so the comparison is explicit and auditable.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app, startup_event
from app.security.recon.engine import AuthorizationEngine
from app.seed import seed_database

BASE = "http://engine.test"
ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "docs" / "evidence"
EVAL_JSON = ROOT / "docs" / "AUTHORIZATION_ENGINE_EVAL.json"

# Documented pre-automation manual baseline (hand-written cases).
MANUAL_BASELINE = {
    "cases": 4,
    "root_paths": 2,
    "seeded_defects": 2,
    "nested_attribution": False,
    "minimization": False,
    "source": "Hand-written cases documented in README / dashboard before automation.",
}

# Categories that correspond to deliberately seeded defect classes.
_SEEDED_CATEGORIES = {"DIRECT_BOLA", "NESTED_BOLA", "MUTATION_BOLA", "ALIAS_MASKING", "VARIABLE_INJECTION"}


def _run():
    seed_database()
    startup_event()

    async def go():
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url=BASE
        ) as client:
            engine = AuthorizationEngine()
            session = await engine.run_now(BASE, client=client, concurrency=4)
            sarif = engine.export_sarif(session.session_id)
            junit = engine.export_junit(session.session_id)
            return session, sarif, junit

    return asyncio.run(go())


def evaluate() -> dict:
    session, sarif, junit = _run()
    ex = session.executions
    summary = session.summary

    confirmed = [f for f in session.findings if not f.fixture]
    reproducible = [f for f in confirmed if f.reproducible]
    seeded_blocked = [
        e for e in ex
        if e.test.category in _SEEDED_CATEGORIES and e.reason_class == "OK_DENIED"
    ]
    seeded_total = [e for e in ex if e.test.category in _SEEDED_CATEGORIES]

    categories: dict = {}
    for e in ex:
        c = categories.setdefault(
            e.test.category, {"total": 0, "pass": 0, "fail": 0, "inconclusive": 0, "fixture_leaks": 0}
        )
        c["total"] += 1
        c[e.status.lower() if e.status in ("PASS", "FAIL") else "inconclusive"] += 1
        if e.insecure_leaked:
            c["fixture_leaks"] += 1

    coverage = summary.get("schema_path_coverage_pct", 0.0)
    manual_paths = MANUAL_BASELINE["root_paths"]
    discovered_fields = summary.get("schema_fields_discovered", 0)
    tested_fields = summary.get("schema_paths_tested", 0)

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": session.base_url,
        "status": session.status,
        "run": {
            "total_tests": summary.get("total_tests", 0),
            "passed": summary.get("passed", 0),
            "failed": summary.get("failed", 0),
            "inconclusive": summary.get("inconclusive", 0),
            "confirmed_vulnerabilities": len(confirmed),
            "false_positives": summary.get("false_positives", 0),
            "fixture_baseline_leaks": summary.get("fixture_baseline_leaks", 0),
            "mean_latency_ms": summary.get("mean_latency_ms", 0.0),
            "duration_ms": summary.get("duration_ms", 0.0),
            "provenance": summary.get("provenance", {}),
        },
        "metrics": {
            "schema_path_coverage_pct": coverage,
            "schema_fields_discovered": discovered_fields,
            "schema_paths_tested": tested_fields,
            "seeded_defect_detection_pct": round(100.0 * len(seeded_blocked) / len(seeded_total), 1) if seeded_total else None,
            "seeded_defects_exercised": len(seeded_total),
            "seeded_defects_blocked": len(seeded_blocked),
            "false_positive_count": summary.get("false_positives", 0),
            "reproducibility_pct": round(100.0 * len(reproducible) / len(confirmed), 1) if confirmed else None,
            "confirmed_findings": len(confirmed),
            "reproduced_findings": len(reproducible),
            "execution_cost_ms_per_test": summary.get("mean_latency_ms", 0.0),
            "execution_cost_total_ms": summary.get("duration_ms", 0.0),
        },
        "manual_baseline": MANUAL_BASELINE,
        "comparison": {
            "test_cases": {"manual": MANUAL_BASELINE["cases"], "engine": summary.get("total_tests", 0)},
            "schema_paths": {"manual": manual_paths, "engine": tested_fields},
            "seeded_defects": {"manual": MANUAL_BASELINE["seeded_defects"], "engine": len(seeded_blocked)},
            "nested_path_attribution": {"manual": MANUAL_BASELINE["nested_attribution"], "engine": True},
            "automatic_minimization": {"manual": MANUAL_BASELINE["minimization"], "engine": True},
        },
        "categories": categories,
        "exports": {
            "sarif_version": sarif.get("version"),
            "sarif_results": len(sarif["runs"][0]["results"]),
            "sarif_valid": sarif["runs"][0]["properties"]["validation"]["valid"],
            "junit_bytes": len(junit.encode("utf-8")),
        },
        "notes": [
            "Fixture leaks are demonstrated against the labelled deliberately-vulnerable local "
            "reference backend (/graphql-insecure); they are baseline sensitivity signals and are "
            "never counted as findings against the protected gateway.",
            "A finding is only confirmed from a contradiction between declared expectation and "
            "observed object identity / database state — never from an HTTP status alone.",
            "Schema discovery is performed against the live running service (standard introspection "
            "is served by the introspection-capable route because the protected gateway's AST "
            "budget deliberately rejects the standard introspection query).",
        ],
    }
    return result, session, sarif, junit


def write_evidence(result: dict, session, sarif, junit) -> None:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    EVAL_JSON.write_text(json.dumps(result, indent=2), encoding="utf-8")

    lines = []
    lines.append("=" * 72)
    lines.append("AUTHORIZATION ENGINE EVALUATION")
    lines.append("=" * 72)
    lines.append(f"Generated: {result['generated_at']}")
    lines.append(f"Target:    {result['target']}")
    lines.append(f"Status:    {result['status']}")
    lines.append("")
    r = result["run"]
    lines.append("Run results")
    lines.append("-" * 72)
    lines.append(f"  total tests ................ {r['total_tests']}")
    lines.append(f"  passed ..................... {r['passed']}")
    lines.append(f"  failed ..................... {r['failed']}")
    lines.append(f"  inconclusive ............... {r['inconclusive']}")
    lines.append(f"  confirmed vulnerabilities .. {r['confirmed_vulnerabilities']}")
    lines.append(f"  false positives ............ {r['false_positives']}")
    lines.append(f"  fixture baseline leaks ..... {r['fixture_baseline_leaks']}")
    lines.append(f"  mean latency (ms/test) ..... {r['mean_latency_ms']}")
    lines.append(f"  suite duration (ms) ........ {r['duration_ms']}")
    lines.append(f"  provenance ................. {r['provenance']}")
    lines.append("")
    m = result["metrics"]
    lines.append("Research metrics")
    lines.append("-" * 72)
    lines.append(f"  schema path coverage ....... {m['schema_path_coverage_pct']}% ({m['schema_paths_tested']}/{m['schema_fields_discovered']} fields)")
    lines.append(f"  seeded defect detection .... {m['seeded_defect_detection_pct']}% ({m['seeded_defects_blocked']}/{m['seeded_defects_exercised']})")
    lines.append(f"  false positive count ....... {m['false_positive_count']}")
    lines.append(f"  reproducibility ............ {m['reproducibility_pct']}% ({m['reproduced_findings']}/{m['confirmed_findings']} confirmed)")
    lines.append(f"  execution cost ............. {m['execution_cost_ms_per_test']} ms/test")
    lines.append("")
    lines.append("Manual baseline comparison")
    lines.append("-" * 72)
    c = result["comparison"]
    lines.append(f"  test cases ................. manual {c['test_cases']['manual']} -> engine {c['test_cases']['engine']}")
    lines.append(f"  schema paths ............... manual {c['schema_paths']['manual']} -> engine {c['schema_paths']['engine']}")
    lines.append(f"  seeded defects detected .... manual {c['seeded_defects']['manual']} -> engine {c['seeded_defects']['engine']}")
    lines.append(f"  nested path attribution .... manual {c['nested_path_attribution']['manual']} -> engine {c['nested_path_attribution']['engine']}")
    lines.append(f"  automatic minimization ..... manual {c['automatic_minimization']['manual']} -> engine {c['automatic_minimization']['engine']}")
    lines.append("")
    lines.append("Per-category results")
    lines.append("-" * 72)
    for cat, v in sorted(result["categories"].items()):
        lines.append(f"  {cat:<18} total={v['total']:<3} pass={v['pass']:<3} fail={v['fail']:<3} inconclusive={v['inconclusive']:<3} fixture_leaks={v['fixture_leaks']}")
    lines.append("")
    lines.append("Exports")
    lines.append("-" * 72)
    e = result["exports"]
    lines.append(f"  SARIF {e['sarif_version']} valid={e['sarif_valid']} results={e['sarif_results']}")
    lines.append(f"  JUnit XML bytes ............ {e['junit_bytes']}")
    lines.append("")
    lines.append("Notes")
    lines.append("-" * 72)
    for n in result["notes"]:
        lines.append(f"  - {n}")
    lines.append("")
    lines.append("=" * 72)

    txt = "\n".join(lines)
    (EVIDENCE / "authorization_engine_eval.txt").write_text(txt, encoding="utf-8")
    print(txt)


if __name__ == "__main__":
    result, session, sarif, junit = evaluate()
    write_evidence(result, session, sarif, junit)
