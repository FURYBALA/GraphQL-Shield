"""
Generates the Schema-Aware Ownership Inference report.

Every number in the report is produced by analyzing the real Strawberry schema
at call time -- nothing is hard-coded.

Usage:
    python scripts/generate_inference_report.py               # write ownership_inference_report.json
    python scripts/generate_inference_report.py --stdout      # print only
"""

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def build_report() -> dict:
    """Analyze the real application schema and return the report as a dict."""
    from app.graphql.schema import schema
    from app.security.ownership_inference import OwnershipInferenceEngine

    engine = OwnershipInferenceEngine()
    report = engine.build_from_strawberry_schema(schema)

    return {
        "summary": {
            "graphql_types_analyzed": report.types_analyzed,
            "candidate_relationships_detected": report.relationships_detected,
            "accepted_rules": len(report.rules),
            "high_confidence_rules": report.high_confidence,
            "medium_confidence_rules": report.medium_confidence,
            "low_confidence_rules": report.low_confidence,
            "rejected_or_ambiguous_relationships": len(report.rejected),
            "analysis_time_ms": report.analysis_time_ms,
        },
        "analyzed_types": report.analyzed_types,
        "accepted_rules": [r.to_dict() for r in report.rules],
        "rejected_or_ambiguous": [r.to_dict() for r in report.rejected],
        "priority": [
            "1. Explicit configured authorization / ownership rule",
            "2. Validated schema-inferred ownership rule",
            "3. UNKNOWN OWNERSHIP -> explicit policy required -> DENY",
        ],
        "source": "app.graphql.schema (analyzed at report generation time)",
    }


def main() -> None:
    report = build_report()
    s = report["summary"]

    print("[Schema Ownership Inference Report]")
    print(f"  GraphQL types analyzed:               {s['graphql_types_analyzed']}")
    print(f"  Ownership relationships detected:      {s['candidate_relationships_detected']}")
    print(f"  High-confidence rules:                 {s['high_confidence_rules']}")
    print(f"  Medium-confidence rules:               {s['medium_confidence_rules']}")
    print(f"  Ambiguous/rejected relationships:      {s['rejected_or_ambiguous_relationships']}")
    print(f"  Analysis time:                         {s['analysis_time_ms']}ms")
    print("\n  Accepted rules:")
    for rule in report["accepted_rules"]:
        print(f"    {rule['source_type']}.{rule['source_field']} -> {rule['target_type']}"
              f"  [{rule['confidence']}] ({rule['pattern']})")
        print(f"      reason: {rule['reason']}")
    if report["rejected_or_ambiguous"]:
        print("\n  Rejected / ambiguous:")
        for item in report["rejected_or_ambiguous"]:
            print(f"    {item['source_type']}.{item['source_field']}"
                  f" [{item['category']}]: {item['reason']}")

    if "--stdout" not in sys.argv:
        out_path = os.path.join(os.path.dirname(__file__), "..", "ownership_inference_report.json")
        out_path = os.path.abspath(out_path)
        with open(out_path, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=True)
        print(f"\n  Written to: {out_path}")


if __name__ == "__main__":
    main()
