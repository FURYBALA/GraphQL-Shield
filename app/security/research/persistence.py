"""
CCNS Research Lab - SQLite Persistence Layer
============================================
Handles schema definition, initial seeding of ground-truth benchmark corpus,
dataset management, manual label review history, experiment recording,
per-case prediction tracing, and ablation result storage.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from app.database import get_db_connection
from app.security.research.models import (
    AddCaseRequest,
    CaseReviewRequest,
    CoverageBreakdown,
    DatasetMetadata,
    TestCaseRecord,
)

logger = logging.getLogger(__name__)

CORPUS_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "ground_truth_corpus.json")
CORPUS_V2_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "generalization_corpus_v2.json")


def init_research_db() -> None:
    """Creates the research tables in the database if they do not exist."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        # 1. Datasets metadata table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS research_datasets (
                id TEXT PRIMARY KEY,
                version TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT,
                source_file TEXT,
                total_cases INTEGER DEFAULT 0,
                valid_security_cases INTEGER DEFAULT 0,
                malformed_syntax_cases INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # 2. Test cases table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS research_cases (
                id TEXT PRIMARY KEY,
                dataset_id TEXT NOT NULL,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                syntax_type TEXT DEFAULT 'BASIC',
                caller_user_id INTEGER,
                caller_role TEXT DEFAULT 'user',
                query TEXT NOT NULL,
                variables_json TEXT DEFAULT '{}',
                operation_name TEXT,
                target_object_id INTEGER,
                target_object_type TEXT DEFAULT 'Resource',
                true_owner_id INTEGER,
                ground_truth_security TEXT NOT NULL,
                ground_truth_attack_type TEXT,
                expected_gateway_decision TEXT DEFAULT 'DENY',
                rationale TEXT,
                provenance TEXT DEFAULT 'constructed_benchmark',
                split TEXT DEFAULT 'tuning',
                expected_paths_json TEXT DEFAULT '[]',
                is_excluded INTEGER DEFAULT 0,
                exclusion_reason TEXT,
                version INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(dataset_id) REFERENCES research_datasets(id)
            )
        """)

        # Migrations for existing database schemas: safe column additions
        try:
            cursor.execute("ALTER TABLE research_cases ADD COLUMN split TEXT DEFAULT 'tuning'")
        except Exception:
            pass
        try:
            cursor.execute("ALTER TABLE research_cases ADD COLUMN expected_paths_json TEXT DEFAULT '[]'")
        except Exception:
            pass
        try:
            cursor.execute("ALTER TABLE research_cases ADD COLUMN caller_tenant_id TEXT")
        except Exception:
            pass
        try:
            cursor.execute("ALTER TABLE research_cases ADD COLUMN target_tenant_id TEXT")
        except Exception:
            pass

        # 3. Label review history table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS research_case_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                previous_security TEXT NOT NULL,
                new_security TEXT NOT NULL,
                previous_attack_type TEXT,
                new_attack_type TEXT,
                reviewer TEXT NOT NULL,
                review_rationale TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(case_id) REFERENCES research_cases(id)
            )
        """)

        # 4. Experiments manifest table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS research_experiments (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                dataset_id TEXT NOT NULL,
                dataset_version TEXT NOT NULL,
                status TEXT NOT NULL,
                manifest_json TEXT NOT NULL,
                started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                completed_at DATETIME,
                FOREIGN KEY(dataset_id) REFERENCES research_datasets(id)
            )
        """)

        # 5. Method run results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS research_method_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                experiment_id TEXT NOT NULL,
                method_id TEXT NOT NULL,
                method_name TEXT NOT NULL,
                method_version TEXT NOT NULL,
                metrics_json TEXT NOT NULL,
                confusion_matrix_json TEXT NOT NULL,
                execution_time_ms REAL DEFAULT 0.0,
                FOREIGN KEY(experiment_id) REFERENCES research_experiments(id)
            )
        """)

        # 6. Per-case predictions and evidence table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS research_predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                experiment_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                method_id TEXT NOT NULL,
                predicted_security TEXT NOT NULL,
                predicted_attack_type TEXT,
                is_conclusive INTEGER DEFAULT 1,
                inconclusive_reason TEXT,
                classification_outcome TEXT NOT NULL,
                execution_id TEXT,
                evidence_json TEXT NOT NULL,
                FOREIGN KEY(experiment_id) REFERENCES research_experiments(id),
                FOREIGN KEY(case_id) REFERENCES research_cases(id)
            )
        """)

        # 7. Ablation comparisons table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS research_ablations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                experiment_id TEXT NOT NULL,
                ablation_id TEXT NOT NULL,
                ablation_name TEXT NOT NULL,
                baseline_method_id TEXT NOT NULL,
                ablated_method_id TEXT NOT NULL,
                result_json TEXT NOT NULL,
                FOREIGN KEY(experiment_id) REFERENCES research_experiments(id)
            )
        """)

        conn.commit()
        logger.info("Research Lab SQLite schemas initialized successfully.")
    finally:
        conn.close()

    # Seed baseline corpus if not already seeded
    seed_benchmark_dataset_if_empty()
    seed_generalization_dataset_if_empty()


def seed_benchmark_dataset_if_empty() -> None:
    """Seeds the benchmark dataset from data/ground_truth_corpus.json if not present."""
    norm_path = os.path.normpath(CORPUS_PATH)
    if not os.path.exists(norm_path):
        logger.warning(f"Corpus file not found at {norm_path}, skipping seed.")
        return

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as cnt FROM research_datasets WHERE id = 'ds_benchmark_v1'")
        row = cursor.fetchone()
        if row and row["cnt"] > 0:
            return  # Already seeded

        with open(norm_path, "r", encoding="utf-8") as f:
            corpus_data = json.load(f)

        total_cases = len(corpus_data)
        malformed_count = sum(1 for c in corpus_data if c.get("syntax_type") == "MALFORMED" or c.get("ground_truth_security") == "MALFORMED")
        valid_count = total_cases - malformed_count

        cursor.execute("""
            INSERT INTO research_datasets (id, version, name, description, source_file, total_cases, valid_security_cases, malformed_syntax_cases)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "ds_benchmark_v1",
            "1.0.0",
            "CCNS GraphQL BOLA Benchmark Corpus v1.0",
            "Standard 115-case ground-truth evaluation corpus covering direct, nested, mutation, and alias BOLA scenarios.",
            "data/ground_truth_corpus.json",
            total_cases,
            valid_count,
            malformed_count
        ))

        for c in corpus_data:
            c_id = c["id"]
            name = c.get("name", c_id)
            category = c.get("category", "GENERAL")
            syntax_type = c.get("syntax_type", "BASIC")
            caller = c.get("caller", {})
            caller_user_id = caller.get("user_id")
            caller_role = caller.get("role", "user")
            query = c.get("query", "")
            variables = json.dumps(c.get("variables", {}))
            op_name = c.get("operation_name")
            target_obj_id = c.get("target_object_id")
            target_obj_type = c.get("target_object_type", "Resource")
            true_owner_id = c.get("true_owner_id")
            gt_sec = c.get("ground_truth_security", "BENIGN")
            gt_atk = c.get("ground_truth_attack_type", "NONE")
            exp_dec = c.get("expected_gateway_decision", "DENY")
            rationale = c.get("rationale", "")
            is_malformed = (syntax_type == "MALFORMED" or gt_sec == "MALFORMED")

            cursor.execute("""
                INSERT OR REPLACE INTO research_cases (
                    id, dataset_id, name, category, syntax_type, caller_user_id, caller_role,
                    query, variables_json, operation_name, target_object_id, target_object_type,
                    true_owner_id, ground_truth_security, ground_truth_attack_type,
                    expected_gateway_decision, rationale, provenance, is_excluded, exclusion_reason, version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                c_id,
                "ds_benchmark_v1",
                name,
                category,
                syntax_type,
                caller_user_id,
                caller_role,
                query,
                variables,
                op_name,
                target_obj_id,
                target_obj_type,
                true_owner_id,
                gt_sec,
                gt_atk,
                exp_dec,
                rationale,
                "constructed_benchmark",
                1 if is_malformed else 0,
                "Syntax malformed / invalid query structure" if is_malformed else None,
                1
            ))

        conn.commit()
        logger.info(f"Seeded {total_cases} benchmark cases into research_cases for ds_benchmark_v1.")
    finally:
        conn.close()


def seed_generalization_dataset_if_empty() -> None:
    """Seeds the v2 generalization & adversarial benchmark from data/generalization_corpus_v2.json if not present."""
    norm_path = os.path.normpath(CORPUS_V2_PATH)
    if not os.path.exists(norm_path):
        logger.warning(f"Corpus v2 file not found at {norm_path}, skipping seed.")
        return

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as cnt FROM research_datasets WHERE id = 'ds_generalization_v2'")
        row = cursor.fetchone()
        if row and row["cnt"] > 0:
            return  # Already seeded

        with open(norm_path, "r", encoding="utf-8") as f:
            corpus_data = json.load(f)

        total_cases = len(corpus_data)
        malformed_count = sum(1 for c in corpus_data if c.get("syntax_type") == "MALFORMED" or c.get("ground_truth_security") == "MALFORMED")
        valid_count = total_cases - malformed_count

        cursor.execute("""
            INSERT INTO research_datasets (id, version, name, description, source_file, total_cases, valid_security_cases, malformed_syntax_cases)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            "ds_generalization_v2",
            "2.0.0",
            "CCNS GraphQL BOLA Generalization & Adversarial Benchmark v2.0",
            "Versioned adversarial evaluation corpus testing multi-tenant isolation, nested traversals, aliases, fragments, variables, edge cases, and mutation state verification.",
            "data/generalization_corpus_v2.json",
            total_cases,
            valid_count,
            malformed_count
        ))

        for c in corpus_data:
            c_id = c["id"]
            name = c.get("name", c_id)
            category = c.get("category", "GENERAL")
            syntax_type = c.get("syntax_type", "BASIC")
            split = c.get("split", "tuning")
            caller = c.get("caller", {})
            caller_user_id = caller.get("user_id")
            caller_role = caller.get("role", "user")
            query = c.get("query", "")
            variables = json.dumps(c.get("variables", {}))
            op_name = c.get("operation_name")
            target_obj_id = c.get("target_object_id")
            target_obj_type = c.get("target_object_type", "Resource")
            true_owner_id = c.get("true_owner_id")
            expected_paths = json.dumps(c.get("expected_paths", []))
            gt_sec = c.get("ground_truth_security", "BENIGN")
            gt_atk = c.get("ground_truth_attack_type", "NONE")
            exp_dec = c.get("expected_gateway_decision", "DENY")
            rationale = c.get("rationale", "")
            caller_tenant = caller.get("tenant_id") or caller.get("tenant")
            target_tenant = c.get("target_tenant_id") or c.get("target_tenant")
            is_malformed = (syntax_type == "MALFORMED" or gt_sec == "MALFORMED")

            cursor.execute("""
                INSERT OR REPLACE INTO research_cases (
                    id, dataset_id, name, category, syntax_type, split, caller_user_id, caller_role,
                    caller_tenant_id, target_tenant_id, query, variables_json, operation_name, target_object_id, target_object_type,
                    true_owner_id, expected_paths_json, ground_truth_security, ground_truth_attack_type,
                    expected_gateway_decision, rationale, provenance, is_excluded, exclusion_reason, version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                c_id,
                "ds_generalization_v2",
                name,
                category,
                syntax_type,
                split,
                caller_user_id,
                caller_role,
                caller_tenant,
                target_tenant,
                query,
                variables,
                op_name,
                target_obj_id,
                target_obj_type,
                true_owner_id,
                expected_paths,
                gt_sec,
                gt_atk,
                exp_dec,
                rationale,
                "generalization_corpus_v2",
                1 if is_malformed else 0,
                "Syntax malformed / invalid query structure" if is_malformed else None,
                1
            ))

        conn.commit()
        logger.info(f"Seeded {total_cases} benchmark cases into research_cases for ds_generalization_v2.")
    finally:
        conn.close()


def get_all_datasets() -> List[DatasetMetadata]:
    """Retrieves all registered datasets."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM research_datasets ORDER BY created_at DESC")
        rows = cursor.fetchall()
        datasets = []
        for r in rows:
            datasets.append(DatasetMetadata(
                id=r["id"],
                version=r["version"],
                name=r["name"],
                description=r["description"] or "",
                source_file=r["source_file"] or "",
                total_cases=r["total_cases"],
                valid_security_cases=r["valid_security_cases"],
                malformed_syntax_cases=r["malformed_syntax_cases"],
                created_at=str(r["created_at"]) if r["created_at"] else None
            ))
        return datasets
    finally:
        conn.close()


def get_dataset_cases(dataset_id: str, include_excluded: bool = True) -> List[TestCaseRecord]:
    """Retrieves test cases belonging to a dataset."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if include_excluded:
            cursor.execute("SELECT * FROM research_cases WHERE dataset_id = ? ORDER BY id ASC", (dataset_id,))
        else:
            cursor.execute("SELECT * FROM research_cases WHERE dataset_id = ? AND is_excluded = 0 ORDER BY id ASC", (dataset_id,))
        rows = cursor.fetchall()
        cases = []
        for r in rows:
            vars_dict = json.loads(r["variables_json"]) if r["variables_json"] else {}
            col_keys = r.keys()
            split_val = r["split"] if "split" in col_keys and r["split"] else "tuning"
            exp_paths = json.loads(r["expected_paths_json"]) if "expected_paths_json" in col_keys and r["expected_paths_json"] else []

            caller_tenant = r["caller_tenant_id"] if "caller_tenant_id" in col_keys else None
            target_tenant = r["target_tenant_id"] if "target_tenant_id" in col_keys else None

            cases.append(TestCaseRecord(
                id=r["id"],
                dataset_id=r["dataset_id"],
                name=r["name"],
                category=r["category"],
                syntax_type=r["syntax_type"] or "BASIC",
                split=split_val,
                caller_user_id=r["caller_user_id"],
                caller_role=r["caller_role"] or "user",
                caller_tenant_id=caller_tenant,
                query=r["query"],
                variables=vars_dict,
                operation_name=r["operation_name"],
                target_object_id=r["target_object_id"],
                target_object_type=r["target_object_type"] or "Resource",
                true_owner_id=r["true_owner_id"],
                target_tenant_id=target_tenant,
                expected_paths=exp_paths,
                ground_truth_security=r["ground_truth_security"],
                ground_truth_attack_type=r["ground_truth_attack_type"],
                expected_gateway_decision=r["expected_gateway_decision"] or "DENY",
                rationale=r["rationale"] or "",
                provenance=r["provenance"] or "constructed_benchmark",
                is_excluded=bool(r["is_excluded"]),
                exclusion_reason=r["exclusion_reason"],
                version=r["version"],
                created_at=str(r["created_at"]) if r["created_at"] else None
            ))
        return cases
    finally:
        conn.close()


def review_case_label(case_id: str, review: CaseReviewRequest) -> Optional[TestCaseRecord]:
    """Applies a manual review/correction to a case's ground-truth label and records audit history."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM research_cases WHERE id = ?", (case_id,))
        row = cursor.fetchone()
        if not row:
            return None

        prev_sec = row["ground_truth_security"]
        prev_atk = row["ground_truth_attack_type"]
        new_version = row["version"] + 1

        # Record review history
        cursor.execute("""
            INSERT INTO research_case_reviews (
                case_id, previous_security, new_security, previous_attack_type, new_attack_type, reviewer, review_rationale
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            case_id,
            prev_sec,
            review.new_security,
            prev_atk,
            review.new_attack_type,
            review.reviewer,
            review.review_rationale
        ))

        # Update case
        cursor.execute("""
            UPDATE research_cases
            SET ground_truth_security = ?,
                ground_truth_attack_type = COALESCE(?, ground_truth_attack_type),
                version = ?
            WHERE id = ?
        """, (review.new_security, review.new_attack_type, new_version, case_id))

        conn.commit()

        # Update dataset counts
        dataset_id = row["dataset_id"]
        update_dataset_counts(dataset_id)

        # Return updated record
        cursor.execute("SELECT * FROM research_cases WHERE id = ?", (case_id,))
        updated_row = cursor.fetchone()
        vars_dict = json.loads(updated_row["variables_json"]) if updated_row["variables_json"] else {}
        col_keys = updated_row.keys()
        split_val = updated_row["split"] if "split" in col_keys and updated_row["split"] else "tuning"
        exp_paths = json.loads(updated_row["expected_paths_json"]) if "expected_paths_json" in col_keys and updated_row["expected_paths_json"] else []

        caller_tenant = updated_row["caller_tenant_id"] if "caller_tenant_id" in col_keys else None
        target_tenant = updated_row["target_tenant_id"] if "target_tenant_id" in col_keys else None

        return TestCaseRecord(
            id=updated_row["id"],
            dataset_id=updated_row["dataset_id"],
            name=updated_row["name"],
            category=updated_row["category"],
            syntax_type=updated_row["syntax_type"] or "BASIC",
            split=split_val,
            caller_user_id=updated_row["caller_user_id"],
            caller_role=updated_row["caller_role"] or "user",
            caller_tenant_id=caller_tenant,
            query=updated_row["query"],
            variables=vars_dict,
            operation_name=updated_row["operation_name"],
            target_object_id=updated_row["target_object_id"],
            target_object_type=updated_row["target_object_type"] or "Resource",
            true_owner_id=updated_row["true_owner_id"],
            target_tenant_id=target_tenant,
            expected_paths=exp_paths,
            ground_truth_security=updated_row["ground_truth_security"],
            ground_truth_attack_type=updated_row["ground_truth_attack_type"],
            expected_gateway_decision=updated_row["expected_gateway_decision"] or "DENY",
            rationale=updated_row["rationale"] or "",
            provenance=updated_row["provenance"] or "constructed_benchmark",
            is_excluded=bool(updated_row["is_excluded"]),
            exclusion_reason=updated_row["exclusion_reason"],
            version=updated_row["version"],
            created_at=str(updated_row["created_at"]) if updated_row["created_at"] else None
        )
    finally:
        conn.close()


def add_custom_case(dataset_id: str, req: AddCaseRequest) -> TestCaseRecord:
    """Adds a new authorized local test case to a dataset with provenance tracking."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        # Find next available ID
        cursor.execute("SELECT id FROM research_cases WHERE dataset_id = ? ORDER BY id DESC", (dataset_id,))
        rows = cursor.fetchall()
        existing_ids = [r["id"] for r in rows]
        idx = len(existing_ids) + 1
        new_id = f"CASE-{dataset_id}-{idx:04d}"
        while new_id in existing_ids:
            idx += 1
            new_id = f"CASE-{dataset_id}-{idx:04d}"

        is_malformed = (req.syntax_type == "MALFORMED" or req.ground_truth_security == "MALFORMED")

        cursor.execute("""
            INSERT INTO research_cases (
                id, dataset_id, name, category, syntax_type, split, caller_user_id, caller_role,
                query, variables_json, operation_name, target_object_id, target_object_type,
                true_owner_id, expected_paths_json, ground_truth_security, ground_truth_attack_type,
                expected_gateway_decision, rationale, provenance, is_excluded, exclusion_reason, version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            new_id,
            dataset_id,
            req.name,
            req.category,
            req.syntax_type,
            req.split,
            req.caller_user_id,
            req.caller_role,
            req.query,
            json.dumps(req.variables),
            req.operation_name,
            req.target_object_id,
            req.target_object_type,
            req.true_owner_id,
            json.dumps(req.expected_paths),
            req.ground_truth_security,
            req.ground_truth_attack_type,
            req.expected_gateway_decision,
            req.rationale,
            req.provenance,
            1 if is_malformed else 0,
            "Syntax malformed / invalid query structure" if is_malformed else None,
            1
        ))

        conn.commit()
        update_dataset_counts(dataset_id)

        return TestCaseRecord(
            id=new_id,
            dataset_id=dataset_id,
            name=req.name,
            category=req.category,
            syntax_type=req.syntax_type,
            split=req.split,
            caller_user_id=req.caller_user_id,
            caller_role=req.caller_role,
            caller_tenant_id=req.caller_tenant_id,
            query=req.query,
            variables=req.variables,
            operation_name=req.operation_name,
            target_object_id=req.target_object_id,
            target_object_type=req.target_object_type,
            true_owner_id=req.true_owner_id,
            target_tenant_id=req.target_tenant_id,
            expected_paths=req.expected_paths,
            ground_truth_security=req.ground_truth_security,
            ground_truth_attack_type=req.ground_truth_attack_type,
            expected_gateway_decision=req.expected_gateway_decision,
            rationale=req.rationale,
            provenance=req.provenance,
            is_excluded=is_malformed,
            exclusion_reason="Syntax malformed / invalid query structure" if is_malformed else None,
            version=1,
            created_at=datetime.now(timezone.utc).isoformat()
        )
    finally:
        conn.close()


def get_dataset_coverage(dataset_id: str) -> CoverageBreakdown:
    """Computes scenario coverage breakdown, split distribution, and verifies zero cross-split leakage."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM research_datasets WHERE id = ?", (dataset_id,))
        ds = cursor.fetchone()
        if not ds:
            raise ValueError(f"Dataset {dataset_id} not found")

        cursor.execute("SELECT * FROM research_cases WHERE dataset_id = ?", (dataset_id,))
        rows = cursor.fetchall()

        by_split: Dict[str, int] = {}
        by_category: Dict[str, int] = {}
        by_security: Dict[str, int] = {}
        by_syntax: Dict[str, int] = {}

        split_queries: Dict[str, set] = {}

        for r in rows:
            col_keys = r.keys()
            sp = r["split"] if "split" in col_keys and r["split"] else "tuning"
            cat = r["category"] or "UNKNOWN"
            sec = r["ground_truth_security"] or "UNKNOWN"
            syn = r["syntax_type"] or "BASIC"

            by_split[sp] = by_split.get(sp, 0) + 1
            by_category[cat] = by_category.get(cat, 0) + 1
            by_security[sec] = by_security.get(sec, 0) + 1
            by_syntax[syn] = by_syntax.get(syn, 0) + 1

            if sp not in split_queries:
                split_queries[sp] = set()
            q_clean = " ".join(r["query"].split()).lower()
            if q_clean:
                split_queries[sp].add(q_clean)

        tuning_queries = split_queries.get("tuning", set())
        held_out_queries = split_queries.get("held_out", set())
        overlap = tuning_queries.intersection(held_out_queries)
        leakage_free = (len(overlap) == 0)

        return CoverageBreakdown(
            dataset_id=ds["id"],
            dataset_version=ds["version"],
            total_cases=ds["total_cases"],
            valid_security_cases=ds["valid_security_cases"],
            malformed_syntax_cases=ds["malformed_syntax_cases"],
            by_split=by_split,
            by_category=by_category,
            by_security=by_security,
            by_syntax=by_syntax,
            leakage_free=leakage_free,
            splits_disjoint=leakage_free,
            unsupported_features_limitations=[
                "Polymorphic interfaces and union types (e.g. Node interface or SearchResult union) are not currently defined in the Strawberry schema.",
                "External slug-based or opaque ID lookups: schema strictly resolves integer primary keys."
            ]
        )
    finally:
        conn.close()



def update_dataset_counts(dataset_id: str) -> None:
    """Recalculates total, valid, and malformed case counts for a dataset."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as total FROM research_cases WHERE dataset_id = ?", (dataset_id,))
        total = cursor.fetchone()["total"]
        cursor.execute("""
            SELECT COUNT(*) as malformed FROM research_cases
            WHERE dataset_id = ? AND (syntax_type = 'MALFORMED' OR ground_truth_security = 'MALFORMED' OR is_excluded = 1)
        """, (dataset_id,))
        malformed = cursor.fetchone()["malformed"]
        valid = total - malformed

        cursor.execute("""
            UPDATE research_datasets
            SET total_cases = ?, valid_security_cases = ?, malformed_syntax_cases = ?
            WHERE id = ?
        """, (total, valid, malformed, dataset_id))
        conn.commit()
    finally:
        conn.close()


def get_case_review_history(case_id: str) -> List[Dict[str, Any]]:
    """Retrieves the review audit history for a case."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM research_case_reviews WHERE case_id = ? ORDER BY created_at DESC", (case_id,))
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def save_experiment_run(
    exp_id: str,
    name: str,
    description: str,
    dataset_id: str,
    dataset_version: str,
    manifest: Dict[str, Any],
    method_runs: List[Dict[str, Any]],
    predictions: List[Dict[str, Any]],
    ablations: List[Dict[str, Any]],
    started_at: str,
    completed_at: str,
) -> None:
    """Persists a complete evaluation experiment with manifest, method results, per-case predictions, and ablations."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        # 1. Insert experiment
        cursor.execute("""
            INSERT INTO research_experiments (
                id, name, description, dataset_id, dataset_version, status, manifest_json, started_at, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            exp_id,
            name,
            description,
            dataset_id,
            dataset_version,
            "COMPLETED",
            json.dumps(manifest),
            started_at,
            completed_at
        ))

        # 2. Insert method runs
        for mr in method_runs:
            cursor.execute("""
                INSERT INTO research_method_runs (
                    experiment_id, method_id, method_name, method_version, metrics_json, confusion_matrix_json, execution_time_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                exp_id,
                mr["method_id"],
                mr["method_name"],
                mr["method_version"],
                json.dumps(mr["metrics"]),
                json.dumps(mr["confusion_matrix"]),
                mr.get("execution_time_ms", 0.0)
            ))

        # 3. Insert predictions (batch insert for efficiency)
        pred_records = []
        for p in predictions:
            pred_records.append((
                exp_id,
                p["case_id"],
                p["method_id"],
                p["predicted_security"],
                p.get("predicted_attack_type"),
                1 if p.get("is_conclusive", True) else 0,
                p.get("inconclusive_reason"),
                p["classification_outcome"],
                p.get("execution_id"),
                json.dumps(p.get("evidence", {}))
            ))

        cursor.executemany("""
            INSERT INTO research_predictions (
                experiment_id, case_id, method_id, predicted_security, predicted_attack_type,
                is_conclusive, inconclusive_reason, classification_outcome, execution_id, evidence_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, pred_records)

        # 4. Insert ablations
        for ab in ablations:
            cursor.execute("""
                INSERT INTO research_ablations (
                    experiment_id, ablation_id, ablation_name, baseline_method_id, ablated_method_id, result_json
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                exp_id,
                ab["ablation_id"],
                ab["ablation_name"],
                ab["baseline_method_id"],
                ab["ablated_method_id"],
                json.dumps(ab)
            ))

        conn.commit()
        logger.info(f"Experiment {exp_id} successfully persisted with {len(predictions)} predictions.")
    finally:
        conn.close()


def get_experiment_by_id(exp_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves an experiment manifest and top-level run details."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM research_experiments WHERE id = ?", (exp_id,))
        row = cursor.fetchone()
        if not row:
            return None

        exp_data = dict(row)
        exp_data["manifest"] = json.loads(row["manifest_json"])

        # Fetch method runs
        cursor.execute("SELECT * FROM research_method_runs WHERE experiment_id = ?", (exp_id,))
        mr_rows = cursor.fetchall()
        method_runs = []
        for mr in mr_rows:
            method_runs.append({
                "method_id": mr["method_id"],
                "method_name": mr["method_name"],
                "method_version": mr["method_version"],
                "metrics": json.loads(mr["metrics_json"]),
                "confusion_matrix": json.loads(mr["confusion_matrix_json"]),
                "execution_time_ms": mr["execution_time_ms"],
            })
        exp_data["method_runs"] = method_runs

        # Fetch ablations
        cursor.execute("SELECT * FROM research_ablations WHERE experiment_id = ?", (exp_id,))
        ab_rows = cursor.fetchall()
        ablations = [json.loads(ab["result_json"]) for ab in ab_rows]
        exp_data["ablations"] = ablations

        return exp_data
    finally:
        conn.close()


def get_all_experiments() -> List[Dict[str, Any]]:
    """Lists all saved experiment runs sorted from newest to oldest."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM research_experiments ORDER BY started_at DESC")
        rows = cursor.fetchall()
        results = []
        for r in rows:
            data = dict(r)
            data["manifest"] = json.loads(r["manifest_json"])
            # Load summary metrics for quick overview
            cursor.execute("SELECT method_id, method_name, metrics_json FROM research_method_runs WHERE experiment_id = ?", (r["id"],))
            mr_rows = cursor.fetchall()
            data["method_summaries"] = [
                {
                    "method_id": mr["method_id"],
                    "method_name": mr["method_name"],
                    "metrics": json.loads(mr["metrics_json"])
                }
                for mr in mr_rows
            ]
            results.append(data)
        return results
    finally:
        conn.close()


def get_experiment_predictions(exp_id: str, method_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieves all predictions for an experiment, optionally filtered by method_id."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        if method_id:
            cursor.execute("SELECT * FROM research_predictions WHERE experiment_id = ? AND method_id = ? ORDER BY case_id ASC", (exp_id, method_id))
        else:
            cursor.execute("SELECT * FROM research_predictions WHERE experiment_id = ? ORDER BY case_id ASC, method_id ASC", (exp_id,))
        rows = cursor.fetchall()
        preds = []
        for r in rows:
            item = dict(r)
            item["is_conclusive"] = bool(r["is_conclusive"])
            item["evidence"] = json.loads(r["evidence_json"])
            preds.append(item)
        return preds
    finally:
        conn.close()
