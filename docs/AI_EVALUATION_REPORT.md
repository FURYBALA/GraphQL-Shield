# Evidence-Grounded AI Security Analyst: Evaluation Report

**Evaluation Date:** October 12, 2026  
**Artifact Evaluated:** `scripts/evaluate_ai_explanations.py`  
**Dataset:** `data/real_world_scenarios.json` (12 Scenarios) + Safety Stress Tests  
**Result Artifact:** `docs/AI_EVALUATION_RESULTS.json`

---

## 1. Executive Summary

This report presents the empirical findings from the contract and fixture evaluation of the **Evidence-Grounded AI Security Analyst** (Phase 10) in the CCNS GraphQL BOLA security system.

### Evaluation Scope & Provider Fixture:
- **Evaluated Provider:** `MockAIProvider` (deterministic template engine) and `FlawedMockAIProvider` (adversarial defect injection).
- **Evaluation Paradigm:** Programmatic invariant testing, referential integrity verification, and structural pipeline isolation. Live open-ended LLMs with human double-blind review were not part of this deterministic benchmark.
- **Enforcement Authority:** 100% deterministic Gateway `PolicyEngine`. The AI Analyst has zero authorization authority.

### Key Highlights:
1. **Audit Completeness (RQ2):** Under an illustrative architectural capability rubric across 10 security metadata dimensions, the Evidence-Grounded AI Analyst achieves **100.0% completeness** (presence of all 10 dimensions), compared to Gateway-Only logging (**40.0%**), Static Taint Analysis alone (**20.0%**), and Correlated Structured Evidence without AI (**70.0%**).
2. **Grounding & Citation Precision (RQ3):** Evaluated across 132 cited evidence items against the deterministic mock fixture, the system achieved a **100.0% valid citation rate** (all 132 referential evidence IDs exist) with **zero hallucinated citation IDs**.
3. **Safety Invariants & Defect Detection (RQ3):** The automated Grounding Engine demonstrated **100.0% detection accuracy** against synthetically injected hallucinated citations (`E99`, `E100`), decision contradictions, and canonical path mutations.
4. **Adversarial Prompt Injection Pipeline Isolation:** Untrusted natural language injection payloads inside GraphQL queries were **100.0% quarantined** within delimited evidence envelopes, and post-generation guardrails verified gateway policy adherence.
5. **Gateway Non-Interference:** Generating AI explanations produced zero deviations in gateway authorization enforcement (100% preserved).

---

## 2. RQ2: Comparative Audit Dimension Completeness

We evaluated 12 real-world security scenarios across the four architectural baselines. Table 1 summarizes the results.

**Table 1: Mean Audit Dimension Completeness across Methods (12 Scenarios)**

| Evaluated Architecture | Satisfied Dimensions (out of 10) | Mean Completeness (%) | Relative Improvement over Baseline |
| :--- | :---: | :---: | :---: |
| **Method A: Gateway-Only Log** | 4.0 / 10 | 40.0% | Baseline |
| **Method B: Static Taint Alone** | 2.0 / 10 | 20.0% | -50.0% (Lacks runtime context) |
| **Method C: Correlated Evidence (No AI)** | 7.0 / 10 | 70.0% | +75.0% |
| **Method D: Grounded AI Analyst (Ours)**| **10.0 / 10** | **100.0%** | **+150.0%** |

### Dimension-by-Dimension Breakdown:

| Security Dimension | Method A (Gateway) | Method B (Static) | Method C (Correlated) | Method D (AI Analyst) |
| :--- | :---: | :---: | :---: | :---: |
| 1. Principal Identity (`user_id`, `role`) | Yes | No | Yes | **Yes** |
| 2. Target Entity Binding (`object_type`, `id`)| Yes | No | Yes | **Yes** |
| 3. Target Owner Binding (`owner_id`) | No | No | Yes | **Yes** |
| 4. Canonical Schema Path | No | Yes | Yes | **Yes** |
| 5. Client Response Path / Alias | No | No | Yes | **Yes** |
| 6. Gateway Enforcement Decision | Yes | No | Yes | **Yes** |
| 7. Policy Rationale (`reason`) | Yes | No | Yes | **Yes** |
| 8. Architectural Root Cause Analysis | No | Yes | No | **Yes** |
| 9. Actionable Developer Remediation | No | No | No | **Yes** |
| 10. Suggested Regression Test Query | No | No | No | **Yes** |

**Discussion:** While Method C provides structured data, it lacks actionable developer utility (root cause narrative, code remediation advice, and regression tests). Method D bridges this gap by synthesizing structured evidence into developer-ready engineering guidance while anchoring every claim to evidence items ($E_1 \dots E_{11}$).

---

## 3. RQ3: AI Grounding, Safety & Defect Detection (Fixture Contract Tests)

To verify the programmatic invariants of the Grounding Engine, we tested nominal template output using `MockAIProvider` and deliberate flaw injection using `FlawedMockAIProvider`.

**Table 2: Safety & Grounding Metrics (Deterministic Fixture Verification)**

| Metric / Test Category | Target Invariant | Measured Value | Benchmark Result |
| :--- | :--- | :---: | :---: |
| **Mean Grounding Score** | Score $\ge 0.90$ on compliant mock fixture | **1.000 (100.0%)** | **PASS** |
| **Citation ID Precision** | Valid / Total Citations (ID existence) | **132 / 132 (100.0%)** | **PASS** |
| **Hallucinated Citation Rate**| Invalid Citations on nominal mock | **0 / 132 (0.0%)** | **PASS** |
| **Decision Consistency Rate** | Matches Gateway Decision | **12 / 12 (100.0%)** | **PASS** |
| **Path Consistency Rate** | Matches Security Graph coordinate | **12 / 12 (100.0%)** | **PASS** |
| **Injected Citation Flaw Detection** | Catch `E99`, `E100` in `FlawedMockAIProvider` | **100.0% Caught** | **PASS** |
| **Injected Decision Contradiction** | Catch inverted decision claims | **100.0% Caught** | **PASS** |
| **Injected Path Mismatch Detection**| Catch schema path mutations | **100.0% Caught** | **PASS** |
| **Prompt Injection Pipeline Isolation** | Untrusted AST query delimited | **100.0% Isolated** | **PASS** |

*Note: Metrics reflect programmatic contract testing and schema validation against deterministic fixtures. They verify that the validator correctly rejects contract violations and prevents untrusted query strings from overriding gateway decisions; they do not claim universal immunity to open-ended LLM jailbreaks or human-graded natural language quality.*

---

## 4. Per-Scenario Performance Breakdown

Every scenario in the 12-case dataset was evaluated against the Grounding Engine.

| Scenario ID | Name & Description | Decision | Grounding Score | Cited Citations | Warnings |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `REAL-HOPP-001` | Hoppscotch Collection IDOR: Foreign Lookup | DENY | 1.0 | 11/11 | 0 |
| `REAL-HOPP-002` | Hoppscotch Collection IDOR: Legitimate Owner | ALLOW | 1.0 | 11/11 | 0 |
| `REAL-HOPP-003` | Hoppscotch Collection IDOR: Admin Override | ALLOW | 1.0 | 11/11 | 0 |
| `REAL-NEST-001` | Team Workspace: Indirect BOLA with Aliases | DENY | 1.0 | 11/11 | 0 |
| `REAL-NEST-002` | Team Workspace: Nested Parameterized Lookup | DENY | 1.0 | 11/11 | 0 |
| `REAL-NEST-003` | Team Workspace: Legitimate Owner Nested Access| ALLOW | 1.0 | 11/11 | 0 |
| `REAL-SAAS-001` | SaaS Multi-Tenant: Cross-Tenant File Theft | DENY | 1.0 | 11/11 | 0 |
| `REAL-SAAS-002` | SaaS Multi-Tenant: Variable Default Injection | DENY | 1.0 | 11/11 | 0 |
| `REAL-SAAS-003` | SaaS Multi-Tenant: Legitimate Tenant Document| ALLOW | 1.0 | 11/11 | 0 |
| `REAL-AUTH-001` | Authentication Layer: Unauthenticated Access | DENY | 1.0 | 11/11 | 0 |
| `REAL-AUTH-002` | Authentication Layer: Invalid JWT Signature | DENY | 1.0 | 11/11 | 0 |
| `REAL-PROJ-001` | Project Resources: Shared Project Attachment | DENY | 1.0 | 11/11 | 0 |

---

## 5. Phase 10.2: Controlled Real-LLM Evaluation Protocol & Environmental Status

To transition beyond deterministic contract tests on mock fixtures, Phase 10.2 developed and pre-registered an empirical real-LLM evaluation protocol in `scripts/evaluate_real_llm_explanations.py`.

### A. Pre-Registered Evaluation Subset & Independent Ground Truth
Four representative scenarios were pre-registered with facts defined independently prior to any model generation:
- **`REAL-HOPP-001` (Direct BOLA, Vulnerable):** Caller 101 requests Resource 102 (owned by 102). Expected: `DENY`, `OWNERSHIP_MISMATCH`, path `Query.resource`.
- **`REAL-HOPP-002` (Resource Owner, Benign):** Caller 102 requests Resource 102. Expected: `ALLOW`, `OWNER_MATCH`, path `Query.resource`.
- **`REAL-NEST-001` (Indirect Nested BOLA, Relational):** Tests GraphQL client alias resolution (`targetUser.userDocs` vs canonical `Query.user.resources`). Expected: `DENY`, `OWNERSHIP_MISMATCH`.
- **`REAL-SAAS-003` (Multi-Tenant Document, Benign):** Tenant document retrieval. Expected: `ALLOW`, `OWNER_MATCH`, path `Query.resource`.

### B. Environmental Prerequisite Check & Transparent Stance
When executed in the local evaluation environment:
- **Prerequisite Check Outcome:** `HALTED_PREREQUISITE_ABSENT`.
- **Environment Status:** No external `AI_API_KEY` or active OpenAI-compatible endpoint was configured (`AI_PROVIDER="mock"`, key empty).
- **Academic Integrity Stance:** Rather than fabricating simulated numbers or disguising mock runs as real LLM outputs, the evaluation script halted cleanly and saved the complete pre-registered protocol, independent ground truth definitions, and 10-point blinded grading rubric to `docs/AI_REAL_LLM_EVALUATION_PROTOCOL.json`.
- **Replication Ready:** Once credentials are added to `.env` (via `.env.example`), running `python scripts/evaluate_real_llm_explanations.py` automatically executes the live test suite with bounded retries and logs real latency, token usage, and required-fact coverage.

---

## 6. Conclusion & Verification Certification

The evaluation confirms that:
1. **Zero Enforcement Interference:** Gateway authorization decisions are strictly enforced by the deterministic `PolicyEngine` (100% preserved). The AI layer remains strictly out-of-band and advisory.
2. **Deterministic Contract Invariants Verified:** Post-generation grounding rules reliably detect synthetically injected hallucinated IDs, decision contradictions, and path mutations.
3. **Mechanical vs. Semantic Rigor Separated:** Referential evidence ID validation is distinguished from natural language semantic claim verification.
4. **Reproducible Real-LLM Protocol:** The Phase 10.2 framework establishes a rigorous, pre-registered methodology for frontier LLM evaluation without manufacturing unverified claims.

