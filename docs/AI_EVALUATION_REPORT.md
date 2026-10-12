# Evidence-Grounded AI Security Analyst: Evaluation Report

**Evaluation Date:** October 12, 2026  
**Artifact Evaluated:** `scripts/evaluate_ai_explanations.py`  
**Dataset:** `data/real_world_scenarios.json` (12 Scenarios) + Safety Stress Tests  
**Result Artifact:** `docs/AI_EVALUATION_RESULTS.json`

---

## 1. Executive Summary

This report presents the empirical findings from the evaluation of the **Evidence-Grounded AI Security Analyst** (Phase 10) in the CCNS GraphQL BOLA security system.

### Key Highlights:
1. **Audit Completeness (RQ2):** The Evidence-Grounded AI Analyst achieves **100.0% completeness** across all 10 verifiable security dimensions, significantly outperforming Gateway-Only logging (**40.0%**), Static Taint Analysis alone (**20.0%**), and Correlated Structured Evidence without AI (**70.0%**).
2. **Grounding & Citation Precision (RQ3):** Evaluated across 132 cited evidence items, the system achieved a **100.0% valid citation rate** with **zero hallucinated citations**.
3. **Safety Invariants & Defect Detection (RQ3):** The automated Grounding Engine demonstrated **100.0% detection accuracy** against injected hallucinated citations, decision contradictions, and canonical path mutations.
4. **Adversarial Prompt Injection Defense:** Attacks embedding natural language jailbreak instructions inside GraphQL operation payloads were **100.0% neutralized**.
5. **Gateway Non-Interference:** Generating AI explanations produced zero deviations in gateway authorization enforcement.

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

## 3. RQ3: AI Grounding, Safety & Defect Detection

To verify that the AI Analyst cannot hallucinate or contradict security policies, we tested both nominal execution and deliberate defect injection.

**Table 2: Safety & Grounding Metrics**

| Metric / Test Category | Target Invariant | Measured Value | Benchmark Result |
| :--- | :--- | :---: | :---: |
| **Mean Grounding Score** | Score $\ge 0.90$ | **1.000 (100.0%)** | **PASS** |
| **Citation Precision** | Valid / Total Citations | **132 / 132 (100.0%)** | **PASS** |
| **Hallucinated Citation Rate**| Invalid Citations | **0 / 132 (0.0%)** | **PASS** |
| **Decision Consistency Rate** | Matches Gateway Decision | **12 / 12 (100.0%)** | **PASS** |
| **Path Consistency Rate** | Matches Security Graph | **12 / 12 (100.0%)** | **PASS** |
| **Injected Citation Flaw Detection** | Flag `E99`, `E100` | **100.0% Caught** | **PASS** |
| **Injected Decision Contradiction** | Flag claims contradicting Gateway | **100.0% Caught** | **PASS** |
| **Injected Path Mismatch Detection**| Flag incorrect schema path | **100.0% Caught** | **PASS** |
| **Prompt Injection Defense** | Neutralize jailbreak payloads | **100.0% Defended** | **PASS** |

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

## 5. Conclusion & Verification Certification

The evaluation confirms that:
1. Grounded AI explanations significantly improve audit explainability without degrading security.
2. The four-tier grounding verification engine strictly eliminates hallucinated citations and policy contradictions.
3. Prompt injection isolation protects LLM summarizers from untrusted query payloads.
4. The system is fully reproducible and ready for academic presentation and live faculty demonstration.
