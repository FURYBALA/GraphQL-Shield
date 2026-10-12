# Reproducibility Guide & Academic Limitations

**Project:** CCNS GraphQL BOLA Security System  
**Audit Scope:** Full System Reproducibility, Benchmark Execution, and Honest Scientific Limitations  
**Date:** October 2026

---

## 1. Academic Integrity & Scientific Claims

To ensure rigorous academic standards and avoid overclaiming, we explicitly document verified findings versus deliberate project boundaries:

1. **Detection Accuracy vs. Explainability:**
   - **Verified:** Correlated defense maintains **100.0% precision** and **100.0% recall** across the 105 valid cases in our benchmark, eliminating the **81.1% false-alarm rate** observed with pure static taint analysis on benign cases.
   - **Boundary Statement:** We do **NOT** claim that the AI layer improves binary blocking accuracy. Binary enforcement is performed exclusively by the deterministic gateway. The AI layer improves **audit explainability, path attribution, and developer remediation completeness**.
2. **Real-World Incident Reproduction:**
   - **Verified:** The Hoppscotch scenarios (`REAL-HOPP-001` to `REAL-HOPP-003`) model the vulnerability pattern disclosed in GHSA-m5pg-r4jp-qq75 (CVE-2024-38370).
   - **Boundary Statement:** The scenarios run within our local Strawberry GraphQL backend rather than the live Hoppscotch production application. We do not claim to have modified or attacked Hoppscotch's production infrastructure.
3. **Behavioral Compatibility:**
   - **Verified:** Across all 115 benchmark cases and all 12 real-world scenarios, audit-only analysis caused **zero divergences** in HTTP response status codes, bodies, or enforcement latency.

---

## 2. Complete Reproduction Protocol

Every result reported in our research paper and evaluation reports is 100% reproducible on a standard Windows/Linux workstation from a clean shell.

### 2.1 Prerequisites
- Python 3.10+ (tested on Python 3.14.5)
- SQLite3
- Required packages: `fastapi`, `uvicorn`, `strawberry-graphql`, `httpx`, `pydantic`, `pytest`, `pyjwt`, `python-multipart`

### 2.2 Execution Steps

#### Step 1: Run Full Automated Test Suite (178 Tests)
```powershell
python -m pytest -q
```
*Expected Result:* `178 passed in ~5.5s`

#### Step 2: Reproduce Benchmark Security Evaluation (115 Cases)
```powershell
python scripts/evaluate_phase_7.py
```
*Expected Result:*
- Precision: 100.0% (M1, M3), 54.7% (M2)
- Recall: 100.0% (M1, M2, M3)
- False Alarm Rate: 81.1% (M2), 0.0% (M1, M3)
- Exact Path Matches: 89.5% (M2, M3), 56.2% (M1)
- Divergence Rate: 0.0% (115/115 Preserved)

#### Step 3: Reproduce Real-World Scenario Evaluation (12 Scenarios)
```powershell
python scripts/evaluate_real_world_scenarios.py
```
*Expected Result:*
- Total Scenarios: 12
- Gateway HTTP Status Match Rate: 12/12 (100.0%)
- Gateway Decision Match Rate: 12/12 (100.0%)
- Path Attribution Match Rate: 12/12 (100.0%)

#### Step 4: Reproduce Evidence-Grounded AI Analyst Evaluation (RQ2 & RQ3)
```powershell
python scripts/evaluate_ai_explanations.py
```
*Expected Result:*
- Audit Completeness: Method A: 40.0%, Method B: 20.0%, Method C: 70.0%, Method D: 100.0%
- Mean Grounding Score: 100.0%
- Citation Accuracy: 100.0% (132/132 valid)
- Injected Citation Flaw Detection: 100% PASS
- Injected Decision Contradiction Detection: 100% PASS
- Adversarial Prompt Injection Defense: 100% PASS

#### Step 5: Launch Live Interactive Demonstration & Dashboard
```powershell
uvicorn app.main:app --port 8000
```
- Open browser to `http://localhost:8000/dashboard`
- Navigate to the **🧪 Real-World Security Scenario Lab** card
- Click **🤖 Generate Evidence-Grounded AI Explanation** to view live synthesis and citation pills.

---

## 3. Explicit Academic Limitations

We document the following limitations to provide full scientific transparency:

1. **Corpus Size:**
   - The synthetic benchmark contains 115 cases, and the real-world dataset contains 12 scenarios. While these cover key IDOR, BOLA, alias-masking, and nesting patterns, larger enterprise schemas with hundreds of interconnected types may exhibit edge cases not represented here.
2. **Database State & Seeding:**
   - The SQLite database (`shield.db`) contains fixed seed tenants (Alice ID 101, Bob ID 102, Charlie Admin ID 103). Modifying or wiping `shield.db` without running `python app/seed.py` will cause ownership resolution lookups to fail.
3. **Mock vs. Live HTTP LLM Providers:**
   - In offline evaluation and CI testing, the system defaults to `MockAIProvider` for deterministic, zero-token, sub-millisecond execution.
   - When configured with live LLM providers (e.g. `AI_PROVIDER=http`, `AI_MODEL=gpt-4o-mini`), network round-trips add 400–1200 ms. Live models may occasionally omit optional fields unless constrained by structured outputs (JSON mode).
4. **Schema Ownership Inference Heuristics:**
   - Automated schema relationship inference inspects Strawberry field types and attribute names (e.g., `owner_id`, `user_id`). Highly unconventional schema naming conventions (e.g., non-standard obfuscated database column names) require manual rule declarations.

---

## 4. Preservation of Database & Gateway State

In accordance with strict reproducibility requirements:
- The database file `shield.db` has **NOT** been modified, truncated, or wiped.
- All 178 tests execute within transactional sandboxes or against pre-seeded records.
- Zero git pushes have been made to any remote repository.
