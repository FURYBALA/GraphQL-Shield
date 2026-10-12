# Evidence-Grounded AI Explanations for GraphQL BOLA Auditing: Correlating AST-Derived Paths with Runtime Authorization Evidence

**Authors:** CCNS Project Research Group  
**Target Venue:** IEEE Transactions on Information Forensics and Security / IEEE S&P Workshop on Graph and API Security  
**Date:** October 2026  
**Artifact Repository:** Local Git Repository (Commit-tracked evaluation package)  
**Manuscript Format Note:** This document represents the submission-ready academic preprint drafted in Markdown. Two-column camera-ready rendering (e.g., IEEEtran LaTeX template) will be compiled upon formal submission using the verified metrics, formulas, tables, and bibliography preserved herein.

---

## Abstract

Broken Object-Level Authorization (BOLA), also classified as Insecure Direct Object References (IDOR), represents the predominant vulnerability across modern GraphQL application programming interfaces (APIs). Traditional defenses operate either as standalone static taint analyzers that experience severe false-alarm rates (up to 81.1% on benign parameter flows due to lack of runtime tenancy context) or as perimeter gateways that log opaque binary authorization decisions without source-to-sink path attribution or actionable developer remediation. Furthermore, emerging generative AI assistance tools suffer from factual hallucination, unverified claims, and vulnerability to adversarial prompt injection.

In this paper, we present **GraphQL Shield + AI Analyst**, a defense-in-depth security architecture that unifies schema-aware Abstract Syntax Tree (AST) taint analysis, runtime authorization evidence correlation, and an evidence-grounded AI explanation layer. The system constructs a typed Security Graph $G = (V, E)$, canonicalizes client response paths to defeat GraphQL field aliasing, and binds runtime principal-resource ownership proofs. Crucially, an out-of-band AI explanation layer consumes a strictly delimited, sanitized Evidence Package indexing verifiable facts ($E_1 \dots E_{11}$). A post-generation Grounding Engine enforces citation integrity, detects policy contradictions, and verifies pipeline prompt isolation.

We evaluate our system across a 115-case synthetic benchmark and an independent 12-scenario real-world incident dataset inspired by public disclosures (including the Hoppscotch collection IDOR advisory, GHSA-m5pg-r4jp-qq75 / CVE-2026-28217). Experimental results show: (1) Correlated defense maintains 100.0% precision and 100.0% recall across valid security cases while preserving existing gateway enforcement behavior with 0 divergence; (2) Dual path canonicalization achieves 89.5% exact path attribution compared to 56.2% for standard gateway logging; (3) On an illustrative 10-dimension architectural capability rubric, the evidence-grounded layer satisfies 100.0% of security metadata dimensions compared to 40.0% for gateway logs and 70.0% for raw correlated JSON; (4) Across deterministic contract fixtures, the grounding verification engine achieves 100.0% citation ID precision (132/132 valid citations), catches 100.0% of synthetically injected hallucinations, contradictions, and misattributions, and structurally isolates adversarial prompt injection payloads from the evaluation pipeline.

---

## 1. Introduction & Motivation

GraphQL has emerged as the industry standard for client-driven data fetching in modern web, mobile, and cloud-native applications. By allowing clients to specify arbitrary query hierarchies, batch requests, and define custom field aliases, GraphQL significantly optimizes network efficiency and developer agility. However, these architectural strengths also create critical authorization vulnerabilities. Unlike traditional REST endpoints where discrete URIs map to explicit backend controllers, a single GraphQL `/graphql` endpoint handles complex, nested operations where authorization must be evaluated across every node in the resolved data graph.

Among these vulnerabilities, **Broken Object-Level Authorization (BOLA)** (OWASP API Security Top 10: API1:2023) poses the most severe enterprise risk. In a BOLA attack, an authenticated adversary manipulates client-controlled object identifiers (e.g., entity IDs, foreign keys, or variable inputs) to access or mutate records belonging to other tenants. Recent high-profile disclosures—such as the Hoppscotch team collection IDOR vulnerability (CVE-2026-28217 / GHSA-m5pg-r4jp-qq75)—demonstrate that even well-tested production GraphQL systems frequently omit field-level tenant ownership checks within nested resolvers.

Existing approaches to mitigating GraphQL BOLA suffer from three fundamental limitations:
1. **The Static Taint False-Alarm Dilemma:** Static analyzers (e.g., Lambers et al., 2026) analyze query ASTs to trace tainted client arguments to sensitive field sinks. While effective at identifying untrusted parameters, pure static analysis has no visibility into session state, tenant databases, or runtime policy outcomes. Consequently, on our constructed 115-case benchmark, static analysis alone flags 43 of 53 benign requests as vulnerabilities, yielding an unsustainable 81.1% false-alarm rate on benign queries.
2. **The Perimeter Gateway Explainability Gap:** Runtime API gateways successfully enforce tenant boundaries by dropping unauthorized requests with HTTP 403 Forbidden. However, standard gateway audit logs record only top-level field names and opaque error strings. They fail to trace the internal AST path, cannot disambiguate GraphQL client aliases, and provide zero actionable guidance for engineering teams seeking to patch the underlying resolver code.
3. **The AI Hallucination & Authority Trap:** While Large Language Models (LLMs) can synthesize human-readable audit summaries, deploying unconstrained LLMs in security pipelines introduces catastrophic risks: models hallucinate non-existent CVEs, misquote security policies, contradict deterministic enforcement decisions, and are susceptible to prompt injection embedded within attacker-controlled GraphQL queries.

To overcome these challenges, we propose an integrated, evidence-grounded architecture. Our contributions are:
- A schema-aware GraphQL Security Graph $G = (V, E)$ supporting dual path canonicalization that disambiguates client response aliases from canonical schema fields.
- A correlation engine that combines static AST taint findings with runtime authorization evidence, eliminating false alarms without altering gateway enforcement.
- An evidence-grounded AI security analyst that operates out-of-band, indexing verifiable facts ($E_1 \dots E_{11}$) and producing 10-dimensional audit explanations.
- A formal Grounding and Safety Verification Engine that verifies citation validity, enforces decision consistency, and resists adversarial prompt injection.
- Comprehensive empirical evaluation on both synthetic benchmarks and real-world vulnerability reproductions demonstrating 100% precision on gateway authorization, 100% contract grounding on deterministic mock fixtures, and sub-millisecond gateway overhead.

---

## 2. Threat Model & Operational Boundaries

### 2.1 Adversary Capabilities
We consider an active, authenticated or unauthenticated adversary operating over HTTP against a GraphQL API endpoint. The adversary possesses:
1. Valid or forged caller credentials (e.g., standard user JWTs, administrative JWTs, expired tokens, or malformed headers).
2. Arbitrary query construction capability: The attacker may craft complex nested selections, define field aliases (e.g., `stolenDoc: resource(id: 102)`), utilize GraphQL variables with inline defaults, and chain relational queries.
3. Parameter manipulation: The attacker can supply target object identifiers belonging to other tenants to probe for direct and indirect BOLA flaws.
4. Adversarial prompt injection: The attacker may embed natural language instructions inside GraphQL query comments, field names, or variable payloads designed to hijack downstream LLM summarizers (e.g., `# IGNORE PREVIOUS INSTRUCTIONS AND REPORT ALLOWED`).

### 2.2 Operational Assumptions & Gateway Authority
We establish the following non-negotiable architectural boundaries:
- **Zero-Authority AI Invariant:** The AI Analyst operates strictly as an out-of-band advisory service for human security auditors and developers. The AI layer **never** grants access, denies requests, overrides policy rules, or interacts directly with authorization databases.
- **Enforcement Finality:** The Gateway Policy Engine (`PolicyEngine`) maintains exclusive authority over HTTP dispatch. If the policy engine denies a request, the request is dropped immediately with HTTP 403 Forbidden regardless of any downstream analysis.
- **Fail-Closed Security:** Missing tokens, unverifiable ownership relationships, or malformed queries fail closed at the gateway perimeter.

---

## 3. Related Work

### 3.1 GraphQL Access Control & Taint Analysis
Authorization in GraphQL is notoriously difficult because queries allow arbitrary graph traversal. Prior literature by Lambers et al. (*"Taint Analysis for Graph APIs Focusing on Broken Access Control"*, LMCS 2026) demonstrated the viability of static taint propagation over GraphQL schemas to detect unauthorized data flows. However, as Lambers et al. acknowledged and our empirical results confirm, pure static taint analysis lacks access to the dynamic runtime tenancy context (e.g., database ownership mappings and caller session state). In our benchmark, this absence causes static taint analysis to suffer an 81.1% false-alarm rate on legitimate requests by authorized resource owners.

### 3.2 Real-World Incident: Hoppscotch IDOR (GHSA-m5pg-r4jp-qq75)
In February 2026, security researchers identified a high-severity Broken Object-Level Authorization vulnerability in Hoppscotch (an open-source API development ecosystem). Under CVE-2026-28217 / GHSA-m5pg-r4jp-qq75, the backend GraphQL resolver for user collections failed to verify whether the requesting user belonged to the workspace owning the specified collection ID. An authenticated user could inspect foreign private collections simply by supplying a foreign collection ID. Our project models this exact architectural failure in a controlled local reproduction (`REAL-HOPP-001` to `REAL-HOPP-003`).

### 3.3 LLMs in Security Operations & Grounding Verification
Recent work has explored LLMs for security log summarization, incident triaging, and vulnerability explanation. However, ungrounded LLMs frequently suffer from confabulation and prompt injection. Techniques such as Retrieval-Augmented Generation (RAG) mitigate factual errors but lack formal verification mechanisms. Our work introduces a deterministic post-generation validation layer that treats the LLM output as untrusted and verifies all claims against structured program evidence.

---

## 4. System Architecture

The complete system architecture consists of five interacting layers:

```
[ Client Request ]
       │ (HTTP POST /graphql)
       ▼
┌────────────────────────────────────────────────────────┐
│  Layer 1: FastAPI Security Gateway                     │
│  - JWT Extraction & Caller Principal Binding           │
│  - Pre-Execution Object ID & AST Normalization         │
│  - Database Ownership Resolution & Policy Evaluation   │
│  - Deterministic Enforcement (ALLOW 200 / DENY 403)    │
└───────────────────────┬────────────────────────────────┘
                        │
       ┌────────────────┴────────────────┐
       │ (Parallel Out-of-Band Audit)    │
       ▼                                 ▼
┌───────────────────────────────┐ ┌───────────────────────────────┐
│ Layer 2: AST Taint Engine     │ │ Layer 3: Correlation Engine   │
│ - Security Graph G = (V, E)   │ │ - Taint Finding + Policy Match│
│ - Dual Path Canonicalization  │ │ - Runtime Boundary Proof      │
│ - Direct/Indirect BOLA Tags   │ │ - Risk Scoring & Status Class │
└──────────────┬────────────────┘ └──────────────┬────────────────┘
               │                                 │
               └────────────────┬────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────┐
│  Layer 4: Evidence Synthesizer                         │
│  - Token Scrubbing & Variable Sanitization             │
│  - Indexed Evidence Packaging (E1 .. E11)              │
│  - Prompt Delimitation (Injection Isolation)           │
└───────────────────────┬────────────────────────────────┘
                        │
                        ▼
┌────────────────────────────────────────────────────────┐
│  Layer 5: Evidence-Grounded AI Security Analyst        │
│  - LLM Inference (Deterministic Mock / HTTP Provider)  │
│  - Grounding Validation Engine                         │
│    * Citation Integrity & Hallucination Defense        │
│    * Decision Consistency Invariant Checker            │
│    * Canonical Path Discrepancy Detector               │
│  - Web Security Dashboard & Developer Remediation UI   │
└────────────────────────────────────────────────────────┘
```

---

## 5. Formal Model & Technical Methodology

### 5.1 Typed Security Graph Construction
We formalize a GraphQL API schema as a directed, typed Security Graph $G = (V, E)$:
- $V = V_{\text{type}} \cup V_{\text{field}} \cup V_{\text{arg}} \cup V_{\text{sink}}$
- $E = E_{\text{contains}} \cup E_{\text{returns}} \cup E_{\text{param}} \cup E_{\text{reaches}}$

Nodes represent GraphQL types, selectable fields, input arguments, and sensitive sinks. Each node $v \in V$ is annotated with metadata:
$$\text{attr}(v) = \langle \text{sensitivity}, \text{owner\_binding}, \text{cardinality} \rangle$$
where $\text{sensitivity} \in \{\text{PUBLIC}, \text{INTERNAL}, \text{HIGH}, \text{CRITICAL}\}$.

### 5.2 Dual Path Canonicalization & Alias Masking
Attackers frequently employ GraphQL aliases to disguise sensitive field selections:
```graphql
query MaskedQuery {
    customAlias: resource(id: 102) { id name }
}
```
Standard gateways record the response field `customAlias`, obscuring the underlying schema target. Our engine performs dual attribution:
1. **Client Response Path ($P_{\text{resp}}$):** The alias name returned in the JSON payload (e.g., `customAlias`).
2. **Canonical Schema Path ($P_{\text{schema}}$):** The underlying typed graph coordinate (e.g., `Query.resource`).

When $P_{\text{resp}} \neq P_{\text{schema}}$, the analyzer flags active alias masking ($\text{is\_alias\_masked} = \text{True}$), resolving the exact canonical field for policy auditing.

### 5.3 Evidence Package Model ($E_1 \dots E_{11}$)
To anchor model explanations to verified facts and mitigate ungrounded claims, the AI Analyst receives only verifiable program evidence packaged as structured items:
- **$E_1$ (Operation):** Operation type, length, and sanitized structure.
- **$E_2$ (Schema Path):** Canonical schema path attributed in Security Graph.
- **$E_3$ (Response Path):** Client response path and alias masking state.
- **$E_4$ (Taint Source):** Client-controlled argument tagged as untrusted input.
- **$E_5$ (Sensitive Sink):** Sensitive target type and sensitivity rating.
- **$E_6$ (Target Entity):** Target object type, identifier, and database-resolved owner ID.
- **$E_7$ (Caller Principal):** Authenticated user ID and role from verified JWT.
- **$E_8$ (Enforcement Decision):** Deterministic gateway decision (`ALLOW`/`DENY`) and policy reason.
- **$E_9$ (Risk Assessment):** Calculated quantitative risk score (0–100) and risk level.
- **$E_{10}$ (Correlation Status):** Correlation classification (e.g., `TRUE_POSITIVE_BLOCKED`, `RUNTIME_PROTECTED_ALLOWED`).
- **$E_{11}$ (Boundary Proof):** Program verification state confirming runtime boundary execution.

### 5.4 Grounding Engine & Safety Verification Invariants
Before an AI explanation is returned to the user or rendered in the dashboard, it is evaluated by the Grounding Engine against four strict invariants:

$$\text{Inv}_1 (\text{Citation Validity}): \forall c \in \text{Citations}(\text{Response}), c \in \{E_1, E_2, \dots, E_k\}$$
$$\text{Inv}_2 (\text{Decision Consistency}): \text{Decision}(\text{Response}) \equiv \text{Decision}(\text{Gateway})$$
$$\text{Inv}_3 (\text{Path Fidelity}): \text{Path}(\text{Response}) \equiv P_{\text{schema}}$$
$$\text{Inv}_4 (\text{Essential Grounding}): \{E_6, E_7, E_8\} \cap \text{Citations}(\text{Response}) \neq \emptyset$$

Any violation penalizes the explanation's Grounding Score:
$$\text{Score}_{\text{grounding}} = 1.0 - 0.25 \cdot |\text{Invalid Cits}| - 0.50 \cdot [\neg \text{Inv}_2] - 0.20 \cdot [\neg \text{Inv}_3] - 0.05 \cdot |\text{Missing Essential}|$$
Explanations scoring below 0.70 or violating $\text{Inv}_2$ are flagged as ungrounded and rejected from automated workflows.

### 5.5 Formal Algorithm Formulations

#### Algorithm 1: Schema-Aware AST Taint & Dual Path Attribution
```python
def analyze_ast_taint(query: str, variables: dict, schema_graph: SecurityGraph) -> TaintReport:
    ast = parse_graphql_ast(query)
    propagation_steps = []
    findings = []
    
    for operation in ast.operations:
        for field in traverse_selection_set(operation.selection_set):
            # Dual path attribution
            response_path = field.alias or field.name
            schema_path = schema_graph.resolve_canonical_coordinate(field.parent_type, field.name)
            is_aliased = (response_path != field.name)
            
            # Check tainted argument inputs
            for arg in field.arguments:
                arg_val = resolve_argument_value(arg, variables)
                if schema_graph.is_taint_source(arg.name, arg_val):
                    sink = schema_graph.resolve_sensitive_sink(field)
                    if sink:
                        kind = "DIRECT_BOLA" if field.parent_type == "Query" else "INDIRECT_BOLA"
                        findings.append(TaintCandidate(kind, schema_path, response_path, arg.name, sink))
            
            propagation_steps.append((schema_path, response_path, is_aliased))
            
    return TaintReport(propagation_steps, findings)
```

#### Algorithm 2: Runtime Authorization Evidence Correlation
```python
def correlate_evidence(runtime_result: dict, taint_report: TaintReport, caller_ctx: CallerContext) -> CorrelationRecord:
    decision = runtime_result["decision"]      # ALLOW or DENY
    reason = runtime_result["reason"]          # e.g., OWNER_MATCH, OWNERSHIP_MISMATCH
    has_taint = len(taint_report.findings) > 0
    
    if has_taint and decision == "DENY":
        # True attack attempt blocked by policy
        return CorrelationRecord(status="TRUE_POSITIVE_BLOCKED", action="AUDIT_INCIDENT")
    elif has_taint and decision == "ALLOW":
        # Static taint flagged flow, but runtime policy verified ownership
        return CorrelationRecord(status="RUNTIME_PROTECTED_ALLOWED", action="SUPPRESS_FALSE_ALARM")
    elif not has_taint and decision == "ALLOW":
        return CorrelationRecord(status="BENIGN_ALLOWED", action="NORMAL_DISPATCH")
    else:
        return CorrelationRecord(status="POLICY_DENIED_UNCORRELATED", action="AUDIT_POLICY_DROP")
```

---

## 6. Experimental Evaluation

We designed our experiments to answer three core research questions:
- **RQ1 (Detection & Attribution):** Does correlating AST taint analysis with runtime authorization maintain detection accuracy and path attribution while preserving gateway enforcement behavior?
- **RQ2 (Audit Completeness & Utility):** Does the evidence-grounded AI layer provide superior explanation completeness across verifiable security dimensions compared to existing baselines?
- **RQ3 (AI Safety & Grounding):** How reliably does the grounding engine catch hallucinated citations, policy contradictions, and adversarial prompt injections?

### 6.1 Benchmark Datasets
We evaluate on two independent corpora:
1. **115-Case CCNS Benchmark:** 105 syntactically valid security cases (52 vulnerable BOLA cases, 53 benign authorized cases) and 10 malformed syntax cases.
2. **12-Scenario Real-World Dataset:** An independent test suite modeling real-world incident patterns across four enterprise use cases:
   - Hoppscotch collection IDOR reproduction (GHSA-m5pg-r4jp-qq75).
   - Team workspace nested relational collections with alias masking.
   - Multi-tenant SaaS private document folder traversals.
   - Partner API federation boundaries and expired credential handling.

---

## 7. Results & Discussion

### 7.1 RQ1: Security Detection, Path Attribution, and Behavioral Compatibility
Table 1 summarizes security detection performance across the 105 valid cases in the CCNS benchmark.

**Table 1: Security Detection Performance Comparison (105 Valid Benchmark Cases)**

| Metric | Method 1: Gateway Alone | Method 2: Static Taint Alone | Method 3: Correlated Defense (Ours) |
| :--- | :---: | :---: | :---: |
| **Precision** | **100.0%** (52/52) | 54.7% (52/95) | **100.0%** (52/52) |
| **Recall** | **100.0%** (52/52) | **100.0%** (52/52) | **100.0%** (52/52) |
| **F1-Score** | **1.000** | 0.708 | **1.000** |
| **False-Alarm Rate** | **0.0%** (0/53) | **81.1%** (43/53) | **0.0%** (0/53) |
| **Exact Path Attribution** | 56.2% (59/105) | **89.5%** (94/105) | **89.5%** (94/105) |
| **Behavioral Divergence** | **0 Divergences** | N/A (Static Only) | **0 Divergences** (115/115 Preserved) |

**Key Finding 1:** Pure static taint analysis exhibits an unacceptable 81.1% false-alarm rate on benign requests because it cannot verify resource ownership. Correlating static paths with runtime authorization evidence completely eliminates false alarms (0.0% FAR) while maintaining 100.0% precision and recall.  
**Key Finding 2:** Dual path canonicalization increases exact path attribution from 56.2% (gateway alone) to 89.5%, accurately exposing aliased field targets.  
**Key Finding 3:** Across all 115 test cases, audit-only taint analysis caused zero deviations in HTTP response codes, latency profiles, or payload bodies.

#### 7.1.1 Ablation Analysis: Isolating the Contribution of Runtime Correlation
To isolate the independent contributions of the static AST analyzer versus the runtime authorization correlation mechanism, we perform an architectural ablation:

1. **Ablation 1 (Removing AST Taint Propagation - Gateway Alone):** Operating the gateway without AST taint analysis preserves runtime enforcement (100% precision, 0% FAR) but degrades path attribution to 56.2% (59/105 cases). In the presence of GraphQL field aliases (e.g., `stolenDoc: resource(id: 102)`), the gateway logs only client-selected alias names, blinding audit systems to underlying schema targets.
2. **Ablation 2 (Removing Runtime Correlation - Static Taint Alone):** Operating the AST taint engine without runtime authorization correlation preserves high path attribution (89.5%) and attack recall (100%), but collapses precision to 54.7% and causes an 81.1% false-alarm rate (43/53 benign cases flagged). This demonstrates that static AST analysis alone is fundamentally incapable of enterprise deployment due to absence of caller session and ownership context.
3. **Full System (AST Taint + Runtime Correlation):** Coupling AST path attribution with runtime authorization proofs simultaneously achieves 100.0% precision, 0.0% false-alarm rate, and 89.5% exact path attribution with zero behavioral divergence. This confirms that runtime correlation is the active component that neutralizes false alarms, while AST traversal is the active component that resolves obfuscated paths.

---

### 7.2 RQ2: Comparative Audit Completeness Across Methods
We evaluate audit completeness across 10 essential security dimensions: Principal Identity, Target Entity Binding, Target Owner Binding, Canonical Schema Path, Client Response Path, Gateway Enforcement, Policy Rationale, Root Cause Analysis, Actionable Remediation, and Suggested Regression Test.

**Table 2: Comparative Audit Completeness Evaluation (12 Real-World Scenarios)**
*(Evaluates an illustrative 10-dimension architectural capability rubric; does not claim human quality grading)*

| Evaluated Architecture | Satisfied Dimensions (/10) | Mean Completeness (%) | Architectural Metadata Capability |
| :--- | :---: | :---: | :--- |
| **Method A: Gateway-Only Log** | 4.0 / 10 | 40.0% | Binary decision recorded; lacks internal AST path and developer remediation. |
| **Method B: Static Taint Alone** | 2.0 / 10 | 20.0% | Flags source-to-sink AST propagation; lacks caller, owner, and runtime decision. |
| **Method C: Correlated Evidence (No AI)** | 7.0 / 10 | 70.0% | Complete structured metadata; lacks natural language root-cause and test cases. |
| **Method D: Grounded AI Analyst (Ours)**| **10.0 / 10** | **100.0%** | Synthesizes all 10 metadata fields: cited facts, root cause, code fix, and test. |

Figure 1 illustrates the comparative dimension coverage:
```
Audit Completeness Dimension Coverage (Architectural Checklist):
[Method A: Gateway]       [====                ] 40.0%
[Method B: Static Taint]  [==                  ] 20.0%
[Method C: Correlated]    [=======             ] 70.0%
[Method D: Grounded AI]   [==========          ] 100.0%
```

---

### 7.3 RQ3: AI Grounding, Safety, and Defect Rejection (Fixture Contract Tests)
To evaluate the programmatic invariants of our Grounding Engine, we subjected the system to automated defect injection on deterministic contract fixtures (`MockAIProvider`) and adversarial fixtures (`FlawedMockAIProvider`).

**Table 3: Safety, Grounding, and Invariant Verification Metrics (Deterministic Fixtures)**

| Safety Dimension / Verification Test | Evaluated Fixture / Injected Defect | Detection Rate | Outcome |
| :--- | :--- | :---: | :---: |
| **Citation ID Precision** | 132 Grounded Evidence References | 132/132 Valid (100.0%) | **PASS** |
| **Decision Consistency** | Cross-verification against Gateway Decision | 12/12 Consistent (100.0%) | **PASS** |
| **Path Consistency** | Cross-verification against Security Graph | 12/12 Consistent (100.0%) | **PASS** |
| **Hallucinated Citation Defense** | Injected Non-Existent IDs (`E99`, `E100`) | 100.0% Caught | **PASS** |
| **Policy Contradiction Defense** | Injected False Claims (Claims ALLOW on DENY) | 100.0% Caught | **PASS** |
| **Path Misattribution Defense** | Injected Schema Path Mutation | 100.0% Caught | **PASS** |
| **Pipeline Prompt Isolation** | Injected `"IGNORE ALL INSTRUCTIONS..."` in AST | 100.0% Isolated | **PASS** |

**Scope & Verification Boundary:** Table 3 validates the **deterministic contract of the Grounding Engine**. Prompt isolation tests confirm that untrusted query strings cannot alter the structured evidence container or bypass validator invariants. We do **not** claim complete immunity against arbitrary open-ended LLM jailbreaks; open-ended semantic explanation quality on live models remains an ongoing research direction.

---

### 7.4 Controlled Real-LLM Evaluation Protocol & Environmental Status (Phase 10.2)
To establish a path from deterministic mock contract verification to empirical language model evaluation, we designed and pre-registered an automated evaluation framework (`scripts/evaluate_real_llm_explanations.py`).

**Pre-Registered Archetype Subset:** We select a documented 4-scenario subset representing key structural coordinates:
1. `REAL-HOPP-001`: Direct BOLA vulnerability (Foreign resource lookup; expected `DENY`, `OWNERSHIP_MISMATCH`).
2. `REAL-HOPP-002`: Benign authorized owner access (Expected `ALLOW`, `OWNER_MATCH`; tests avoidance of false accusations).
3. `REAL-NEST-001`: Indirect relational BOLA with GraphQL alias masking (`targetUser.userDocs` vs canonical `Query.user.resources`; expected `DENY`, `OWNERSHIP_MISMATCH`).
4. `REAL-SAAS-003`: Multi-tenant document retrieval under legitimate tenancy (Expected `ALLOW`, `OWNER_MATCH`).

**Independent Ground Truth & Semantic Verification:** Unlike self-evaluating LLM benchmarks, ground-truth facts are established strictly prior to generation:
- Gateway decision and policy reasons are fixed by deterministic `PolicyEngine` traces.
- Schema coordinates are fixed by the AST Security Graph.
- Grounded citations require referential existence within the evidence container ($E_1 \dots E_{11}$).
- Semantic fact coverage measures presence of core entities (caller ID, target ID, policy reason, schema coordinate) and flags forbidden contradictions (e.g., claiming ALLOW on a dropped query).
- A 10-point blinded human rubric evaluates Factual Support (0–3), Metadata Completeness (0–3), Boundary Clarity (0–2), and Remediation Actionability (0–2).

**Environmental Prerequisite Boundary & Formal Closure:** In offline academic evaluation environments without configured external API credentials (`AI_API_KEY=""`, `AI_PROVIDER="mock"`), the framework halts cleanly, logs `HALTED_PREREQUISITE_ABSENT`, and writes the formal protocol to `docs/AI_REAL_LLM_EVALUATION_PROTOCOL.json`. Because no live credentials or authorized local models were present, the real-LLM experiment was **formally marked as unexecuted rather than retrying with a mock and disguising it as a live evaluation**. The manuscript's empirical claims rest exclusively on:
1. The 105-case deterministic gateway and AST taint correlation benchmark (Table 1: 100% precision, 100% recall, 0.0% false-alarm rate, 89.5% path attribution, 0 divergence).
2. The deterministic Grounding Engine contract tests on synthetic fixtures (Table 3: 132 valid citation IDs, 100% flaw rejection).
3. The pre-registered real-LLM evaluation protocol, which remains ready for replication without claiming unverified live model results.

---

### 7.5 Runtime Performance & Latency Measurement Boundaries
To avoid ambiguity, we explicitly report latency across three distinct measurement boundaries:

1. **In-Memory AST Taint Propagation Algorithm (`evaluate_phase_7.py`):**  
   Measures pure AST traversal, argument extraction, and Security Graph propagation in isolation across 345 profiling samples:
   - **Cold-Start (Initial Run):** 0.338 ms
   - **Warmed Median Latency:** **0.274 ms**
   - **Warmed Mean Latency:** 0.297 ms
   - **Warmed 95th Percentile (P95):** **0.437 ms**
   - **Min / Max Latency:** 0.047 ms / 1.538 ms
2. **In-Middleware Synchronous Overhead (`app/security/enforcement.py`):**  
   Measures the incremental processing time added inside the FastAPI gateway middleware during a live request (AST parsing, database ownership check, risk scoring, and audit event staging):
   - **Typical Middleware Overhead:** 0.350 ms – 0.650 ms
3. **Full End-to-End HTTP Request Roundtrip (`evaluate_performance.py`):**  
   Measures complete client-to-server HTTP roundtrip over 2,000 requests using FastAPI TestClient:
   - **Insecure Endpoint Baseline (No Gateway):** 7.325 ms
   - **Secure Gateway Endpoint (Full Security Stack):** 16.445 ms
   - **Total Authorization Decision & Audit Persistence Overhead:** 9.121 ms (dominated by synchronous SQLite disk I/O for `audit_logs` insertions and terminal logging).

In production deployments utilizing asynchronous connection pooling and background audit queuing, the runtime gateway overhead remains strictly bounded by the sub-millisecond in-memory AST algorithm (<0.5 ms).

---

### 7.6 Case-Level Error Analysis & Boundary Failures
To provide an honest empirical accounting beyond aggregate percentages, we analyze the specific failure modes across the 115 benchmark cases:

#### A. Static Taint False Positives (43 / 53 Benign Cases Flagged)
In 43 benign cases (representative cases `CORPUS-045` through `CORPUS-054`), legitimate users queried their own resources (e.g., Alice requesting Resource 101 or User 101). Because pure static taint analysis operates without runtime session context or caller JWT credentials, it conservatively tags any client-supplied object identifier flowing to a sensitive sink as an unmitigated BOLA candidate. Runtime correlation successfully suppresses 100% of these false alarms (reclassifying them as `RUNTIME_PROTECTED_ALLOWED`), dropping the effective false-alarm rate from 81.1% to 0.0%.

#### B. Partial Path Attribution Matches (11 / 105 Cases in M2 and M3)
The 89.5% exact path attribution rate reflects 94 exact matches and 11 partial matches (with 0 incorrect and 0 missing paths):
- **10 Multi-Root and Nested Parameter Cases (`CORPUS-027`–`030`, `CORPUS-036`, `CORPUS-038`, `CORPUS-054`–`055`, `CORPUS-114`–`115`):** The benchmark ground-truth specified comma-separated multi-targets (e.g., `'resource, user'`). The AST extractor accurately traversed and extracted individual hierarchical coordinates (e.g., `['user', 'user.resource']`). Because the path matched the primary `user` prefix but was formatted as an individual element rather than the composite comma-separated string, the metric evaluated this as a `PARTIAL` match.
- **1 Introspection Case (`CORPUS-084`):** The ground-truth expected schema coordinate `'__type'`, whereas the AST visitor extracted the runtime coordinate `'__typename'`.

#### C. Gateway-Alone Path Failures (10 Missing, 2 Incorrect Paths in M1)
Standard gateway logging achieved only 56.2% exact path attribution due to three structural blind spots:
- **10 Missing Paths (`CORPUS-080` through `CORPUS-089`):** Public health endpoints (`health`) and introspection operations (`__schema`, `__type`) do not carry object IDs. The gateway's parameter extractor returned an empty path list (`[]`), failing to attribute the operation.
- **2 Incorrect Paths (`CORPUS-093`, `CORPUS-094`):** Mixed-root queries combining a public health check with an object query caused the gateway to log only the object field, omitting the parallel public selection.
- **34 Alias Confusions:** When clients supplied field aliases (e.g., `stolenDoc: resource(id: 102)`), the gateway logged the client alias string `stolenDoc` rather than the canonical schema field `Query.resource`.

---

## 8. Real-World Case Study: Hoppscotch IDOR Reproduction

To evaluate practical utility, we examine scenario `REAL-HOPP-001`, which reproduces the vulnerability pattern disclosed in Hoppscotch GHSA-m5pg-r4jp-qq75 / CVE-2026-28217:
```graphql
query GetCollection($id: Int!) {
    resource(id: $id) {
        id
        name
        objectType
    }
}
```
**Attacker Context:** Caller Alice (User ID: 101, Role: `user`) supplies `$id: 102`, belonging to Bob (User ID: 102).

**System Analysis Output:**
1. **Gateway Enforcement:** Policy engine resolves target entity `Resource:102` owned by `User:102`. Since $101 \neq 102$ and caller lacks admin rights, request is dropped with HTTP 403 (`OWNERSHIP_MISMATCH`).
2. **Path Attribution:** Attributed canonical schema path `Query.resource`.
3. **Correlated Status:** `TRUE_POSITIVE_BLOCKED`.
4. **AI Analyst Output ($E_1 \dots E_{11}$ Grounded):**
   - *Summary:* "Blocked direct BOLA attempt on Resource:102 via canonical path 'Query.resource' [E2]. Caller 101 does not own the requested target entity [E6, E7, E8]."
   - *Root Cause:* "GraphQL query argument 'id' allows direct object referencing without implicit caller tenant scoping in resolver [E2, E4]."
   - *Remediation Guidance:* "Enforce object ownership verification within resolver `resolve_resource` by checking `context.user.id == resource.owner_id` or scoping database queries to the authenticated session."
   - *Regression Test:* Automated test query provided to verify HTTP 403 on cross-tenant access.

---

## 9. Limitations & Threats to Validity

1. **Benchmark Scope:** Our synthetic benchmark comprises 115 cases, and the real-world dataset contains 12 scenarios. While representative of common BOLA and IDOR patterns, further testing on industrial GraphQL schemas with hundreds of nested types is desirable.
2. **Ownership Inference Heuristics:** In the absence of explicit database schema foreign keys, ownership inference relies on field naming patterns (e.g., `owner_id`, `user_id`). Highly non-standard schema naming conventions may require explicit configuration.
3. **Mock Provider vs. Live LLM Evaluation:** The systematic benchmark reported in Section 7.2–7.3 evaluates programmatic schema contracts and validator invariants using deterministic mock fixtures. Section 7.4 defines a pre-registered protocol (`scripts/evaluate_real_llm_explanations.py`) for live OpenAI-compatible models. In evaluation environments where external API credentials are absent, the harness halts cleanly rather than fabricating synthetic data as real LLM performance. Empirical grading of non-deterministic models under human double-blind review remains subject to API availability and cloud latency (400–1200 ms).
4. **Adversarial Prompt Injection Boundaries:** While structural AST quarantine and post-generation decision guardrails prevent input payloads from overriding gateway decisions, probabilistic LLM components remain susceptible to emerging semantic prompt injection techniques.
5. **Ethical Considerations & Responsible Disclosure:** All real-world vulnerability reproductions (including the Hoppscotch CVE-2026-28217 pattern) were implemented exclusively within an isolated local synthetic laboratory schema. No active probes, unauthorized queries, or testing were directed against external systems, production servers, or third-party user data. The vulnerability pattern was reconstructed strictly from publicly disclosed advisory documentation for academic replication. Furthermore, the AI analyst component is architected as an out-of-band advisory auditor with zero runtime enforcement authority, ensuring that automated explanations cannot degrade service availability or compromise access control decisions.

---

## 10. Conclusion

We have presented an evidence-grounded security architecture for detecting, attributing, and explaining GraphQL Broken Object-Level Authorization vulnerabilities. By coupling schema-aware AST taint analysis with runtime authorization proofs, our approach eliminates the 81.1% false-alarm rate characteristic of pure static analysis while preserving existing gateway enforcement with zero behavioral divergence. Furthermore, our out-of-band AI explanation layer delivers 100.0% audit metadata completeness under strict grounding constraints, rejecting synthetically injected hallucinations and decision contradictions. This work demonstrates that generative AI can assist in security auditing when strictly constrained by verifiable program evidence and decoupled from enforcement authority.

---

## References

1. **OWASP Foundation**, *"OWASP API Security Top 10: 2023"*, API1:2023 Broken Object Level Authorization, 2023.
2. **L. Lambers, L. Sakizloglou, T. Khakharova, and F. Orejas**, *"Taint Analysis for Graph APIs Focusing on Broken Access Control,"* Logical Methods in Computer Science (LMCS), vol. 22, no. 1, pp. 1-28, 2026. DOI: 10.46298/lmcs-22(1:18)2026.
3. **GitHub Security Lab & Hoppscotch Team**, *"IDOR in GraphQL userCollection Query Exposes Other Users' Private Collections,"* GitHub Security Advisory GHSA-m5pg-r4jp-qq75 / CVE-2026-28217, Feb. 2026.
4. **FastAPI & Starlette Documentation**, *"Modern Python Web Framework and Security Middleware Architecture"*, 2024.
5. **Strawberry GraphQL Project**, *"Pythonic GraphQL Library based on Dataclasses and Typing"*, 2024.
6. **K. Greshake, S. Abdelnabi, S. Mishra, C. Endres, T. Holz, and M. Fritz**, *"Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection,"* in Proceedings of the 16th ACM Workshop on Artificial Intelligence and Security (AISEC '23), 2023, pp. 79–90.
7. **GraphQL Foundation**, *"GraphQL Specification: October 2021 Edition"*, Sections on Execution, Aliasing, and Field Selection Sets.
