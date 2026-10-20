const fs = require("fs");
const path = require("path");
const { Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType, Table, TableRow, TableCell, WidthType, BorderStyle, ShadingType, LevelFormat } = require("docx");

const ROOT = path.join(__dirname, "..", "..");
const OUT = path.join(ROOT, "VIVA_QA.docx");
const FONT = "Calibri";
const MONO = "Consolas";
const ACCENT = "1F3A5F";
const ACCENT2 = "2E6E9E";
const QFILL = "EEF3F8";

function t(text, o = {}) { return new TextRun({ text, font: O(o).mono ? MONO : FONT, size: o.mono ? 18 : (o.size || 22), bold: o.bold, italics: o.italics, color: o.color }); }
function O(o) { return o || {}; }
function H1(text) { return new Paragraph({ text, heading: HeadingLevel.HEADING_1, spacing: { before: 320, after: 140 } }); }
function H2(text) { return new Paragraph({ text, heading: HeadingLevel.HEADING_2, spacing: { before: 200, after: 100 } }); }
function Q(text) { return new Paragraph({ children: [new TextRun({ text: "Q: ", font: FONT, size: 22, bold: true, color: ACCENT }), new TextRun({ text, font: FONT, size: 22, bold: true, color: ACCENT })], spacing: { before: 180, after: 60 }, shading: { type: ShadingType.CLEAR, fill: QFILL }, indent: { left: 0 } }); }
function A(text) {
  const runs = Array.isArray(text) ? text : [new TextRun({ text, font: FONT, size: 21 })];
  return new Paragraph({ children: [new TextRun({ text: "A: ", font: FONT, size: 21, bold: true, color: ACCENT2 }), ...runs], spacing: { after: 120, line: 268 } });
}
function code(lines, o = {}) {
  const arr = Array.isArray(lines) ? lines : [lines];
  return arr.map((ln, i) => new Paragraph({ children: [new TextRun({ text: ln === "" ? " " : ln, font: MONO, size: 17, color: "1B1B1B" })], shading: { type: ShadingType.CLEAR, fill: "F4F6F8" }, spacing: { after: i === arr.length - 1 ? 140 : 0, line: 236 } }));
}
function bm(txt) { return new TextRun({ text: txt, font: FONT, size: 21, bold: true }); }
function nm(txt) { return new TextRun({ text: txt, font: FONT, size: 21 }); }

const c = [];
c.push(new Paragraph({ spacing: { before: 1200, after: 0 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "GraphQL Shield", font: FONT, size: 54, bold: true, color: ACCENT })] }));
c.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 80 }, children: [new TextRun({ text: "Viva / Defense — Question and Answer Handbook (Examiner Rigor Edition)", font: FONT, size: 26, color: ACCENT2 })] }));
c.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 300 }, children: [new TextRun({ text: "Schema-Aware Security Gateway for Preventing GraphQL BOLA Vulnerabilities", font: FONT, size: 20, italics: true, color: "55606B" })] }));
c.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 400 }, children: [new TextRun({ text: "Team: Agnihotram Chinmayanand (RA2311053010116), B.V. Balanilavan (RA2311053010123), Kapilesh.N (RA2311053010125), Sakthivel.B (RA2311053010126)  —  CCNS Capstone", font: FONT, size: 20, color: "55606B" })] }));
c.push(new Paragraph({ children: [new TextRun({ text: "Use this document to prepare for the viva presentation and faculty cross-examination. Every factual claim matches the delivered codebase and the 299/299 automated test suite, including the 15-check automated remediation verification suite.", font: FONT, size: 18, italics: true, color: "55606B" })] }));

// SECTION A - Problem
c.push(H1("A. Problem, motivation and scope"));
c.push(Q("What exactly is BOLA, and why did you choose it?"));
c.push(A("Broken Object Level Authorization (also called IDOR) is when an API accepts an object identifier from the client and returns the object without verifying that the caller is allowed to access that specific object. An attacker changes id=101 to id=102 and reads another user's data. OWASP ranks it API Security Risk #1 because it is extremely common and high impact. It is also entirely preventable with centralized enforcement, which is what we built."));
c.push(Q("Why is BOLA harder in GraphQL than in REST?"));
c.push(A("Three reasons. First, a single GraphQL endpoint fronts every resource, so the attack surface is large and discoverable. Second, resolvers are plain functions that execute in a depth-first traversal; authorization has to be repeated for every object-returning field and every path, and is easy to omit. Third, objects are often reachable through nested paths (e.g. a resource nested under a user), so a developer may protect the top-level field yet leave the nested path open."));
c.push(Q("What is the scope of the project?"));
c.push(A("A working prototype gateway in front of a GraphQL backend; a contextual policy and deterministic risk engine; schema-aware ownership inference; audit logging; a live dashboard; a differential-testing engine; an authorization research engine; an adaptive behavioural anomaly layer; and multi-tenant identity integrity with header anti-spoofing. It is evaluated by 299 automated tests across 28 test files and reproducible scripts, with all limitations explicitly stated."));
c.push(Q("What is your single strongest, defensible novelty claim?"));
c.push(A("Our defensible contribution is an evidence-grounded workflow combining schema-aware static analysis with runtime authorization evidence to provide both an enforceable security verdict and a traceable explanation of the affected GraphQL path. On our 115-case benchmark, this eliminates the 81.1% false-positive rate of static taint analysis on benign requests while maintaining 100% binary detection, providing 90.5% strict canonical AST path attribution (95/105) and 100.0% semantic target attribution across aliases and fragments."));

// SECTION B - Architecture
c.push(H1("B. Architecture and request flow"));
c.push(Q("Walk me through one malicious request end to end."));
c.push(A("A client POSTs a GraphQL query with an id it does not own, accompanied by a valid JWT. The enforcement dependency authenticates the JWT, derives the authoritative tenant, checks and rejects any conflicting X-Tenant-Id header, verifies query depth/cost budgets, extracts AST objects (resolving aliases and fragments), queries authoritative ownership, validates it against inferred schema rules, evaluates the zero-trust policy, computes a risk score, persists an audit row, and — because the decision is DENY — raises HTTP 403. The backend resolver never executes."));
c.push(Q("Where is the gateway in the stack, and why there?"));
c.push(A("It is a FastAPI dependency (app/security/enforcement.py) that runs before the GraphQL route handler. That position is ideal because it runs after authentication but before any resolver, so we can reject a request before any backend work or data access happens — the cheapest and safest place to stop an attack."));
c.push(Q("What does fail-closed mean in your design?"));
c.push(A("If the gateway cannot establish an ownership rule for a requested object type, cannot resolve the owner, or encounters a missing tenant claim on a multi-tenant resource, it does not guess — it denies access with reasons like UNKNOWN_OWNERSHIP or TENANT_CONTEXT_MISSING and assigns a HIGH risk score. Uncertainty always results in denial, never access."));
c.push(Q("How do you handle identifiers hidden in variables or fragments?"));
c.push(A("object_extractor.normalize_query parses the document and resolves fragment spreads and variable placeholders before extracting objects, so an id supplied via a GraphQL variable is treated identically to one written inline. There are dedicated regression tests for variable and fragment based BOLA."));

// SECTION C - Ownership inference
c.push(H1("C. Schema-aware ownership inference"));
c.push(Q("Why infer ownership from the schema instead of hard-coding it?"));
c.push(A("Hard-coding owner relationships does not scale: every new entity requires manual code changes in the security gateway, and the gateway cannot explain why an object belongs to a user. GraphQL schemas already describe relationships through fields like owner, owner_id or back-reference collections. We infer and validate those relationships once at startup."));
c.push(Q("How does the inference actually work?"));
c.push(A("At startup we inspect the Strawberry type registry once and convert every object type into a model of (field name, resolved type name). We normalize field names (ownerId -> owner_id) and type names (Resource == ResourceType) so query and schema align. Matching is driven by a configurable naming list. The result is cached in a read-only singleton."));
c.push(Q("What patterns do you support, and what do you reject?"));
c.push(A("Four patterns: A (object reference: Resource.owner: User), B (collection: User.resources: [Resource]), C (scalar id: Resource.ownerId: ID), and D (nested chains of A/B/C). Ambiguous matches (e.g. createdBy: String, which is a label, not a typed reference) are rejected and recorded as ambiguous rather than guessed."));
c.push(Q("Does inference ever override an explicit rule?"));
c.push(A("Never. The priority is fixed: explicit configured rules and authoritative database lookups always win; inferred rules explain and gate the lookup; if neither exists, it is UNKNOWN_OWNERSHIP and the request is denied. Inference never fabricates an owner id."));

// SECTION D - Policy, risk, enforcement
c.push(H1("D. Policy, risk and enforcement"));
c.push(Q("How does the policy engine decide?"));
c.push(A("It constructs a structured AuthorizationContext — user id, tenant id, role, operation, object type, object id, path, resolved owner id, and metadata — and applies zero-trust rules to produce ALLOW or DENY with an explicit reason. Examples: OWNER_MATCH allows; OWNERSHIP_MISMATCH, NESTED_AUTHORIZATION_VIOLATION, TENANT_ISOLATION_VIOLATION, and TENANT_CONTEXT_MISSING deny. A SUPERADMIN_CROSS_TENANT_OVERRIDE rule permits administrative access and generates a dedicated audit record."));
c.push(Q("How is the risk score computed?"));
c.push(A("Deterministically, in risk_engine.calculate_risk. +80 if the reason is an ownership or authorization violation, +20 if the access is nested (the path contains a dot), +10 if the user had any DENY in the last 10 minutes, capped at 100. The bands are LOW below 30, MEDIUM below 60, HIGH at 60 or above. It is rule-based and fully auditable — no machine learning in the enforcement path."));
c.push(Q("What happens on a DENY?"));
c.push(A("The gateway raises HTTPException(403) carrying decision, user id, object id, reason, risk score and risk level. Crucially, the Strawberry backend is never invoked — the resolver does not run."));
c.push(Q("Why log every decision if it costs overhead?"));
c.push(A("Auditability is essential for a security control: you must be able to reconstruct what was requested, by whom, and why it was allowed or denied. It is also the data source for the differential-testing engine and the anomaly layer. Enforcement never depends on audit success — a logging failure is caught and the request is still decided on its merits."));

// SECTION E - Contributions
c.push(H1("E. Contributions — Primary, Secondary, and Calibrated Findings"));
c.push(Q("What is the primary contribution and how is exact path attribution defined?"));
c.push(A("Our primary contribution is an evidence-grounded workflow combining schema-aware static analysis with runtime authorization evidence to provide both an enforceable security verdict and a traceable explanation of the affected GraphQL path. In our 115-case benchmark, 10 malformed queries are excluded as unparseable syntax errors that cannot possess an AST path, leaving 105 valid eligible cases (52 vulnerable BOLA, 53 benign authorized). Exact path attribution requires canonical AST path equality (Norm(Reported) = Norm(Expected)), resolving client aliases to schema targets and inlining fragments. Across the 105 eligible cases, runtime correlation achieves 95 exact matches (90.5%), 10 partial matches (9.5% — 10 nested-target representations), 0 incorrect, and 0 missing, while eliminating all 43 false alarms from static taint analysis on benign owner requests (0.0% false-alarm rate)."));
c.push(Q("Are the 10 non-exact cases genuine attribution failures or output representation mismatches?"));
c.push(A("“We found that strict string matching penalized some semantically equivalent nested-path representations. We therefore report strict canonical matching separately from semantic attribution. We also identified and corrected a ground-truth classification defect involving __typename (CORPUS-084), where a substring check mislabeled expected path as __type; correcting this using exact GraphQL AST schema coordinates raised strict exact matching to 90.5% (95/105). For the remaining 10 nested cases, the extractor successfully identified and attributed each individual hierarchical coordinate (['user', 'user.resource']), whereas the ground truth stored flat comma-delimited strings ('resource, user'). When evaluated using explicit target-path semantics rather than relying on string similarity, all target entities were fully identified with 0 incorrect paths and 0 missing targets, confirming 100.0% semantic target attribution (105/105).”"));
c.push(Q("Why did static taint analysis have an 81.1% false-positive rate?"));
c.push(A("This is an empirical result under our evaluated configuration, not a universal flaw of Lambers et al. Static taint analysis tracks source-to-sink data flow from client query inputs to database fetchers without access to runtime authentication or ownership tables. When an authorized user queries their own record, static taint flags it as a tainted object lookup because it cannot verify that the caller owns the object. Runtime evidence correlation resolves this ambiguity."));
c.push(Q("What is the real-time authorization research engine?"));
c.push(A("It is app/security/recon/, a self-contained capability that discovers the schema of a live service over real HTTP, generates a provenance-tracked test suite, executes tests against both the protected gateway and a labeled vulnerable backend, and confirms findings only when observed object identity or persisted state contradicts expectations — never from HTTP status codes alone."));
c.push(Q("What gap does the secondary novelty (adaptive anomaly detection) address?"));
c.push(A("Per-event risk scoring has no principal-level memory. It scores each request in isolation, so it cannot tell a one-off mistake from sustained abuse, and it assigns risk 0 to a fully-authorized account that is enumerating every record it can reach (mass authorized enumeration). The adaptive anomaly engine computes four aggregate features (deny_ratio, target_breadth, velocity, deny_trend) using robust median/MAD baselining."));
c.push(Q("What did the anomaly evaluation show?"));
c.push(A("On real gateway traffic with four principals, the static per-event baseline detected only 50% of attacks (missing the authorized mass enumeration entirely), while the adaptive engine detected 100% of attacks, with 0% false positives on benign users. The anomaly layer is strictly advisory: it reads audit rows and never alters enforcement decisions."));

// SECTION F - Evaluation
c.push(H1("F. Evaluation and testing"));
c.push(Q("How many automated tests exist and what do they verify?"));
c.push(A("299 automated tests across 28 test suites, all passing with 0 failures (python -m pytest tests/ -q). They cover authentication, direct/nested/multi-ID BOLA, variables, fragments, ownership inference, policy rules, risk scoring, audit logging, adaptive anomaly detection, real-time research engine, multi-tenant boundaries, and a dedicated 15-test automated remediation suite."));
c.push(Q("How fast does the test suite run?"));
c.push(A("The full 299-test suite completes in approximately 60 seconds on a standard laptop. The dedicated remediation verification script (scripts/verify_audit_remediation.py) executes all 15 automated checks in under 7 seconds."));
c.push(Q("What is the runtime performance overhead?"));
c.push(A("Measured over 2,000 requests (1,000 baseline, 1,000 protected), the average latency without the gateway was ~9.3-10.5 ms and with the gateway was ~25.6-26.2 ms, adding approximately 15-17 ms per request. This includes AST parsing, ownership caching, policy evaluation, and audit persistence."));
c.push(Q("How does the test suite exercise the HTTP gateway without relying on a pre-running background server?"));
c.push(A("The test suite and verification scripts utilize FastAPI's ASGI TestClient(app) transport, which instantiates the complete application dependency graph, executes middleware and route dependencies, dispatches requests through the Strawberry GraphQL engine, and records true HTTP status codes and headers in-process. This allows evaluators to reproduce all 299 tests and 15 remediation checks cleanly from a fresh checkout using the standard pytest runner, without depending on an external server daemon. Alternatively, when uvicorn is launched following SETUP.md, the exact same endpoints execute over network TCP sockets."));

// SECTION G - Demo & operations
c.push(H1("G. Demonstration and operations"));
c.push(Q("How do I run the project from scratch for the examiner?"));
c.push(...code([
  "python -m venv venv",
  "venv\\Scripts\\activate            (Windows)",
  "pip install -r requirements.txt",
  "python -m app.seed",
  "python scripts/verify_audit_remediation.py   # 15/15 checks pass in <7s",
  "uvicorn app.main:app --host 127.0.0.1 --port 8000",
  "open http://localhost:8000/dashboard",
]));
c.push(Q("What does the live demo show?"));
c.push(A("1. Legitimate query returning 200 OK. 2. Direct BOLA returning 403 OWNERSHIP_MISMATCH (risk 80). 3. Nested BOLA returning 403 NESTED_AUTHORIZATION_VIOLATION (risk 100). 4. Tenant header override returning 403 TENANT_HEADER_MISMATCH. 5. Live audit logging and anomaly scores on the dashboard. 6. Automated execution of generalization corpus v2."));

// SECTION H - Automated Technical Remediations & Examiner Defense
c.push(H1("H. Automated Technical Remediations & Examiner Defense"));
c.push(Q("Remediation 1: 'Gateway-only' was not an actual gateway execution in the research evaluator. How did you fix this?"));
c.push(A("We implemented evaluate_case_method_b_live_gateway() in app/security/research/evaluator.py. This executes test cases via real HTTP POST requests to /graphql over an active HTTP client transport, recording true HTTP status codes, GraphQL error structures, response headers, and persisted audit records. We retained the direct policy evaluation as evaluate_case_method_b_direct_policy to serve as an explicit, honest comparative baseline."));
c.push(Q("Remediation 2: Mutation safety was not executing mutations. How was this fixed?"));
c.push(A("We completely overhauled verify_mutation_safety(). It now performs genuine execution: it captures the pre-mutation SQLite row state, dispatches the unauthorized mutation to /graphql, verifies the 403 DENY response, captures post-mutation SQLite row state, asserts exact bitwise state preservation (db_state_preserved=True), and rolls back test data. Read queries are explicitly marked NOT_TESTED rather than reported as safe mutations."));
c.push(Q("Remediation 3: Metric correlation: how did you disentangle binary detection from path attribution?"));
c.push(A("We separated evaluation metrics into four independent fields: (1) binary_detection (TP/FP/TN/FN), (2) exact_path_attribution (canonical AST path matching), (3) target_object_attribution (correct object ID isolated), and (4) evidence_provenance. This proves that runtime correlation's primary benefit is eliminating static false alarms and providing exact AST path explainability, without conflating path accuracy with binary detection."));
c.push(Q("Remediation 4: Generalization corpus v2 semantics — how did you verify it?"));
c.push(A("We verified that all 60 cases across 9 categories in data/generalization_corpus_v2.json (including tuning, held_out, and adversarial_stress splits) execute through the live gateway. In held_out execution, the gateway correctly blocked 100% of held-out BOLA mutations and aliases over HTTP with zero state tampering."));
c.push(Q("Remediation 5: Statistical rigor and McNemar test p-value formatting — how is it fixed?"));
c.push(A("Earlier versions truncated p-values below 0.0001 to 0.0000. In app/security/research/evaluator.py, compute_mcnemar_test() now uses scientific notation formatting (p_value_formatted, e.g. 4.52e-11). This demonstrates that the reduction in false alarms achieved by runtime correlation is statistically significant (p < 10^-4) without deceptive rounding."));
c.push(Q("Security Remediation: Tenant identity integrity — how do you prevent client X-Tenant-Id header spoofing?"));
c.push(A("In app/security/enforcement.py, resolve_authoritative_tenant() derives tenant identity directly from the cryptographically signed JWT. If a non-admin client provides an X-Tenant-Id header that differs from their JWT tenant, the gateway immediately rejects it with HTTP 403 TENANT_HEADER_MISMATCH. Unauthenticated tenant headers return 403 TENANT_UNAUTHORIZED_HEADER. Missing tenant claims on multi-tenant resources fail closed with TENANT_CONTEXT_MISSING. Admin cross-tenant access is governed by SUPERADMIN_CROSS_TENANT_OVERRIDE with explicit audit logging."));
c.push(Q("Security Remediation: Production route hardening — how are research write routes protected?"));
c.push(A("All evaluation write routes (/api/v1/research/run-case, /run-batch, /evaluate-case) are protected with require_admin_user. Unauthenticated callers receive 401, non-admin callers receive 403, and test runs cannot modify system state without administrative authorization."));

// SECTION I - Competitive Calibration & Future Work
c.push(H1("I. Competitive Calibration and Proposed Future Extensions"));
c.push(Q("How does CCNS compare to GraphQL Armor, Apollo Router, and Inigo?"));
c.push(A("We maintain strict academic calibration: Apollo supports field/type authorization directives (@authenticated) and policy-based authorization; GraphQL Armor provides alias and cost limits; Inigo offers query planning controls. Our empirical benchmark evaluates specific capabilities: under our evaluated testbed, CCNS uniquely provides canonical AST path attribution (resolving aliases and fragments) correlated with dynamic object ownership evidence at the pre-resolver gateway layer. We do not claim competitors lack all security features."));
c.push(Q("What are your four proposed extensions, and why are they future work?"));
c.push(A("We designed: (1) Temporal traversal detection (sequential ID distance + velocity bursts to catch automated scraping), (2) Field-level selective masking (nullifying unauthorized fields rather than dropping entire queries), (3) Cross-platform policy synthesis (exporting Cedar/Rego policies), and (4) Role-based introspection filtering. In accordance with examiner guidance and our deadline, these are strictly categorized as proposed future work to focus 100% of our defense on our verified, tested core contributions."));
c.push(Q("What is the team breakdown?"));
c.push(A("The project spans AST extraction & query normalization, ownership inference & DB integration, policy & risk engine, tenant identity integrity, live gateway execution, test suite & automated remediations, and reporting/presentation artifacts. Each member can speak to specific architectural modules and test assertions."));

const doc = new Document({
  creator: "GraphQL Shield Team",
  title: "GraphQL Shield — Viva Q&A (Examiner Rigor Edition)",
  styles: { default: { document: { run: { font: FONT, size: 22 } }, heading1: { run: { font: FONT, size: 28, bold: true, color: ACCENT } }, heading2: { run: { font: FONT, size: 24, bold: true, color: ACCENT2 } } } },
  numbering: { config: [{ reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT, style: { run: { font: FONT }, paragraph: { indent: { left: 540, hanging: 280 } } } }] }] },
  sections: [{ properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } } }, children: c }],
});

Packer.toBuffer(doc).then((buf) => { fs.writeFileSync(OUT, buf); console.log("WROTE " + OUT + " (" + buf.length + " bytes)"); }).catch((e) => { console.error(e); process.exit(1); });
