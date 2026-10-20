const fs = require("fs");
const path = require("path");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, AlignmentType,
  Table, TableRow, TableCell, WidthType, BorderStyle, ImageRun,
  TableOfContents, PageBreak, ShadingType, LevelFormat,
} = require("docx");

const ROOT = path.join(__dirname, "..", "..");
const OUT = path.join(ROOT, "CCNS_Project_Report.docx");
const FONT = "Calibri";
const MONO = "Consolas";
const ACCENT = "1F3A5F";
const ACCENT2 = "2E6E9E";
const LIGHT = "EEF3F8";

function t(text, opts = {}) { return new TextRun({ text, font: FONT, size: opts.size || 22, bold: opts.bold, italics: opts.italics, color: opts.color, break: opts.break }); }
function P(text, opts = {}) {
  const runs = Array.isArray(text) ? text : [t(text, opts)];
  return new Paragraph({ children: runs, spacing: { after: opts.after || 140, line: 276 }, alignment: opts.align, ...(opts.para || {}) });
}
function H1(text) { return new Paragraph({ text, heading: HeadingLevel.HEADING_1, spacing: { before: 320, after: 160 }, thematicBreak: false }); }
function H2(text) { return new Paragraph({ text, heading: HeadingLevel.HEADING_2, spacing: { before: 240, after: 120 } }); }
function H3(text) { return new Paragraph({ text, heading: HeadingLevel.HEADING_3, spacing: { before: 180, after: 100 } }); }
function B(items) {
  return items.map((it) => new Paragraph({
    children: Array.isArray(it) ? it : [t(it)],
    numbering: { reference: "bullets", level: 0 },
    spacing: { after: 80, line: 264 },
  }));
}
function code(lines) {
  const arr = Array.isArray(lines) ? lines : [lines];
  return arr.map((ln, i) => new Paragraph({
    children: [new TextRun({ text: ln === "" ? " " : ln, font: MONO, size: 18, color: "1B1B1B" })],
    shading: { type: ShadingType.CLEAR, fill: "F4F6F8" },
    spacing: { after: i === arr.length - 1 ? 160 : 0, line: 240 },
  }));
}
function cell(text, o = {}) {
  const runs = Array.isArray(text) ? text : [new TextRun({ text: String(text), font: FONT, size: o.size || 19, bold: o.bold, color: o.color, italics: o.italics })];
  return new TableCell({
    children: [new Paragraph({ children: runs, spacing: { after: 20, line: 240 }, alignment: o.align })],
    width: { size: o.w, type: WidthType.DXA },
    shading: o.fill ? { type: ShadingType.CLEAR, fill: o.fill } : undefined,
    margins: { top: 60, bottom: 60, left: 100, right: 100 },
  });
}
function table(header, rows, widths) {
  const head = new TableRow({ tableHeader: true, children: header.map((h, i) => cell(h, { bold: true, color: "FFFFFF", fill: ACCENT, w: widths[i] })) });
  const body = rows.map((r, ri) => new TableRow({ children: r.map((c, i) => cell(c, { w: widths[i], fill: ri % 2 ? LIGHT : undefined })) }));
  return new Table({ rows: [head, ...body], width: { size: widths.reduce((a, b) => a + b, 0), type: WidthType.DXA }, columnWidths: widths, borders: { top: { style: BorderStyle.SINGLE, size: 2, color: "BFCBD6" }, bottom: { style: BorderStyle.SINGLE, size: 2, color: "BFCBD6" }, left: { style: BorderStyle.SINGLE, size: 2, color: "BFCBD6" }, right: { style: BorderStyle.SINGLE, size: 2, color: "BFCBD6" }, insideHorizontal: { style: BorderStyle.SINGLE, size: 1, color: "D6DEE6" }, insideVertical: { style: BorderStyle.SINGLE, size: 1, color: "D6DEE6" } } });
}
function img(file, w, h, caption) {
  const out = [];
  if (fs.existsSync(file)) {
    out.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 120, after: 40 }, children: [new ImageRun({ type: "png", data: fs.readFileSync(file), transformation: { width: w, height: h } })] }));
    if (caption) out.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 160 }, children: [new TextRun({ text: caption, font: FONT, size: 18, italics: true, color: "55606B" })] }));
  } else {
    out.push(new Paragraph({ children: [new TextRun({ text: `[Figure not found: ${path.basename(file)}]`, font: FONT, size: 18, italics: true, color: "A33" })] }));
  }
  return out;
}

const children = [];

// ---------- Cover ----------
children.push(new Paragraph({ spacing: { before: 1400, after: 0 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "GraphQL Shield", font: FONT, size: 60, bold: true, color: ACCENT })] }));
children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 80 }, children: [new TextRun({ text: "Schema-Aware Security Gateway for Preventing GraphQL BOLA Vulnerabilities", font: FONT, size: 28, color: ACCENT2 })] }));
children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 400 }, children: [new TextRun({ text: "Project Report", font: FONT, size: 24, italics: true, color: "55606B" })] }));
children.push(table(
  ["Field", "Detail"],
  [
    ["Course", "Computer Communication and Network Security (CCNS)"],
    ["Project Title", "GraphQL Shield: Schema-Aware Security Gateway for Preventing GraphQL BOLA Vulnerabilities"],
    ["Team Members", "Agnihotram Chinmayanand (RA2311053010116), B.V. Balanilavan (RA2311053010123), Kapilesh.N (RA2311053010125), Sakthivel.B (RA2311053010126)"],
    ["Deliverable Type", "Working prototype + report + presentation + live demonstration"],
    ["Repository", "GraphQL-Shield (FastAPI + Strawberry GraphQL gateway)"],
    ["Status", "Complete - 299 automated tests passing; 15/15 audit remediation checks verified"],
  ],
  [2600, 6760]
));
children.push(new Paragraph({ spacing: { before: 300 }, children: [new TextRun({ text: "All results, screenshots and measurements in this report were produced from the actual running system described in the repository. Traffic, scores and latency figures are not fabricated; they are the real output of the evaluation scripts and live gateway.", font: FONT, size: 18, italics: true, color: "55606B" })] }));
children.push(new Paragraph({ children: [new PageBreak()] }));

// ---------- TOC ----------
children.push(new Paragraph({ text: "Table of Contents", heading: HeadingLevel.HEADING_1 }));
children.push(new TableOfContents("Contents", { hyperlink: true, headingStyleRange: "1-3" }));
children.push(new Paragraph({ children: [new PageBreak()] }));

// 1 Abstract
children.push(H1("1. Abstract"));
children.push(P("GraphQL is increasingly deployed as a single, richly-typed endpoint for modern APIs, but its flexible query language moves authorization decisions into application resolvers where they are easy to implement inconsistently. The most serious resulting class of vulnerability is Broken Object Level Authorization (BOLA / IDOR), ranked OWASP API Security Top 10 #1, in which a client requests an object it does not own by manipulating an identifier. Because GraphQL resolvers execute in a depth-first traversal of the query graph and often nest objects beneath other objects, an object may be reached through paths the developer never explicitly protected."));
children.push(P("GraphQL Shield is a dedicated, schema-aware security gateway that sits in front of a GraphQL backend and enforces zero-trust authorization before any resolver executes. It parses the incoming query's abstract syntax tree (AST), extracts every object type and identifier the query will touch - including nested and variable-driven accesses - resolves ownership from an explicit database lookup that is validated against ownership relationships inferred from the GraphQL schema itself, evaluates a context-sensitive policy, computes a deterministic risk score, persists a full audit record, and blocks denied requests at the edge with HTTP 403 before backend processing."));
children.push(P("The project makes two clearly separated contributions. Its primary contribution is a schema-aware AST taint analysis whose findings are correlated with runtime authorization evidence, producing accurate source-to-sink path attribution without changing enforcement: on an independent 115-case benchmark it eliminates the 81.1% false-alarm rate of pure static taint analysis (down to 0.0%) while raising exact path attribution from 56.2% to 90.5% (95/105) under strict canonical matching and 100.0% (105/105) under semantic target attribution, with zero policy divergence. Its secondary, complementary novelty is an adaptive, unsupervised behavioural anomaly-detection layer over the audit stream: where a static per-event engine scores each request in isolation, this layer aggregates per-principal features - denial ratio, target breadth, request velocity and denial trend - into an explainable 0-100 score using a robust peer-relative baseline blended with absolute behavioural floors. On real gateway traffic the static baseline detected 50% of a two-behaviour attack set while the adaptive engine detected 100%, with 0% false positives in both cases. The anomaly layer is strictly advisory: it never grants, denies, or alters an enforcement decision."));

// 2 Introduction
children.push(H1("2. Introduction and Motivation"));
children.push(P("Modern applications increasingly expose a single GraphQL endpoint that fronts many resources. This concentration of functionality gives clients enormous expressive power: one request can traverse users, their resources, nested resources, and sensitive fields in a single round trip. The same power that makes GraphQL productive also makes it dangerous, because the surface an attacker can probe is far larger than in a REST API of comparable scope."));
children.push(P("Broken Object Level Authorization (BOLA) - also known as Insecure Direct Object Reference (IDOR) - occurs when an endpoint accepts an object identifier from the client and returns the corresponding object without verifying that the caller is authorized to access that specific object. It is consistently ranked as the single most prevalent API security risk (OWASP API Security Top 10 2019/2023: API1). In GraphQL the problem is amplified because objects are frequently reachable through multiple paths, and a resolver for a nested field may return an object whose ownership is never checked against the requesting user."));
children.push(P([t("The core insight motivating this project is that "), t("security must not depend on every resolver author remembering to perform an ownership check", { bold: true, color: ACCENT }), t(". A centralized gateway that understands the shape of the data (the GraphQL schema) and the shape of each request (its AST) can enforce ownership uniformly, at one place, before any backend work happens.")]));
children.push(H3("Objectives"));
children.push(...B([
  "Intercept GraphQL queries before resolver execution and reject unauthorized object access at the edge.",
  "Extract every requested object type and identifier from the AST, including nested, aliased, variable-driven and fragment-spread accesses.",
  "Resolve ownership from authoritative instance data, validated and explained by relationships inferred from the GraphQL schema.",
  "Fail closed: any object type whose ownership cannot be explained by an explicit or inferred rule is denied.",
  "Produce a deterministic, auditable risk score for every decision and persist it.",
  "Add a complementary adaptive behavioural layer that detects aggregate abuse patterns invisible to per-event scoring.",
  "Demonstrate measurably lower BOLA exposure versus an unprotected endpoint, with quantified performance overhead.",
]));

// 3 Background / Related work
children.push(H1("3. Background and Related Work"));
children.push(H2("3.1 The GraphQL execution model"));
children.push(P("A GraphQL server publishes a strongly-typed schema. A client submits a query document; the server validates it against the schema and then executes it by resolving fields, potentially recursively, along the query's selection set. Field resolvers are plain functions and execute with no built-in notion of \"the current user's rights to this object\". Authorization is entirely the application's responsibility, which is precisely where BOLA arises."));
children.push(H2("3.2 Existing mitigations and their gaps"));
children.push(...B([
  [t("Resolver-level checks. ", { bold: true }), t("Effective when applied, but must be repeated for every object-returning field and every path, and are easy to omit. They are also hard to audit centrally.")],
  [t("Field-level authorization libraries. ", { bold: true }), t("Libraries such as graphql-shield express per-field rules; they remain per-field declarations and do not reason about instance-level ownership of the objects a query will touch.")],
  [t("Query cost / depth limiting. ", { bold: true }), t("Caps resource-exhaustion attacks but does not distinguish an authorized bulk read from an unauthorized one; both count as cost.")],
  [t("WAF / rate limiting. ", { bold: true }), t("Operates on transport-level signals and cannot see which object identifiers a GraphQL body actually dereferences.")],
]));
children.push(P("GraphQL Shield differs by moving the enforcement point to a schema-aware gateway that reads the query AST, understands which instances would be dereferenced, resolves their ownership, and blocks at the edge - and, on top of that, by attributing each taint finding to a canonical schema path (its primary contribution) and layering a behavioural anomaly engine on the resulting audit stream (a secondary, complementary novelty)."));

// 4 Architecture
children.push(H1("4. System Architecture"));
children.push(P("GraphQL Shield is implemented as an ASGI application (FastAPI) with a Strawberry GraphQL backend running behind a security gateway. The gateway is realized as a FastAPI dependency - bola_enforcement_middleware in app/security/enforcement.py - that runs before the GraphQL route handler and therefore before any resolver. The pipeline is linear, fail-closed, and fully auditable."));
children.push(H3("Request pipeline"));
children.push(table(
  ["#", "Stage", "Component", "Responsibility"],
  [
    ["1", "Authentication", "app/core/security.py", "Extract and verify the JWT; resolve user_id and role."],
    ["2", "Body parse", "enforcement.py", "Read the JSON body; extract query, variables, operationName."],
    ["3", "Budget check", "graphql_parser.validate_query_budget", "Reject queries exceeding depth 15 / complexity 150."],
    ["4", "AST taint analysis", "taint_engine.analyze_query_taint", "Audit-only static taint over the query (fail-safe)."],
    ["5", "AST normalization", "object_extractor.normalize_query", "Extract every (type, id, path) the query dereferences."],
    ["6", "Ownership resolution", "ownership.resolve_ownership", "Explicit DB lookup validated by schema-inferred rules; else fail closed."],
    ["7", "Policy evaluation", "authorization.PolicyEngine", "Apply zero-trust ownership rules; produce ALLOW/DENY + reason."],
    ["8", "Risk scoring", "risk_engine.calculate_risk", "Deterministic 0-100 score with LOW/MEDIUM/HIGH band."],
    ["9", "Audit logging", "audit.log_decision", "Persist full decision context to SQLite."],
    ["10", "Enforcement", "enforcement.py", "ALLOW -> Strawberry executes; DENY -> HTTP 403, backend never runs."],
  ],
  [600, 1900, 2900, 3960]
));
children.push(P("Two additional, advisory subsystems read the persisted audit stream: the differential-testing engine (app/security/differential_testing) and the adaptive anomaly engine (app/security/anomaly_engine.py). Neither can change an enforcement outcome. The AI analyst (app/security/ai_analyst) produces natural-language explanations of decisions."));
children.push(H2("4.1 Demonstration schema"));
children.push(P("The prototype ships a deliberately minimal but realistic schema that models the ownership relationships BOLA exploits depend on:"));
children.push(...code([
  "type User    { id: ID!, username: String!, role: String!, resources: [Resource!]!, resource(id: ID): Resource, secret_token: String! }",
  "type Resource{ id: ID!, name: String!, owner_id: ID!, object_type: String!, parent_id: ID, children: [Resource!]!, secret_key: String! }",
]));
children.push(P("User.resources and User.resource model nested access paths (the classic nested-BOLA vector); Resource.owner_id models scalar ownership; User.id models self-ownership. Resource.secret_key and User.secret_token model sensitive fields subject to field-level leakage."));
children.push(H2("4.2 Data flow diagram"));
children.push(...img(path.join(ROOT, "docs", "screenshots", "dashboard_top.png"), 600, 400, "Figure 1 - Live security dashboard (top of page) served by the gateway at /dashboard, showing real audit summary counters updated from actual traffic."));
children.push(P("The dashboard is a live HTML client of the public aggregation endpoint /api/v1/dashboard-stats. It renders total events, allowed/blocked counts, BOLA blocks, a live connection indicator with a last-update timestamp, and the adaptive anomaly panel described in Section 8."));

// 5 Tech stack
children.push(H1("5. Technology Stack"));
children.push(table(
  ["Layer", "Technology", "Role"],
  [
    ["Application server", "FastAPI (ASGI, Starlette)", "Routing, dependency injection, middleware boundary."],
    ["GraphQL engine", "Strawberry GraphQL", "Typed schema, resolvers, AST-aware types."],
    ["Gateway logic", "Python 3.14 standard library + custom modules", "AST extraction, ownership, policy, risk, enforcement."],
    ["Persistence", "SQLite (sqlite3)", "Users, objects, audit logs, taint audit records."],
    ["Auth", "JWT (HS256)", "Signed bearer tokens carrying user_id and role."],
    ["Front-end", "Vanilla HTML/CSS/JS dashboard", "Live monitoring UI, polling aggregation endpoints."],
    ["Testing", "pytest", "299 automated tests across 28 files, including 15 dedicated audit remediation checks."],
    ["Reporting tooling", "Node.js + docx / pptxgenjs", "Generation of this report and the slide deck."],
  ],
  [2200, 3300, 3860]
));

// 6 Design & implementation
children.push(H1("6. Design and Implementation"));
children.push(H2("6.1 Authentication"));
children.push(P("POST /api/v1/auth/login verifies a username/password pair against the seeded SQLite users table and issues an HS256 JWT containing the user id and role. All protected routes depend on get_current_user, which decodes and validates the token; an invalid or missing token yields HTTP 401 before the gateway sees any query. A demo-session endpoint can mint short-lived tokens when ENABLE_DEMO_SESSION is enabled."));
children.push(H2("6.2 AST parsing and object extraction"));
children.push(P("object_extractor.normalize_query parses the GraphQL document and traverses its selection set. It resolves fragment spreads and variable placeholders so that an identifier supplied through a variable is treated exactly like one written inline. For every reachable object it emits a record of (type, id, path), where path is the dotted field path (for example user.resource or resource.children). The result is the authoritative list of instances the query would dereference - computed before anything is executed."));
children.push(H2("6.3 Schema-aware ownership inference"));
children.push(P("The gateway does not hard-code which field of which type owns an object. At startup (the startup event in app/main.py) app/security/ownership_inference.py walks the Strawberry type registry once and builds an internal model of (field name, resolved type name) for every object type. Field names and type names are normalized (ownerId to owner_id; Resource equals ResourceType) so that query-derived names and schema names line up. The model is stored in a read-only singleton; no schema analysis is repeated per request."));
children.push(P("The engine accepts a defined and explainable set of patterns rather than inferring arbitrary ownership:"));
children.push(...B([
  [t("Pattern A - object reference: ", { bold: true }), it2("Resource.owner: User -> Resource.owner -> User")],
  [t("Pattern B - collection: ", { bold: true }), it2("User.resources: [Resource] -> User.resources -> Resource")],
  [t("Pattern C - scalar identifier: ", { bold: true }), it2("Resource.ownerId: ID -> Resource.ownerId -> User")],
  [t("Pattern D - nested chains of A/B/C. ", { bold: true }), it2("User -> resources -> Resource -> owner")],
]));
children.push(P("Matching is driven by a configurable naming list (owner, owner_id, user_id, created_by, author, ...). A relationship that matches a name but cannot be validated - for example createdBy: String, a label rather than a reference - is not accepted; it is recorded as ambiguous in the report."));
children.push(H2("6.4 Explicit policies always take precedence"));
children.push(P("Ownership is resolved in a fixed priority order, printed by the inspection endpoint and the startup log:"));
children.push(...code([
  "1. Explicit configured authorization / ownership rule (and the authoritative database ownership lookup)",
  "2. Validated schema-inferred ownership rule (used to explain and to gate the lookup)",
  "3. UNKNOWN OWNERSHIP -> explicit policy required -> DENY",
]));
children.push(P("Inference never overrides an explicit rule and never invents an owner id: the owner of an instance is always read from the explicit database lookup. The inference engine only tells the gateway which relationship to expect for a type, and annotates every decision with the rule that justified it. The current real schema yields:"));
children.push(...code([
  "GraphQL types analyzed:               3",
  "Ownership relationships detected:      3",
  "High-confidence rules:                 2   (ResourceType.owner_id->UserType, UserType.id->UserType)",
  "Medium-confidence rules:               1   (UserType.resources->ResourceType)",
  "Ambiguous/rejected relationships:      0",
]));
children.push(H2("6.5 Policy engine"));
children.push(P("authorization.PolicyEngine evaluates a structured AuthorizationContext (user_id, role, operation, object_type, object_id, path, owner_id, metadata) and returns a decision with a machine-readable reason. Representative reasons include OWNER_MATCH (allow), OWNERSHIP_MISMATCH (deny), NESTED_AUTHORIZATION_VIOLATION (deny), UNKNOWN_OWNERSHIP (deny, fail-closed), and TENANT_ISOLATION_VIOLATION (deny). A global ADMIN override is supported for administrative reads."));
children.push(H2("6.6 Risk engine"));
children.push(P("risk_engine.calculate_risk produces a deterministic 0-100 score and a severity band (LOW < 30, MEDIUM < 60, HIGH >= 60) using explicit, auditable rules:"));
children.push(...code([
  "+80  decision reason is an ownership/authorization violation (OWNERSHIP_MISMATCH, NESTED_AUTHORIZATION_VIOLATION,",
  "     UNKNOWN_OWNERSHIP, TENANT_ISOLATION_VIOLATION)",
  "+20  the access is nested (path contains '.')",
  "+10  the principal has >=1 DENY in the last 10 minutes",
  "cap  score at 100; map to LOW / MEDIUM / HIGH",
]));
children.push(H2("6.7 Enforcement and audit logging"));
children.push(P("When a decision is DENY, the gateway raises HTTPException(403) carrying decision, user_id, object_id, reason, risk_score and risk_level; the Strawberry backend is never invoked. When ALLOW, control passes to the GraphQL engine. Every decision is persisted by audit.log_decision to the audit_logs table (user_id, role, operation, object_type, object_id, path, decision, reason, risk_score, risk_level, timestamp). Enforcement never depends on audit success: a logging failure is caught and the request proceeds or is blocked on its merits."));
children.push(H2("6.8 Primary contribution: schema-aware AST taint analysis and dual-path attribution"));
children.push(P("A static taint engine (app/security/taint_engine.py + taint_correlation.py) analyses the query before execution, identifying direct and indirect BOLA candidates, then correlates each candidate with the runtime authorization decision. In the current configuration (TAINT_ANALYSIS_MODE=audit_only) it records findings but does not gate traffic; it is fail-safe - an analyzer error never breaks a live request."));
children.push(P("This is the project's primary research contribution. On the independent 115-case benchmark (105 valid: 52 vulnerable / 53 benign, 10 malformed), pure static taint analysis flags 43 of 53 benign owner requests, an 81.1% false-alarm rate; correlating taint findings with runtime authorization evidence removes those false alarms entirely (0.0% FAR) while preserving the gateway's 100% precision and recall. Dual-path canonicalization also raises exact source-to-sink path attribution from 56.2% (gateway logging alone) to 90.5% (95/105) under strict canonical matching and 100.0% (105/105) under semantic target attribution, by resolving client aliases to canonical schema coordinates. Across all 115 cases the correlated layer changed zero enforcement decisions."));
children.push(table(
  ["Method", "Precision", "Recall", "False-Alarm Rate", "Exact Canonical Match", "Semantic Attribution"],
  [
    ["M1 - Gateway alone", "100.0%", "100.0%", "0.0%", "56.2% (59/105)", "65.7% (69/105)"],
    ["M2 - Static taint alone", "54.7%", "100.0%", "81.1%", "90.5% (95/105)", "100.0% (105/105)"],
    ["M3 - Correlated (ours)", "100.0%", "100.0%", "0.0%", "90.5% (95/105)", "100.0% (105/105)"],
  ],
  [2200, 1200, 1200, 1600, 1800, 1360]
));
children.push(P([t("Strict Canonical Match vs. Semantic Attribution Correctness: ", { bold: true }), t("The benchmark corpus contains 115 total cases. Ten malformed queries test parser resilience and cannot yield an AST path, leaving 105 valid, parseable cases (52 vulnerable BOLA cases and 53 benign authorized queries) as the eligible denominator. Under strict verbatim string equality against ground truth (Norm(Reported) = Norm(Expected)), Methods 2 and 3 achieved 95 exact matches (90.48%) and 10 partial matches (9.52%). Analysis of the evaluation ground-truth identified an introspection defect: for CORPUS-084 (query { __typename }), a substring check for '__type' originally misassigned expected path '__type'; evaluating via exact GraphQL AST schema coordinates resolves CORPUS-084 to '__typename' (matching the extractor). The remaining 10 non-exact cases are nested queries (CORPUS-027-030, CORPUS-036, CORPUS-038, CORPUS-054-055, CORPUS-114-115) where the extractor correctly isolated hierarchical coordinates (['user', 'user.resource']) vs. ground truth's flat root string ('resource, user'). When evaluated using explicit target-path semantics rather than flat string similarity, both User and Resource targets are fully identified, yielding 0 incorrect attributions (0.0%) and 0 omitted targets (0.0%), confirming 100.0% semantic target attribution (105/105).")]));
children.push(P([t("Reproduce: ", { bold: true }), t("scripts/build_ground_truth_corpus.py, scripts/evaluate_taint_corpus.py and scripts/evaluate_phase_7.py (see SETUP.md section 5). Canonical metrics: docs/RESULTS_SUMMARY.json; raw transcripts: docs/evidence/.")]));
children.push(H2("6.9 Differential-testing engine"));
children.push(P("app/security/differential_testing discovers authorization paths, generates queries, executes them against the secured endpoint, minimizes failing queries, and exports results as SARIF and JUnit for CI integration. It is exposed under /api/v1/differential-testing/*."));
children.push(H2("6.10 AI analyst"));
children.push(P("app/security/ai_analyst assembles the evidence for a decision and produces a natural-language explanation. It is provider-agnostic (a deterministic local provider plus optional external LLM providers), and is advisory only. Status and explanation endpoints are available under /api/v1/security/ai-analyst/*."));
children.push(H2("6.11 Authorization research engine (real-time discovery to verified finding)"));
children.push(P("Beyond the experimental differential-testing engine, app/security/recon/ is a self-contained research engine that closes the loop from a running service to a machine-checkable finding. Given the base URL of a live GraphQL service it (1) discovers the schema over real HTTP, (2) generates an authorization test suite from the discovered types and ownership-shaped fields, (3) executes every test as a real HTTP request against both the protected gateway and a labelled deliberately-vulnerable reference backend, (4) decides each finding from a contradiction between the declared expectation and the object identity or persisted database state actually observed - never from an HTTP status code alone, (5) minimizes and reproduces any non-fixture finding, and (6) exports SARIF 2.1.0 and JUnit for CI. It is exposed under /api/v1/authorization-engine/* (discover, generate, run, runs, cancel, reproduce, export/sarif, export/junit), with a dark research workbench served at /workbench."));
children.push(P("Every test carries provenance: it is generated from the live schema, not hand-written. Because the only vulnerable target in the repository is the deliberately-labelled local reference backend, the engine reports leaks against that fixture as baseline sensitivity signals rather than findings against the protected gateway - a finding is only confirmed when the observed object identity or persisted state contradicts the expectation. Measured evaluation (scripts/evaluate_authorization_engine.py; raw output in docs/AUTHORIZATION_ENGINE_EVAL.json):"));
children.push(table(
  ["Metric", "Measured"],
  [
    ["Tests generated and executed", "18"],
    ["Passed / failed / inconclusive", "17 / 0 / 1"],
    ["Confirmed vulnerabilities", "0"],
    ["False positives", "0"],
    ["Fixture-baseline leaks (labelled vulnerable reference backend)", "11"],
    ["Schema path coverage", "87.5% (7 / 8 discovered fields)"],
    ["Seeded-defect detection", "100.0% (9 / 9)"],
    ["Mean latency per test", "118.12 ms"],
    ["Total run duration", "812.73 ms"],
  ],
  [6760, 2600]
));
children.push(P("Automation versus the hand-written baseline: test cases 4 -> 18, schema paths exercised 2 -> 7, seeded defects exercised 2 -> 9, nested path attribution absent -> present, and automatic minimization absent -> present. Reproduce with python scripts/evaluate_authorization_engine.py; the engine's own acceptance suite is tests/test_authorization_engine.py."));

// 7 API
children.push(H1("7. API Surface"));
children.push(table(
  ["Method", "Path", "Auth", "Purpose"],
  [
    ["GET", "/health", "none", "Liveness probe."],
    ["POST", "/api/v1/auth/login", "none", "Issue JWT for valid credentials."],
    ["POST", "/api/v1/auth/demo-session", "optional", "Mint a short-lived demo token (if enabled)."],
    ["POST", "/graphql", "JWT", "Secured GraphQL endpoint (gateway-enforced)."],
    ["POST", "/graphql-insecure", "none", "Unprotected replica used only for latency benchmarks."],
    ["GET", "/dashboard", "none", "Live HTML monitoring dashboard."],
    ["GET", "/api/v1/dashboard-stats", "none", "Aggregated stats + anomaly summary for the dashboard."],
    ["GET", "/api/v1/audit-logs", "ADMIN", "Recent security events."],
    ["GET", "/api/v1/security/schema-ownership", "ADMIN", "Inferred ownership rules, rejections and priority."],
    ["GET", "/api/v1/security/anomaly", "ADMIN", "Adaptive per-principal anomaly feed (secondary novelty)."],
    ["GET", "/api/v1/security/security-graph", "ADMIN", "Security relationship graph export."],
    ["GET", "/api/v1/security/taint-audit", "ADMIN", "Taint-audit records."],
    ["GET", "/api/v1/security/scenario-lab", "none", "Scenario catalogue for demos."],
    ["GET/POST", "/api/v1/differential-testing/*", "varies", "Discover, run, minimize, export differential suites."],
    ["GET/POST", "/api/v1/authorization-engine/*", "none", "Discover, generate, run, cancel, reproduce and export engine runs (SARIF/JUnit)."],
    ["GET", "/workbench", "none", "Research workbench UI for the authorization engine."],
    ["GET/POST", "/api/v1/security/ai-analyst/*", "JWT", "Explanation status and generation."],
  ],
  [1100, 3600, 900, 3760]
));

// 8 Novelty (secondary / complementary)
children.push(H1("8. Complementary Novelty (Secondary): Adaptive Behavioural Anomaly Detection"));
children.push(H2("8.1 The gap in per-event scoring"));
children.push(P("The deterministic risk engine scores every decision in isolation: an ownership mismatch is 80/HIGH, a clean access is 0/LOW. This is sufficient for single-request BOLA, but it has no principal-level memory. It cannot distinguish a one-off mistake from sustained abuse, and it assigns risk 0 to a compromised account that stays fully authorized while enumerating every record it can reach (mass data access), or to a low-and-slow scan that hides between ordinary reads. These are exactly the behaviours that per-event rules structurally cannot see."));
children.push(H2("8.2 Design"));
children.push(P("app/security/anomaly_engine.py adds a complementary, unsupervised, principal-level layer. It reads the audit events the gateway has already persisted and derives four behavioural signals per principal:"));
children.push(table(
  ["Signal", "Definition"],
  [
    ["deny_ratio", "Share of the principal's requests that were denied."],
    ["target_breadth", "Number of distinct object identifiers requested."],
    ["velocity", "Requests per minute within the principal's own activity span."],
    ["deny_trend", "Escalation of the deny ratio between the older and recent half of the history."],
  ],
  [2600, 6760]
));
children.push(P("Two adaptive mechanisms turn these into a score instead of a fixed table:"));
children.push(...B([
  [t("Robust peer-relative baseline. ", { bold: true }), t("Each feature becomes a median/MAD robust z-score against the observed principal population, so \"normal\" moves with the traffic rather than being hard-coded.")],
  [t("Temporal drift. ", { bold: true }), t("deny_trend compares a principal against its own earlier behaviour, catching a stable principal that suddenly turns abusive.")],
]));
children.push(P("Each feature's deviation is max(peer z-score, value / documented absolute threshold). The absolute term is a floor that keeps the engine usable on the three-user demo population and during cold start, where a robust z-score against a tiny population saturates. Per-feature contributions are combined as (1-0.4)*weighted_mean + 0.4*peak, so one unmistakable indicator is not diluted by otherwise ordinary features. The output is a 0-100 score, a LOW/MEDIUM/HIGH level, and an explainable pattern label."));
children.push(...code([
  "Higher-level design (actual constants in anomaly_engine.py):",
  "  FEATURE_WEIGHTS   = { deny_ratio: 0.35, target_breadth: 0.25, velocity: 0.20, deny_trend: 0.20 }",
  "  AGGREGATION       = 0.6 * weighted_mean + 0.4 * peak",
  "  HIGH_THRESHOLD    = 60      MEDIUM_THRESHOLD = 30",
  "  Patterns          = SUSTAINED_AUTHORIZATION_ABUSE | HIGH_VELOCITY_ENUMERATION",
  "                      BROAD_TARGET_SCAN | ESCALATING_DENY_PATTERN | NO_PATTERN",
]));
children.push(P("The layer is strictly advisory: it never grants, denies, or mutates an enforcement decision. It reads persisted audit rows only. It is exposed at GET /api/v1/security/anomaly (ADMIN) and rendered live in dashboard panel 5."));
children.push(H2("8.3 Measured evaluation versus the baseline"));
children.push(P("scripts/evaluate_anomaly.py generates real traffic through the live gateway (so every audit row is produced by the real enforcement middleware) and compares the static per-event baseline (max single-event risk >= 60) against the adaptive engine (score >= 60) on the identical audit stream. Actual output:"));
children.push(table(
  ["Principal", "Ground truth", "Events", "Max static risk", "Static flagged", "Adaptive score", "Adaptive level", "Pattern"],
  [
    ["101", "benign", "3", "0", "no", "34", "MEDIUM", "NO_PATTERN"],
    ["102", "attack (mass authorized enumeration)", "15", "0", "no", "65", "HIGH", "HIGH_VELOCITY_ENUMERATION"],
    ["103", "benign (admin)", "2", "0", "no", "25", "LOW", "NO_PATTERN"],
    ["104", "attack (direct BOLA burst)", "6", "90", "yes", "80", "HIGH", "SUSTAINED_AUTHORIZATION_ABUSE"],
  ],
  [900, 2300, 700, 1000, 1000, 1100, 1150, 1410]
));
children.push(table(
  ["Engine", "Detection rate", "False-positive rate"],
  [
    ["Static per-event baseline", "50.0%", "0.0%"],
    ["Adaptive behavioural engine", "100.0%", "0.0%"],
  ],
  [4680, 2340, 2340]
));
children.push(P("The static engine flags the direct BOLA burst (risk 90) but structurally cannot flag the mass authorized enumeration, because every one of those events is a legitimate ALLOW with risk 0. The adaptive engine detects both behaviours from aggregate signals without flagging either benign principal. Full machine-readable output is written to anomaly_evaluation.json."));
children.push(H2("8.4 Honest limitations"));
children.push(...B([
  "The mass-enumeration case is authorized activity (no BOLA bypass); it is a behavioural anomaly, not an authorization failure. The layer complements - it does not replace - per-event BOLA enforcement.",
  "Thresholds and feature weights are configurable and were tuned on the small demo population. The benign principal scored 34 (MEDIUM, below the flag threshold). Larger deployments should re-tune on real traffic.",
  "The peer-relative term needs at least two active principals to discriminate; below that it falls back to absolute behavioural thresholds.",
  "The dashboard automatically runs the built-in differential-testing suite when it loads; those are real requests, so the anomaly panel legitimately aggregates them and test callers that repeatedly provoke denials will legitimately score HIGH. The controlled evaluation above uses an isolated database with no harness traffic.",
]));

// 9 Evaluation
children.push(H1("9. Evaluation and Results"));
children.push(H2("9.1 BOLA detection efficacy"));
children.push(P("scripts/evaluate_performance.py issues 2,000 requests to an unprotected replica (/graphql-insecure) and to the secured gateway (/graphql), comprising 500 legitimate accesses and 500 direct BOLA attempts per endpoint. Real measured results:"));
children.push(table(
  ["Endpoint", "Legitimate requests", "BOLA attempts", "BOLA blocked", "Detection rate", "False positives"],
  [
    ["/graphql-insecure (no gateway)", "500", "500", "0", "0.0%", "n/a"],
    ["/graphql (secured gateway)", "500", "500", "500", "100.0%", "0 / 0.0%"],
  ],
  [3000, 1400, 1100, 1100, 1400, 1360]
));
children.push(P("The protected endpoint blocks 100% of BOLA attempts while allowing 100% of legitimate requests - zero false positives."));
children.push(H2("9.2 Performance overhead"));
children.push(table(
  ["Metric", "Measured"],
  [
    ["Average latency without gateway (insecure)", "9.276 ms"],
    ["Average latency with gateway (secured)", "26.260 ms"],
    ["Authorization decision overhead added", "16.984 ms"],
    ["Requests measured", "2,000"],
  ],
  [6000, 3360]
));
children.push(P("The added overhead (about 15-17 ms on this host, measured across runs; latency is machine- and warm-state-dependent) is the cost of AST parsing, ownership resolution (with a 30-second TTL cache) and policy evaluation per request. As noted in Section 11, this is acceptable for the prototype and would be reduced in production by caching and connection pooling."));
children.push(H2("9.3 Live dashboard evidence"));
children.push(P("The dashboard below was captured from the running gateway after real traffic (legitimate access, direct BOLA, nested BOLA, forged token and the anomaly recon burst) had been recorded. It reflects genuine audit rows, not simulated data."));
children.push(...img(path.join(ROOT, "docs", "screenshots", "dashboard_full.png"), 430, 975, "Figure 2 - Full dashboard page showing event counters, BOLA blocks, recent audit table and the adaptive anomaly panel populated from real gateway traffic."));

// 10 Testing
children.push(H1("10. Testing and Verification"));
children.push(P("The system ships an automated test suite covering authentication, authorization, direct/nested/multi-ID/variable/fragment BOLA, the policy engine, risk scoring, audit logging, dashboards, schema-aware ownership inference, the security graph, taint propagation, the differential-testing engine, the AI analyst, adaptive anomaly detection, multi-tenant boundaries, and a dedicated 15-test audit remediation suite."));
children.push(...code([
  "$ python -m pytest tests/ -q",
  "299 passed in 60.52s",
  "$ python scripts/verify_audit_remediation.py",
  "All 15 audit remediation checks PASSED in 5.31s.",
]));
children.push(table(
  ["Metric", "Value"],
  [
    ["Test files", "28"],
    ["Tests collected", "299"],
    ["Passing", "299"],
    ["Failing", "0"],
    ["Audit remediation tests", "15 (tests/test_audit_remediation.py)"],
    ["Novelty-specific tests", "9 (tests/test_anomaly_detection.py)"],
    ["Engine acceptance tests", "13 (tests/test_authorization_engine.py)"],
  ],
  [4000, 5360]
));
children.push(P("Reproducibility: the following commands were executed against the delivered code and their real output is reflected throughout this report."));
children.push(...code([
  "python scripts/verify_audit_remediation.py -> 15 passed in 5.31s (all 5 audit findings remediated)",
  "python -m pytest tests/ -q                 -> 299 passed in 60.52s",
  "python -m app.seed                          -> Database successfully seeded",
  "python scripts/evaluate_anomaly.py          -> static 50.0% / adaptive 100.0% detection, 0% FP",
  "python -m scripts.evaluate_performance      -> secure 100% / insecure 0% BOLA block, ~15-17 ms overhead",
  "python scripts/generate_inference_report.py -> 3 types, 3 relationships, 2 high / 1 medium",
  "python scripts/evaluate_authorization_engine.py -> 18 tests, 87.5% schema coverage, 100% seeded-defect detection, 0 FP",
]));

// 11 Security analysis
children.push(H1("11. Security Analysis and Threat Model"));
children.push(H2("11.1 Threats addressed"));
children.push(...B([
  [t("Direct BOLA/IDOR: ", { bold: true }), t("client supplies an object id it does not own (resource(id: 102) as user 101) -> OWNERSHIP_MISMATCH, HTTP 403, risk 80.")],
  [t("Nested BOLA: ", { bold: true }), t("object reached under another object (user(id:101){ resource(id:102) }) -> NESTED_AUTHORIZATION_VIOLATION, HTTP 403, risk 100.")],
  [t("Variable/fragment-based BOLA: ", { bold: true }), t("identifier hidden in a variable or fragment -> resolved by the AST extractor and treated identically.")],
  [t("Tenant header spoofing: ", { bold: true }), t("client supplies X-Tenant-Id differing from JWT tenant -> TENANT_HEADER_MISMATCH, HTTP 403, logged.")],
  [t("Missing tenant context: ", { bold: true }), t("multi-tenant resource queried without tenant claim -> TENANT_CONTEXT_MISSING, HTTP 403, fail closed.")],
  [t("Forged / expired tokens: ", { bold: true }), t("rejected with HTTP 401 before the gateway runs.")],
  [t("Unknown-ownership types: ", { bold: true }), t("no explicit or inferred rule -> UNKNOWN_OWNERSHIP, fail closed.")],
  [t("Mass authorized enumeration: ", { bold: true }), t("detected by the advisory anomaly layer (behavioural, not an authorization failure).")],
]));
children.push(H2("11.2 Design principles"));
children.push(...B([
  [t("Fail closed: ", { bold: true }), t("uncertainty denies access; enforcement never depends on audit or analytics success.")],
  [t("Defense in depth: ", { bold: true }), t("budget limits, taint analysis, policy, risk and anomaly layers are independent.")],
  [t("Explainability: ", { bold: true }), t("every decision carries a machine-readable reason and the ownership rule that justified it.")],
  [t("Least privilege: ", { bold: true }), t("the gateway reads only what it needs; inference is read-only and never fabricates owners.")],
]));
children.push(H2("11.3 Automated Remediation Verification & Technical Defensibility"));
children.push(P("Following examiner feedback, five critical and high-priority technical remediations were implemented and verified with dedicated automated test coverage:"));
children.push(...B([
  [t("1. Live HTTP Gateway Execution: ", { bold: true }), t("evaluate_case_method_b_live_gateway() executes test queries through the real /graphql HTTP endpoint over a live socket, recording actual HTTP status codes, error payloads, and audit events, while direct-policy evaluation is retained as a distinct comparative baseline.")],
  [t("2. Genuine Mutation Safety Execution: ", { bold: true }), t("verify_mutation_safety() executes unauthorized mutations against the live endpoint and captures pre/post SQLite row states, verifying that the mutation was blocked (HTTP 403) and asserting bitwise state preservation (db_state_preserved=True). Read queries are explicitly marked NOT_TESTED.")],
  [t("3. Metric Disentanglement: ", { bold: true }), t("Binary detection accuracy (TP/FP/TN/FN) is evaluated independently from exact canonical AST path attribution and target object attribution, proving that runtime correlation's value is in eliminating static false alarms and providing exact path explainability.")],
  [t("4. Strict Tenant Identity Integrity: ", { bold: true }), t("Authoritative tenant identity is derived solely from the signed JWT payload. Client-supplied X-Tenant-Id headers that disagree are rejected with HTTP 403 TENANT_HEADER_MISMATCH. Missing tenant claims fail closed with TENANT_CONTEXT_MISSING. Admin cross-tenant access is governed by SUPERADMIN_CROSS_TENANT_OVERRIDE and audited.")],
  [t("5. Statistical Precision & Route Hardening: ", { bold: true }), t("McNemar test p-values are formatted in scientific notation (p < 10^-4) rather than truncated to 0.0000. All evaluation write routes are hardened with require_admin_user.")],
]));
children.push(H2("11.4 Residual risks"));
children.push(P("The prototype does not implement per-field RBAC beyond a global ADMIN override, relies on a naming heuristic for schema inference, and does not yet rate-limit by IP. These are documented as limitations and future work rather than presented as solved."));

// 12 limitations
children.push(H1("12. Known Limitations"));
children.push(...B([
  [t("Type inference. ", { bold: true }), t("The AST parser infers object types from field names (e.g. resource -> Resource) rather than full schema reflection; highly complex polymorphic schemas may bypass it.")],
  [t("Role-based limits. ", { bold: true }), t("Authorization is ownership matching plus a global ADMIN override; fine-grained per-field RBAC is not supported in this prototype.")],
  [t("Database overhead. ", { bold: true }), t("Ownership lookup queries SQLite per requested object (mitigated by a 30-second TTL cache); production would use Redis/Memcached.")],
  [t("Schema inference scope. ", { bold: true }), t("Only the defined pattern set is inferred; polymorphic owners, join tables and multi-tenant scoping fall back to UNKNOWN_OWNERSHIP unless explicitly configured.")],
  [t("Anomaly tuning. ", { bold: true }), t("Thresholds and weights were tuned on a small demo population and should be re-tuned on real traffic.")],
]));

// 13 future work
children.push(H1("13. Future Work"));
children.push(...B([
  [t("Learned anomaly models. ", { bold: true }), t("compare the current unsupervised, explainable layer against trained models (isolation forests, sequence models) once multi-day traffic is available.")],
  [t("Rate-limiting engine. ", { bold: true }), t("add a strict rate limiter for high-risk IPs or principals exhibiting medium-risk patterns.")],
  [t("Full schema introspection. ", { bold: true }), t("bind the gateway to the Strawberry schema registry to map aliases and unions to exact database tables without inference.")],
  [t("Distributed cache. ", { bold: true }), t("front ownership lookups with Redis to cut the per-request overhead.")],
  [t("Per-field authorization. ", { bold: true }), t("extend the policy engine from object-level to field-level RBAC.")],
]));

// 14 demo
children.push(H1("14. Demonstration Runbook (Summary)"));
children.push(P("The primary evaluation is a live manual demonstration. The full procedure is in DEMO_RUNBOOK.md; the abbreviated sequence is:"));
children.push(...code([
  "python -m venv venv; venv\\Scripts\\activate",
  "pip install -r requirements.txt",
  "python -m app.seed",
  "uvicorn app.main:app --host 127.0.0.1 --port 8000",
  "  -> open http://localhost:8000/dashboard",
  "  -> run the requests in LIVE_DEMONSTRATION_GUIDE.md (or: python scripts/run_demo.py)",
]));
children.push(P("The seven-step live script exercises: legitimate access (200), direct BOLA (403 OWNERSHIP_MISMATCH), nested BOLA (403 NESTED_AUTHORIZATION_VIOLATION), forged JWT (401), schema-ownership inspection (ADMIN), dashboard aggregation, and the adaptive anomaly feed showing a HIGH-scored principal."));

// 15 conclusion
children.push(H1("15. Conclusion"));
children.push(P("GraphQL Shield demonstrates that BOLA in GraphQL can be addressed centrally and measurably. By parsing the query AST before execution, resolving ownership from authoritative instance data validated against schema-inferred relationships, and failing closed when ownership is unexplainable, the gateway blocks 100% of direct and nested BOLA attempts in evaluation while allowing 100% of legitimate traffic, at a measured overhead of about 15-17 ms per request. The schema-aware inference layer removes hard-coded ownership knowledge from the gateway and makes every decision explainable."));
children.push(P("The project's primary contribution - correlating schema-aware AST taint analysis with runtime authorization evidence - removes the 81.1% false-alarm rate of static taint analysis and raises exact path attribution from 56.2% to 90.5% (95/105) under strict canonical matching and 100.0% (105/105) under semantic target attribution without changing a single enforcement decision across 115 benchmark cases. Its secondary contribution - an adaptive, unsupervised behavioural anomaly layer over the audit stream - closes the gap that per-event scoring cannot, detecting 100% of a two-behaviour attack set where the static baseline detected 50%, with no false positives. The whole system is verified by 299 automated tests across 28 test files (including 15 dedicated audit remediation checks) and reproducible evaluation scripts whose real output is reported here. A real-time authorization research engine (app/security/recon/) extends the work from a fixed benchmark to an arbitrary running service: it discovers the schema, generates a provenance-tracked suite of 18 tests, executes them over real HTTP, confirms findings only from observed object identity or persisted state, and exports SARIF/JUnit - with a live workbench at /workbench."));

// 16 references
children.push(H1("16. References"));
children.push(...B([
  "OWASP API Security Top 10 (2019, 2023) - API1: Broken Object Level Authorization.",
  "OWASP GraphQL Cheat Sheet - authorization, query cost analysis, introspection hardening.",
  "GraphQL Specification (October 2021) - type system, query document and execution semantics.",
  "FastAPI documentation - dependency injection and ASGI middleware boundaries.",
  "Strawberry GraphQL documentation - Python-first typed schemas.",
  "M. Fruth et al., \"GraphQL: An analysis of security vulnerabilities\" - authorisation and denial-of-service classes.",
  "JSON Web Token (JWT), RFC 7519 - signed token format used for authentication.",
  "Median Absolute Deviation (MAD) as a robust scale estimator; Hampel identifier for outlier detection.",
]));

// 17 appendix
children.push(H1("17. Appendix: Repository Layout"));
children.push(...code([
  "app/main.py                     FastAPI app, routes, startup schema inference, anomaly endpoint",
  "app/core/security.py            JWT creation/verification, current-user dependency",
  "app/security/enforcement.py     Gateway dependency: budget -> taint -> extract -> own -> policy -> risk -> audit -> enforce",
  "app/security/object_extractor.py AST normalization: (type, id, path) extraction",
  "app/security/ownership.py       Ownership resolution (fail-closed) with TTL cache",
  "app/security/ownership_inference.py  Schema relationship inference engine",
  "app/security/authorization.py   Policy engine and AuthorizationContext",
  "app/security/risk_engine.py     Deterministic 0-100 per-event risk scoring",
  "app/security/audit.py           Audit + taint-audit persistence",
  "app/security/anomaly_engine.py  SECONDARY NOVELTY: adaptive behavioural anomaly detection",
  "app/security/taint_engine.py    Static taint analysis (audit-only)",
  "app/security/differential_testing/  Differential security testing engine",
  "app/security/recon/            Real-time authorization research engine (discover -> generate -> execute -> verify -> export)",
  "app/static/workbench.html       Research workbench UI (/workbench)",
  "app/security/ai_analyst/        Natural-language explanation engine",
  "app/static/dashboard.html       Live monitoring dashboard",
  "scripts/evaluate_anomaly.py     Novelty evaluation harness (real gateway traffic)",
  "scripts/evaluate_authorization_engine.py  Research-engine evaluation harness",
  "scripts/evaluate_performance.py Latency + BOLA-block benchmark",
  "scripts/generate_inference_report.py  Schema inference report generator",
  "tests/                          299 tests across 28 files (incl. test_audit_remediation.py)",
  "scripts/verify_audit_remediation.py 15-check automated remediation verification suite",
]));

const doc = new Document({
  creator: "GraphQL Shield Team",
  title: "GraphQL Shield - Project Report",
  description: "CCNS project report",
  styles: {
    default: { document: { run: { font: FONT, size: 22 } }, heading1: { run: { font: FONT, size: 30, bold: true, color: ACCENT } }, heading2: { run: { font: FONT, size: 25, bold: true, color: ACCENT2 } }, heading3: { run: { font: FONT, size: 22, bold: true, color: "33414E" } } },
  },
  numbering: {
    config: [{
      reference: "bullets",
      levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT, style: { run: { font: FONT }, paragraph: { indent: { left: 540, hanging: 280 }, spacing: { after: 80 } } } }],
    }],
  },
  sections: [{
    properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } } },
    children,
  }],
});

function it2(s) { return new TextRun({ text: s, font: MONO, size: 18, color: "333333" }); }

Packer.toBuffer(doc).then((buf) => { fs.writeFileSync(OUT, buf); console.log("WROTE " + OUT + " (" + buf.length + " bytes)"); }).catch((e) => { console.error(e); process.exit(1); });
