const path = require("path");
const pptxgen = require("pptxgenjs");

const ROOT = path.join(__dirname, "..", "..");
const OUT = path.join(ROOT, "CCNS_Presentation.pptx");

const DARK = "0E1B2A";
const DARK2 = "16324F";
const ACCENT = "10B981";
const ACCENT2 = "38BDF8";
const BLOCK = "EF4444";
const WHITE = "FFFFFF";
const MUTED = "64748B";
const CARD = "F1F5F9";
const INK = "0E1B2A";
const FONT = "Calibri";
const HFONT = "Cambria";

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE"; // 13.333 x 7.5
pres.author = "GraphQL Shield Team";
pres.title = "GraphQL Shield — Defensible Security Gateway";

function badge(slide, x, y, d, label, color) {
  slide.addShape(pres.ShapeType.ellipse, { x, y, w: d, h: d, fill: { color: color || ACCENT }, line: { color: color || ACCENT } });
  slide.addText(label, { x, y, w: d, h: d, align: "center", valign: "middle", fontFace: HFONT, fontSize: d > 0.7 ? 20 : 14, bold: true, color: DARK });
}
function darkBG(slide) { slide.background = { color: DARK }; }
function lightBG(slide) { slide.background = { color: WHITE }; }
function kicker(slide, text, color) {
  slide.addText(text, { x: 0.7, y: 0.45, w: 11.9, h: 0.4, fontFace: FONT, fontSize: 13, bold: true, charSpacing: 2, color: color || ACCENT2 });
}
function title(slide, text, color, y) {
  slide.addText(text, { x: 0.7, y: y === undefined ? 0.85 : y, w: 11.9, h: 0.9, fontFace: HFONT, fontSize: 34, bold: true, color: color || INK });
}
function footer(slide, n) {
  slide.addText("GraphQL Shield — CCNS Capstone", { x: 0.7, y: 7.05, w: 8, h: 0.3, fontFace: FONT, fontSize: 9, color: MUTED });
  slide.addText(String(n), { x: 12.3, y: 7.05, w: 0.5, h: 0.3, fontFace: FONT, fontSize: 9, color: MUTED, align: "right" });
}
function card(slide, x, y, w, h, fill) {
  slide.addShape(pres.ShapeType.roundRect, { x, y, w, h, rectRadius: 0.08, fill: { color: fill || CARD }, line: { color: "E2E8F0", width: 1 }, shadow: { type: "outer", color: "94A3B8", blur: 6, offset: 2, angle: 90, opacity: 0.25 } });
}
function bullets(slide, items, x, y, w, h, size, color) {
  const runs = [];
  items.forEach((it) => {
    const isObj = typeof it === "object";
    runs.push({ text: isObj ? it.t : it, options: { bullet: true, breakLine: true, ...(isObj && it.o ? it.o : {}), fontSize: size || 15, color: color || INK, fontFace: FONT, paraSpaceAfter: 8 } });
  });
  slide.addText(runs, { x, y, w, h, valign: "top" });
}

/* ---------- 1. Title ---------- */
let s = pres.addSlide(); darkBG(s);
s.addShape(pres.ShapeType.roundRect, { x: 0.9, y: 1.5, w: 1.6, h: 1.6, rectRadius: 0.2, fill: { color: ACCENT }, line: { color: ACCENT } });
s.addText("GS", { x: 0.9, y: 1.5, w: 1.6, h: 1.6, align: "center", valign: "middle", fontFace: HFONT, fontSize: 40, bold: true, color: DARK });
s.addText("GraphQL Shield", { x: 2.9, y: 1.45, w: 9.6, h: 1.0, fontFace: HFONT, fontSize: 46, bold: true, color: WHITE });
s.addText("Schema-Aware Security Gateway for Preventing GraphQL BOLA Vulnerabilities", { x: 2.95, y: 2.5, w: 9.6, h: 1.0, fontFace: FONT, fontSize: 19, color: ACCENT2 });
s.addText("Agnihotram Chinmayanand (RA2311053010116)   ·   B.V. Balanilavan (RA2311053010123)\nKapilesh.N (RA2311053010125)   ·   Sakthivel.B (RA2311053010126)", { x: 0.95, y: 5.5, w: 11.9, h: 0.7, fontFace: FONT, fontSize: 13.5, color: WHITE });
s.addText("Computer Communication and Network Security  ·  Faculty Viva & Technical Defense", { x: 0.95, y: 6.3, w: 11.9, h: 0.4, fontFace: FONT, fontSize: 12.5, color: "9FB3C8" });
s.addNotes("Title. Introduce the project: an evidence-grounded security gateway that combines schema-aware static analysis with runtime authorization evidence to block BOLA at the edge while providing exact AST path attribution.");

/* ---------- 2. The problem ---------- */
s = pres.addSlide(); lightBG(s); kicker(s, "THE PROBLEM", ACCENT); title(s, "Broken Object Level Authorization");
card(s, 0.7, 2.0, 5.7, 4.3, CARD);
s.addText("BOLA / IDOR", { x: 1.0, y: 2.2, w: 5.1, h: 0.5, fontFace: HFONT, fontSize: 22, bold: true, color: INK });
bullets(s, [
  "An API accepts an object identifier from the client and returns the object without checking that the caller may access THAT object.",
  "Attacker changes id=101 to id=102 and reads someone else's data.",
  "Ranked #1 in the OWASP API Security Top 10.",
  "Prevalent, high-impact, and entirely avoidable.",
], 1.0, 2.8, 5.1, 3.3, 15);
card(s, 6.9, 2.0, 5.7, 4.3, DARK2);
s.addText("Why GraphQL amplifies it", { x: 7.2, y: 2.2, w: 5.1, h: 0.5, fontFace: HFONT, fontSize: 22, bold: true, color: WHITE });
bullets(s, [
  "One endpoint fronts every resource — a huge, discoverable attack surface.",
  "Resolvers traverse the query graph depth-first; auth is easy to forget per field.",
  "Objects are reachable through many nested paths and field aliases.",
  "There is no built-in notion of 'the caller's right to THIS object'.",
], 7.2, 2.8, 5.1, 3.3, 15, WHITE);
footer(s, 2);
s.addNotes("Motivate: BOLA is the top API risk; GraphQL's flexibility and nested traversal make centralized enforcement hard. That's the gap.");

/* ---------- 3. Objectives ---------- */
s = pres.addSlide(); lightBG(s); kicker(s, "OBJECTIVES", ACCENT); title(s, "What the gateway must do");
const objs = [
  ["1", "Intercept", "Reject unauthorized object access at the edge, before any resolver executes."],
  ["2", "Understand the query", "Extract every object type and id from the AST — nested, aliased, variable and fragment based."],
  ["3", "Understand ownership", "Resolve ownership from authoritative data, validated against schema-inferred relationships."],
  ["4", "Fail closed", "If ownership cannot be explained by a rule or tenant context is missing, deny."],
  ["5", "Score and audit", "Deterministic 0-100 risk per decision, persisted for review."],
  ["6", "Tenant integrity", "Derive tenant from validated JWT; reject client header spoofing."],
];
objs.forEach((o, i) => {
  const col = i % 2, row = Math.floor(i / 2);
  const x = 0.7 + col * 6.2, y = 2.0 + row * 1.45;
  card(s, x, y, 5.7, 1.25, CARD);
  badge(s, x + 0.2, y + 0.28, 0.68, o[0], ACCENT);
  s.addText(o[1], { x: x + 1.05, y: y + 0.14, w: 4.4, h: 0.4, fontFace: FONT, fontSize: 15, bold: true, color: INK });
  s.addText(o[2], { x: x + 1.05, y: y + 0.5, w: 4.4, h: 0.65, fontFace: FONT, fontSize: 11.5, color: MUTED });
});
footer(s, 3);
s.addNotes("Six objectives: intercept, understand the query, understand ownership, fail closed, score+audit, and enforce tenant integrity.");

/* ---------- 4. Architecture ---------- */
s = pres.addSlide(); lightBG(s); kicker(s, "ARCHITECTURE", ACCENT); title(s, "One gateway, ten fail-closed stages");
const stages = [
  ["1", "Authenticate", "JWT -> user, role, tenant"],
  ["2", "Tenant Guard", "reject X-Tenant spoofing"],
  ["3", "Budget check", "depth 15 / cost 150"],
  ["4", "Taint analysis", "audit-only, fail-safe"],
  ["5", "AST extract", "(type, id, path, alias)"],
  ["6", "Ownership", "DB lookup + schema rule"],
  ["7", "Policy", "ALLOW / DENY + reason"],
  ["8", "Risk score", "0-100, low/med/high"],
  ["9", "Audit", "persist SQLite row"],
  ["10", "Enforce", "ALLOW run / DENY 403"],
];
stages.forEach((st, i) => {
  const col = i % 5, row = Math.floor(i / 5);
  const x = 0.7 + col * 2.44, y = 2.1 + row * 2.2;
  card(s, x, y, 2.25, 1.9, row === 0 ? CARD : DARK2);
  const dark = row === 1;
  badge(s, x + 0.18, y + 0.18, 0.6, st[0], dark ? ACCENT2 : ACCENT);
  s.addText(st[1], { x: x + 0.15, y: y + 0.85, w: 1.95, h: 0.4, fontFace: FONT, fontSize: 13.5, bold: true, color: dark ? WHITE : INK });
  s.addText(st[2], { x: x + 0.15, y: y + 1.22, w: 1.95, h: 0.55, fontFace: FONT, fontSize: 10.5, color: dark ? "BBD0E0" : MUTED });
});
s.addText("Advisory subsystems (read audit stream, cannot change a decision): differential-testing  ·  adaptive anomaly engine  ·  research evaluator", { x: 0.7, y: 6.5, w: 11.9, h: 0.4, fontFace: FONT, fontSize: 11.5, italics: true, color: MUTED });
footer(s, 4);
s.addNotes("The gateway is a FastAPI dependency that runs before the GraphQL route. Ten stages, fully fail-closed with tenant identity integrity.");

/* ---------- 5. Schema-aware ownership inference ---------- */
s = pres.addSlide(); lightBG(s); kicker(s, "CORE IDEA", ACCENT); title(s, "Ownership inferred from the schema");
card(s, 0.7, 2.0, 5.7, 4.3, CARD);
s.addText("The schema already describes ownership", { x: 1.0, y: 2.2, w: 5.1, h: 0.5, fontFace: FONT, fontSize: 15, bold: true, color: INK });
s.addText([
  { text: "type User {\n", options: { fontFace: "Consolas", fontSize: 12.5, color: "0F766E", breakLine: true } },
  { text: "    id: ID!\n", options: { fontFace: "Consolas", fontSize: 12.5, color: INK, breakLine: true } },
  { text: "    resources: [Resource]\n", options: { fontFace: "Consolas", fontSize: 12.5, color: INK, breakLine: true } },
  { text: "}\n", options: { fontFace: "Consolas", fontSize: 12.5, color: INK, breakLine: true } },
  { text: "type Resource {\n", options: { fontFace: "Consolas", fontSize: 12.5, color: "0F766E", breakLine: true } },
  { text: "    id: ID!\n", options: { fontFace: "Consolas", fontSize: 12.5, color: INK, breakLine: true } },
  { text: "    owner_id: ID!\n", options: { fontFace: "Consolas", fontSize: 12.5, color: INK, breakLine: true } },
  { text: "}", options: { fontFace: "Consolas", fontSize: 12.5, color: INK } },
], { x: 1.0, y: 2.75, w: 5.1, h: 2.2, fill: { color: "0E1B2A" }, align: "left", valign: "middle" });
s.addText("Field names (ownerId -> owner_id) and type names (Resource = ResourceType) are normalized so query and schema line up.", { x: 1.0, y: 5.3, w: 5.1, h: 0.9, fontFace: FONT, fontSize: 12, color: MUTED });
card(s, 6.9, 2.0, 5.7, 4.3, CARD);
s.addText("Validated, explainable patterns", { x: 7.2, y: 2.2, w: 5.1, h: 0.5, fontFace: FONT, fontSize: 15, bold: true, color: INK });
bullets(s, [
  "A — object reference: Resource.owner: User",
  "B — collection: User.resources: [Resource]",
  "C — scalar id: Resource.ownerId: ID",
  "D — nested chains of A/B/C",
  "Matching driven by configurable naming list (owner, user_id, created_by, ...).",
  "Ambiguous matches (createdBy: String) are rejected, not guessed.",
  "Priority: explicit rule > inferred rule > UNKNOWN_OWNERSHIP (deny).",
], 7.2, 2.8, 5.1, 3.3, 13.5);
footer(s, 5);
s.addNotes("The schema publishes ownership as fields. We infer and validate those relationships once at startup, keep explicit rules on top, and fail closed when nothing explains ownership.");

/* ---------- 6. Policy + risk ---------- */
s = pres.addSlide(); lightBG(s); kicker(s, "DECISION", ACCENT); title(s, "Policy engine and deterministic risk");
card(s, 0.7, 2.0, 5.7, 4.3, CARD);
s.addText("Policy evaluation", { x: 1.0, y: 2.2, w: 5.1, h: 0.5, fontFace: FONT, fontSize: 16, bold: true, color: INK });
bullets(s, [
  "Structured AuthorizationContext: user, tenant, role, type, id, path, owner.",
  "OWNER_MATCH -> ALLOW",
  "OWNERSHIP_MISMATCH -> DENY",
  "NESTED_AUTHORIZATION_VIOLATION -> DENY",
  "TENANT_ISOLATION_VIOLATION -> DENY",
  "TENANT_CONTEXT_MISSING -> DENY (fail closed)",
  "SUPERADMIN_CROSS_TENANT_OVERRIDE -> ALLOW (audited)",
], 1.0, 2.8, 5.1, 3.3, 13.5);
card(s, 6.9, 2.0, 5.7, 4.3, DARK2);
s.addText("Risk engine (0-100)", { x: 7.2, y: 2.2, w: 5.1, h: 0.5, fontFace: FONT, fontSize: 16, bold: true, color: WHITE });
bullets(s, [
  "+80  ownership / authorization / tenant violation",
  "+20  nested access (path contains '.')",
  "+10  >=1 DENY in the last 10 minutes",
  "cap at 100",
  "band: LOW < 30 | MEDIUM < 60 | HIGH >= 60",
  "Deterministic, auditable — no black-box ML in the enforcement path.",
], 7.2, 2.8, 5.1, 3.3, 14, WHITE);
footer(s, 6);
s.addNotes("Policy produces a decision and machine-readable reason; risk engine computes score band. Direct BOLA -> 80, nested BOLA -> 100, tenant violation -> 80.");

/* ---------- 7. Enforcement + audit ---------- */
s = pres.addSlide(); lightBG(s); kicker(s, "ENFORCEMENT", ACCENT); title(s, "Block at the edge, audit everything");
card(s, 0.7, 2.1, 3.8, 3.9, CARD);
badge(s, 1.0, 2.35, 0.7, "ALLOW", ACCENT);
s.addText("200 / execute", { x: 1.0, y: 3.2, w: 3.2, h: 0.4, fontFace: FONT, fontSize: 15, bold: true, color: INK });
s.addText("Control passes to the Strawberry GraphQL engine. The resolver runs only for authorized objects.", { x: 1.0, y: 3.7, w: 3.2, h: 2.0, fontFace: FONT, fontSize: 13, color: MUTED });
card(s, 4.75, 2.1, 3.8, 3.9, "FDECEA");
badge(s, 5.05, 2.35, 0.7, "DENY", BLOCK);
s.addText("403 / drop", { x: 5.05, y: 3.2, w: 3.2, h: 0.4, fontFace: FONT, fontSize: 15, bold: true, color: INK });
s.addText("HTTP 403 with decision, user, object, reason, risk score and level. The backend is never invoked.", { x: 5.05, y: 3.7, w: 3.2, h: 2.0, fontFace: FONT, fontSize: 13, color: MUTED });
card(s, 8.8, 2.1, 3.8, 3.9, DARK2);
badge(s, 9.1, 2.35, 0.7, "LOG", ACCENT2);
s.addText("Persist every decision", { x: 9.1, y: 3.2, w: 3.2, h: 0.4, fontFace: FONT, fontSize: 15, bold: true, color: WHITE });
s.addText("Full decision context written to SQLite audit_logs. Enforcement never depends on audit success.", { x: 9.1, y: 3.7, w: 3.2, h: 2.0, fontFace: FONT, fontSize: 13, color: "BBD0E0" });
footer(s, 7);
s.addNotes("Denied requests never reach the backend — the resolver is the expensive, risky part and we short-circuit before it. Every decision is persisted.");

/* ---------- 8. Primary contribution ---------- */
s = pres.addSlide(); lightBG(s); kicker(s, "PRIMARY CONTRIBUTION", ACCENT); title(s, "Static-Runtime Evidence Correlation");
s.addText("Evaluated on 115-case benchmark (105 valid: 52 vulnerable / 53 benign, 10 malformed).", { x: 0.7, y: 1.8, w: 11.9, h: 0.4, fontFace: FONT, fontSize: 14, color: MUTED });
const mpts = [
  ["M1 Gateway Alone", "100% / 0.0%", "precision / false-alarm rate", "56.2% exact (65.7% semantic)", "15803D"],
  ["M2 Static Taint Alone", "54.7% / 81.1%", "precision / false-alarm rate", "90.5% exact (100% semantic)", "B45309"],
  ["M3 Correlated (Ours)", "100% / 0.0%", "precision / false-alarm rate", "90.5% exact (100% semantic)", "15803D"],
];
mpts.forEach((m, i) => {
  const x = 0.7 + i * 4.11;
  card(s, x, 2.4, 3.85, 3.3, CARD);
  s.addText(m[0], { x: x + 0.2, y: 2.6, w: 3.45, h: 0.4, fontFace: FONT, fontSize: 14, bold: true, color: INK });
  s.addText(m[1], { x: x + 0.2, y: 3.05, w: 3.45, h: 0.7, fontFace: HFONT, fontSize: 23, bold: true, color: m[4] });
  s.addText(m[2], { x: x + 0.2, y: 3.75, w: 3.45, h: 0.4, fontFace: FONT, fontSize: 11, color: MUTED });
  s.addText(m[3], { x: x + 0.2, y: 4.3, w: 3.45, h: 0.4, fontFace: FONT, fontSize: 12.0, bold: true, color: ACCENT });
});
s.addText("Correlating AST taint findings with runtime evidence eliminates the 81.1% static false-alarm rate on benign owner requests and achieves 90.5% exact canonical match (95/105) and 100.0% semantic target attribution (0 incorrect, 0 missing) — with zero policy divergence.", { x: 0.7, y: 5.95, w: 11.9, h: 0.7, fontFace: FONT, fontSize: 13.5, color: INK });
footer(s, 8);
s.addNotes("PRIMARY contribution: combines schema-aware static analysis with runtime authorization evidence. 105 valid cases denominator; 95 exact canonical matches (90.5%) and 10 nested formatting differences, achieving 100% semantic path attribution with 0 incorrect and 0 missing.");

/* ---------- 9. Novelty (secondary) ---------- */
s = pres.addSlide(); darkBG(s); kicker(s, "SECONDARY NOVELTY", ACCENT);
title(s, "Adaptive behavioural anomaly detection", WHITE);
s.addText("Per-event scoring has no principal-level memory. It cannot see a fully-authorized account enumerating every record it can reach, or a low-and-slow scan hiding between ordinary reads.", { x: 0.7, y: 1.85, w: 11.9, h: 0.8, fontFace: FONT, fontSize: 15, color: "CBD5E1" });
const feats = [
  ["deny_ratio", "share of requests denied"],
  ["target_breadth", "distinct object ids touched"],
  ["velocity", "requests per minute"],
  ["deny_trend", "recent vs earlier denial escalation"],
];
feats.forEach((f, i) => {
  const x = 0.7 + i * 3.05;
  card(s, x, 2.85, 2.85, 1.6, DARK2);
  s.addText(f[0], { x: x + 0.18, y: 3.0, w: 2.5, h: 0.4, fontFace: "Consolas", fontSize: 13.5, bold: true, color: ACCENT });
  s.addText(f[1], { x: x + 0.18, y: 3.45, w: 2.5, h: 0.9, fontFace: FONT, fontSize: 11.5, color: "CBD5E1" });
});
card(s, 0.7, 4.75, 11.9, 1.75, "12293B");
s.addText([
  { text: "Two adaptive mechanisms: ", options: { fontSize: 14, bold: true, color: WHITE } },
  { text: "a robust median/MAD peer-relative z-score that moves with observed traffic, and a temporal drift term against the principal's own history. ", options: { fontSize: 14, color: "CBD5E1" } },
  { text: "Score = 0.6 x weighted-mean + 0.4 x peak. ", options: { fontSize: 14, bold: true, color: ACCENT2 } },
  { text: "Strictly advisory — it never changes an enforcement decision.", options: { fontSize: 14, color: "CBD5E1" } },
], { x: 0.95, y: 4.9, w: 11.4, h: 1.5, valign: "middle" });
footer(s, 9);
s.addNotes("Secondary novelty. Four behavioural signals, adaptively baselined, combined into an explainable 0-100 score. Advisory only — flags for humans, never alters enforcement.");

/* ---------- 10. Anomaly evaluation ---------- */
s = pres.addSlide(); lightBG(s); kicker(s, "RESULTS - SECONDARY NOVELTY", ACCENT); title(s, "Static 50% -> adaptive 100% detection");
const rows = [
  [
    { text: "Principal", options: { bold: true, color: WHITE, fill: DARK2, fontSize: 12 } },
    { text: "Truth", options: { bold: true, color: WHITE, fill: DARK2, fontSize: 12 } },
    { text: "Events", options: { bold: true, color: WHITE, fill: DARK2, fontSize: 12 } },
    { text: "Static risk", options: { bold: true, color: WHITE, fill: DARK2, fontSize: 12 } },
    { text: "Static?", options: { bold: true, color: WHITE, fill: DARK2, fontSize: 12 } },
    { text: "Adaptive", options: { bold: true, color: WHITE, fill: DARK2, fontSize: 12 } },
    { text: "Level", options: { bold: true, color: WHITE, fill: DARK2, fontSize: 12 } },
    { text: "Pattern", options: { bold: true, color: WHITE, fill: DARK2, fontSize: 12 } },
  ],
  [{ text: "101" }, { text: "benign" }, { text: "3" }, { text: "0" }, { text: "no" }, { text: "34" }, { text: "MEDIUM" }, { text: "NO_PATTERN" }],
  [{ text: "102" }, { text: "attack" }, { text: "15" }, { text: "0" }, { text: "no" }, { text: "65" }, { text: "HIGH" }, { text: "HIGH_VELOCITY_ENUMERATION" }],
  [{ text: "103" }, { text: "benign" }, { text: "2" }, { text: "0" }, { text: "no" }, { text: "25" }, { text: "LOW" }, { text: "NO_PATTERN" }],
  [{ text: "104" }, { text: "attack" }, { text: "6" }, { text: "90" }, { text: "yes" }, { text: "80" }, { text: "HIGH" }, { text: "SUSTAINED_AUTHORIZATION_ABUSE" }],
];
s.addTable(rows, { x: 0.7, y: 2.0, w: 11.9, colW: [1.1, 1.1, 0.9, 1.2, 1.1, 1.3, 1.3, 3.9], border: { type: "solid", color: "CBD5E1", pt: 1 }, fontSize: 11.5, color: INK, valign: "middle", rowH: 0.42, align: "center" });
card(s, 0.7, 4.55, 5.7, 1.9, "ECFDF5");
s.addText("50.0%", { x: 0.95, y: 4.7, w: 2.2, h: 0.7, fontFace: HFONT, fontSize: 34, bold: true, color: "334155" });
s.addText("Static per-event baseline\nstructurally misses mass authorized enumeration", { x: 0.95, y: 5.45, w: 5.2, h: 0.9, fontFace: FONT, fontSize: 12, color: MUTED });
card(s, 6.9, 4.55, 5.7, 1.9, "DCFCE7");
s.addText("100.0%", { x: 7.15, y: 4.7, w: 2.8, h: 0.7, fontFace: HFONT, fontSize: 34, bold: true, color: "15803D" });
s.addText("Adaptive engine — both attacks caught, both benign users clean. 0% false positives.", { x: 7.15, y: 5.45, w: 5.2, h: 0.9, fontFace: FONT, fontSize: 12, color: MUTED });
footer(s, 10);
s.addNotes("Real gateway traffic, isolated DB. Static detects direct BOLA burst only; adaptive detects mass enumeration too, with zero false positives.");

/* ---------- 11. Performance ---------- */
s = pres.addSlide(); lightBG(s); kicker(s, "RESULTS - PERFORMANCE", ACCENT); title(s, "Efficacy and overhead, measured");
card(s, 0.7, 2.0, 3.8, 4.3, CARD);
s.addText("100%", { x: 0.95, y: 2.3, w: 3.3, h: 0.9, fontFace: HFONT, fontSize: 44, bold: true, color: "15803D" });
s.addText("BOLA attempts blocked by the secured gateway.", { x: 0.95, y: 3.3, w: 3.3, h: 1.0, fontFace: FONT, fontSize: 13, color: MUTED });
s.addText("0.0%", { x: 0.95, y: 4.3, w: 3.3, h: 0.9, fontFace: HFONT, fontSize: 44, bold: true, color: "15803D" });
s.addText("False positives on 500 legitimate requests.", { x: 0.95, y: 5.3, w: 3.3, h: 0.9, fontFace: FONT, fontSize: 13, color: MUTED });
card(s, 4.75, 2.0, 7.85, 4.3, CARD);
s.addText("Latency (2,000 requests)", { x: 5.0, y: 2.2, w: 7.35, h: 0.5, fontFace: FONT, fontSize: 16, bold: true, color: INK });
s.addChart(pres.ChartType.bar, [
  { name: "Avg latency (ms)", labels: ["Without gateway", "With gateway"], values: [9.276, 26.26] },
], { x: 5.0, y: 2.75, w: 7.35, h: 3.3, barDir: "bar", chartColors: [ACCENT2], showValue: true, dataLabelPosition: "outEnd", dataLabelColor: INK, dataLabelFontSize: 12, showTitle: false, showLegend: false, catAxisLabelColor: INK, valAxisLabelColor: MUTED, valGridLine: { color: "E2E8F0", size: 1 }, catGridLine: { style: "none" }, valAxisMinVal: 0 });
s.addText("Authorization decision overhead: ~15-17 ms per request (AST parse + cached ownership + policy).", { x: 5.0, y: 6.05, w: 7.35, h: 0.3, fontFace: FONT, fontSize: 11, italics: true, color: MUTED });
footer(s, 11);
s.addNotes("Real benchmark: 500 legit + 500 BOLA per endpoint. 100% block, 0% false positives, ~15-17 ms overhead. Acceptable for prototype; reducible with Redis.");

/* ---------- 12. Dashboard evidence ---------- */
s = pres.addSlide(); lightBG(s); kicker(s, "EVIDENCE", ACCENT); title(s, "Live dashboard from real traffic");
s.addImage({ path: path.join(ROOT, "docs", "screenshots", "dashboard_top.png"), x: 0.7, y: 2.0, w: 7.4, h: 4.93 });
card(s, 8.4, 2.0, 4.2, 4.3, CARD);
s.addText("Captured from the running gateway", { x: 8.6, y: 2.2, w: 3.8, h: 0.5, fontFace: FONT, fontSize: 14, bold: true, color: INK });
bullets(s, [
  "Live audit counters: events, allowed, blocked, BOLA.",
  "Connection + last-update indicators.",
  "Recent decisions table with reason and risk.",
  "Adaptive anomaly panel per principal.",
  "Reflects genuine requests, not simulated data.",
], 8.6, 2.75, 3.85, 3.4, 12.5);
footer(s, 12);
s.addNotes("Real screenshot of /dashboard after live traffic: legit access, direct and nested BOLA, forged token, and the anomaly burst.");

/* ---------- 13. Testing & Verification ---------- */
s = pres.addSlide(); lightBG(s); kicker(s, "VERIFICATION", ACCENT); title(s, "299 automated tests, all passing");
card(s, 0.7, 2.0, 5.7, 4.3, DARK2);
s.addText("299", { x: 0.95, y: 2.25, w: 3.0, h: 1.0, fontFace: HFONT, fontSize: 56, bold: true, color: ACCENT });
s.addText("passed / 299 collected", { x: 0.95, y: 3.35, w: 4.5, h: 0.4, fontFace: FONT, fontSize: 15, color: WHITE });
s.addText("28 test files  ·  0 failures  ·  ~60s runtime\nIncludes dedicated 15-test automated remediation suite", { x: 0.95, y: 3.85, w: 4.7, h: 0.9, fontFace: FONT, fontSize: 13.5, color: "BBD0E0" });
s.addText("$ python -m pytest tests/ -q", { x: 0.95, y: 4.9, w: 5.2, h: 0.4, fontFace: "Consolas", fontSize: 12.5, color: ACCENT2 });
s.addText("299 passed in 60.52s", { x: 0.95, y: 5.35, w: 5.2, h: 0.4, fontFace: "Consolas", fontSize: 12.5, color: "9FE8C6" });
card(s, 6.9, 2.0, 5.7, 4.3, CARD);
s.addText("Coverage", { x: 7.15, y: 2.2, w: 5.1, h: 0.5, fontFace: FONT, fontSize: 16, bold: true, color: INK });
bullets(s, [
  "Authentication and JWT tenant claims",
  "Direct, nested, multi-ID, variable and fragment BOLA",
  "Policy engine, multi-tenant ABAC, risk scoring",
  "Audit logging, dashboards, and live events",
  "Schema-aware ownership inference singleton",
  "Security graph and taint propagation",
  "Adaptive anomaly detection (9 dedicated tests)",
  "Real-time research engine (13 dedicated tests)",
  "Automated remediation verification (15 dedicated tests)",
], 7.15, 2.65, 5.1, 3.5, 12);
footer(s, 13);
s.addNotes("299 automated tests cover every module. 0 failures across 28 files.");

/* ---------- 14. Technical Remediations ---------- */
s = pres.addSlide(); lightBG(s); kicker(s, "RIGOR & DEFENSE", ACCENT); title(s, "Five Automated Technical Remediations");
const rems = [
  ["1", "Live HTTP Gateway", "Method B executes over real HTTP POST to /graphql; direct policy kept as explicit baseline."],
  ["2", "Real Mutation Execution", "Actual mutation execution verifies 403 denial with bitwise SQLite state preservation (zero tamper)."],
  ["3", "Metric Disentanglement", "Separated binary detection (TP/FP) from exact canonical AST path and object attribution."],
  ["4", "Tenant Header Anti-Spoof", "JWT tenant is authoritative; X-Tenant-Id mismatch rejected (403 TENANT_HEADER_MISMATCH)."],
  ["5", "Statistical Precision", "McNemar test uses scientific notation (p < 10^-4); production write endpoints admin-guarded."],
];
rems.forEach((r, i) => {
  const y = 2.0 + i * 0.95;
  card(s, 0.7, y, 11.9, 0.85, CARD);
  badge(s, 0.9, y + 0.15, 0.55, r[0], ACCENT);
  s.addText(r[1], { x: 1.6, y: y + 0.1, w: 3.2, h: 0.35, fontFace: FONT, fontSize: 13.5, bold: true, color: INK });
  s.addText(r[2], { x: 4.9, y: y + 0.1, w: 7.5, h: 0.65, fontFace: FONT, fontSize: 11.5, color: MUTED });
});
s.addText("Verified in under 7 seconds: python scripts/verify_audit_remediation.py -> 15/15 PASS", { x: 0.7, y: 6.75, w: 11.9, h: 0.3, fontFace: "Consolas", fontSize: 11, bold: true, color: "0F766E" });
footer(s, 14);


/* ---------- 15. Limitations & Future Work ---------- */
s = pres.addSlide(); lightBG(s); kicker(s, "HONESTY", ACCENT); title(s, "Limitations and proposed extensions");
card(s, 0.7, 2.0, 5.7, 4.3, "FFF7ED");
s.addText("Current limitations", { x: 0.95, y: 2.2, w: 5.1, h: 0.5, fontFace: FONT, fontSize: 16, bold: true, color: "9A3412" });
bullets(s, [
  "Schema inference is pattern-based; polymorphic ownership requires explicit rules.",
  "Object-level gateway; does not rewrite queries into partial null fields.",
  "Ownership lookup hits SQLite (mitigated by in-memory TTL cache).",
  "Benchmark results reflect our evaluated corpus under defined configurations.",
  "Anomaly baseline requires at least 2 active principals.",
], 0.95, 2.75, 5.1, 3.4, 12.5);
card(s, 6.9, 2.0, 5.7, 4.3, "EFF6FF");
s.addText("Proposed extensions (future work)", { x: 7.15, y: 2.2, w: 5.1, h: 0.5, fontFace: FONT, fontSize: 16, bold: true, color: "1E40AF" });
bullets(s, [
  "Temporal traversal detection: sequential ID distance + velocity bursts.",
  "Field-level selective masking: nullify unauthorized fields safely.",
  "Cross-platform policy synthesis: export Cedar / Rego OPA policies.",
  "Role-based introspection filtering: hide unauthenticated schema types.",
  "Redis-backed distributed ownership cache for multi-instance gateway.",
], 7.15, 2.75, 5.1, 3.4, 12.5);
footer(s, 15);
s.addNotes("Strict academic honesty: we separate implemented capabilities, empirical findings, and proposed future work.");

/* ---------- 16. Conclusion ---------- */
s = pres.addSlide(); darkBG(s); kicker(s, "CONCLUSION", ACCENT);
title(s, "Centralized, measurable, defensible", WHITE);
const concl = [
  ["100%", "BOLA attempts blocked over live gateway"],
  ["0.0%", "false alarms on benign owner traffic"],
  ["90.5%", "exact canonical AST path attribution (100% semantic)"],
  ["299/299", "automated tests passing (0 failures)"],
];
concl.forEach((c, i) => {
  const x = 0.7 + i * 3.05;
  card(s, x, 2.1, 2.85, 2.3, DARK2);
  s.addText(c[0], { x: x + 0.15, y: 2.35, w: 2.55, h: 0.9, fontFace: HFONT, fontSize: 28, bold: true, color: ACCENT });
  s.addText(c[1], { x: x + 0.15, y: 3.3, w: 2.55, h: 1.0, fontFace: FONT, fontSize: 12, color: "CBD5E1" });
});
s.addText("GraphQL Shield demonstrates that combining schema-aware static analysis with runtime authorization evidence provides both strict pre-resolver protection and traceable path attribution — verified across live HTTP execution, genuine mutation safety, multi-tenant anti-spoofing, and 299 automated tests.", { x: 0.7, y: 4.85, w: 11.9, h: 1.2, fontFace: FONT, fontSize: 15, color: WHITE });
s.addText("Thank you  ·  Questions welcome", { x: 0.7, y: 6.25, w: 11.9, h: 0.5, fontFace: FONT, fontSize: 14, italics: true, color: ACCENT2 });
footer(s, 16);
s.addNotes("Close on the four headline metrics and verified technical defensibility.");

pres.writeFile({ fileName: OUT }).then((f) => console.log("WROTE " + f)).catch((e) => { console.error(e); process.exit(1); });
