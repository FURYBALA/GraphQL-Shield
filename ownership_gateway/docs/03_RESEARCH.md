# 3. Research: novelty, methodology, results, paper plan

> **Rule for this whole document:** claim only what is implemented **and** measured. Everything below is
> labelled ✅ *implemented & measured*, 🛠 *implemented, not yet measured*, or 📝 *proposed*.
> Before writing "to the best of our knowledge, no prior work...", do the systematic search in §3.2 and keep a
> log of queries and results. Examiners respect that much more than a bold claim.

## 3.1 Related work (verify every citation in Google Scholar before using it)

| Group | Work | What it does | What it does *not* do (relative to us) |
|---|---|---|---|
| Problem framing | OWASP API Security Top 10 (2023), API1:2023 BOLA | Defines BOLA as the #1 API risk | No mechanism |
| Problem evidence | Inigo analysis of GraphQL CVEs/HackerOne reports (reported via DevOps.com): authorization bypass ≈ 54.8% of GraphQL vulnerabilities; Escape "State of GraphQL Security 2024" (vendor report) | Shows that authz is the dominant GraphQL weakness | Industry, not peer-reviewed. Cite as motivation only |
| GraphQL hardening | GraphQL Armor (Escape, open-source middleware); query cost analysis, e.g. Cha et al., "A Principled Approach to GraphQL Query Cost Analysis", ESEC/FSE 2020 | Limits depth, cost, aliases, directives (DoS-oriented) | No notion of object ownership. Our "depth" baseline represents this group |
| In-process authz frameworks | `graphql-shield` (npm permission-rule middleware); Apollo Router authorization directives `@authenticated`, `@requiresScopes`, `@policy` | Developers attach rules to types/fields; `@policy` hands decisions to scripts/coprocessors | Rules are written **by hand** per type/field. Ownership is not inferred, and there is no response-side verification of returned objects |
| GraphQL testing/scanning | InQL, graphql-cop, Clairvoyance, BatchQL; EvoMaster for GraphQL (Belhadi, Zhang, Arcuri) | Find weaknesses offline, generate tests | Detection, not runtime prevention |
| REST BOLA detection | Santos Filho, Rodríguez & Feitosa, *Int. J. Information Security* 2025: OpenAPI → Coloured Petri Nets + execution traces (Links2CPN, >95% accuracy reported); AuthProbe (arXiv 2026 preprint): multi-identity black-box BOLA scanner from OpenAPI; Unit 42 BOLABuster (LLM-assisted, industry) | Detect BOLA in **REST** using specs and multiple identities | REST-oriented and mostly detection/testing. They do not address GraphQL aliasing/batching/nested traversal, and they do not enforce inline |
| Theory | Hartig & Pérez, "Semantics and Complexity of GraphQL", WWW 2018 | Formal semantics | Not security |

> ⚠️ **Name collision.** An npm library called **graphql-shield** already exists (a permissions layer). Say this
> yourself before an examiner does: "GraphQLShield (our gateway) is unrelated to the `graphql-shield` npm library. That
> library needs hand-written rules inside the server process; ours is an out-of-process gateway that infers ownership from the schema."
> For the paper, consider a distinct name (e.g. *OwnerGuard-QL* or *GQL-BOLAGuard*) to avoid confusion.

## 3.2 Systematic search protocol (do this before the final review; 2-3 hours)

Databases: Google Scholar, IEEE Xplore, ACM DL, arXiv, USENIX/NDSS proceedings.
Queries: `"GraphQL" AND (authorization OR "access control")`, `"GraphQL" AND (BOLA OR IDOR)`,
`"broken object level authorization"`, `"GraphQL" AND gateway AND security`, `"GraphQL" AND "query rewriting"`.
Record for each query: date, number of hits, relevant papers, and why each is or isn't overlapping. Put the table in the
paper's appendix or report. If you find a paper doing *response-verification via query rewriting for GraphQL
authorization*, re-position the contribution to the evaluation/benchmark (C3/C4) and the hybrid ablation.

## 3.3 Research gap (defensible formulation)

> Existing GraphQL defenses are either **structural** (depth/cost/alias limits, which are blind to ownership),
> **developer-written** (per-resolver or per-field rules that are as easy to forget as the original check), or
> **offline** (scanners/testers that detect but do not prevent). BOLA research with automatic reasoning has
> focused on REST and OpenAPI. We found little work on **runtime, application-agnostic BOLA prevention for GraphQL that
> derives ownership semantics automatically from the schema and stays robust to GraphQL-specific access paths**
> (aliases, batching, fragments, `node`, nested traversal, unscoped lists). *(Confirm with §3.2 before submission.)*

## 3.4 Contributions (status-labelled)

* **C1, Schema-derived ownership model** ✅: automatic inference of owned types, owner fields, look-up fields,
  ID-argument→type mapping and Relay node fields from introspection, with a reviewable/overridable policy.
* **C2, Hybrid enforcement** ✅: pre-flight ownership resolution for state-changing operations, combined with
  *query augmentation* (injecting `__typename`/owner/id under reserved aliases) and *field-aware response verification* for reads.
  The ablation shows that each half is necessary.
* **C3, GraphQL BOLA benchmark** ✅: 14 attacks in 10 GraphQL-specific categories plus 14 benign requests, with an
  automatic canary/state-change oracle. It is reusable for comparing defenses.
* **C4, Comparative evaluation** ✅ (one app) / 📝 (multiple apps): against no protection, structural hardening,
  an argument-level ID check, and a response-only ablation.
* **C5, Enumeration detection** 🛠: a sliding-window detector of distinct foreign-object violations (implemented
  and unit-tested; detection-rate experiments not yet run).

## 3.5 Hypotheses and research questions

| RQ | Question | Hypothesis | Status |
|---|---|---|---|
| RQ1 | How many BOLA variants does each defense prevent? | H1: hybrid prevents more than structural limits and argument-level checks | ✅ supported on ClinicHub |
| RQ2 | Do defenses break legitimate traffic? | H2: field-aware response verification has fewer false positives than argument-level checking | ✅ supported (0 vs 1 of 14) |
| RQ3 | Is each enforcement point necessary? | H3: response-only fails on mutations; argument-only fails on traversal/lists | ✅ supported (ablation) |
| RQ4 | How accurate is ownership inference across real schemas? | H4: heuristics plus a small override file reach high precision/recall | 📝 planned |
| RQ5 | What is the performance cost? | H5: overhead stays small relative to the proxy hop | ✅ measured (single host, dev server) |

## 3.6 Methodology

* **Target:** ClinicHub (healthcare-style GraphQL API, 3 owned types, 7 queries, 3 mutations, node interface, batching).
  It is deliberately missing ownership checks.
* **Threat model:** an authenticated, non-privileged user (Bob) who knows or can guess other users' IDs and can craft
  arbitrary GraphQL. Out of scope: token theft, injection in the backend, and a compromised gateway.
* **Oracle:** each victim's secret data contains a unique canary (`CANARY-ALICE…`). An attack counts as *successful* if a victim canary
  appears in the attacker's response, or if a mutation changed victim state (checked independently via a privileged query).
  The backend is reset before every case.
* **Configurations:** `off`, `depth` (structural hardening), `argcheck` (pre-flight on all root ID arguments, using the
  *same* inferred mapping, so this is a deliberately strong baseline), `response_only` (ablation), and `shield` (full).
* **Metrics:** prevention rate = prevented/attacks; FPR = benign requests failing/benign requests; latency p50/p95
  over 50 iterations × 12 read-only benign queries (600 samples per configuration), plus direct-backend latency as the reference.
* **Reproduce:** `python -m eval.run_eval --iterations 50` produces `eval/results/results.md`, `.json`, `.csv` and the charts.

## 3.7 Results (✅ measured, ClinicHub, single machine, Flask development server)

| Configuration | Attacks prevented | False positives | p50 (ms) | p95 (ms) |
|---|---|---|---|---|
| No protection (plain proxy) | 0/14 (0%) | 0/14 | 8.73 | 13.83 |
| Depth/alias limits | 0/14 (0%) | 0/14 | 10.03 | 14.80 |
| Argument-level ID check | 12/14 (86%) | 1/14 (7%) | 9.77 | 14.50 |
| Response verification only | 11/14 (79%) | 0/14 | 10.61 | 15.56 |
| **GraphQLShield (hybrid)** | **14/14 (100%)** | **0/14** | 11.28 | 19.00 |
| *Direct to backend* | *(n/a)* | | *3.52* | *5.44* |

Observations you can state:
1. Structural hardening prevented none of the BOLA attacks. Shape limits are orthogonal to ownership.
2. The argument-level check missed the two attacks with no attacker-supplied victim ID (A09 nested pivot via search,
   A10 unscoped search). It also blocked a legitimate public-profile view (B05), because it cannot see which fields are requested.
3. Response-only verification missed all three mutation attacks. The edit, payment and deletion **executed** even though
   the response was redacted (A14 returns only a Boolean, so there was no object to redact).
4. The hybrid prevented all 14 with no false positives. Its p50 latency was about **2.6 ms above a plain proxy** and
   about 7.8 ms above calling the backend directly (most of that is the extra HTTP hop through a Python dev server).
   Latency numbers vary run to run. Report them as indicative, not as a production benchmark.

**Threats to validity (put these in the paper):** single synthetic application, and attacks written by the authors (bias toward
cases the design anticipates); a small corpus; a heuristic ownership model tuned on a schema we designed; single-owner
semantics only; local single-host latency on a development server; and a 30 s owner cache (stale-ownership window and TOCTOU
between pre-flight and execution).

## 3.8 Experiments still to run (to make the paper strong)

1. 📝 **Generality:** put the gateway, **unchanged**, in front of a second/third GraphQL app (e.g. DVGA, the *Damn
   Vulnerable GraphQL Application*, or a small open-source app). Inspect its schema first. Report how many policy overrides were needed.
2. 📝 **RQ4 inference accuracy:** collect 5-10 public GraphQL schemas (SDL files), hand-label owner fields, run only the
   schema analyzer, and report precision/recall/F1 per rule. This needs no running servers and is cheap.
3. 📝 **Corpus growth:** generate attack variants automatically (for every root field × ID argument × alias/batch/fragment/variable
   wrapper) to reach 100+ cases and reduce author bias.
4. 📝 **Load test:** gunicorn + locust at 50/100/200 concurrent users. Report throughput and p95.
5. 📝 **Enumeration detector:** mix benign and enumerating sessions and report detection rate and time-to-detect.

## 3.9 Paper plan

**Title options**
* "GraphQLShield: Schema-Derived Ownership Enforcement for Preventing BOLA in GraphQL APIs"
* "Closing Every Path to the Object: A Hybrid Gateway Defense Against Broken Object Level Authorization in GraphQL"

**Abstract outline (5 sentences)**
1. Context: GraphQL adoption, with BOLA as the top API risk (OWASP API1:2023) and authorization bypass dominant among GraphQL vulnerabilities.
2. Problem: per-resolver checks are easy to forget, GraphQL offers many access paths, and existing defenses are structural, manual or offline.
3. Approach: a gateway that infers an ownership model from introspection and enforces it with pre-flight look-ups for mutations and query-augmented response verification for reads.
4. Evaluation: a benchmark of N attacks in 10 categories and M benign requests, on K apps, against structural, argument-level and ablated baselines.
5. Results: prevention X% vs Y%, FPR, overhead in ms, and inference accuracy. Fill these in only from measured numbers.

**Structure (IEEE conference, 6-8 pages)**
I Introduction (motivation, contributions C1-C4) · II Background (GraphQL, BOLA, threat model) · III Related Work (§3.1 table) ·
IV Design (ownership model, inference rules, hybrid enforcement, augmentation algorithm, detector) · V Implementation ·
VI Evaluation (RQ1-RQ5, Tables 1-4, Figures: effectiveness, latency) · VII Discussion & Limitations (§3.7 threats, shared
ownership, subscriptions, TOCTOU) · VIII Conclusion.

**Figures/tables already generated:** `eval/results/effectiveness.png`, `latency.png`, Tables 1-4 in `results.md`,
architecture (docs/02 §2.3), and the per-attack matrix (`detection_matrix.csv`).

**Venue ideas (student level):** IEEE/Springer conferences on computing and security (e.g., ICCCNT, ICACCI, SIN, or
Springer LNNS proceedings). Check the scope and indexing of each before submitting, and avoid predatory venues.

## 3.10 Limitations (say them before you are asked)

* **Single-owner model.** Shared ownership (a doctor reading their patients' records, team membership) needs relationship rules (📝 planned).
* **Owner field must be obtainable.** If the schema does not expose an owner field, a configured override or look-up is required.
* **Side-effecting queries** (a query that writes) would only be checked after execution. Treat them like mutations through config.
* **Redaction granularity** is per-object. A field-level mask (keep `name`, drop `records`) is possible future work.
* **Subscriptions** are not handled.
* **TOCTOU / cache:** ownership could change between pre-flight and execution. The cache TTL (30 s) trades latency against freshness.
