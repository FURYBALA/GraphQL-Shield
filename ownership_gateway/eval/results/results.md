# GraphQLShield evaluation results

Target: ClinicHub (deliberately vulnerable demo backend)

Generated 2026-10-21 00:19:33 - 14 attacks, 14 benign requests, latency over 50 iterations x 12 read-only queries.

## Table 1 - Effectiveness, precision and overhead

| Configuration | Attacks prevented | Prevention rate | False positives | FPR | p50 latency (ms) | p95 latency (ms) | p50 overhead vs direct (ms) |
|---|---|---|---|---|---|---|---|
| No protection | 0/14 | 0% | 0/14 | 0% | 33.56 | 51.34 | 18.1 |
| Depth/alias limits (hardening baseline) | 0/14 | 0% | 0/14 | 0% | 34.94 | 55.72 | 19.48 |
| Argument-level ID check (WAF-style baseline) | 12/14 | 86% | 1/14 | 7% | 32.85 | 59.46 | 17.39 |
| Response verification only (ablation) | 11/14 | 79% | 0/14 | 0% | 34.97 | 62.37 | 19.51 |
| GraphQLShield (full) | 14/14 | 100% | 0/14 | 0% | 36.56 | 62.87 | 21.1 |

Direct backend (no gateway): p50 15.46 ms, p95 30.66 ms.

## Table 2 - Prevention by attack category

| Category | off | depth | argcheck | response_only | shield |
|---|---|---|---|---|---|
| Direct object reference | 0/2 | 0/2 | 2/2 | 2/2 | 2/2 |
| Alias enumeration | 0/1 | 0/1 | 1/1 | 1/1 | 1/1 |
| Query batching | 0/1 | 0/1 | 1/1 | 1/1 | 1/1 |
| Variables | 0/1 | 0/1 | 1/1 | 1/1 | 1/1 |
| Fragments | 0/1 | 0/1 | 1/1 | 1/1 | 1/1 |
| Node interface | 0/1 | 0/1 | 1/1 | 1/1 | 1/1 |
| Nested traversal | 0/2 | 0/2 | 1/2 | 2/2 | 2/2 |
| Unscoped list | 0/1 | 0/1 | 0/1 | 1/1 | 1/1 |
| Field-level exposure | 0/1 | 0/1 | 1/1 | 1/1 | 1/1 |
| Mutation tampering | 0/3 | 0/3 | 3/3 | 0/3 | 3/3 |

## Table 3 - Per-attack outcome (B = blocked/redacted, L = attack succeeded)

| Case | Category | Attack | off | depth | argcheck | response_only | shield |
|---|---|---|---|---|---|---|---|
| A01 | Direct object reference | Read another patient's medical record by ID | L | L | B | B | B |
| A02 | Direct object reference | Read another patient's invoice by ID | L | L | B | B | B |
| A03 | Alias enumeration | Enumerate 5 foreign objects in one request using aliases | L | L | B | B | B |
| A04 | Query batching | Batched array of operations targeting other users | L | L | B | B | B |
| A05 | Variables | Victim ID hidden in GraphQL variables | L | L | B | B | B |
| A06 | Fragments | Victim fields requested through a named fragment | L | L | B | B | B |
| A07 | Node interface | Relay node(id) with base64 global ID | L | L | B | B | B |
| A08 | Nested traversal | Pivot from a PUBLIC profile into private nested records | L | L | B | B | B |
| A09 | Nested traversal | Pivot through a foreign record to its patient's contact details | L | L | L | B | B |
| A10 | Unscoped list | Search endpoint returns everybody's records | L | L | L | B | B |
| A11 | Field-level exposure | Read private fields (email/phone) of a public type | L | L | B | B | B |
| A12 | Mutation tampering | Overwrite another patient's prescription | L | L | B | L | B |
| A13 | Mutation tampering | Mark another patient's invoice as paid (invoiceId arg) | L | L | B | L | B |
| A14 | Mutation tampering | Delete another patient's invoice (Boolean return, no object) | L | L | B | L | B |

## Table 4 - Benign requests (P = passed, FP = wrongly blocked)

| Case | Request | off | depth | argcheck | response_only | shield |
|---|---|---|---|---|---|---|
| B01 | Read own record | P | P | P | P | P |
| B02 | Read own invoice + nested record | P | P | P | P | P |
| B03 | me { records invoices } | P | P | P | P | P |
| B04 | myRecords list | P | P | P | P | P |
| B05 | View a doctor-visible PUBLIC profile (name/role only) | P | P | **FP** | P | P |
| B06 | Own record via node(id) | P | P | P | P | P |
| B07 | Own record via fragment + variables | P | P | P | P | P |
| B08 | Update own prescription | P | P | P | P | P |
| B09 | Pay own invoice | P | P | P | P | P |
| B10 | Own data with aliases | P | P | P | P | P |
| B11 | Search own diagnoses (backend returns all; own must survive) | P | P | P | P | P |
| B12 | Admin reads any patient record | P | P | P | P | P |
| B13 | Admin batch over several patients | P | P | P | P | P |
| B14 | Carol reads own invoice by variable | P | P | P | P | P |
