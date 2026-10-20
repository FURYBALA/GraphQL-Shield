"""Attack and benign test corpus.

Attacker = Bob (uid 2). Victims = Alice (uid 1) and Carol (uid 3).
An attack SUCCEEDS if (a) a victim's CANARY string appears in Bob's response, or
(b) for mutations, the victim's data changed in the backend (checked as admin).
A benign case PASSES if the expected own-data marker appears in the response.
"""
import base64


def gid(t, i):
    return base64.b64encode(f"{t}:{i}".encode()).decode()


VICTIM_CANARIES = ["CANARY-ALICE", "CANARY-CAROL"]

ATTACKS = [
    {"id": "A01", "category": "Direct object reference", "title": "Read another patient's medical record by ID",
     "body": {"query": '{ record(id: "101") { id diagnosis prescription } }'}},
    {"id": "A02", "category": "Direct object reference", "title": "Read another patient's invoice by ID",
     "body": {"query": '{ invoice(id: "501") { id amount status record { diagnosis } } }'}},
    {"id": "A03", "category": "Alias enumeration", "title": "Enumerate 5 foreign objects in one request using aliases",
     "body": {"query": '{ a: record(id:"101"){diagnosis} b: record(id:"102"){diagnosis} c: record(id:"301"){diagnosis} '
                       'd: invoice(id:"501"){amount record{diagnosis}} e: invoice(id:"701"){amount record{diagnosis}} }'}},
    {"id": "A04", "category": "Query batching", "title": "Batched array of operations targeting other users",
     "body": [{"query": '{ record(id:"101"){diagnosis} }'}, {"query": '{ record(id:"201"){diagnosis} }'},
              {"query": '{ record(id:"301"){diagnosis} }'}]},
    {"id": "A05", "category": "Variables", "title": "Victim ID hidden in GraphQL variables",
     "body": {"query": "query Q($id: ID!) { invoice(id: $id) { amount status record { diagnosis } } }", "variables": {"id": "701"}}},
    {"id": "A06", "category": "Fragments", "title": "Victim fields requested through a named fragment",
     "body": {"query": 'query { record(id: "301") { ...Sensitive } } fragment Sensitive on MedicalRecord { diagnosis prescription }'}},
    {"id": "A07", "category": "Node interface", "title": "Relay node(id) with base64 global ID",
     "body": {"query": '{ node(id: "%s") { id ... on MedicalRecord { diagnosis } } }' % gid("MedicalRecord", "102")}},
    {"id": "A08", "category": "Nested traversal", "title": "Pivot from a PUBLIC profile into private nested records",
     "body": {"query": '{ user(id: "1") { name records { diagnosis prescription } invoices { amount } } }'}},
    {"id": "A09", "category": "Nested traversal", "title": "Pivot through a foreign record to its patient's contact details",
     "body": {"query": '{ searchRecords(term: "Asthma") { patient { name email phone } } }'}},
    {"id": "A10", "category": "Unscoped list", "title": "Search endpoint returns everybody's records",
     "body": {"query": '{ searchRecords(term: "CANARY") { id patientId diagnosis } }'}},
    {"id": "A11", "category": "Field-level exposure", "title": "Read private fields (email/phone) of a public type",
     "body": {"query": '{ user(id: "3") { name email phone } }'}},
    {"id": "A12", "category": "Mutation tampering", "title": "Overwrite another patient's prescription",
     "body": {"query": 'mutation { updateRecord(id: "101", prescription: "HACKED") { id } }'},
     "verify": {"query": '{ record(id: "101") { prescription } }', "tampered": lambda d: d["record"]["prescription"] == "HACKED"}},
    {"id": "A13", "category": "Mutation tampering", "title": "Mark another patient's invoice as paid (invoiceId arg)",
     "body": {"query": 'mutation { payInvoice(invoiceId: "501") { status } }'},
     "verify": {"query": '{ invoice(id: "501") { status } }', "tampered": lambda d: d["invoice"]["status"] == "PAID"}},
    {"id": "A14", "category": "Mutation tampering", "title": "Delete another patient's invoice (Boolean return, no object)",
     "body": {"query": 'mutation { deleteInvoice(id: "701") }'},
     "verify": {"query": '{ invoice(id: "701") { id } }', "tampered": lambda d: d["invoice"] is None}},
]

BENIGN = [
    {"id": "B01", "title": "Read own record", "user": "bob", "body": {"query": '{ record(id: "201") { diagnosis } }'}, "expect": "CANARY-BOB-DIAG"},
    {"id": "B02", "title": "Read own invoice + nested record", "user": "bob", "body": {"query": '{ invoice(id: "601") { amount record { diagnosis } } }'}, "expect": "CANARY-BOB-DIAG"},
    {"id": "B03", "title": "me { records invoices }", "user": "bob", "body": {"query": "{ me { name email records { diagnosis } invoices { amount } } }"}, "expect": "CANARY-BOB"},
    {"id": "B04", "title": "myRecords list", "user": "bob", "body": {"query": "{ myRecords { id diagnosis } }"}, "expect": "CANARY-BOB-DIAG"},
    {"id": "B05", "title": "View a doctor-visible PUBLIC profile (name/role only)", "user": "bob", "body": {"query": '{ user(id: "1") { name role } }'}, "expect": "Alice"},
    {"id": "B06", "title": "Own record via node(id)", "user": "bob", "body": {"query": '{ node(id: "%s") { ... on MedicalRecord { diagnosis } } }' % gid("MedicalRecord", "201")}, "expect": "CANARY-BOB-DIAG"},
    {"id": "B07", "title": "Own record via fragment + variables", "user": "bob",
     "body": {"query": "query($r: ID!) { record(id: $r) { ...F } } fragment F on MedicalRecord { diagnosis }", "variables": {"r": "201"}}, "expect": "CANARY-BOB-DIAG"},
    {"id": "B08", "title": "Update own prescription", "user": "bob", "body": {"query": 'mutation { updateRecord(id: "201", prescription: "Rest+Fluids") { prescription } }'}, "expect": "Rest+Fluids"},
    {"id": "B09", "title": "Pay own invoice", "user": "bob", "body": {"query": 'mutation { payInvoice(invoiceId: "601") { status } }'}, "expect": "PAID"},
    {"id": "B10", "title": "Own data with aliases", "user": "alice", "body": {"query": '{ a: record(id:"101"){diagnosis} b: record(id:"102"){diagnosis} }'}, "expect": "CANARY-ALICE-DIAG-102"},
    {"id": "B11", "title": "Search own diagnoses (backend returns all; own must survive)", "user": "bob", "body": {"query": '{ searchRecords(term: "flu") { diagnosis } }'}, "expect": "CANARY-BOB-DIAG"},
    {"id": "B12", "title": "Admin reads any patient record", "user": "admin", "body": {"query": '{ record(id: "301") { diagnosis } }'}, "expect": "CANARY-CAROL-DIAG"},
    {"id": "B13", "title": "Admin batch over several patients", "user": "admin",
     "body": [{"query": '{ record(id:"101"){diagnosis} }'}, {"query": '{ invoice(id:"701"){amount} }'}], "expect": "CANARY-ALICE-DIAG"},
    {"id": "B14", "title": "Carol reads own invoice by variable", "user": "carol",
     "body": {"query": "query($i: ID!){ invoice(id:$i){ amount record { diagnosis } } }", "variables": {"i": "701"}}, "expect": "CANARY-CAROL-DIAG"},
]

ATTACKER = "bob"
CREDENTIALS = {"alice": "alice123", "bob": "bob123", "carol": "carol123", "admin": "admin123"}
CONSOLE = {"users": ["bob", "alice", "carol", "admin"], "query": '{ record(id: "101") { id diagnosis prescription } }'}
