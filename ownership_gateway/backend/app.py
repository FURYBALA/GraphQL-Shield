"""ClinicHub: a deliberately VULNERABLE GraphQL API (the "target application").

It authenticates users (it knows WHO is calling) but it never checks whether
the caller OWNS the object they ask for. That missing check is BOLA
(Broken Object Level Authorization, OWASP API Security Top 10 2023 - API1).

Do not deploy this anywhere. It exists so GraphQLShield has something to protect.
Run:  python -m backend.app        (listens on :5001)
"""
import base64
import copy

from flask import Flask, jsonify, request
from graphql import build_schema, graphql_sync

from common.auth import claims_from_header, issue_token

SDL = """
interface Node { id: ID! }

type User implements Node {
  id: ID!
  name: String!
  role: String!
  email: String!
  phone: String
  records: [MedicalRecord!]!
  invoices: [Invoice!]!
}

type MedicalRecord implements Node {
  id: ID!
  patientId: ID!
  patient: User!
  doctor: String!
  diagnosis: String!
  prescription: String
}

type Invoice implements Node {
  id: ID!
  patientId: ID!
  amount: Float!
  status: String!
  record: MedicalRecord
}

type Query {
  me: User
  user(id: ID!): User
  record(id: ID!): MedicalRecord
  invoice(id: ID!): Invoice
  node(id: ID!): Node
  myRecords: [MedicalRecord!]!
  searchRecords(term: String!): [MedicalRecord!]!
}

type Mutation {
  updateRecord(id: ID!, prescription: String!): MedicalRecord
  payInvoice(invoiceId: ID!): Invoice
  deleteInvoice(id: ID!): Boolean
}
"""

# Every secret value contains a CANARY string so the evaluation can detect leaks
# automatically: if bob's response contains "CANARY-ALICE", alice's data leaked.
SEED = {
    "users": {
        "1": {"id": "1", "name": "Alice", "role": "patient", "email": "alice@CANARY-ALICE.mail", "phone": "CANARY-ALICE-PHONE", "password": "alice123"},
        "2": {"id": "2", "name": "Bob", "role": "patient", "email": "bob@CANARY-BOB.mail", "phone": "CANARY-BOB-PHONE", "password": "bob123"},
        "3": {"id": "3", "name": "Carol", "role": "patient", "email": "carol@CANARY-CAROL.mail", "phone": "CANARY-CAROL-PHONE", "password": "carol123"},
        "9": {"id": "9", "name": "Dr. Admin", "role": "admin", "email": "admin@clinic.local", "phone": None, "password": "admin123"},
    },
    "records": {
        "101": {"id": "101", "patientId": "1", "doctor": "Dr. Rao", "diagnosis": "CANARY-ALICE-DIAG-101 Type 2 diabetes", "prescription": "Metformin"},
        "102": {"id": "102", "patientId": "1", "doctor": "Dr. Iyer", "diagnosis": "CANARY-ALICE-DIAG-102 Hypertension", "prescription": "Amlodipine"},
        "201": {"id": "201", "patientId": "2", "doctor": "Dr. Rao", "diagnosis": "CANARY-BOB-DIAG-201 Seasonal flu", "prescription": "Rest"},
        "301": {"id": "301", "patientId": "3", "doctor": "Dr. Khan", "diagnosis": "CANARY-CAROL-DIAG-301 Asthma", "prescription": "Inhaler"},
    },
    "invoices": {
        "501": {"id": "501", "patientId": "1", "amount": 1200.0, "status": "UNPAID", "recordId": "101"},
        "601": {"id": "601", "patientId": "2", "amount": 300.0, "status": "UNPAID", "recordId": "201"},
        "701": {"id": "701", "patientId": "3", "amount": 950.0, "status": "UNPAID", "recordId": "301"},
    },
}
DB = copy.deepcopy(SEED)


def _typed(kind, obj):
    return None if obj is None else {**obj, "__typename": kind}


def user_obj(uid):
    return _typed("User", DB["users"].get(str(uid)))


def record_obj(rid):
    return _typed("MedicalRecord", DB["records"].get(str(rid)))


def invoice_obj(iid):
    return _typed("Invoice", DB["invoices"].get(str(iid)))


def to_global_id(type_name, raw_id):
    return base64.b64encode(f"{type_name}:{raw_id}".encode()).decode()


def from_global_id(gid):
    type_name, raw_id = base64.b64decode(gid).decode().split(":", 1)
    return type_name, raw_id


schema = build_schema(SDL)
Q, M = schema.query_type.fields, schema.mutation_type.fields
T = schema.type_map


def caller(info):
    return info.context["claims"]


# ---- Query resolvers: authentication only, NO ownership checks (the BOLA bug) ----
Q["me"].resolve = lambda _, info: user_obj(caller(info)["uid"])
Q["user"].resolve = lambda _, info, id: user_obj(id)
Q["record"].resolve = lambda _, info, id: record_obj(id)
Q["invoice"].resolve = lambda _, info, id: invoice_obj(id)
Q["myRecords"].resolve = lambda _, info: [record_obj(r) for r, v in DB["records"].items() if v["patientId"] == caller(info)["uid"]]
# Bug: the search forgets to filter by the caller, so it returns everybody's records.
Q["searchRecords"].resolve = lambda _, info, term: [record_obj(r) for r, v in DB["records"].items() if term.lower() in v["diagnosis"].lower()]


def resolve_node(_, info, id):
    kind, raw = from_global_id(id)
    return {"User": user_obj, "MedicalRecord": record_obj, "Invoice": invoice_obj}[kind](raw)


Q["node"].resolve = resolve_node
T["Node"].resolve_type = lambda obj, info, abstract_type: obj["__typename"]
T["User"].fields["records"].resolve = lambda u, info: [record_obj(r) for r, v in DB["records"].items() if v["patientId"] == u["id"]]
T["User"].fields["invoices"].resolve = lambda u, info: [invoice_obj(i) for i, v in DB["invoices"].items() if v["patientId"] == u["id"]]
T["MedicalRecord"].fields["patient"].resolve = lambda r, info: user_obj(r["patientId"])
T["Invoice"].fields["record"].resolve = lambda inv, info: record_obj(inv["recordId"])


# ---- Mutation resolvers: also no ownership checks ----
def update_record(_, info, id, prescription):
    if id in DB["records"]:
        DB["records"][id]["prescription"] = prescription
    return record_obj(id)


def pay_invoice(_, info, invoiceId):
    if invoiceId in DB["invoices"]:
        DB["invoices"][invoiceId]["status"] = "PAID"
    return invoice_obj(invoiceId)


def delete_invoice(_, info, id):
    return DB["invoices"].pop(id, None) is not None


M["updateRecord"].resolve = update_record
M["payInvoice"].resolve = pay_invoice
M["deleteInvoice"].resolve = delete_invoice

app = Flask(__name__)


@app.post("/login")
def login():
    body = request.get_json(force=True)
    for u in DB["users"].values():
        if u["name"].split()[-1].lower() == str(body.get("username", "")).lower() and u["password"] == body.get("password"):
            return jsonify({"token": issue_token(u["id"], u["role"]), "uid": u["id"], "role": u["role"]})
    return jsonify({"error": "invalid credentials"}), 401


@app.post("/reset")
def reset():
    """Restore seed data (used between evaluation runs)."""
    DB.clear()
    DB.update(copy.deepcopy(SEED))
    return jsonify({"ok": True})


def run_one(op, claims):
    result = graphql_sync(schema, op.get("query", ""), variable_values=op.get("variables"),
                          operation_name=op.get("operationName"), context_value={"claims": claims})
    out = {"data": result.data}
    if result.errors:
        out["errors"] = [e.formatted for e in result.errors]
    return out


@app.post("/graphql")
def graphql_endpoint():
    claims = claims_from_header(request.headers.get("Authorization"))
    if not claims:
        return jsonify({"errors": [{"message": "Unauthenticated"}]}), 401
    body = request.get_json(force=True)
    # Query batching (a JSON array of operations) is supported, as in many real servers.
    if isinstance(body, list):
        return jsonify([run_one(op, claims) for op in body])
    return jsonify(run_one(body, claims))


if __name__ == "__main__":
    app.run(port=5001, threaded=True)
