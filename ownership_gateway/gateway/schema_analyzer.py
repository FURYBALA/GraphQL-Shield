"""Module 1: Schema Analyzer.

Introspects the backend's GraphQL schema and derives an *ownership model*:

  owned_types     : which object types belong to a user, and which field holds the owner id
                    (e.g. MedicalRecord.patientId, Invoice.patientId, User.id)
  public_fields   : fields of an owned type that anyone may read (e.g. User.name)
  lookup_fields   : a root query field that fetches type T by id (record(id) -> MedicalRecord).
                    Used for ownership "pre-flight" look-ups before a mutation runs.
  id_arguments    : for each root field, which ID arguments point at which owned type
                    (payInvoice(invoiceId) -> Invoice, deleteInvoice(id) -> Invoice)
  node_field      : the Relay-style node(id) field whose ids are base64 "Type:id" strings

Inference is heuristic (naming conventions + types). Anything it gets wrong can be
overridden in policy.json, and the dashboard shows the inferred model so a human can
review it. How accurate the heuristics are is one of the research questions.
"""
import re

import requests
from graphql import (
    GraphQLInterfaceType,
    GraphQLList,
    GraphQLNonNull,
    GraphQLObjectType,
    GraphQLScalarType,
    GraphQLUnionType,
    build_client_schema,
    get_introspection_query,
)

OWNER_FIELD_NAMES = ["ownerId", "userId", "patientId", "customerId", "accountId", "authorId", "createdById"]


def unwrap(t):
    while isinstance(t, (GraphQLNonNull, GraphQLList)):
        t = t.of_type
    return t


def is_id_scalar(t, name=None):
    """True for ID fields/arguments. Many real schemas (e.g. Strawberry/FastAPI ones) use Int
    instead of ID, so an Int also counts when its name says it is an identifier (id, ownerId, ...)."""
    t = unwrap(t)
    if not isinstance(t, GraphQLScalarType):
        return False
    if t.name == "ID":
        return True
    return t.name == "Int" and name is not None and (name in ("id", "ids") or bool(re.search(r"[a-z]Ids?$", name)))


def type_stem(type_name):
    """'ResourceType' -> 'resource', 'MedicalRecord' -> 'medicalrecord' (for matching against field/argument names)."""
    stem = type_name.lower()
    return stem[:-4] if stem.endswith("type") and len(stem) > 4 else stem


def fetch_schema(backend_url, token):
    resp = requests.post(backend_url, json={"query": get_introspection_query()},
                         headers={"Authorization": f"Bearer {token}"}, timeout=10)
    resp.raise_for_status()
    return build_client_schema(resp.json()["data"])


class OwnershipModel:
    def __init__(self, schema, policy):
        self.schema = schema
        self.policy = policy
        self.principal = policy.get("principal_type", "User")
        self.owned_types = {}      # type name -> owner field name
        self.inferred_by = {}      # type name -> "config" | "heuristic" | "principal"
        self.public_fields = {k: set(v) for k, v in policy.get("public_fields", {}).items()}
        self.lookup_fields = {}    # type name -> root query field name
        self.id_arguments = {"query": {}, "mutation": {}}  # field -> {arg: type}
        self.node_field = None
        self._infer()

    # ------------------------------------------------------------------ inference
    def _object_types(self):
        for name, t in self.schema.type_map.items():
            if name.startswith("__") or not isinstance(t, GraphQLObjectType):
                continue
            if t in (self.schema.query_type, self.schema.mutation_type, self.schema.subscription_type):
                continue
            yield name, t

    def _infer(self):
        overrides = self.policy.get("owner_fields", {})
        for name, t in self._object_types():
            if name in overrides:
                self.owned_types[name] = overrides[name]
                self.inferred_by[name] = "config"
            elif name == self.principal and "id" in t.fields:
                self.owned_types[name] = "id"
                self.inferred_by[name] = "principal"
            else:
                for candidate in OWNER_FIELD_NAMES:
                    if candidate in t.fields and is_id_scalar(t.fields[candidate].type, candidate):
                        self.owned_types[name] = candidate
                        self.inferred_by[name] = "heuristic"
                        break

        q = self.schema.query_type
        for fname, f in q.fields.items():
            ret = unwrap(f.type)
            id_args = [a for a, ad in f.args.items() if is_id_scalar(ad.type, a)]
            if fname == "node" and isinstance(ret, GraphQLInterfaceType) and id_args:
                self.node_field = fname
                continue
            if (isinstance(f.type, GraphQLList) or isinstance(getattr(f.type, "of_type", None), GraphQLList)):
                continue
            if ret.name in self.owned_types and len(id_args) == 1 and ret.name not in self.lookup_fields:
                self.lookup_fields[ret.name] = fname

        for kind, root in (("query", self.schema.query_type), ("mutation", self.schema.mutation_type)):
            if root is None:
                continue
            for fname, f in root.fields.items():
                mapping = {}
                for aname, adef in f.args.items():
                    if not is_id_scalar(adef.type, aname) or fname == self.node_field:
                        continue
                    target = self._target_for_arg(fname, aname, unwrap(f.type))
                    if target:
                        mapping[aname] = target
                if mapping:
                    self.id_arguments[kind][fname] = mapping
        for kind in ("query", "mutation"):
            self.id_arguments[kind].update(self.policy.get("id_argument_overrides", {}).get(kind, {}))

    def _target_for_arg(self, field_name, arg_name, return_type):
        owned = list(self.owned_types)
        # 1) argument name says it: invoiceId -> Invoice, recordId -> MedicalRecord
        m = re.match(r"(.+?)Ids?$", arg_name)
        if m:
            stem = m.group(1).lower()
            for t in owned:
                if type_stem(t) == stem or type_stem(t).endswith(stem):
                    return t
        if arg_name not in ("id", "ids"):
            return None
        # 2) the field returns the owned type: updateRecord(id) -> MedicalRecord
        if return_type.name in self.owned_types:
            return return_type.name
        # 3) the field name mentions the type: deleteInvoice(id) -> Invoice, deleteResource(id) -> ResourceType
        for t in sorted(owned, key=lambda n: len(type_stem(n)), reverse=True):
            if type_stem(t) in field_name.lower():
                return t
        return None

    # ------------------------------------------------------------------ helpers
    def possible_owned_types(self, t):
        """Owned concrete types a value of (possibly abstract) type t could be."""
        if isinstance(t, GraphQLObjectType):
            return [t.name] if t.name in self.owned_types else []
        if isinstance(t, (GraphQLInterfaceType, GraphQLUnionType)):
            return [p.name for p in self.schema.get_possible_types(t) if p.name in self.owned_types]
        return []

    def summary(self):
        return {
            "principal_type": self.principal,
            "owned_types": [
                {"type": t, "owner_field": f, "inferred_by": self.inferred_by[t],
                 "lookup_field": self.lookup_fields.get(t), "public_fields": sorted(self.public_fields.get(t, []))}
                for t, f in self.owned_types.items()
            ],
            "id_arguments": self.id_arguments,
            "node_field": self.node_field,
        }
