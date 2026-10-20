"""Modules 2-4: the enforcement pipeline.

For every incoming operation the gateway runs:

  1. parse + validate against the introspected schema      (reject malformed queries)
  2. structural limits: depth / aliases / batch size         (classic GraphQL hardening)
  3. PRE-FLIGHT ownership check on ID arguments              (stops side effects of mutations)
  4. QUERY AUGMENTATION: inject  __gs_type: __typename,
     __gs_owner: <ownerField>, __gs_id: id  into every selection set that can hold an owned object
  5. forward to the backend
  6. RESPONSE VERIFICATION: walk the JSON, redact every owned object whose owner != caller
     (catches nested traversal, list/search leaks, node(id), fragments, aliases)
  7. strip injected fields, log, update the enumeration detector

Modes (used for the baseline comparison in the evaluation):
  off            plain reverse proxy, no protection
  depth          step 2 only (what GraphQL hardening middleware typically provides)
  argcheck       steps 2+3 on every root field (parameter-based BOLA check, like a WAF rule)
  response_only  steps 2+4+6 (ablation: no pre-flight)
  shield         full GraphQLShield: 2 + 3 (mutations) + 4 + 6 + enumeration detection
"""
import base64
import time
from collections import defaultdict, deque

import requests
from graphql import (
    FieldNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    GraphQLObjectType,
    InlineFragmentNode,
    NamedTypeNode,
    NameNode,
    OperationDefinitionNode,
    SelectionSetNode,
    is_composite_type,
    parse,
    print_ast,
    validate,
)
from graphql.utilities import get_operation_ast, value_from_ast_untyped

from common.auth import SERVICE_TOKEN
from .schema_analyzer import is_id_scalar, unwrap

MODES = ["off", "depth", "argcheck", "response_only", "shield"]
PREFIX = "__gs_"


def _field(alias, name):
    return FieldNode(alias=NameNode(value=alias), name=NameNode(value=name), arguments=(), directives=(), selection_set=None)


def _replace(node, **changes):
    """Copy an immutable graphql-core AST node with some attributes changed."""
    return node.__class__(**{**{k: getattr(node, k) for k in node.keys}, **changes})


class Rejection(Exception):
    def __init__(self, reason, violations=None, status=200):
        super().__init__(reason)
        self.reason, self.violations, self.status = reason, violations or [], status


class Shield:
    def __init__(self, model, backend_url, config, store):
        self.model, self.schema = model, model.schema
        self.backend_url, self.cfg, self.store = backend_url, config, store
        self.mode = config.get("mode", "shield")
        self.http = requests.Session()
        self.owner_cache = {}
        self.reset_detector()

    def reset_detector(self):
        self.recent_violations = defaultdict(deque)  # uid -> deque[(ts, "Type:id")]
        self.locked_until = {}

    # =================================================================== entry point
    def handle(self, body, claims, auth_header, test_case=None):
        start = time.perf_counter()
        uid, role = claims["uid"], claims.get("role")
        is_batch = isinstance(body, list)
        ops = body if is_batch else [body]
        results, decisions, all_violations, reasons = [], [], [], []
        try:
            if self.mode != "off" and is_batch and len(ops) > self.cfg["max_batch"]:
                raise Rejection(f"batch of {len(ops)} operations exceeds limit {self.cfg['max_batch']}")
            if self.mode == "shield" and self.locked_until.get(uid, 0) > time.time():
                raise Rejection("caller temporarily blocked: suspected BOLA enumeration", status=429)
            for op in ops:
                res, decision, violations, reason = self._handle_one(op, uid, role, auth_header)
                results.append(res)
                decisions.append(decision)
                all_violations += violations
                if reason:
                    reasons.append(reason)
        except Rejection as r:
            results = [{"data": None, "errors": [{"message": f"GraphQLShield: {r.reason}", "extensions": {"code": "GS_BLOCKED"}}]}] * len(ops)
            decisions, all_violations, reasons = ["blocked"], r.violations, [r.reason]
            status = r.status
        else:
            status = 200

        decision = "blocked" if "blocked" in decisions else "redacted" if "redacted" in decisions else "allowed"
        if self.mode == "shield":
            self._detect_enumeration(uid, all_violations)
        latency = (time.perf_counter() - start) * 1000
        self.store.log_request(uid=uid, role=role, mode=self.mode,
                               operation="batch" if is_batch else self._op_kind(ops[0]),
                               query=str(body if is_batch else ops[0].get("query", ""))[:4000],
                               decision=decision, reason="; ".join(reasons)[:500], violations=all_violations,
                               latency_ms=round(latency, 2), test_case=test_case)
        return (results if is_batch else results[0]), status

    def _op_kind(self, op):
        try:
            o = get_operation_ast(parse(op.get("query", "")), op.get("operationName"))
            return o.operation.value if o else "unknown"
        except Exception:
            return "invalid"

    # =================================================================== per operation
    def _handle_one(self, op, uid, role, auth_header):
        if self.mode == "off":
            return self._forward(op, auth_header), "allowed", [], None

        query, variables = op.get("query", ""), op.get("variables") or {}
        try:
            doc = parse(query)
        except Exception as e:
            return {"data": None, "errors": [{"message": f"Syntax error: {e}"}]}, "blocked", [], "syntax error"
        errors = validate(self.schema, doc)
        if errors:
            return {"data": None, "errors": [{"message": e.message} for e in errors]}, "blocked", [], "schema validation failed"
        operation = get_operation_ast(doc, op.get("operationName"))
        if operation is None:
            return {"data": None, "errors": [{"message": "operation not found"}]}, "blocked", [], "no operation"
        fragments = {d.name.value: d for d in doc.definitions if isinstance(d, FragmentDefinitionNode)}
        privileged = role in self.cfg["bypass_roles"]

        # ---- step 2: structural limits
        depth = self._depth(operation.selection_set, fragments)
        aliases = self._count_aliases(doc)
        if depth > self.cfg["max_depth"]:
            return self._deny(f"query depth {depth} exceeds {self.cfg['max_depth']}")
        if aliases > self.cfg["max_aliases"]:
            return self._deny(f"{aliases} aliases exceed limit {self.cfg['max_aliases']}")
        if self.mode == "depth":
            return self._forward(op, auth_header), "allowed", [], None
        if any((f.alias and f.alias.value.startswith(PREFIX)) for f in self._all_fields(doc)):
            return self._deny("reserved alias prefix __gs_")

        kind = operation.operation.value
        # ---- step 3: pre-flight ownership check
        if not privileged and (self.mode == "argcheck" or (self.mode == "shield" and kind == "mutation")):
            violations = self._preflight(operation, fragments, variables, kind, uid)
            if violations:
                return self._deny("pre-flight ownership check failed", violations)
        if self.mode == "argcheck":
            return self._forward(op, auth_header), "allowed", [], None

        # ---- steps 4-6: augmentation, forward, response verification
        res = self._forward({**op, "query": print_ast(self._augment(doc))}, auth_header)
        violations = []
        if isinstance(res.get("data"), dict):
            res["data"] = self._verify(res["data"], [], uid, privileged, violations)
        if violations:
            res.setdefault("errors", [])
            res["errors"] += [{"message": f"GraphQLShield: access denied to {v['type']} owned by another user",
                               "path": v["path"], "extensions": {"code": "BOLA_REDACTED"}} for v in violations]
            return res, "redacted", violations, f"{len(violations)} object(s) redacted"
        return res, "allowed", [], None

    def _deny(self, reason, violations=None):
        return ({"data": None, "errors": [{"message": f"GraphQLShield: {reason}", "extensions": {"code": "GS_BLOCKED"}}]},
                "blocked", violations or [], reason)

    def _forward(self, op, auth_header):
        r = self.http.post(self.backend_url, json=op, headers={"Authorization": auth_header}, timeout=10)
        return r.json()

    # =================================================================== structural limits
    def _depth(self, sel_set, fragments, seen=frozenset()):
        if sel_set is None:
            return 0
        best = 0
        for s in sel_set.selections:
            if isinstance(s, FieldNode):
                best = max(best, (1 + self._depth(s.selection_set, fragments, seen)) if s.selection_set else 1)
            elif isinstance(s, InlineFragmentNode):
                best = max(best, self._depth(s.selection_set, fragments, seen))
            elif isinstance(s, FragmentSpreadNode) and s.name.value not in seen and s.name.value in fragments:
                best = max(best, self._depth(fragments[s.name.value].selection_set, fragments, seen | {s.name.value}))
        return best

    def _all_fields(self, doc):
        stack = [d.selection_set for d in doc.definitions if hasattr(d, "selection_set")]
        while stack:
            ss = stack.pop()
            for s in ss.selections:
                if isinstance(s, FieldNode):
                    yield s
                if getattr(s, "selection_set", None):
                    stack.append(s.selection_set)

    def _count_aliases(self, doc):
        return sum(1 for f in self._all_fields(doc) if f.alias)

    # =================================================================== step 3: pre-flight
    def _root_fields(self, sel_set, fragments):
        for s in sel_set.selections:
            if isinstance(s, FieldNode):
                yield s
            elif isinstance(s, InlineFragmentNode):
                yield from self._root_fields(s.selection_set, fragments)
            elif isinstance(s, FragmentSpreadNode) and s.name.value in fragments:
                yield from self._root_fields(fragments[s.name.value].selection_set, fragments)

    def _preflight(self, operation, fragments, variables, kind, uid):
        violations = []
        mapping = self.model.id_arguments.get(kind, {})
        for f in self._root_fields(operation.selection_set, fragments):
            fname = f.name.value
            args = {a.name.value: value_from_ast_untyped(a.value, variables) for a in (f.arguments or ())}
            targets = []
            if fname == self.model.node_field and "id" in args:
                try:
                    tname, raw = base64.b64decode(str(args["id"])).decode().split(":", 1)
                    targets.append((tname, raw))
                except Exception:
                    pass
            for aname, tname in mapping.get(fname, {}).items():
                vals = args.get(aname)
                for v in (vals if isinstance(vals, list) else [vals]):
                    if v is not None:
                        targets.append((tname, str(v)))
            for tname, oid in targets:
                if tname not in self.model.owned_types:
                    continue
                owner = self._lookup_owner(tname, oid)
                if owner == "__unverifiable__" and self.cfg["fail_closed"]:
                    violations.append({"type": tname, "id": oid, "owner": None, "path": [f.alias.value if f.alias else fname],
                                       "stage": "preflight", "detail": "no lookup field to verify ownership"})
                elif owner is not None and owner != "__unverifiable__" and str(owner) != str(uid):
                    violations.append({"type": tname, "id": oid, "owner": owner, "path": [f.alias.value if f.alias else fname],
                                       "stage": "preflight"})
        return violations

    def _lookup_owner(self, tname, oid):
        """Ask the backend (as the gateway service identity) who owns object tname:oid."""
        if tname == self.model.principal:
            return oid
        key = (tname, oid)
        hit = self.owner_cache.get(key)
        if hit and hit[1] > time.time():
            return hit[0]
        field = self.model.lookup_fields.get(tname)
        if not field:
            return "__unverifiable__"
        arg, adef = next((a, d) for a, d in self.schema.query_type.fields[field].args.items() if is_id_scalar(d.type, a))
        value = oid
        if unwrap(adef.type).name == "Int":
            try:
                value = int(oid)
            except ValueError:
                return None  # not a valid id for this backend, so it cannot name anyone's object
        q = f"query($v: {unwrap(adef.type).name}!) {{ x: {field}({arg}: $v) {{ o: {self.model.owned_types[tname]} }} }}"
        data = self._forward({"query": q, "variables": {"v": value}}, f"Bearer {SERVICE_TOKEN}").get("data") or {}
        owner = (data.get("x") or {}).get("o")
        self.owner_cache[key] = (owner, time.time() + self.cfg["owner_cache_ttl_s"])
        return owner

    # =================================================================== step 4: augmentation
    def _augment(self, doc):
        """Return a NEW document with ownership fields injected (AST nodes are immutable)."""
        defs = []
        for d in doc.definitions:
            if isinstance(d, OperationDefinitionNode):
                ss = self._augment_set(d.selection_set, self.schema.get_root_type(d.operation), is_root=True)
            elif isinstance(d, FragmentDefinitionNode):
                ss = self._augment_set(d.selection_set, self.schema.get_type(d.type_condition.name.value))
            else:
                defs.append(d)
                continue
            defs.append(_replace(d, selection_set=ss))
        return _replace(doc, definitions=tuple(defs))

    def _augment_set(self, sel_set, parent, is_root=False):
        out = []
        for s in sel_set.selections:
            if isinstance(s, FieldNode) and s.selection_set and not s.name.value.startswith("__"):
                fdef = parent.fields.get(s.name.value) if hasattr(parent, "fields") else None
                if fdef is not None:
                    s = _replace(s, selection_set=self._augment_set(s.selection_set, unwrap(fdef.type)))
            elif isinstance(s, InlineFragmentNode):
                t = self.schema.get_type(s.type_condition.name.value) if s.type_condition else parent
                s = _replace(s, selection_set=self._augment_set(s.selection_set, t))
            out.append(s)
        if not is_root and is_composite_type(parent):
            out.append(_field(PREFIX + "type", "__typename"))
            for tname in self.model.possible_owned_types(parent):
                t = self.schema.get_type(tname)
                inject = [_field(PREFIX + "owner", self.model.owned_types[tname])]
                if "id" in t.fields:
                    inject.append(_field(PREFIX + "id", "id"))
                if isinstance(parent, GraphQLObjectType):
                    out += inject
                else:
                    out.append(InlineFragmentNode(type_condition=NamedTypeNode(name=NameNode(value=tname)), directives=(),
                                                  selection_set=SelectionSetNode(selections=tuple(inject))))
        return SelectionSetNode(selections=tuple(out))

    # =================================================================== step 6: verification
    def _verify(self, node, path, uid, privileged, violations):
        if isinstance(node, list):
            return [self._verify(v, path + [i], uid, privileged, violations) for i, v in enumerate(node)]
        if not isinstance(node, dict):
            return node
        tname, owner, oid = node.get(PREFIX + "type"), node.get(PREFIX + "owner"), node.get(PREFIX + "id")
        visible = [k for k in node if not k.startswith(PREFIX)]
        if (not privileged and tname in self.model.owned_types and owner is not None and str(owner) != str(uid)):
            exposed = set(visible) - self.model.public_fields.get(tname, set()) - {"__typename"}
            if exposed:
                violations.append({"type": tname, "id": oid, "owner": owner, "path": path,
                                   "fields": sorted(exposed), "stage": "response"})
                return None
        return {k: self._verify(v, path + [k], uid, privileged, violations) for k, v in node.items() if not k.startswith(PREFIX)}

    # =================================================================== enumeration detector
    def _detect_enumeration(self, uid, violations):
        if not violations:
            return
        now, window = time.time(), self.cfg["enum_window_s"]
        q = self.recent_violations[uid]
        for v in violations:
            q.append((now, f"{v['type']}:{v.get('id')}"))
        while q and q[0][0] < now - window:
            q.popleft()
        distinct = len({k for _, k in q})
        if distinct >= self.cfg["enum_threshold"] and self.locked_until.get(uid, 0) < now:
            self.locked_until[uid] = now + self.cfg["enum_lockout_s"]
            self.store.log_alert(uid, "BOLA_ENUMERATION",
                                 f"user {uid} touched {distinct} foreign objects in {window}s; locked out for {self.cfg['enum_lockout_s']}s")
