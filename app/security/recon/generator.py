"""
FEATURE 2 - Automated Authorization Test Generation
====================================================
Turns a :class:`DiscoveryResult` into executable authorization tests using the
explicitly seeded local accounts and resources.

Every generated test records:
  * its provenance (``seeded_fixture`` vs ``exploratory``),
  * the generator rule that produced it,
  * and the expected outcome from the shared policy oracle.

Known seeded flaws (the deliberately vulnerable fixture resolvers) are handled
separately from defects discovered during exploratory testing: exploratory
tests that do not map to a seeded owner are still emitted, but are tagged so
their results are never conflated with seeded-fixture results.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from app.database import get_db_connection
from app.security.recon.introspection import discover_local_schema
from app.security.recon.models import DiscoveryResult, GeneratedTest, SchemaFieldRef
from app.security.recon.oracle import compute_expected_outcome

# Documented fallback matching app/seed.py (used only if the DB is not seeded).
_DEFAULT_USERS: List[Tuple[int, str]] = [(101, "user"), (102, "user"), (103, "admin")]
_DEFAULT_OBJECTS: List[Tuple[int, int]] = [
    (101, 101), (102, 102), (103, 103), (201, 101), (202, 101), (203, 101),
]

_ENTITY_SELECTION = {
    "ResourceType": "id name ownerId",
    "UserType": "id username role",
    "HealthCheckType": "status message",
}


@dataclass
class Fixture:
    users: List[Tuple[int, str]]
    objects: List[Tuple[int, int]]  # (object_id, owner_id)

    def ids_by_owner(self, owner_id: int) -> List[int]:
        return [oid for oid, owner in self.objects if owner == owner_id]

    def owner_of(self, object_id: int) -> Optional[int]:
        for oid, owner in self.objects:
            if oid == object_id:
                return owner
        return None

    @property
    def user_ids(self) -> List[int]:
        return [uid for uid, _ in self.users]

    @property
    def first_owner(self) -> Optional[int]:
        for _, owner in self.objects:
            return owner
        return None

    def first_owner_with_object(self) -> Optional[int]:
        return self.objects[0][1] if self.objects else None

    def other_owner(self, exclude: int) -> Optional[int]:
        for _, owner in self.objects:
            if owner != exclude:
                return owner
        return None

    def admin_id(self) -> Optional[int]:
        for uid, role in self.users:
            if role.lower() == "admin":
                return uid
        return None


def load_fixture() -> Tuple[Fixture, bool]:
    """Load seeded accounts/resources from the DB; fall back to documented defaults."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, role FROM users ORDER BY id")
        users = [(row["id"], row["role"]) for row in cursor.fetchall()]
        cursor.execute("SELECT id, owner_id FROM objects ORDER BY id")
        objects = [(row["id"], row["owner_id"]) for row in cursor.fetchall()]
        conn.close()
        if users and objects:
            return Fixture(users=users, objects=objects), True
    except Exception:
        pass
    return Fixture(users=list(_DEFAULT_USERS), objects=list(_DEFAULT_OBJECTS)), False


def _selection_for(target_type: str, boundary_fields: Optional[List[str]] = None) -> str:
    if target_type in _ENTITY_SELECTION:
        return _ENTITY_SELECTION[target_type]
    if target_type == "Boolean":
        return ""
    fields = ["id"]
    if boundary_fields:
        fields.extend(f for f in boundary_fields if f not in fields)
    return " ".join(fields)


def _target_kind(target_type: str) -> str:
    low = target_type.lower()
    if "user" in low:
        return "user"
    if any(k in low for k in ("resource", "object", "document", "folder", "item")):
        return "resource"
    return "unknown"


def _test_id(category: str, schema_path: str, caller: Optional[int], target: Optional[int], suffix: str = "") -> str:
    raw = f"AE-{category}-{schema_path}-{caller if caller is not None else 'anon'}-{target if target is not None else 'na'}{suffix}"
    return re.sub(r"[^A-Za-z0-9_.-]", "_", raw)


def _expected(query: str, caller_id: Optional[int], role: str, variables: Optional[Dict] = None):
    return compute_expected_outcome(query, variables or {}, caller_id, role)


class TestGenerator:
    def __init__(self, discovery: Optional[DiscoveryResult] = None):
        self.discovery = discovery or discover_local_schema()
        self.fixture, self.db_seeded = load_fixture()
        self._seen: set = set()

    # -- helpers -----------------------------------------------------------
    def _emit(self, tests: List[GeneratedTest], **kwargs) -> None:
        query = kwargs["query"]
        caller = kwargs.get("caller_id")
        role = kwargs.get("caller_role", "user")
        variables = kwargs.get("variables", {})
        decision, reason, status, rationale = _expected(query, caller, role, variables)
        tid = kwargs.pop("test_id")
        if tid in self._seen:
            return
        self._seen.add(tid)
        tests.append(
            GeneratedTest(
                test_id=tid,
                name=kwargs["name"],
                category=kwargs["category"],
                provenance=kwargs.get("provenance", "seeded_fixture"),
                schema_path=kwargs["schema_path"],
                query=query,
                variables=variables,
                operation_name=kwargs.get("operation_name"),
                caller_id=caller,
                caller_role=role,
                target_object_type=kwargs.get("target_object_type", "Resource"),
                target_object_id=kwargs.get("target_object_id"),
                target_owner_id=kwargs.get("target_owner_id"),
                is_mutation=kwargs.get("is_mutation", False),
                expected_decision=decision,
                expected_reason=reason,
                expected_http_status=status,
                oracle_rationale=rationale,
                generator_rule=kwargs.get("generator_rule", ""),
            )
        )

    def _root_field_for(self, root_field: str) -> Optional[SchemaFieldRef]:
        for f in self.discovery.fields:
            if f.path_key == root_field and not f.is_nested and f.id_argument:
                return f
        return None

    # -- generation --------------------------------------------------------
    def generate(self) -> List[GeneratedTest]:
        tests: List[GeneratedTest] = []
        self._generate_root_entity_tests(tests)
        self._generate_nested_tests(tests)
        self._generate_mutation_tests(tests)
        self._generate_variants(tests)
        return tests

    def _generate_root_entity_tests(self, tests: List[GeneratedTest]) -> None:
        owner = self.fixture.first_owner_with_object()
        if owner is None:
            return
        own_ids = self.fixture.ids_by_owner(owner)
        admin = self.fixture.admin_id()
        other = self.fixture.other_owner(owner)
        victim_ids = self.fixture.ids_by_owner(other) if other is not None else own_ids

        for f in self.discovery.fields:
            if f.is_nested or not f.id_argument:
                continue
            if f.parent_type == "Mutation":
                # mutation fields are exercised by _generate_mutation_tests
                continue
            kind = _target_kind(f.target_type)
            if kind == "user":
                own_target, victim_target = owner, other
            elif kind == "resource":
                own_target = own_ids[0] if own_ids else None
                victim_target = victim_ids[0] if victim_ids else None
            else:
                kind = "resource"
                own_target = own_ids[0] if own_ids else None
                victim_target = victim_ids[0] if victim_ids else None

            provenance = "seeded_fixture" if self.db_seeded else "exploratory"
            sel = _selection_for(f.target_type, f.authorization_boundary_fields)

            if own_target is not None:
                self._emit(
                    tests,
                    test_id=_test_id("BENIGN_OWNER", f.canonical_path, owner, own_target),
                    name=f"Benign owner access: {f.canonical_path} #{own_target}",
                    category="BENIGN_OWNER",
                    schema_path=f.path_key,
                    query=f"query {{ {f.field_name}({f.id_argument}: {own_target}) {{ {sel} }} }}",
                    caller_id=owner,
                    caller_role="user",
                    target_object_type=kind,
                    target_object_id=own_target,
                    target_owner_id=owner,
                    provenance=provenance,
                    generator_rule=f"root entity accessor {f.canonical_path}; caller owns target",
                )

            if victim_target is not None and other is not None:
                self._emit(
                    tests,
                    test_id=_test_id("DIRECT_BOLA", f.canonical_path, owner, victim_target),
                    name=f"Direct cross-owner access: {f.canonical_path} #{victim_target}",
                    category="DIRECT_BOLA",
                    schema_path=f.path_key,
                    query=f"query {{ {f.field_name}({f.id_argument}: {victim_target}) {{ {sel} }} }}",
                    caller_id=owner,
                    caller_role="user",
                    target_object_type=kind,
                    target_object_id=victim_target,
                    target_owner_id=other,
                    provenance=provenance,
                    generator_rule=f"root entity accessor {f.canonical_path}; caller != owner",
                )

                if admin is not None:
                    self._emit(
                        tests,
                        test_id=_test_id("ADMIN_OVERRIDE", f.canonical_path, admin, victim_target),
                        name=f"Administrative override access: {f.canonical_path} #{victim_target}",
                        category="ADMIN_OVERRIDE",
                        schema_path=f.path_key,
                        query=f"query {{ {f.field_name}({f.id_argument}: {victim_target}) {{ {sel} }} }}",
                        caller_id=admin,
                        caller_role="admin",
                        target_object_type=kind,
                        target_object_id=victim_target,
                        target_owner_id=other,
                        provenance=provenance,
                        generator_rule="admin role crosses ownership boundary",
                    )

                self._emit(
                    tests,
                    test_id=_test_id("ANONYMOUS", f.canonical_path, None, victim_target),
                    name=f"Anonymous access: {f.canonical_path} #{victim_target}",
                    category="ANONYMOUS",
                    schema_path=f.path_key,
                    query=f"query {{ {f.field_name}({f.id_argument}: {victim_target}) {{ {sel} }} }}",
                    caller_id=None,
                    caller_role="anonymous",
                    target_object_type=kind,
                    target_object_id=victim_target,
                    target_owner_id=other,
                    provenance=provenance,
                    generator_rule="unauthenticated caller has no identity context",
                )

    def _generate_nested_tests(self, tests: List[GeneratedTest]) -> None:
        owner = self.fixture.first_owner_with_object()
        if owner is None:
            return
        own_ids = self.fixture.ids_by_owner(owner)
        other = self.fixture.other_owner(owner)
        victim_ids = self.fixture.ids_by_owner(other) if other is not None else own_ids

        for f in self.discovery.fields:
            if not f.is_nested:
                continue
            if f.parent_type == "Mutation":
                continue
            root = self._root_field_for(f.root_field)
            if root is None or not root.id_argument:
                continue
            sel = _selection_for(f.target_type, f.authorization_boundary_fields)
            provenance = "seeded_fixture" if self.db_seeded else "exploratory"

            if f.id_argument and victim_ids and other is not None:
                # nested entity traversal into another owner's resource
                child = victim_ids[0]
                self._emit(
                    tests,
                    test_id=_test_id("NESTED_BOLA", f.path_key, owner, child),
                    name=f"Nested traversal: {f.path_key} #{child} under {f.root_field} #{owner}",
                    category="NESTED_BOLA",
                    schema_path=f.path_key,
                    query=(
                        f"query {{ {root.field_name}({root.id_argument}: {owner}) "
                        f"{{ id {f.field_name}({f.id_argument}: {child}) {{ {sel} }} }} }}"
                    ),
                    caller_id=owner,
                    caller_role="user",
                    target_object_type=_target_kind(f.target_type),
                    target_object_id=child,
                    target_owner_id=other,
                    provenance=provenance,
                    generator_rule=f"nested id-bearing edge {f.canonical_path} under owned root {root.canonical_path}",
                )
                if own_ids:
                    benign_child = own_ids[0]
                    self._emit(
                        tests,
                        test_id=_test_id("BENIGN_OWNER", f.path_key, owner, benign_child, suffix="-nested"),
                        name=f"Benign nested: {f.path_key} #{benign_child} under {f.root_field} #{owner}",
                        category="BENIGN_OWNER",
                        schema_path=f.path_key,
                        query=(
                            f"query {{ {root.field_name}({root.id_argument}: {owner}) "
                            f"{{ id {f.field_name}({f.id_argument}: {benign_child}) {{ {sel} }} }} }}"
                        ),
                        caller_id=owner,
                        caller_role="user",
                        target_object_type=_target_kind(f.target_type),
                        target_object_id=benign_child,
                        target_owner_id=owner,
                        provenance=provenance,
                        generator_rule=f"benign nested id-bearing edge {f.canonical_path}",
                    )
            elif f.is_collection and other is not None:
                # nested collection reached through a root owned by a different principal
                root_id = self.fixture.ids_by_owner(other)[0] if self.fixture.ids_by_owner(other) else None
                if root_id is None:
                    continue
                self._emit(
                    tests,
                    test_id=_test_id("NESTED_BOLA", f.path_key, owner, root_id, suffix="-coll"),
                    name=f"Nested collection BOLA: {f.path_key} via {f.root_field} #{root_id}",
                    category="NESTED_BOLA",
                    schema_path=f.path_key,
                    query=(
                        f"query {{ {root.field_name}({root.id_argument}: {root_id}) "
                        f"{{ id {f.field_name} {{ {sel} }} }} }}"
                    ),
                    caller_id=owner,
                    caller_role="user",
                    target_object_type=_target_kind(f.target_type),
                    target_object_id=root_id,
                    target_owner_id=other,
                    provenance=provenance,
                    generator_rule=f"nested collection edge {f.canonical_path} through unowned root",
                )

    def _mutation_args(self, f: SchemaFieldRef, target_id: int, caller_id: Optional[int]) -> Optional[str]:
        parts: List[str] = []
        for name, type_name in f.argument_types.items():
            if name == f.id_argument:
                parts.append(f"{name}: {target_id}")
            elif type_name in ("Int", "ID", "Long", "BigInt") or name.lower().endswith("id"):
                if caller_id is None:
                    return None
                parts.append(f"{name}: {caller_id}")
            elif type_name == "String":
                parts.append(f'{name}: "shield_probe"')
            elif type_name == "Boolean":
                parts.append(f"{name}: true")
            else:
                return None
        return ", ".join(parts) if parts else None

    def _generate_mutation_tests(self, tests: List[GeneratedTest]) -> None:
        owner = self.fixture.first_owner_with_object()
        if owner is None:
            return
        own_ids = self.fixture.ids_by_owner(owner)
        other = self.fixture.other_owner(owner)
        victim_ids = self.fixture.ids_by_owner(other) if other is not None else own_ids
        provenance = "seeded_fixture" if self.db_seeded else "exploratory"

        for f in self.discovery.fields:
            if f.parent_type != "Mutation" or not f.id_argument:
                continue
            sel = _selection_for(f.target_type, f.authorization_boundary_fields)
            tail = f" {{ {sel} }}" if sel else ""

            if victim_ids and other is not None:
                args = self._mutation_args(f, victim_ids[0], owner)
                if args:
                    self._emit(
                        tests,
                        test_id=_test_id("MUTATION_BOLA", f.canonical_path, owner, victim_ids[0]),
                        name=f"Cross-owner mutation: {f.canonical_path} on #{victim_ids[0]}",
                        category="MUTATION_BOLA",
                        schema_path=f.field_name,
                        query=f"mutation {{ {f.field_name}({args}){tail} }}",
                        caller_id=owner,
                        caller_role="user",
                        target_object_type=_target_kind(f.target_type),
                        target_object_id=victim_ids[0],
                        target_owner_id=other,
                        is_mutation=True,
                        provenance=provenance,
                        generator_rule=f"state-altering mutation {f.canonical_path}; caller != owner",
                    )

            if own_ids:
                args = self._mutation_args(f, own_ids[0], owner)
                if args:
                    self._emit(
                        tests,
                        test_id=_test_id("BENIGN_OWNER", f.canonical_path, owner, own_ids[0], suffix="-mut"),
                        name=f"Benign owner mutation: {f.canonical_path} on #{own_ids[0]}",
                        category="BENIGN_OWNER",
                        schema_path=f.field_name,
                        query=f"mutation {{ {f.field_name}({args}){tail} }}",
                        caller_id=owner,
                        caller_role="user",
                        target_object_type=_target_kind(f.target_type),
                        target_object_id=own_ids[0],
                        target_owner_id=owner,
                        is_mutation=True,
                        provenance=provenance,
                        generator_rule=f"benign owner mutation {f.canonical_path}",
                    )

    def _generate_variants(self, tests: List[GeneratedTest]) -> None:
        """Alias-cloaking and variable-parameterized variants of the first direct BOLA."""
        direct = next((t for t in tests if t.category == "DIRECT_BOLA"), None)
        if direct is None or direct.target_object_id is None:
            return

        alias_query = direct.query.replace("{", "{ shieldAlias: ", 1)
        self._emit(
            tests,
            test_id=_test_id("ALIAS_MASKING", direct.schema_path, direct.caller_id, direct.target_object_id),
            name=f"Alias-cloaked cross-owner access: {direct.schema_path}",
            category="ALIAS_MASKING",
            schema_path=direct.schema_path,
            query=alias_query,
            caller_id=direct.caller_id,
            caller_role=direct.caller_role,
            target_object_type=direct.target_object_type,
            target_object_id=direct.target_object_id,
            target_owner_id=direct.target_owner_id,
            provenance=direct.provenance,
            generator_rule="response-path alias applied to a direct BOLA query",
        )

        id_arg = None
        for f in self.discovery.fields:
            if f.path_key == direct.schema_path and f.id_argument:
                id_arg = f.id_argument
                break
        if id_arg:
            var_query = (
                direct.query
                .replace(f"query {{", "query Probe($v: Int!) {", 1)
                .replace(f"({id_arg}: {direct.target_object_id})", f"({id_arg}: $v)")
            )
            self._emit(
                tests,
                test_id=_test_id("VARIABLE_INJECTION", direct.schema_path, direct.caller_id, direct.target_object_id),
                name=f"Variable-parameterized cross-owner access: {direct.schema_path}",
                category="VARIABLE_INJECTION",
                schema_path=direct.schema_path,
                query=var_query,
                variables={"v": direct.target_object_id},
                operation_name="Probe",
                caller_id=direct.caller_id,
                caller_role=direct.caller_role,
                target_object_type=direct.target_object_type,
                target_object_id=direct.target_object_id,
                target_owner_id=direct.target_owner_id,
                provenance=direct.provenance,
                generator_rule="id argument bound through a GraphQL variable",
            )


def generate_tests_from_discovery(discovery: Optional[DiscoveryResult] = None) -> List[GeneratedTest]:
    """Public entry point for FEATURE 2."""
    return TestGenerator(discovery).generate()
