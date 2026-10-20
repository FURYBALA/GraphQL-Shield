"""
FEATURE 1 - Live Schema Reconnaissance
======================================
Connects to a real GraphQL endpoint, performs standard introspection when it is
available, and otherwise accepts an SDL schema file. From the *actual* schema it
builds a navigation graph of query/mutation operations, object-returning fields,
arguments, nested relationships and authorization boundaries.

No schema path is ever fabricated: every ``SchemaFieldRef`` originates from the
introspected schema or the supplied SDL. Relationships are labelled
``discovered`` / ``inferred`` / ``unverified`` so the provenance is explicit.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from graphql import (
    GraphQLList,
    GraphQLNonNull,
    GraphQLObjectType,
    GraphQLSchema,
    build_client_schema,
    build_schema,
    get_introspection_query,
)

from .models import DiscoveryResult, SchemaFieldRef

INTROSPECTION_QUERY = get_introspection_query(descriptions=False)

_ID_SCALARS = {"Int", "ID", "Long", "BigInt"}
_SENSITIVE_HINTS = ("secret", "token", "apikey", "api_key", "password", "credential", "private")
_OWNERSHIP_HINTS = ("ownerid", "owner_id", "owner", "userid", "user_id", "tenantid", "tenant_id", "createdby", "authorid")
_MAX_RELATIONSHIP_DEPTH = 6
_ROOT_TYPES = {"Query", "Mutation", "Subscription"}


def _unwrap(type_ref: Any) -> Tuple[Any, bool]:
    is_list = False
    while isinstance(type_ref, (GraphQLNonNull, GraphQLList)):
        if isinstance(type_ref, GraphQLList):
            is_list = True
        type_ref = type_ref.of_type
    return type_ref, is_list


def _scalar_args(field: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for name, arg in field.args.items():
        inner, _ = _unwrap(arg.type)
        out[name] = getattr(inner, "name", str(inner))
    return out


def _id_argument(field: Any) -> Optional[str]:
    args = _scalar_args(field)
    if args.get("id") in _ID_SCALARS:
        return "id"
    for name, type_name in args.items():
        if type_name in _ID_SCALARS and (name.lower() == "id" or name.lower().endswith("id")):
            return name
    return None


def _boundary_fields(obj_type: GraphQLObjectType) -> Tuple[List[str], List[str]]:
    boundary: List[str] = []
    sensitive: List[str] = []
    for fname, f in obj_type.fields.items():
        low = fname.lower()
        if any(h in low for h in _OWNERSHIP_HINTS):
            boundary.append(fname)
        if any(h in low for h in _SENSITIVE_HINTS):
            sensitive.append(fname)
    return boundary, sensitive


def build_discovery_from_schema(
    schema: GraphQLSchema,
    *,
    source: str,
    target: str,
    introspectable: bool,
    notes: Optional[List[str]] = None,
) -> DiscoveryResult:
    """Walk the real schema graph and produce a deterministic discovery result."""
    fields: List[SchemaFieldRef] = []
    roots: List[str] = []
    operations: Dict[str, List[str]] = {"query": [], "mutation": []}
    notes = list(notes or [])

    root_type_pairs: List[Tuple[str, GraphQLObjectType]] = []
    if schema.query_type is not None:
        root_type_pairs.append(("query", schema.query_type))
    if schema.mutation_type is not None:
        root_type_pairs.append(("mutation", schema.mutation_type))

    queue: List[Tuple[GraphQLObjectType, str]] = []

    # --- Pass 1: explicitly discovered root entity accessors -----------------
    for op_name, root_type in root_type_pairs:
        for field_name, field in root_type.fields.items():
            target_type, is_list = _unwrap(field.type)
            if not isinstance(target_type, GraphQLObjectType):
                continue
            operations[op_name].append(field_name)
            roots.append(f"{root_type.name}.{field_name}")
            boundary, sensitive = _boundary_fields(target_type)
            id_arg = _id_argument(field)
            fields.append(
                SchemaFieldRef(
                    canonical_path=f"{root_type.name}.{field_name}",
                    path_key=field_name,
                    root_field=field_name,
                    field_name=field_name,
                    parent_type=root_type.name,
                    target_type=target_type.name,
                    is_nested=False,
                    is_collection=is_list,
                    arguments=list(field.args.keys()),
                    argument_types=_scalar_args(field),
                    id_argument=id_arg,
                    is_sensitive_sink=bool(id_arg) or bool(sensitive),
                    authorization_boundary_fields=sorted(set(boundary + sensitive)),
                    relationship_status="discovered",
                    discovery_source=source,
                )
            )
            queue.append((target_type, field_name))

    # --- Pass 2: inferred relationship edges (BFS from discovered roots) ------
    seen_edges: set = set()
    depth = 0
    while queue and depth < _MAX_RELATIONSHIP_DEPTH:
        next_queue: List[Tuple[GraphQLObjectType, str]] = []
        for obj_type, prefix in queue:
            for field_name, field in obj_type.fields.items():
                target_type, is_list = _unwrap(field.type)
                if not isinstance(target_type, GraphQLObjectType):
                    continue
                edge = (obj_type.name, field_name)
                if edge in seen_edges:
                    continue
                seen_edges.add(edge)
                boundary, sensitive = _boundary_fields(target_type)
                id_arg = _id_argument(field)
                path_key = f"{prefix}.{field_name}"
                fields.append(
                    SchemaFieldRef(
                        canonical_path=f"{obj_type.name}.{field_name}",
                        path_key=path_key,
                        root_field=prefix.split(".")[0],
                        field_name=field_name,
                        parent_type=obj_type.name,
                        target_type=target_type.name,
                        is_nested=True,
                        is_collection=is_list,
                        arguments=list(field.args.keys()),
                        argument_types=_scalar_args(field),
                        id_argument=id_arg,
                        is_sensitive_sink=bool(id_arg) or bool(sensitive),
                        authorization_boundary_fields=sorted(set(boundary + sensitive)),
                        relationship_status="inferred",
                        discovery_source=source,
                    )
                )
                next_queue.append((target_type, path_key))
        queue = next_queue
        depth += 1

    # --- Pass 3: unverified object fields on types never reached from a root --
    reached_types = {d.target_type for d in fields}
    for type_name, type_def in schema.type_map.items():
        if not isinstance(type_def, GraphQLObjectType):
            continue
        if type_name.startswith("__") or type_name in _ROOT_TYPES or type_name in reached_types:
            continue
        for field_name, field in type_def.fields.items():
            target_type, is_list = _unwrap(field.type)
            if not isinstance(target_type, GraphQLObjectType):
                continue
            fields.append(
                SchemaFieldRef(
                    canonical_path=f"{type_name}.{field_name}",
                    path_key=field_name,
                    root_field=field_name,
                    field_name=field_name,
                    parent_type=type_name,
                    target_type=target_type.name,
                    is_nested=True,
                    is_collection=is_list,
                    arguments=list(field.args.keys()),
                    argument_types=_scalar_args(field),
                    id_argument=_id_argument(field),
                    relationship_status="unverified",
                    discovery_source=source,
                )
            )

    types_analyzed = sum(1 for t in schema.type_map.values() if isinstance(t, GraphQLObjectType) and not t.name.startswith("__"))
    if not introspectable:
        notes.append("Introspection was unavailable; discovery was built from the supplied SDL schema file.")

    return DiscoveryResult(
        target=target,
        source=source,
        introspectable=introspectable,
        schema_types_analyzed=types_analyzed,
        roots=roots,
        operations=operations,
        fields=fields,
        notes=notes,
    )


def discover_from_sdl(sdl: str, target: str = "schema-file") -> DiscoveryResult:
    """Discovery from an SDL document (used when introspection is disabled)."""
    schema = build_schema(sdl)
    return build_discovery_from_schema(
        schema, source="sdl", target=target, introspectable=False
    )


def discover_from_introspection(payload: Dict[str, Any], target: str = "live-endpoint") -> DiscoveryResult:
    """Discovery from a raw ``{"data": {"__schema": ...}}`` introspection response."""
    data = payload.get("data", payload)
    if "__schema" not in data:
        raise ValueError("Introspection payload does not contain a __schema entry")
    schema = build_client_schema(data)
    return build_discovery_from_schema(
        schema, source="introspection", target=target, introspectable=True
    )


def discover_local_schema() -> DiscoveryResult:
    """
    In-process discovery against the application's own Strawberry schema.
    Used as a deterministic fallback and by the offline evaluation harness.
    """
    from app.graphql.schema import schema as strawberry_schema

    graphql_schema = build_schema(strawberry_schema.as_str())
    return build_discovery_from_schema(
        graphql_schema,
        source="introspection",
        target="in-process-schema",
        introspectable=True,
        notes=["Discovered from the running application schema (strawberry .as_str())."],
    )


async def discover_live(
    base_url: str,
    client: Any,
    token: Optional[str] = None,
    schema_file: Optional[str] = None,
) -> DiscoveryResult:
    """
    FEATURE 1 entry point:
      1. Try real HTTP introspection against ``{base_url}/graphql``.
      2. If the protected gateway rejects introspection (its AST depth/complexity
         budget is a deliberate anti-DoS hardening we do not weaken), retry the
         introspection-capable route ``{base_url}/graphql-insecure`` which serves
         the *same* schema over real HTTP.
      3. Otherwise use a supplied SDL file.
      4. Otherwise surface the failure honestly (never fabricate paths).
    """
    root = base_url.rstrip("/")
    headers: Dict[str, str] = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    errors: List[str] = []
    for path in ("/graphql", "/graphql-insecure"):
        try:
            resp = await client.post(
                f"{root}{path}", json={"query": INTROSPECTION_QUERY}, headers=headers
            )
            body = resp.json()
            if resp.status_code == 200 and isinstance(body, dict) and body.get("data", {}).get("__schema"):
                notes = []
                if path != "/graphql":
                    notes.append(
                        f"Introspection was served by {path}: the protected gateway "
                        "rejected standard introspection under its AST budget (anti-DoS hardening). "
                        "The same live schema is exposed there."
                    )
                result = discover_from_introspection(body, target=f"{root}{path}")
                result.notes.extend(notes)
                return result
            errors.append(f"{path} -> HTTP {resp.status_code}: {str(body)[:180]}")
        except Exception as exc:  # network error / non-JSON
            errors.append(f"{path} -> {type(exc).__name__}: {exc}")

    if schema_file:
        with open(schema_file, "r", encoding="utf-8") as fh:
            return discover_from_sdl(fh.read(), target=schema_file)

    raise RuntimeError(
        "Live introspection failed and no schema file was provided. "
        f"Attempts: {'; '.join(errors)}"
    )
