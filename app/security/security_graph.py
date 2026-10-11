"""
GraphQL Security Graph Module

Constructs a formal, typed, in-memory Security Graph G = (V, E) from a GraphQL
schema (Strawberry Schema or graphql-core GraphQLSchema).

The Security Graph provides a structural representation of:
1. Object types, interface types, union types, and scalar/enum definitions.
2. Fields, their exact argument signatures, and complete type-wrapper unwrapping
   (supporting non-null wrappers, arbitrary list nesting depths, etc.).
3. Directed containment edges (DEFINES_FIELD), type return edges (RETURNS_TYPE),
   cross-type navigation edges (NAVIGATES_TO), and interface implementation edges (IMPLEMENTS).
4. Structural candidate-identifier identification without guessing runtime semantics.
5. Cycle-safe relationship traversal and deterministic JSON serialization.

Design principles:
- Pure structural analysis; does not invoke resolvers or touch databases.
- Graph-theoretic; types and fields reference stable IDs, preventing recursion errors on cyclic types.
- Deterministic serialization; produces identical, sorted output across builds.
- Fail-closed regarding unresolved or unmodeled schema constructs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field as dc_field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from graphql import (
    GraphQLEnumType,
    GraphQLField,
    GraphQLInputField,
    GraphQLInputObjectType,
    GraphQLInterfaceType,
    GraphQLList,
    GraphQLNonNull,
    GraphQLObjectType,
    GraphQLScalarType,
    GraphQLSchema,
    GraphQLType,
    GraphQLUnionType,
)


class TypeKind(str, Enum):
    """Kinds of GraphQL types recognized by the Security Graph."""
    OBJECT = "OBJECT"
    INTERFACE = "INTERFACE"
    UNION = "UNION"
    SCALAR = "SCALAR"
    ENUM = "ENUM"
    INPUT_OBJECT = "INPUT_OBJECT"
    UNKNOWN = "UNKNOWN"


class EdgeType(str, Enum):
    """Explicit relationship types between nodes in the Security Graph."""
    DEFINES_FIELD = "DEFINES_FIELD"        # TypeNode -> FieldNode (Field containment)
    RETURNS_TYPE = "RETURNS_TYPE"          # FieldNode -> TypeNode (Field return type)
    NAVIGATES_TO = "NAVIGATES_TO"          # TypeNode -> TypeNode (High-level type navigation)
    IMPLEMENTS = "IMPLEMENTS"              # TypeNode (Object) -> TypeNode (Interface)
    UNRESOLVED_RELATIONSHIP = "UNRESOLVED_RELATIONSHIP"  # FieldNode -> Missing/Ambiguous Type


class Cardinality(str, Enum):
    """Cardinality of a field navigation edge."""
    ONE_TO_ONE = "ONE_TO_ONE"
    ONE_TO_MANY = "ONE_TO_MANY"
    NONE = "NONE"


# Field and argument names that often serve as candidate entity identifiers
IDENTIFIER_NAME_PATTERNS = {
    "id",
    "uuid",
    "pk",
    "owner_id",
    "ownerid",
    "user_id",
    "userid",
    "parent_id",
    "parentid",
}


def is_candidate_identifier_name(name: str) -> bool:
    """Checks whether a field/argument name matches candidate identifier patterns."""
    normalized = (name or "").lower().strip()
    if normalized in IDENTIFIER_NAME_PATTERNS:
        return True
    return normalized.endswith("_id") or normalized.endswith("id") and len(normalized) > 2


def unwrap_type_structure(gql_type: GraphQLType) -> Tuple[str, str, bool, bool, int, bool]:
    """
    Unwraps any arbitrary nesting of GraphQLNonNull and GraphQLList wrappers.

    Returns a 6-tuple:
      (raw_signature, base_type_name, is_list, is_top_non_null, list_depth, is_base_non_null)

    Examples:
      Int -> ('Int', 'Int', False, False, 0, False)
      Int! -> ('Int!', 'Int', False, True, 0, True)
      [ResourceType!]! -> ('[ResourceType!]!', 'ResourceType', True, True, 1, True)
      [[String]] -> ('[[String]]', 'String', True, False, 2, False)
    """
    raw_signature = str(gql_type)
    is_top_non_null = isinstance(gql_type, GraphQLNonNull)

    curr = gql_type
    list_depth = 0
    prev = None

    while isinstance(curr, (GraphQLNonNull, GraphQLList)):
        if isinstance(curr, GraphQLList):
            list_depth += 1
        prev = curr
        curr = curr.of_type

    is_base_non_null = isinstance(prev, GraphQLNonNull)
    base_type_name = getattr(curr, "name", str(curr))
    is_list = list_depth > 0

    return (
        raw_signature,
        base_type_name,
        is_list,
        is_top_non_null,
        list_depth,
        is_base_non_null,
    )


def determine_type_kind(gql_type: GraphQLType) -> TypeKind:
    """Maps a graphql-core type to its corresponding TypeKind."""
    if isinstance(gql_type, GraphQLObjectType):
        return TypeKind.OBJECT
    if isinstance(gql_type, GraphQLInterfaceType):
        return TypeKind.INTERFACE
    if isinstance(gql_type, GraphQLUnionType):
        return TypeKind.UNION
    if isinstance(gql_type, GraphQLScalarType):
        return TypeKind.SCALAR
    if isinstance(gql_type, GraphQLEnumType):
        return TypeKind.ENUM
    if isinstance(gql_type, GraphQLInputObjectType):
        return TypeKind.INPUT_OBJECT
    return TypeKind.UNKNOWN


@dataclass(frozen=True)
class ArgumentNode:
    """Represents a formal argument definition of a GraphQL field."""
    name: str
    raw_type: str
    base_type: str
    is_required: bool
    is_list: bool
    default_value: Any
    is_identifier_candidate: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "raw_type": self.raw_type,
            "base_type": self.base_type,
            "is_required": self.is_required,
            "is_list": self.is_list,
            "default_value": None if self.default_value is None else str(self.default_value),
            "is_identifier_candidate": self.is_identifier_candidate,
        }


@dataclass
class FieldNode:
    """Represents a concrete GraphQL field belonging to a parent type."""
    id: str  # Format: "field:{parent_type}.{field_name}"
    name: str
    parent_type: str
    raw_type: str
    base_type: str
    base_kind: TypeKind
    is_list: bool
    list_depth: int
    is_non_null: bool
    is_base_non_null: bool
    arguments: Dict[str, ArgumentNode] = dc_field(default_factory=dict)
    has_id_argument: bool = False
    is_identifier_candidate: bool = False
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "parent_type": self.parent_type,
            "raw_type": self.raw_type,
            "base_type": self.base_type,
            "base_kind": self.base_kind.value,
            "is_list": self.is_list,
            "list_depth": self.list_depth,
            "is_non_null": self.is_non_null,
            "is_base_non_null": self.is_base_non_null,
            "arguments": {
                k: v.to_dict()
                for k, v in sorted(self.arguments.items())
            },
            "has_id_argument": self.has_id_argument,
            "is_identifier_candidate": self.is_identifier_candidate,
            "description": self.description,
        }


@dataclass
class TypeNode:
    """Represents a GraphQL Object, Interface, Union, Scalar, or Enum type."""
    id: str  # Format: "type:{name}"
    name: str
    kind: TypeKind
    is_root: bool = False
    root_operation: Optional[str] = None  # "query", "mutation", "subscription", or None
    interfaces: List[str] = dc_field(default_factory=list)
    fields: List[str] = dc_field(default_factory=list)
    candidate_id_fields: List[str] = dc_field(default_factory=list)
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "kind": self.kind.value,
            "is_root": self.is_root,
            "root_operation": self.root_operation,
            "interfaces": sorted(self.interfaces),
            "fields": sorted(self.fields),
            "candidate_id_fields": sorted(self.candidate_id_fields),
            "description": self.description,
        }


@dataclass(frozen=True)
class Edge:
    """Represents a directed relationship between nodes in the Security Graph."""
    source_id: str
    target_id: str
    edge_type: EdgeType
    field_name: Optional[str] = None
    cardinality: Cardinality = Cardinality.NONE
    metadata: Dict[str, Any] = dc_field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "field_name": self.field_name,
            "cardinality": self.cardinality.value,
            "metadata": dict(sorted(self.metadata.items())),
        }


@dataclass(frozen=True)
class UnresolvedRelationship:
    """Represents an unresolvable or ambiguous relationship in the schema."""
    source_type: str
    field_name: str
    observed_target: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_type": self.source_type,
            "field_name": self.field_name,
            "observed_target": self.observed_target,
            "reason": self.reason,
        }


class SecurityGraph:
    """
    In-memory, typed, cycle-safe GraphQL Security Graph G = (V, E).

    Thread-safe and read-only once constructed.
    """

    def __init__(
        self,
        types: Dict[str, TypeNode],
        fields: Dict[str, FieldNode],
        edges: List[Edge],
        unresolved: List[UnresolvedRelationship],
        roots: Dict[str, str],
    ):
        self._types = types
        self._fields = fields
        self._edges = edges
        self._unresolved = unresolved
        self._roots = roots

        # Fast lookup indices
        self._fields_by_type: Dict[str, List[FieldNode]] = {}
        for f in fields.values():
            self._fields_by_type.setdefault(f.parent_type, []).append(f)

        self._navigation_edges_by_source: Dict[str, List[Edge]] = {}
        for e in edges:
            if e.edge_type == EdgeType.NAVIGATES_TO:
                # source_id is "type:{source_type}"
                source_name = e.source_id.replace("type:", "", 1)
                self._navigation_edges_by_source.setdefault(source_name, []).append(e)

        self._implementors_by_interface: Dict[str, List[str]] = {}
        for t in types.values():
            for iface in t.interfaces:
                self._implementors_by_interface.setdefault(iface, []).append(t.name)

    # -------------------------------------------------------------------------
    # Public Accessors & Query APIs
    # -------------------------------------------------------------------------

    @property
    def types(self) -> Dict[str, TypeNode]:
        """Returns all type nodes indexed by type name."""
        return dict(self._types)

    @property
    def fields(self) -> Dict[str, FieldNode]:
        """Returns all field nodes indexed by field ID ('field:{parent}.{name}')."""
        return dict(self._fields)

    @property
    def edges(self) -> List[Edge]:
        """Returns all edges in the graph."""
        return list(self._edges)

    @property
    def unresolved_relationships(self) -> List[UnresolvedRelationship]:
        """Returns all unresolved or ambiguous relationships identified during build."""
        return list(self._unresolved)

    @property
    def root_operations(self) -> Dict[str, str]:
        """Returns root operation mapping, e.g. {'query': 'Query'}."""
        return dict(self._roots)

    def get_type(self, type_name: str) -> Optional[TypeNode]:
        """Retrieves a TypeNode by its GraphQL type name."""
        return self._types.get(type_name)

    def get_field(self, parent_type: str, field_name: str) -> Optional[FieldNode]:
        """Retrieves a FieldNode by parent type name and field name."""
        field_id = f"field:{parent_type}.{field_name}"
        return self._fields.get(field_id)

    def get_fields_for_type(self, type_name: str) -> List[FieldNode]:
        """Retrieves all fields declared by a specific type."""
        return list(self._fields_by_type.get(type_name, []))

    def resolve_field_return_type(self, parent_type: str, field_name: str) -> Optional[TypeNode]:
        """
        Resolves the concrete/base return TypeNode for a given field on a parent type.

        Crucially replaces brittle heuristics (e.g., field_name.capitalize()) with
        authoritative schema type system resolution.
        """
        f = self.get_field(parent_type, field_name)
        if not f:
            return None
        return self.get_type(f.base_type)

    def get_navigable_edges(self, source_type: str) -> List[Edge]:
        """Returns all outgoing NAVIGATES_TO edges from a source type."""
        return list(self._navigation_edges_by_source.get(source_type, []))

    def get_implementors(self, interface_name: str) -> List[TypeNode]:
        """Returns all object TypeNodes implementing the given interface."""
        impl_names = self._implementors_by_interface.get(interface_name, [])
        return [self._types[n] for n in impl_names if n in self._types]

    def find_navigation_paths(
        self,
        start_type: str,
        target_type: str,
        max_depth: int = 5,
    ) -> List[List[Tuple[str, str]]]:
        """
        Finds all cycle-safe navigation paths from start_type to target_type.

        Returns a list of paths, where each path is a list of (field_name, next_type) tuples.
        Example: [('user', 'UserType'), ('resources', 'ResourceType')]
        """
        results: List[List[Tuple[str, str]]] = []
        if start_type not in self._types or target_type not in self._types:
            return results

        def dfs(current: str, target: str, depth: int, visited_types: Set[str], current_path: List[Tuple[str, str]]):
            if current == target and current_path:
                results.append(list(current_path))
                return
            if depth >= max_depth:
                return

            for edge in self.get_navigable_edges(current):
                next_type = edge.target_id.replace("type:", "", 1)
                field_name = edge.field_name or ""
                # Cycle prevention: do not visit the same type twice in one path branch
                if next_type in visited_types:
                    # Allow reaching the target even if visited earlier in the path
                    if next_type == target:
                        results.append(current_path + [(field_name, next_type)])
                    continue

                visited_types.add(next_type)
                current_path.append((field_name, next_type))
                dfs(next_type, target, depth + 1, visited_types, current_path)
                current_path.pop()
                visited_types.remove(next_type)

        dfs(start_type, target_type, 0, {start_type}, [])
        return results

    # -------------------------------------------------------------------------
    # Serialization & Summaries
    # -------------------------------------------------------------------------

    def summary(self) -> Dict[str, Any]:
        """Returns a concise summary dictionary of graph dimensions."""
        kinds_count: Dict[str, int] = {}
        for t in self._types.values():
            kinds_count[t.kind.value] = kinds_count.get(t.kind.value, 0) + 1

        edges_count: Dict[str, int] = {}
        for e in self._edges:
            edges_count[e.edge_type.value] = edges_count.get(e.edge_type.value, 0) + 1

        return {
            "total_types": len(self._types),
            "types_by_kind": dict(sorted(kinds_count.items())),
            "total_fields": len(self._fields),
            "total_edges": len(self._edges),
            "edges_by_type": dict(sorted(edges_count.items())),
            "root_operations": dict(sorted(self._roots.items())),
            "unresolved_relationships_count": len(self._unresolved),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Produces a deterministic, fully sorted dictionary representation of the graph."""
        return {
            "summary": self.summary(),
            "roots": dict(sorted(self._roots.items())),
            "types": {
                name: self._types[name].to_dict()
                for name in sorted(self._types.keys())
            },
            "fields": {
                fid: self._fields[fid].to_dict()
                for fid in sorted(self._fields.keys())
            },
            "edges": [
                e.to_dict()
                for e in sorted(
                    self._edges,
                    key=lambda x: (x.source_id, x.target_id, x.edge_type.value, x.field_name or "")
                )
            ],
            "unresolved_relationships": [
                u.to_dict()
                for u in sorted(
                    self._unresolved,
                    key=lambda x: (x.source_type, x.field_name, x.observed_target)
                )
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        """Serializes the graph to a deterministic JSON string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    # -------------------------------------------------------------------------
    # Factory & Builder Logic
    # -------------------------------------------------------------------------

    @classmethod
    def from_schema(
        cls,
        schema_input: Any,
        include_introspection: bool = False,
    ) -> SecurityGraph:
        """
        Builds a SecurityGraph from a Strawberry Schema or a graphql-core GraphQLSchema.

        Args:
            schema_input: A strawberry.Schema instance, or a graphql-core GraphQLSchema.
            include_introspection: Whether to include GraphQL '__' internal types. Default False.
        """
        core_schema = _extract_core_schema(schema_input)

        types: Dict[str, TypeNode] = {}
        fields: Dict[str, FieldNode] = {}
        edges: List[Edge] = []
        unresolved: List[UnresolvedRelationship] = []
        roots: Dict[str, str] = {}

        # 1. Identify Root Operations
        if core_schema.query_type:
            roots["query"] = core_schema.query_type.name
        if core_schema.mutation_type:
            roots["mutation"] = core_schema.mutation_type.name
        if core_schema.subscription_type:
            roots["subscription"] = core_schema.subscription_type.name

        root_type_names = set(roots.values())

        # 2. First Pass: Construct all TypeNodes
        for type_name, gql_type in core_schema.type_map.items():
            if not include_introspection and type_name.startswith("__"):
                continue

            kind = determine_type_kind(gql_type)
            is_root = type_name in root_type_names
            root_op = next((op for op, name in roots.items() if name == type_name), None)

            interfaces: List[str] = []
            if isinstance(gql_type, GraphQLObjectType):
                interfaces = [iface.name for iface in gql_type.interfaces]

            type_node = TypeNode(
                id=f"type:{type_name}",
                name=type_name,
                kind=kind,
                is_root=is_root,
                root_operation=root_op,
                interfaces=interfaces,
                description=getattr(gql_type, "description", None),
            )
            types[type_name] = type_node

        # 3. Second Pass: Build FieldNodes, Arguments, and Containment / Return / Navigation Edges
        for type_name, gql_type in core_schema.type_map.items():
            if not include_introspection and type_name.startswith("__"):
                continue

            type_node = types[type_name]
            field_dict: Dict[str, GraphQLField] = {}

            if isinstance(gql_type, (GraphQLObjectType, GraphQLInterfaceType)):
                field_dict = gql_type.fields
            elif isinstance(gql_type, GraphQLInputObjectType):
                field_dict = gql_type.fields

            # Record interface implementation edges
            for iface_name in type_node.interfaces:
                if iface_name in types:
                    edges.append(Edge(
                        source_id=type_node.id,
                        target_id=f"type:{iface_name}",
                        edge_type=EdgeType.IMPLEMENTS,
                        metadata={"implementor": type_name, "interface": iface_name},
                    ))

            for field_name, gql_field in field_dict.items():
                (
                    raw_sig,
                    base_type_name,
                    is_list,
                    is_top_non_null,
                    list_depth,
                    is_base_non_null,
                ) = unwrap_type_structure(gql_field.type)

                # Record field name in parent type
                type_node.fields.append(field_name)

                # Evaluate identifier candidacy
                is_id_field = (
                    is_candidate_identifier_name(field_name)
                    or base_type_name in ("ID", "Int") and field_name.lower() == "id"
                )
                if is_id_field:
                    type_node.candidate_id_fields.append(field_name)

                # Construct argument nodes
                arg_nodes: Dict[str, ArgumentNode] = {}
                has_id_arg = False

                raw_args = getattr(gql_field, "args", {})
                for arg_name, gql_arg in raw_args.items():
                    (
                        arg_raw,
                        arg_base,
                        arg_is_list,
                        arg_non_null,
                        _,
                        _,
                    ) = unwrap_type_structure(gql_arg.type)

                    is_arg_id = (
                        is_candidate_identifier_name(arg_name)
                        or arg_base in ("ID", "Int") and arg_name.lower() == "id"
                    )
                    if is_arg_id:
                        has_id_arg = True

                    arg_nodes[arg_name] = ArgumentNode(
                        name=arg_name,
                        raw_type=arg_raw,
                        base_type=arg_base,
                        is_required=arg_non_null,
                        is_list=arg_is_list,
                        default_value=getattr(gql_arg, "default_value", None),
                        is_identifier_candidate=is_arg_id,
                    )

                # Target base kind
                target_type_node = types.get(base_type_name)
                base_kind = target_type_node.kind if target_type_node else TypeKind.UNKNOWN

                field_id = f"field:{type_name}.{field_name}"
                field_node = FieldNode(
                    id=field_id,
                    name=field_name,
                    parent_type=type_name,
                    raw_type=raw_sig,
                    base_type=base_type_name,
                    base_kind=base_kind,
                    is_list=is_list,
                    list_depth=list_depth,
                    is_non_null=is_top_non_null,
                    is_base_non_null=is_base_non_null,
                    arguments=arg_nodes,
                    has_id_argument=has_id_arg,
                    is_identifier_candidate=is_id_field,
                    description=getattr(gql_field, "description", None),
                )
                fields[field_id] = field_node

                # Edge: ParentType DEFINES_FIELD FieldNode
                edges.append(Edge(
                    source_id=type_node.id,
                    target_id=field_node.id,
                    edge_type=EdgeType.DEFINES_FIELD,
                    field_name=field_name,
                ))

                # Edge: FieldNode RETURNS_TYPE TargetType
                if target_type_node:
                    edges.append(Edge(
                        source_id=field_node.id,
                        target_id=target_type_node.id,
                        edge_type=EdgeType.RETURNS_TYPE,
                        field_name=field_name,
                    ))

                    # High-Level Navigation Edge if target is Object or Interface
                    if target_type_node.kind in (TypeKind.OBJECT, TypeKind.INTERFACE):
                        cardinality = Cardinality.ONE_TO_MANY if is_list else Cardinality.ONE_TO_ONE
                        edges.append(Edge(
                            source_id=type_node.id,
                            target_id=target_type_node.id,
                            edge_type=EdgeType.NAVIGATES_TO,
                            field_name=field_name,
                            cardinality=cardinality,
                            metadata={
                                "via_field": field_id,
                                "is_collection": is_list,
                                "requires_arguments": any(a.is_required for a in arg_nodes.values()),
                                "has_id_argument": has_id_arg,
                                "raw_type": raw_sig,
                            },
                        ))
                else:
                    # Unresolved relationship edge
                    unres = UnresolvedRelationship(
                        source_type=type_name,
                        field_name=field_name,
                        observed_target=base_type_name,
                        reason=f"Return type '{base_type_name}' is not registered in the schema type map",
                    )
                    unresolved.append(unres)
                    edges.append(Edge(
                        source_id=field_node.id,
                        target_id=f"type:{base_type_name}",
                        edge_type=EdgeType.UNRESOLVED_RELATIONSHIP,
                        field_name=field_name,
                        metadata={"reason": unres.reason},
                    ))

        return cls(
            types=types,
            fields=fields,
            edges=edges,
            unresolved=unresolved,
            roots=roots,
        )


def _extract_core_schema(schema_input: Any) -> GraphQLSchema:
    """Extracts an underlying graphql-core GraphQLSchema safely from various inputs."""
    if isinstance(schema_input, GraphQLSchema):
        return schema_input
    if hasattr(schema_input, "_schema") and isinstance(schema_input._schema, GraphQLSchema):
        return schema_input._schema
    if hasattr(schema_input, "schema") and isinstance(schema_input.schema, GraphQLSchema):
        return schema_input.schema
    raise TypeError(
        f"Expected strawberry.Schema or graphql.GraphQLSchema, got {type(schema_input).__name__}"
    )


# -----------------------------------------------------------------------------
# Module Singleton / Application Cache
# -----------------------------------------------------------------------------

_CACHED_SECURITY_GRAPH: Optional[SecurityGraph] = None


def get_security_graph(schema_instance: Any = None) -> SecurityGraph:
    """
    Retrieves or builds the singleton SecurityGraph for the application.

    If schema_instance is omitted, defaults to app.graphql.schema.schema.
    Thread-safe and cached; built once at startup or first access.
    """
    global _CACHED_SECURITY_GRAPH
    if _CACHED_SECURITY_GRAPH is not None and schema_instance is None:
        return _CACHED_SECURITY_GRAPH

    if schema_instance is None:
        from app.graphql.schema import schema as default_schema
        schema_instance = default_schema

    built_graph = SecurityGraph.from_schema(schema_instance)
    if _CACHED_SECURITY_GRAPH is None:
        _CACHED_SECURITY_GRAPH = built_graph
    return built_graph


def reset_security_graph_cache() -> None:
    """Clears the cached SecurityGraph singleton (primarily for test fixtures)."""
    global _CACHED_SECURITY_GRAPH
    _CACHED_SECURITY_GRAPH = None
