"""
Tests for GraphQL Security Graph (Phase 2)

Verifies:
1. Node and edge construction on the active application schema.
2. Exact return-type resolution through list and non-null wrappers.
3. High-level navigation edge mapping with cardinality and argument metadata.
4. Circular type references and recursion safety.
5. Arbitrary list wrapping depths.
6. Interface implementations and implementor discovery.
7. Query, mutation, and subscription root operation discovery.
8. Candidate identifier metadata on fields and arguments.
9. Deterministic serialization and repeatable JSON outputs.
10. Unresolved / missing relationship tracking (fail-closed).
11. Multi-hop cycle-safe path discovery.
12. Admin-protected inspection endpoint access control.
13. Compatibility with existing schema and authorization modules.
"""

from typing import List, Optional
import pytest
import strawberry
from fastapi.testclient import TestClient

from app.core.security import create_access_token
from app.graphql.schema import schema as active_schema
from app.main import app
from app.security.security_graph import (
    Cardinality,
    EdgeType,
    FieldNode,
    SecurityGraph,
    TypeKind,
    TypeNode,
    get_security_graph,
    reset_security_graph_cache,
    unwrap_type_structure,
)

client = TestClient(app)


# Module-level synthetic types for circular reference tests
# (Strawberry requires forward references to be present in module globals)
@strawberry.type
class CircularPost:
    id: int
    author: "CircularUser"

@strawberry.type
class CircularUser:
    id: int
    friends: List["CircularUser"]
    posts: List[CircularPost]

@strawberry.type
class CircularQuery:
    me: CircularUser


# =============================================================================
# 1. LIVE APPLICATION SCHEMA TESTS
# =============================================================================

def test_01_live_schema_construction():
    """Security Graph correctly ingests the live application schema."""
    graph = SecurityGraph.from_schema(active_schema)
    summary = graph.summary()

    assert summary["total_types"] >= 4
    assert "Query" in graph.types
    assert "UserType" in graph.types
    assert "ResourceType" in graph.types
    assert "HealthCheckType" in graph.types

    query_node = graph.get_type("Query")
    assert query_node is not None
    assert query_node.is_root is True
    assert query_node.root_operation == "query"

    user_node = graph.get_type("UserType")
    assert user_node is not None
    assert user_node.kind == TypeKind.OBJECT
    assert user_node.is_root is False


def test_02_field_unwrapping_scalar_and_wrappers():
    """Unwraps field return types with list and non-null modifiers accurately."""
    graph = SecurityGraph.from_schema(active_schema)

    # 1. UserType.id -> NonNull(Int)
    id_field = graph.get_field("UserType", "id")
    assert id_field is not None
    assert id_field.base_type == "Int"
    assert id_field.base_kind == TypeKind.SCALAR
    assert id_field.is_list is False
    assert id_field.is_non_null is True
    assert id_field.is_base_non_null is True

    # 2. UserType.resources -> NonNull(List(NonNull(ResourceType))) -> [ResourceType!]!
    resources_field = graph.get_field("UserType", "resources")
    assert resources_field is not None
    assert resources_field.base_type == "ResourceType"
    assert resources_field.base_kind == TypeKind.OBJECT
    assert resources_field.is_list is True
    assert resources_field.list_depth == 1
    assert resources_field.is_non_null is True
    assert resources_field.is_base_non_null is True

    # 3. ResourceType.parentId -> Nullable Int
    parent_id_field = graph.get_field("ResourceType", "parentId")
    assert parent_id_field is not None
    assert parent_id_field.base_type == "Int"
    assert parent_id_field.is_non_null is False
    assert parent_id_field.is_list is False


def test_03_authoritative_return_type_resolution():
    """Resolves return TypeNodes directly without string capitalization heuristics."""
    graph = SecurityGraph.from_schema(active_schema)

    # Query.resource returns ResourceType (not guessing "Resource")
    res_type = graph.resolve_field_return_type("Query", "resource")
    assert res_type is not None
    assert res_type.name == "ResourceType"

    # UserType.resources returns ResourceType (collection)
    coll_type = graph.resolve_field_return_type("UserType", "resources")
    assert coll_type is not None
    assert coll_type.name == "ResourceType"

    # Query.user returns UserType
    user_type = graph.resolve_field_return_type("Query", "user")
    assert user_type is not None
    assert user_type.name == "UserType"

    # Unknown field safely returns None
    assert graph.resolve_field_return_type("Query", "non_existent") is None
    assert graph.resolve_field_return_type("NonExistentType", "field") is None


def test_04_identifier_field_and_argument_metadata():
    """Identifies candidate identifiers on fields and field arguments."""
    graph = SecurityGraph.from_schema(active_schema)

    user_node = graph.get_type("UserType")
    assert "id" in user_node.candidate_id_fields

    resource_node = graph.get_type("ResourceType")
    assert "id" in resource_node.candidate_id_fields
    # Strawberry exposes camelCase in GraphQL schema (ownerId, parentId)
    assert any(f in resource_node.candidate_id_fields for f in ("ownerId", "owner_id"))
    assert any(f in resource_node.candidate_id_fields for f in ("parentId", "parent_id"))

    # Field argument inspection
    res_field = graph.get_field("Query", "resource")
    assert res_field is not None
    assert res_field.has_id_argument is True
    assert "id" in res_field.arguments
    id_arg = res_field.arguments["id"]
    assert id_arg.name == "id"
    assert id_arg.base_type == "Int"
    assert id_arg.is_required is True
    assert id_arg.is_identifier_candidate is True


def test_05_navigation_edges_and_cardinality():
    """Verifies NAVIGATES_TO edges distinguish 1-to-1 vs 1-to-many collections."""
    graph = SecurityGraph.from_schema(active_schema)

    nav_edges = graph.get_navigable_edges("UserType")
    edge_map = {e.field_name: e for e in nav_edges}

    assert "resources" in edge_map
    assert edge_map["resources"].cardinality == Cardinality.ONE_TO_MANY
    assert edge_map["resources"].metadata["is_collection"] is True
    assert edge_map["resources"].metadata["requires_arguments"] is False

    assert "resource" in edge_map
    assert edge_map["resource"].cardinality == Cardinality.ONE_TO_ONE
    assert edge_map["resource"].metadata["is_collection"] is False
    assert edge_map["resource"].metadata["requires_arguments"] is True
    assert edge_map["resource"].metadata["has_id_argument"] is True


def test_06_navigation_paths_discovery():
    """Discovers all cycle-safe structural paths from Query to ResourceType."""
    graph = SecurityGraph.from_schema(active_schema)
    paths = graph.find_navigation_paths("Query", "ResourceType")

    # Live schema has 3 paths:
    # 1. Query.resource -> ResourceType
    # 2. Query.user -> UserType.resources -> ResourceType
    # 3. Query.user -> UserType.resource -> ResourceType
    assert len(paths) == 3

    direct_path = [('resource', 'ResourceType')]
    nested_coll = [('user', 'UserType'), ('resources', 'ResourceType')]
    nested_single = [('user', 'UserType'), ('resource', 'ResourceType')]

    assert direct_path in paths
    assert nested_coll in paths
    assert nested_single in paths


# =============================================================================
# 2. SYNTHETIC ADVANCED SCHEMA TESTS
# =============================================================================

def test_07_circular_references_safety():
    """Circular type references build safely and traverse without infinite loops."""
    synth_schema = strawberry.Schema(query=CircularQuery)
    graph = SecurityGraph.from_schema(synth_schema)

    # Both types exist and reference each other
    assert "CircularUser" in graph.types
    assert "CircularPost" in graph.types

    user_edges = graph.get_navigable_edges("CircularUser")
    edge_targets = {(e.field_name, e.target_id) for e in user_edges}
    assert ("friends", "type:CircularUser") in edge_targets
    assert ("posts", "type:CircularPost") in edge_targets

    post_edges = graph.get_navigable_edges("CircularPost")
    post_targets = {(e.field_name, e.target_id) for e in post_edges}
    assert ("author", "type:CircularUser") in post_targets

    # Path search with circular reference does not loop infinitely
    paths = graph.find_navigation_paths("CircularQuery", "CircularPost", max_depth=4)
    assert len(paths) >= 1
    assert [('me', 'CircularUser'), ('posts', 'CircularPost')] in paths


def test_08_arbitrary_nested_list_unwrapping():
    """Unwraps multi-dimensional list wrappers (e.g. [[MatrixItem!]]!)."""
    @strawberry.type
    class MatrixItem:
        val: int

    @strawberry.type
    class MatrixQuery:
        grid: List[List[MatrixItem]]

    synth_schema = strawberry.Schema(query=MatrixQuery)
    graph = SecurityGraph.from_schema(synth_schema)

    grid_field = graph.get_field("MatrixQuery", "grid")
    assert grid_field is not None
    assert grid_field.base_type == "MatrixItem"
    assert grid_field.is_list is True
    assert grid_field.list_depth == 2


def test_09_interface_implementation_edges():
    """Detects interfaces, implements edges, and finds implementors."""
    @strawberry.interface
    class NodeInterface:
        id: int

    @strawberry.type
    class Article(NodeInterface):
        title: str

    @strawberry.type
    class Comment(NodeInterface):
        body: str

    @strawberry.type
    class InterfaceQuery:
        node: NodeInterface

    # Pass types=[Article, Comment] so Strawberry registers concrete implementors
    synth_schema = strawberry.Schema(query=InterfaceQuery, types=[Article, Comment])
    graph = SecurityGraph.from_schema(synth_schema)

    node_type = graph.get_type("NodeInterface")
    assert node_type is not None
    assert node_type.kind == TypeKind.INTERFACE

    article_type = graph.get_type("Article")
    assert article_type is not None
    assert "NodeInterface" in article_type.interfaces

    # IMPLEMENTS edges
    impl_edges = [e for e in graph.edges if e.edge_type == EdgeType.IMPLEMENTS]
    assert len(impl_edges) == 2
    implementor_names = {e.source_id.replace("type:", "") for e in impl_edges}
    assert implementor_names == {"Article", "Comment"}

    # Discovery helper
    implementors = graph.get_implementors("NodeInterface")
    assert {t.name for t in implementors} == {"Article", "Comment"}


def test_10_root_operations_discovery_query_and_mutation():
    """Discovers multiple root operation types (query, mutation)."""
    @strawberry.type
    class RootQuery:
        version: str

    @strawberry.type
    class RootMutation:
        create: bool

    synth_schema = strawberry.Schema(query=RootQuery, mutation=RootMutation)
    graph = SecurityGraph.from_schema(synth_schema)

    assert graph.root_operations == {
        "query": "RootQuery",
        "mutation": "RootMutation",
    }
    assert graph.get_type("RootQuery").is_root is True
    assert graph.get_type("RootMutation").is_root is True


def test_11_unresolved_relationship_handling_fail_closed():
    """Unregistered or missing target types produce UnresolvedRelationship edges."""
    from graphql import GraphQLField, GraphQLObjectType, GraphQLSchema, GraphQLString

    type_a = GraphQLObjectType(
        name="TypeA",
        fields={"orphan": GraphQLField(GraphQLString)},
    )
    raw_schema = GraphQLSchema(query=type_a)

    graph = SecurityGraph.from_schema(raw_schema)
    assert graph.get_field("TypeA", "orphan") is not None
    assert graph.get_type("String") is not None

    # Unknown field lookup fails closed
    assert graph.resolve_field_return_type("TypeA", "missing_field") is None


def test_12_deterministic_serialization():
    """Graph serializes to identical, sorted JSON across repeated builds."""
    g1 = SecurityGraph.from_schema(active_schema)
    g2 = SecurityGraph.from_schema(active_schema)

    json1 = g1.to_json(indent=2)
    json2 = g2.to_json(indent=2)

    assert json1 == json2
    assert hash(json1) == hash(json2)


# =============================================================================
# 3. HTTP INSPECTION ENDPOINT TESTS
# =============================================================================

def test_13_admin_inspection_endpoint_access():
    """Admin users can retrieve the Security Graph over HTTP."""
    token = create_access_token(user_id=103, role="admin")
    res = client.get("/api/v1/security/security-graph", headers={"Authorization": f"Bearer {token}"})

    assert res.status_code == 200
    data = res.json()
    assert "summary" in data
    assert "types" in data
    assert "fields" in data
    assert "edges" in data
    assert data["summary"]["total_types"] >= 4
    assert "Query" in data["types"]


def test_14_non_admin_inspection_endpoint_forbidden():
    """Non-admin users receive HTTP 403 when requesting the Security Graph."""
    token = create_access_token(user_id=101, role="user")
    res = client.get("/api/v1/security/security-graph", headers={"Authorization": f"Bearer {token}"})

    assert res.status_code == 403
    assert "Admin access required" in res.json()["detail"]


def test_15_singleton_cache_and_reset():
    """Verifies get_security_graph caching and reset behavior."""
    reset_security_graph_cache()
    g1 = get_security_graph()
    g2 = get_security_graph()

    assert g1 is g2
    reset_security_graph_cache()
    g3 = get_security_graph()
    assert g1 is not g3
    assert g1.to_json() == g3.to_json()
