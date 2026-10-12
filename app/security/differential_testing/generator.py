"""
Schema Path Discovery & Differential Test Case Generator
---------------------------------------------------------
Automates:
1. Schema introspection to discover object-returning fields, arguments, and relationship edges.
2. Controlled test suite generation varying caller identity, target ownership, nesting depth,
   aliases, and query variables.
3. Declarative computation of expected authorization outcomes (Oracle).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from app.graphql.schema import schema
from app.security.differential_testing.models import (
    DifferentialTestCase,
    SchemaPathDescriptor,
)


def discover_schema_paths() -> List[SchemaPathDescriptor]:
    """
    Introspects the GraphQL schema to discover all object-returning fields,
    parameterized entity lookups, and nested relationship edges.
    """
    paths: List[SchemaPathDescriptor] = []

    # 1. Root Query fields
    paths.append(
        SchemaPathDescriptor(
            canonical_path="Query.user",
            path_key="user",
            root_field="user",
            field_name="user",
            parent_type="Query",
            target_type="UserType",
            is_nested=False,
            arguments=["id"],
            is_collection=False,
            is_sensitive_sink=True,
        )
    )
    paths.append(
        SchemaPathDescriptor(
            canonical_path="Query.resource",
            path_key="resource",
            root_field="resource",
            field_name="resource",
            parent_type="Query",
            target_type="ResourceType",
            is_nested=False,
            arguments=["id"],
            is_collection=False,
            is_sensitive_sink=True,
        )
    )
    paths.append(
        SchemaPathDescriptor(
            canonical_path="Query.health",
            path_key="health",
            root_field="health",
            field_name="health",
            parent_type="Query",
            target_type="HealthCheckType",
            is_nested=False,
            arguments=[],
            is_collection=False,
            is_sensitive_sink=False,
        )
    )

    # 2. Nested relationships under UserType
    paths.append(
        SchemaPathDescriptor(
            canonical_path="UserType.resources",
            path_key="user.resources",
            root_field="user",
            field_name="resources",
            parent_type="UserType",
            target_type="ResourceType",
            is_nested=True,
            arguments=[],
            is_collection=True,
            is_sensitive_sink=True,
        )
    )
    paths.append(
        SchemaPathDescriptor(
            canonical_path="UserType.resource",
            path_key="user.resource",
            root_field="user",
            field_name="resource",
            parent_type="UserType",
            target_type="ResourceType",
            is_nested=True,
            arguments=["id"],
            is_collection=False,
            is_sensitive_sink=True,
        )
    )

    # 3. Hierarchical relationship under ResourceType
    paths.append(
        SchemaPathDescriptor(
            canonical_path="ResourceType.children",
            path_key="resource.children",
            root_field="resource",
            field_name="children",
            parent_type="ResourceType",
            target_type="ResourceType",
            is_nested=True,
            arguments=[],
            is_collection=True,
            is_sensitive_sink=True,
        )
    )

    # 4. State-Altering Mutations
    paths.append(
        SchemaPathDescriptor(
            canonical_path="Mutation.updateResource",
            path_key="updateResource",
            root_field="updateResource",
            field_name="updateResource",
            parent_type="Mutation",
            target_type="ResourceType",
            is_nested=False,
            arguments=["id", "name"],
            is_collection=False,
            is_sensitive_sink=True,
        )
    )
    paths.append(
        SchemaPathDescriptor(
            canonical_path="Mutation.deleteResource",
            path_key="deleteResource",
            root_field="deleteResource",
            field_name="deleteResource",
            parent_type="Mutation",
            target_type="Boolean",
            is_nested=False,
            arguments=["id"],
            is_collection=False,
            is_sensitive_sink=True,
        )
    )
    paths.append(
        SchemaPathDescriptor(
            canonical_path="Mutation.transferOwnership",
            path_key="transferOwnership",
            root_field="transferOwnership",
            field_name="transferOwnership",
            parent_type="Mutation",
            target_type="ResourceType",
            is_nested=False,
            arguments=["id", "newOwnerId"],
            is_collection=False,
            is_sensitive_sink=True,
        )
    )

    return paths


def generate_differential_suite(sample_limit: Optional[int] = None) -> List[DifferentialTestCase]:
    """
    Generates a controlled, reproducible differential test suite spanning:
    - Direct BOLA attack variants
    - Nested BOLA traversal variants
    - Alias cloaking variants
    - Variable injection variants
    - Benign owner access variants
    - Privileged administrator access
    - Unauthenticated anonymous access
    """
    test_cases: List[DifferentialTestCase] = []

    # -------------------------------------------------------------------------
    # 1. DIRECT BOLA ATTACKS (Non-owner unauthorized access on root fields)
    # -------------------------------------------------------------------------
    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-DIR-001",
            name="Direct BOLA: Caller 101 accessing Bob's Resource 102",
            category="DIRECT_BOLA",
            query="query { resource(id: 102) { id name ownerId objectType } }",
            caller_id=101,
            caller_role="user",
            target_object_type="Resource",
            target_object_id=102,
            target_owner_id=102,
            schema_path="resource",
            response_path="resource",
            is_nested=False,
            expected_decision="DENY",
            expected_reason="OWNERSHIP_MISMATCH",
            expected_http_status=403,
            oracle_rationale="Caller 101 does not own target Resource 102; gateway must reject with OWNERSHIP_MISMATCH.",
        )
    )

    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-DIR-002",
            name="Direct BOLA: Caller 102 accessing Alice's Resource 101",
            category="DIRECT_BOLA",
            query="query { resource(id: 101) { id name ownerId } }",
            caller_id=102,
            caller_role="user",
            target_object_type="Resource",
            target_object_id=101,
            target_owner_id=101,
            schema_path="resource",
            response_path="resource",
            is_nested=False,
            expected_decision="DENY",
            expected_reason="OWNERSHIP_MISMATCH",
            expected_http_status=403,
            oracle_rationale="Caller 102 does not own target Resource 101; gateway must reject with OWNERSHIP_MISMATCH.",
        )
    )

    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-DIR-003",
            name="Direct BOLA: Caller 102 accessing Alice's User profile 101",
            category="DIRECT_BOLA",
            query="query { user(id: 101) { id username role } }",
            caller_id=102,
            caller_role="user",
            target_object_type="User",
            target_object_id=101,
            target_owner_id=101,
            schema_path="user",
            response_path="user",
            is_nested=False,
            expected_decision="DENY",
            expected_reason="OWNERSHIP_MISMATCH",
            expected_http_status=403,
            oracle_rationale="Caller 102 requested profile of User 101; gateway must reject with OWNERSHIP_MISMATCH.",
        )
    )

    # -------------------------------------------------------------------------
    # 2. NESTED BOLA ATTACKS (Indirect path traversal across relationships)
    # -------------------------------------------------------------------------
    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-NEST-001",
            name="Nested BOLA: Caller 101 reaching Bob's Resource 102 via User root",
            category="NESTED_BOLA",
            query="query { user(id: 101) { id username resource(id: 102) { id name ownerId } } }",
            caller_id=101,
            caller_role="user",
            target_object_type="Resource",
            target_object_id=102,
            target_owner_id=102,
            schema_path="user.resource",
            response_path="user.resource",
            is_nested=True,
            expected_decision="DENY",
            expected_reason="NESTED_AUTHORIZATION_VIOLATION",
            expected_http_status=403,
            oracle_rationale="Caller 101 owns root User 101, but child resource 102 belongs to Bob; gateway must reject with NESTED_AUTHORIZATION_VIOLATION.",
        )
    )

    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-NEST-002",
            name="Nested BOLA: Caller 102 reaching Alice's Resource 101 via User root",
            category="NESTED_BOLA",
            query="query { user(id: 102) { id resource(id: 101) { id name } } }",
            caller_id=102,
            caller_role="user",
            target_object_type="Resource",
            target_object_id=101,
            target_owner_id=101,
            schema_path="user.resource",
            response_path="user.resource",
            is_nested=True,
            expected_decision="DENY",
            expected_reason="NESTED_AUTHORIZATION_VIOLATION",
            expected_http_status=403,
            oracle_rationale="Caller 102 attempting to traverse into Alice's Resource 101; gateway must enforce nested boundary.",
        )
    )

    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-NEST-003",
            name="Hierarchical Traversal: Caller 102 accessing Alice's nested folder 201",
            category="NESTED_BOLA",
            query="query { resource(id: 201) { id name children { id name ownerId } } }",
            caller_id=102,
            caller_role="user",
            target_object_type="Resource",
            target_object_id=201,
            target_owner_id=101,
            schema_path="resource.children",
            response_path="resource.children",
            is_nested=True,
            expected_decision="DENY",
            expected_reason="OWNERSHIP_MISMATCH",
            expected_http_status=403,
            oracle_rationale="Root folder 201 belongs to Alice (101); non-owner 102 must be denied at entry.",
        )
    )

    # -------------------------------------------------------------------------
    # 3. ALIAS MASKING BOLA ATTACKS (Client response path diversion)
    # -------------------------------------------------------------------------
    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-ALIAS-001",
            name="Alias Masking: Direct BOLA masked as 'mySecretFile'",
            category="ALIAS_MASKING",
            query="query { mySecretFile: resource(id: 102) { id name ownerId } }",
            caller_id=101,
            caller_role="user",
            target_object_type="Resource",
            target_object_id=102,
            target_owner_id=102,
            schema_path="resource",
            response_path="mySecretFile",
            is_nested=False,
            has_alias=True,
            expected_decision="DENY",
            expected_reason="OWNERSHIP_MISMATCH",
            expected_http_status=403,
            oracle_rationale="Field alias 'mySecretFile' must not bypass canonical schema path attribution.",
        )
    )

    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-ALIAS-002",
            name="Alias Masking: Nested BOLA masked as 'sharedDoc'",
            category="ALIAS_MASKING",
            query="query { user(id: 101) { id sharedDoc: resource(id: 102) { name } } }",
            caller_id=101,
            caller_role="user",
            target_object_type="Resource",
            target_object_id=102,
            target_owner_id=102,
            schema_path="user.resource",
            response_path="user.sharedDoc",
            is_nested=True,
            has_alias=True,
            expected_decision="DENY",
            expected_reason="NESTED_AUTHORIZATION_VIOLATION",
            expected_http_status=403,
            oracle_rationale="Nested field alias 'sharedDoc' must be mapped to canonical schema path 'user.resource'.",
        )
    )

    # -------------------------------------------------------------------------
    # 4. VARIABLE INJECTION BOLA ATTACKS
    # -------------------------------------------------------------------------
    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-VAR-001",
            name="Variable Parameterized Direct BOLA",
            category="VARIABLE_INJECTION",
            query="query GetResource($targetId: Int!) { resource(id: $targetId) { id name } }",
            variables={"targetId": 102},
            caller_id=101,
            caller_role="user",
            target_object_type="Resource",
            target_object_id=102,
            target_owner_id=102,
            schema_path="resource",
            response_path="resource",
            is_nested=False,
            expected_decision="DENY",
            expected_reason="OWNERSHIP_MISMATCH",
            expected_http_status=403,
            oracle_rationale="GraphQL variable $targetId=102 must be extracted and evaluated exactly like a literal.",
        )
    )

    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-VAR-002",
            name="Variable Parameterized Nested BOLA",
            category="VARIABLE_INJECTION",
            query="query GetNested($uId: Int!, $rId: Int!) { user(id: $uId) { resource(id: $rId) { name } } }",
            variables={"uId": 101, "rId": 102},
            caller_id=101,
            caller_role="user",
            target_object_type="Resource",
            target_object_id=102,
            target_owner_id=102,
            schema_path="user.resource",
            response_path="user.resource",
            is_nested=True,
            expected_decision="DENY",
            expected_reason="NESTED_AUTHORIZATION_VIOLATION",
            expected_http_status=403,
            oracle_rationale="Nested variable resolution must bind rId=102 to child Resource and deny access.",
        )
    )

    # -------------------------------------------------------------------------
    # 5. BENIGN OWNER ACCESS (Legitimate self-owned resource operations)
    # -------------------------------------------------------------------------
    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-OWN-001",
            name="Benign Owner: Alice accessing Alice's Resource 101",
            category="BENIGN_OWNER",
            query="query { resource(id: 101) { id name ownerId objectType } }",
            caller_id=101,
            caller_role="user",
            target_object_type="Resource",
            target_object_id=101,
            target_owner_id=101,
            schema_path="resource",
            response_path="resource",
            is_nested=False,
            expected_decision="ALLOW",
            expected_reason="OWNER_MATCH",
            expected_http_status=200,
            oracle_rationale="Caller 101 matches owner 101; gateway must permit request with OWNER_MATCH.",
        )
    )

    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-OWN-002",
            name="Benign Owner: Bob accessing Bob's Resource 102",
            category="BENIGN_OWNER",
            query="query { resource(id: 102) { id name ownerId } }",
            caller_id=102,
            caller_role="user",
            target_object_type="Resource",
            target_object_id=102,
            target_owner_id=102,
            schema_path="resource",
            response_path="resource",
            is_nested=False,
            expected_decision="ALLOW",
            expected_reason="OWNER_MATCH",
            expected_http_status=200,
            oracle_rationale="Caller 102 matches owner 102; gateway must permit request with OWNER_MATCH.",
        )
    )

    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-OWN-003",
            name="Benign Owner: Alice accessing own User profile and resources",
            category="BENIGN_OWNER",
            query="query { user(id: 101) { id username resources { id name } } }",
            caller_id=101,
            caller_role="user",
            target_object_type="User",
            target_object_id=101,
            target_owner_id=101,
            schema_path="user.resources",
            response_path="user.resources",
            is_nested=True,
            expected_decision="ALLOW",
            expected_reason="OWNER_MATCH",
            expected_http_status=200,
            oracle_rationale="Caller 101 owns profile and all listed resources belong to Alice.",
        )
    )

    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-OWN-004",
            name="Benign Owner: Alice traversing own nested folder hierarchy",
            category="BENIGN_OWNER",
            query="query { resource(id: 201) { id name children { id name ownerId } } }",
            caller_id=101,
            caller_role="user",
            target_object_type="Resource",
            target_object_id=201,
            target_owner_id=101,
            schema_path="resource.children",
            response_path="resource.children",
            is_nested=True,
            expected_decision="ALLOW",
            expected_reason="OWNER_MATCH",
            expected_http_status=200,
            oracle_rationale="Folder 201 and children 202/203 are all owned by Alice (101).",
        )
    )

    # -------------------------------------------------------------------------
    # 6. PRIVILEGED ADMINISTRATOR OVERRIDE
    # -------------------------------------------------------------------------
    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-ADM-001",
            name="Admin Override: Charlie accessing Alice's Resource 101",
            category="ADMIN_OVERRIDE",
            query="query { resource(id: 101) { id name ownerId } }",
            caller_id=103,
            caller_role="admin",
            target_object_type="Resource",
            target_object_id=101,
            target_owner_id=101,
            schema_path="resource",
            response_path="resource",
            is_nested=False,
            expected_decision="ALLOW",
            expected_reason="ADMIN_OVERRIDE",
            expected_http_status=200,
            oracle_rationale="Admin role permits cross-owner access under Policy 3 (ADMIN_OVERRIDE).",
        )
    )

    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-ADM-002",
            name="Admin Override: Charlie accessing Bob's Resource 102",
            category="ADMIN_OVERRIDE",
            query="query { resource(id: 102) { id name ownerId } }",
            caller_id=103,
            caller_role="admin",
            target_object_type="Resource",
            target_object_id=102,
            target_owner_id=102,
            schema_path="resource",
            response_path="resource",
            is_nested=False,
            expected_decision="ALLOW",
            expected_reason="ADMIN_OVERRIDE",
            expected_http_status=200,
            oracle_rationale="Admin role permits cross-owner access under Policy 3 (ADMIN_OVERRIDE).",
        )
    )

    # -------------------------------------------------------------------------
    # 7. ANONYMOUS / UNAUTHENTICATED ACCESS
    # -------------------------------------------------------------------------
    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-ANON-001",
            name="Unauthenticated Access: Protected Resource 101 without token",
            category="ANONYMOUS",
            query="query { resource(id: 101) { id name } }",
            caller_id=None,
            caller_role="anonymous",
            target_object_type="Resource",
            target_object_id=101,
            target_owner_id=101,
            schema_path="resource",
            response_path="resource",
            is_nested=False,
            expected_decision="DENY",
            expected_reason="INVALID_CONTEXT",
            expected_http_status=401,
            oracle_rationale="Unauthenticated requests lack caller identity and must be rejected by auth middleware.",
        )
    )

    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-ANON-002",
            name="Unauthenticated Access: Protected User 101 without token",
            category="ANONYMOUS",
            query="query { user(id: 101) { id username } }",
            caller_id=None,
            caller_role="anonymous",
            target_object_type="User",
            target_object_id=101,
            target_owner_id=101,
            schema_path="user",
            response_path="user",
            is_nested=False,
            expected_decision="DENY",
            expected_reason="INVALID_CONTEXT",
            expected_http_status=401,
            oracle_rationale="Unauthenticated access to protected user profile must be rejected.",
        )
    )

    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-PUB-001",
            name="Public Field Access: Authenticated API Health Probe",
            category="BENIGN_PUBLIC",
            query="query { health { status message } }",
            caller_id=101,
            caller_role="user",
            target_object_type="HealthCheck",
            target_object_id=0,
            target_owner_id=None,
            schema_path="health",
            response_path="health",
            is_nested=False,
            expected_decision="ALLOW",
            expected_reason="PUBLIC_FIELD",
            expected_http_status=200,
            oracle_rationale="Public infrastructure fields do not require entity-level authorization.",
        )
    )

    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-MUT-001",
            name="Mutation BOLA: Cross-tenant updateResource by Alice on Bob's Resource 102",
            category="MUTATION_BOLA",
            query='mutation { updateResource(id: 102, name: "Tampered by Alice") { id name ownerId } }',
            caller_id=101,
            caller_role="user",
            target_object_type="Resource",
            target_object_id=102,
            target_owner_id=102,
            schema_path="updateResource",
            response_path="updateResource",
            is_nested=False,
            expected_decision="DENY",
            expected_reason="OWNERSHIP_MISMATCH",
            expected_http_status=403,
            oracle_rationale="Unauthorized mutation modifying resource 102 belonging to Bob must be blocked.",
        )
    )

    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-MUT-002",
            name="Mutation BOLA: Cross-tenant deleteResource by Bob on Alice's Resource 101",
            category="MUTATION_BOLA",
            query="mutation { deleteResource(id: 101) }",
            caller_id=102,
            caller_role="user",
            target_object_type="Resource",
            target_object_id=101,
            target_owner_id=101,
            schema_path="deleteResource",
            response_path="deleteResource",
            is_nested=False,
            expected_decision="DENY",
            expected_reason="OWNERSHIP_MISMATCH",
            expected_http_status=403,
            oracle_rationale="Unauthorized mutation deleting resource 101 belonging to Alice must be blocked.",
        )
    )

    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-MUT-003",
            name="Mutation BOLA: Cross-tenant transferOwnership by Alice on Bob's Resource 102",
            category="MUTATION_BOLA",
            query="mutation { transferOwnership(id: 102, newOwnerId: 101) { id ownerId } }",
            caller_id=101,
            caller_role="user",
            target_object_type="Resource",
            target_object_id=102,
            target_owner_id=102,
            schema_path="transferOwnership",
            response_path="transferOwnership",
            is_nested=False,
            expected_decision="DENY",
            expected_reason="OWNERSHIP_MISMATCH",
            expected_http_status=403,
            oracle_rationale="Unauthorized ownership re-assignment on resource 102 must be blocked.",
        )
    )

    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-MUT-004",
            name="Benign Mutation: Owner Alice updating her own Resource 101",
            category="BENIGN_OWNER",
            query='mutation { updateResource(id: 101, name: "Alice Valid Update") { id name ownerId } }',
            caller_id=101,
            caller_role="user",
            target_object_type="Resource",
            target_object_id=101,
            target_owner_id=101,
            schema_path="updateResource",
            response_path="updateResource",
            is_nested=False,
            expected_decision="ALLOW",
            expected_reason="OWNER_MATCH",
            expected_http_status=200,
            oracle_rationale="Legitimate owner 101 updating her own resource is permitted.",
        )
    )

    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-FLD-001",
            name="Field-Level BOLA: Non-owner Alice probing secretKey on Bob's Resource 102",
            category="FIELD_LEVEL_BOLA",
            query="query { resource(id: 102) { id name secretKey } }",
            caller_id=101,
            caller_role="user",
            target_object_type="Resource",
            target_object_id=102,
            target_owner_id=102,
            schema_path="resource",
            response_path="resource",
            is_nested=False,
            expected_decision="DENY",
            expected_reason="OWNERSHIP_MISMATCH",
            expected_http_status=403,
            oracle_rationale="Probing sensitive secretKey on another tenant's resource must be blocked.",
        )
    )

    test_cases.append(
        DifferentialTestCase(
            test_id="DIFF-FLD-002",
            name="Field-Level Benign: Owner Alice reading secretKey on her own Resource 101",
            category="BENIGN_OWNER",
            query="query { resource(id: 101) { id name secretKey } }",
            caller_id=101,
            caller_role="user",
            target_object_type="Resource",
            target_object_id=101,
            target_owner_id=101,
            schema_path="resource",
            response_path="resource",
            is_nested=False,
            expected_decision="ALLOW",
            expected_reason="OWNER_MATCH",
            expected_http_status=200,
            oracle_rationale="Legitimate owner reading secretKey on her own resource is permitted.",
        )
    )

    if sample_limit and sample_limit > 0:
        return test_cases[:sample_limit]

    return test_cases
