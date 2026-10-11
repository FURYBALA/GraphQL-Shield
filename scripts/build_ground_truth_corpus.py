#!/usr/bin/env python3
"""
Ground-Truth Evaluation Corpus Builder (Phase 6)

Constructs an independently labeled evaluation corpus of 115 test cases
for measuring GraphQL BOLA detection across:
1. Direct BOLA (cross-user document, user, folder, and admin targets)
2. Indirect BOLA (nested collection traversals, nested resources, parent-child relations)
3. Legitimate Owner Access (direct objects, collections, and nested relationships)
4. Admin Privileged Access (cross-tenant administrative overrides)
5. Public and Introspection Queries (health checks, schema queries)
6. Multi-Root Selections (dual attacks, mixed legitimate + attack, multi-own)
7. Syntax Errors & Malformed Queries (unclosed braces, invalid fields, empty bodies)
8. Edge Cases & Boundary Conditions (zero/negative IDs, deep hierarchies)

Every test case defines:
- id: Unique stable identifier (e.g. "CORPUS-001")
- name: Descriptive title
- category: High-level scenario category
- syntax_type: GraphQL syntactic structure (BASIC, ALIAS, VARIABLE, FRAGMENT, etc.)
- caller: Authenticated principal context {"user_id": int, "role": str}
- query: Full GraphQL document string
- variables: Variables dictionary
- operation_name: Optional operation name
- ground_truth_security: Independent ground truth ("VULNERABLE", "BENIGN", "MALFORMED")
- ground_truth_attack_type: Expected vulnerability category ("DIRECT_BOLA", "INDIRECT_BOLA", "NONE")
- expected_gateway_decision: Expected access decision ("DENY", "ALLOW", "ERROR")
- rationale: Concrete authorization and security rationale
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List


def generate_corpus() -> List[Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []

    def add_case(
        case_id: str,
        name: str,
        category: str,
        syntax_type: str,
        caller_id: int,
        caller_role: str,
        query: str,
        variables: Dict[str, Any],
        ground_truth_security: str,
        ground_truth_attack_type: str,
        expected_gateway_decision: str,
        rationale: str,
        operation_name: str | None = None,
        target_object_id: int | None = None,
        target_object_type: str | None = None,
        true_owner_id: int | None = None,
    ) -> None:
        cases.append({
            "id": case_id,
            "name": name,
            "category": category,
            "syntax_type": syntax_type,
            "caller": {"user_id": caller_id, "role": caller_role},
            "query": query.strip(),
            "variables": variables,
            "operation_name": operation_name,
            "target_object_id": target_object_id,
            "target_object_type": target_object_type,
            "true_owner_id": true_owner_id,
            "ground_truth_security": ground_truth_security,
            "ground_truth_attack_type": ground_truth_attack_type,
            "expected_gateway_decision": expected_gateway_decision,
            "rationale": rationale,
        })

    # =========================================================================
    # 1. DIRECT BOLA — UNAUTHORIZED CROSS-USER ACCESS (22 cases)
    # =========================================================================
    add_case(
        "CORPUS-001", "Direct cross-user document lookup (Alice -> Bob doc)",
        "DIRECT_BOLA", "BASIC", 101, "user",
        "query { resource(id: 102) { id name } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Alice (101) accesses Bob's document 102 without authorization.",
        target_object_id=102, target_object_type="Resource", true_owner_id=102
    )
    add_case(
        "CORPUS-002", "Direct cross-user document lookup (Bob -> Alice doc)",
        "DIRECT_BOLA", "BASIC", 102, "user",
        "query { resource(id: 101) { id name } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Bob (102) accesses Alice's document 101 without authorization.",
        target_object_id=101, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-003", "Direct access to admin confidential document (Alice -> Charlie doc)",
        "DIRECT_BOLA", "BASIC", 101, "user",
        "query { resource(id: 103) { id name } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Alice (101) accesses Admin Charlie's document 103 without admin privileges.",
        target_object_id=103, target_object_type="Resource", true_owner_id=103
    )
    add_case(
        "CORPUS-004", "Direct access to admin confidential document (Bob -> Charlie doc)",
        "DIRECT_BOLA", "BASIC", 102, "user",
        "query { resource(id: 103) { id name } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Bob (102) accesses Admin Charlie's document 103 without admin privileges.",
        target_object_id=103, target_object_type="Resource", true_owner_id=103
    )
    add_case(
        "CORPUS-005", "Direct cross-user folder access (Bob -> Alice folder 201)",
        "DIRECT_BOLA", "BASIC", 102, "user",
        "query { resource(id: 201) { id name object_type } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Bob (102) accesses Alice's project folder 201 without authorization.",
        target_object_id=201, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-006", "Direct cross-user sub-document access (Bob -> Alice plan 202)",
        "DIRECT_BOLA", "BASIC", 102, "user",
        "query { resource(id: 202) { id name parent_id } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Bob (102) directly targets Alice's plan document 202.",
        target_object_id=202, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-007", "Direct cross-user sub-document access (Bob -> Alice plan 203)",
        "DIRECT_BOLA", "BASIC", 102, "user",
        "query { resource(id: 203) { id name parent_id } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Bob (102) directly targets Alice's second plan document 203.",
        target_object_id=203, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-008", "Direct cross-user profile access (Alice -> Bob user profile)",
        "DIRECT_BOLA", "BASIC", 101, "user",
        "query { user(id: 102) { id username role } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Alice (101) accesses Bob's user profile object 102.",
        target_object_id=102, target_object_type="User", true_owner_id=102
    )
    add_case(
        "CORPUS-009", "Direct cross-user profile access (Bob -> Alice user profile)",
        "DIRECT_BOLA", "BASIC", 102, "user",
        "query { user(id: 101) { id username role } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Bob (102) accesses Alice's user profile object 101.",
        target_object_id=101, target_object_type="User", true_owner_id=101
    )
    add_case(
        "CORPUS-010", "Direct cross-user profile access (Alice -> Admin Charlie profile)",
        "DIRECT_BOLA", "BASIC", 101, "user",
        "query { user(id: 103) { id username role } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Alice (101) accesses Admin Charlie's profile object 103.",
        target_object_id=103, target_object_type="User", true_owner_id=103
    )
    add_case(
        "CORPUS-011", "Direct cross-user profile access (Bob -> Admin Charlie profile)",
        "DIRECT_BOLA", "BASIC", 102, "user",
        "query { user(id: 103) { id username role } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Bob (102) accesses Admin Charlie's profile object 103.",
        target_object_id=103, target_object_type="User", true_owner_id=103
    )
    add_case(
        "CORPUS-012", "Aliased direct BOLA on document (Alice -> Bob doc)",
        "DIRECT_BOLA", "ALIAS", 101, "user",
        "query { victimDoc: resource(id: 102) { id name } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Alice obfuscates access to Bob's document using the response alias 'victimDoc'.",
        target_object_id=102, target_object_type="Resource", true_owner_id=102
    )
    add_case(
        "CORPUS-013", "Aliased direct BOLA on user (Bob -> Alice profile)",
        "DIRECT_BOLA", "ALIAS", 102, "user",
        "query { stolenUser: user(id: 101) { username role } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Bob obfuscates access to Alice's profile using alias 'stolenUser'.",
        target_object_id=101, target_object_type="User", true_owner_id=101
    )
    add_case(
        "CORPUS-014", "Variable-driven direct BOLA (Alice -> Bob doc)",
        "DIRECT_BOLA", "VARIABLE", 101, "user",
        "query GetRes($rId: Int!) { resource(id: $rId) { id name } }", {"rId": 102},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Alice passes Bob's document ID via GraphQL variable $rId.",
        target_object_id=102, target_object_type="Resource", true_owner_id=102
    )
    add_case(
        "CORPUS-015", "Variable-driven direct BOLA (Bob -> Alice folder)",
        "DIRECT_BOLA", "VARIABLE", 102, "user",
        "query GetFolder($fId: Int!) { resource(id: $fId) { id name } }", {"fId": 201},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Bob passes Alice's folder ID 201 via GraphQL variable $fId.",
        target_object_id=201, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-016", "Named fragment direct BOLA (Alice -> Bob doc)",
        "DIRECT_BOLA", "FRAGMENT", 101, "user",
        """
        query { resource(id: 102) { ...DocData } }
        fragment DocData on ResourceType { id name object_type }
        """, {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Alice queries Bob's document 102 using a named fragment spread.",
        target_object_id=102, target_object_type="Resource", true_owner_id=102
    )
    add_case(
        "CORPUS-017", "Inline fragment direct BOLA (Bob -> Alice plan)",
        "DIRECT_BOLA", "INLINE_FRAGMENT", 102, "user",
        "query { resource(id: 202) { ... on ResourceType { id name } } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Bob accesses Alice's plan 202 wrapped inside an inline fragment.",
        target_object_id=202, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-018", "Variable with default value direct BOLA (Alice -> Bob doc)",
        "DIRECT_BOLA", "VARIABLE", 101, "user",
        "query GetDoc($target: Int = 102) { resource(id: $target) { name } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Alice accesses Bob's document using a GraphQL variable default value of 102.",
        target_object_id=102, target_object_type="Resource", true_owner_id=102
    )
    add_case(
        "CORPUS-019", "Reconnaissance probe for non-existent unowned ID (Alice -> ID 999)",
        "DIRECT_BOLA", "BASIC", 101, "user",
        "query { resource(id: 999) { id name } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Alice probes unowned resource ID 999 (not owned by Alice, fails-closed at gateway).",
        target_object_id=999, target_object_type="Resource", true_owner_id=None
    )
    add_case(
        "CORPUS-020", "Reconnaissance probe for non-existent unowned ID (Bob -> ID 888)",
        "DIRECT_BOLA", "BASIC", 102, "user",
        "query { resource(id: 888) { id name } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Bob probes unowned resource ID 888 (unowned, fails-closed).",
        target_object_id=888, target_object_type="Resource", true_owner_id=None
    )
    add_case(
        "CORPUS-021", "Aliased user probe with variable (Alice -> Bob profile)",
        "DIRECT_BOLA", "ALIAS_VARIABLE", 101, "user",
        "query FetchVictim($vId: Int!) { victim: user(id: $vId) { id username } }", {"vId": 102},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Combined alias and variable pointing to Bob's profile.",
        target_object_id=102, target_object_type="User", true_owner_id=102
    )
    add_case(
        "CORPUS-022", "Fragment with alias on unauthorized target (Bob -> Alice doc)",
        "DIRECT_BOLA", "FRAGMENT_ALIAS", 102, "user",
        """
        query { stolen: resource(id: 101) { ...F } }
        fragment F on ResourceType { id name }
        """, {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Combined alias and named fragment on Alice's document.",
        target_object_id=101, target_object_type="Resource", true_owner_id=101
    )

    # =========================================================================
    # 2. INDIRECT / NESTED BOLA — UNAUTHORIZED RELATIONSHIP ACCESS (22 cases)
    # =========================================================================
    add_case(
        "CORPUS-023", "Indirect BOLA via User.resources collection (Alice -> Bob resources)",
        "INDIRECT_BOLA", "BASIC", 101, "user",
        "query { user(id: 102) { resources { id name } } }", {},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Alice accesses Bob's entire resources collection through the user navigation field.",
        target_object_id=102, target_object_type="User", true_owner_id=102
    )
    add_case(
        "CORPUS-024", "Indirect BOLA via User.resources collection (Bob -> Alice resources)",
        "INDIRECT_BOLA", "BASIC", 102, "user",
        "query { user(id: 101) { resources { id name parent_id } } }", {},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Bob accesses Alice's complete collection of resources through User(id: 101).",
        target_object_id=101, target_object_type="User", true_owner_id=101
    )
    add_case(
        "CORPUS-025", "Indirect BOLA on admin resources (Alice -> Charlie resources)",
        "INDIRECT_BOLA", "BASIC", 101, "user",
        "query { user(id: 103) { resources { id name } } }", {},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Alice traverses Admin Charlie's resources collection.",
        target_object_id=103, target_object_type="User", true_owner_id=103
    )
    add_case(
        "CORPUS-026", "Indirect BOLA on admin resources (Bob -> Charlie resources)",
        "INDIRECT_BOLA", "BASIC", 102, "user",
        "query { user(id: 103) { resources { id name } } }", {},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Bob traverses Admin Charlie's resources collection.",
        target_object_id=103, target_object_type="User", true_owner_id=103
    )
    add_case(
        "CORPUS-027", "Nested parameterized BOLA under own user node (Alice -> Bob doc)",
        "INDIRECT_BOLA", "NESTED_PARAM", 101, "user",
        "query { user(id: 101) { resource(id: 102) { id name } } }", {},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Alice queries her own user node but requests Bob's resource 102 inside nested field.",
        target_object_id=102, target_object_type="Resource", true_owner_id=102
    )
    add_case(
        "CORPUS-028", "Nested parameterized BOLA under own user node (Bob -> Alice doc)",
        "INDIRECT_BOLA", "NESTED_PARAM", 102, "user",
        "query { user(id: 102) { resource(id: 101) { id name } } }", {},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Bob queries his own user node but requests Alice's resource 101 inside nested field.",
        target_object_id=101, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-029", "Nested parameterized BOLA under victim user node (Alice -> Bob user -> Bob doc)",
        "INDIRECT_BOLA", "NESTED_PARAM", 101, "user",
        "query { user(id: 102) { resource(id: 102) { id name } } }", {},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Alice traverses Bob's user node to fetch Bob's document 102.",
        target_object_id=102, target_object_type="User", true_owner_id=102
    )
    add_case(
        "CORPUS-030", "Nested parameterized BOLA under victim user node (Bob -> Alice user -> Alice doc)",
        "INDIRECT_BOLA", "NESTED_PARAM", 102, "user",
        "query { user(id: 101) { resource(id: 101) { id name } } }", {},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Bob traverses Alice's user node to fetch Alice's document 101.",
        target_object_id=101, target_object_type="User", true_owner_id=101
    )
    add_case(
        "CORPUS-031", "Indirect traversal of victim folder hierarchy (Bob -> Alice folder children)",
        "INDIRECT_BOLA", "RELATIONSHIP", 102, "user",
        "query { resource(id: 201) { children { id name } } }", {},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Bob queries Alice's folder 201 and navigates to its child documents.",
        target_object_id=201, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-032", "Aliased indirect BOLA on collection (Alice -> Bob user)",
        "INDIRECT_BOLA", "ALIAS", 101, "user",
        "query { u: user(id: 102) { docs: resources { id name } } }", {},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Alice queries Bob's resources using aliases on root and nested collections.",
        target_object_id=102, target_object_type="User", true_owner_id=102
    )
    add_case(
        "CORPUS-033", "Aliased indirect BOLA on collection (Bob -> Alice user)",
        "INDIRECT_BOLA", "ALIAS", 102, "user",
        "query { targetUser: user(id: 101) { allDocs: resources { name } } }", {},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Bob queries Alice's resources using nested aliases.",
        target_object_id=101, target_object_type="User", true_owner_id=101
    )
    add_case(
        "CORPUS-034", "Variable-driven indirect BOLA (Alice -> Bob user resources)",
        "INDIRECT_BOLA", "VARIABLE", 101, "user",
        "query TraverseUser($userId: Int!) { user(id: $userId) { resources { id name } } }", {"userId": 102},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Alice passes Bob's user ID into variable $userId and selects resources collection.",
        target_object_id=102, target_object_type="User", true_owner_id=102
    )
    add_case(
        "CORPUS-035", "Variable-driven indirect BOLA (Bob -> Alice user resources)",
        "INDIRECT_BOLA", "VARIABLE", 102, "user",
        "query TraverseUser($userId: Int!) { user(id: $userId) { resources { id name } } }", {"userId": 101},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Bob passes Alice's user ID into variable $userId and selects resources collection.",
        target_object_id=101, target_object_type="User", true_owner_id=101
    )
    add_case(
        "CORPUS-036", "Variable in nested field parameter (Alice -> own user with Bob resId)",
        "INDIRECT_BOLA", "NESTED_PARAM_VAR", 101, "user",
        "query Nested($rId: Int!) { user(id: 101) { resource(id: $rId) { name } } }", {"rId": 102},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Alice queries her own user ID 101 but binds Bob's document ID 102 into nested variable $rId.",
        target_object_id=102, target_object_type="Resource", true_owner_id=102
    )
    add_case(
        "CORPUS-037", "Named fragment on indirect collection traversal (Alice -> Bob user)",
        "INDIRECT_BOLA", "FRAGMENT", 101, "user",
        """
        query { user(id: 102) { ...UserResources } }
        fragment UserResources on UserType { id resources { id name } }
        """, {},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Alice traverses Bob's user resources through a named fragment spread.",
        target_object_id=102, target_object_type="User", true_owner_id=102
    )
    add_case(
        "CORPUS-038", "Named fragment on nested resource field (Bob -> Alice user)",
        "INDIRECT_BOLA", "FRAGMENT", 102, "user",
        """
        query { user(id: 101) { ...NestedRes } }
        fragment NestedRes on UserType { resource(id: 101) { id name } }
        """, {},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Bob spreads a fragment accessing Alice's nested resource.",
        target_object_id=101, target_object_type="User", true_owner_id=101
    )
    add_case(
        "CORPUS-039", "Inline fragment on indirect collection traversal (Alice -> Bob user)",
        "INDIRECT_BOLA", "INLINE_FRAGMENT", 101, "user",
        "query { user(id: 102) { ... on UserType { resources { id name } } } }", {},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Alice accesses Bob's resources through an inline fragment.",
        target_object_id=102, target_object_type="User", true_owner_id=102
    )
    add_case(
        "CORPUS-040", "Indirect probe of unowned non-existent user collection (Alice -> User 999)",
        "INDIRECT_BOLA", "BASIC", 101, "user",
        "query { user(id: 999) { resources { id name } } }", {},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Alice probes unowned non-existent user ID 999 resources collection.",
        target_object_id=999, target_object_type="User", true_owner_id=None
    )
    add_case(
        "CORPUS-041", "Indirect probe of unowned non-existent user collection (Bob -> User 888)",
        "INDIRECT_BOLA", "BASIC", 102, "user",
        "query { user(id: 888) { resources { id name } } }", {},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Bob probes unowned non-existent user ID 888 resources collection.",
        target_object_id=888, target_object_type="User", true_owner_id=None
    )
    add_case(
        "CORPUS-042", "Indirect traversal with operation name (Alice -> Bob user resources)",
        "INDIRECT_BOLA", "BASIC", 101, "user",
        "query InfiltrateBob { user(id: 102) { resources { id name } } }", {},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Named operation traversing Bob's resources collection.",
        operation_name="InfiltrateBob",
        target_object_id=102, target_object_type="User", true_owner_id=102
    )
    add_case(
        "CORPUS-043", "Multi-hop indirect traversal through victim folder and children (Bob -> Alice folder)",
        "INDIRECT_BOLA", "DEEP_TRAVERSAL", 102, "user",
        "query { resource(id: 201) { children { children { id name } } } }", {},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Bob traverses multiple hops down Alice's folder hierarchy.",
        target_object_id=201, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-044", "Indirect collection traversal with field selection only (Alice -> Bob resources)",
        "INDIRECT_BOLA", "BASIC", 101, "user",
        "query { user(id: 102) { resources { name } } }", {},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Alice accesses Bob's resources selecting only the name field.",
        target_object_id=102, target_object_type="User", true_owner_id=102
    )

    # =========================================================================
    # 3. LEGITIMATE OWNER ACCESS — AUTHORIZED (25 cases)
    # =========================================================================
    add_case(
        "CORPUS-045", "Legitimate direct access to own document (Alice -> Alice doc 101)",
        "LEGITIMATE_OWNER", "BASIC", 101, "user",
        "query { resource(id: 101) { id name } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Alice accesses her own document 101. Principal matches owner.",
        target_object_id=101, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-046", "Legitimate direct access to own folder (Alice -> Alice folder 201)",
        "LEGITIMATE_OWNER", "BASIC", 101, "user",
        "query { resource(id: 201) { id name object_type } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Alice accesses her own folder 201. Principal matches owner.",
        target_object_id=201, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-047", "Legitimate direct access to own plan (Alice -> Alice doc 202)",
        "LEGITIMATE_OWNER", "BASIC", 101, "user",
        "query { resource(id: 202) { id name parent_id } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Alice accesses her own plan document 202.",
        target_object_id=202, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-048", "Legitimate direct access to own plan (Alice -> Alice doc 203)",
        "LEGITIMATE_OWNER", "BASIC", 101, "user",
        "query { resource(id: 203) { id name parent_id } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Alice accesses her own plan document 203.",
        target_object_id=203, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-049", "Legitimate direct access to own document (Bob -> Bob doc 102)",
        "LEGITIMATE_OWNER", "BASIC", 102, "user",
        "query { resource(id: 102) { id name } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Bob accesses his own document 102.",
        target_object_id=102, target_object_type="Resource", true_owner_id=102
    )
    add_case(
        "CORPUS-050", "Legitimate direct access to own profile (Alice -> Alice user 101)",
        "LEGITIMATE_OWNER", "BASIC", 101, "user",
        "query { user(id: 101) { id username role } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Alice accesses her own user profile.",
        target_object_id=101, target_object_type="User", true_owner_id=101
    )
    add_case(
        "CORPUS-051", "Legitimate direct access to own profile (Bob -> Bob user 102)",
        "LEGITIMATE_OWNER", "BASIC", 102, "user",
        "query { user(id: 102) { id username role } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Bob accesses his own user profile.",
        target_object_id=102, target_object_type="User", true_owner_id=102
    )
    add_case(
        "CORPUS-052", "Legitimate indirect access to own resources (Alice -> Alice resources)",
        "LEGITIMATE_OWNER", "BASIC", 101, "user",
        "query { user(id: 101) { resources { id name } } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Alice accesses her own resources collection.",
        target_object_id=101, target_object_type="User", true_owner_id=101
    )
    add_case(
        "CORPUS-053", "Legitimate indirect access to own resources (Bob -> Bob resources)",
        "LEGITIMATE_OWNER", "BASIC", 102, "user",
        "query { user(id: 102) { resources { id name } } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Bob accesses his own resources collection.",
        target_object_id=102, target_object_type="User", true_owner_id=102
    )
    add_case(
        "CORPUS-054", "Legitimate nested resource access (Alice -> Alice user -> Alice doc 101)",
        "LEGITIMATE_OWNER", "NESTED_PARAM", 101, "user",
        "query { user(id: 101) { resource(id: 101) { id name } } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Alice accesses her own document 101 under her own user node.",
        target_object_id=101, target_object_type="User", true_owner_id=101
    )
    add_case(
        "CORPUS-055", "Legitimate nested resource access (Bob -> Bob user -> Bob doc 102)",
        "LEGITIMATE_OWNER", "NESTED_PARAM", 102, "user",
        "query { user(id: 102) { resource(id: 102) { id name } } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Bob accesses his own document 102 under his own user node.",
        target_object_id=102, target_object_type="User", true_owner_id=102
    )
    add_case(
        "CORPUS-056", "Legitimate folder hierarchy traversal (Alice -> Alice folder 201 children)",
        "LEGITIMATE_OWNER", "RELATIONSHIP", 101, "user",
        "query { resource(id: 201) { children { id name parent_id } } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Alice traverses children of folder 201 which she owns.",
        target_object_id=201, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-057", "Aliased legitimate document access (Alice -> Alice doc 101)",
        "LEGITIMATE_OWNER", "ALIAS", 101, "user",
        "query { myNote: resource(id: 101) { id name } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Alice accesses her own document 101 using alias 'myNote'.",
        target_object_id=101, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-058", "Aliased legitimate document access (Bob -> Bob doc 102)",
        "LEGITIMATE_OWNER", "ALIAS", 102, "user",
        "query { financialRecord: resource(id: 102) { id name } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Bob accesses his own document 102 using alias 'financialRecord'.",
        target_object_id=102, target_object_type="Resource", true_owner_id=102
    )
    add_case(
        "CORPUS-059", "Variable-driven legitimate access (Alice -> Alice doc 101)",
        "LEGITIMATE_OWNER", "VARIABLE", 101, "user",
        "query GetMyDoc($id: Int!) { resource(id: $id) { id name } }", {"id": 101},
        "BENIGN", "NONE", "ALLOW",
        "Alice passes her own document ID 101 via variable.",
        target_object_id=101, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-060", "Variable-driven legitimate access (Bob -> Bob doc 102)",
        "LEGITIMATE_OWNER", "VARIABLE", 102, "user",
        "query GetMyDoc($id: Int!) { resource(id: $id) { id name } }", {"id": 102},
        "BENIGN", "NONE", "ALLOW",
        "Bob passes his own document ID 102 via variable.",
        target_object_id=102, target_object_type="Resource", true_owner_id=102
    )
    add_case(
        "CORPUS-061", "Named fragment legitimate document access (Alice -> Alice doc 101)",
        "LEGITIMATE_OWNER", "FRAGMENT", 101, "user",
        """
        query { resource(id: 101) { ...MyFields } }
        fragment MyFields on ResourceType { id name object_type }
        """, {},
        "BENIGN", "NONE", "ALLOW",
        "Alice accesses her own document through a named fragment.",
        target_object_id=101, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-062", "Named fragment legitimate document access (Bob -> Bob doc 102)",
        "LEGITIMATE_OWNER", "FRAGMENT", 102, "user",
        """
        query { resource(id: 102) { ...BobFields } }
        fragment BobFields on ResourceType { id name object_type }
        """, {},
        "BENIGN", "NONE", "ALLOW",
        "Bob accesses his own document through a named fragment.",
        target_object_id=102, target_object_type="Resource", true_owner_id=102
    )
    add_case(
        "CORPUS-063", "Inline fragment legitimate access (Alice -> Alice folder 201)",
        "LEGITIMATE_OWNER", "INLINE_FRAGMENT", 101, "user",
        "query { resource(id: 201) { ... on ResourceType { id name object_type } } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Alice accesses her folder using an inline fragment.",
        target_object_id=201, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-064", "Variable-driven legitimate collection traversal (Alice -> User 101 resources)",
        "LEGITIMATE_OWNER", "VARIABLE", 101, "user",
        "query MyResources($uid: Int!) { user(id: $uid) { resources { id name } } }", {"uid": 101},
        "BENIGN", "NONE", "ALLOW",
        "Alice queries her own resources passing $uid = 101.",
        target_object_id=101, target_object_type="User", true_owner_id=101
    )
    add_case(
        "CORPUS-065", "Variable-driven legitimate collection traversal (Bob -> User 102 resources)",
        "LEGITIMATE_OWNER", "VARIABLE", 102, "user",
        "query MyResources($uid: Int!) { user(id: $uid) { resources { id name } } }", {"uid": 102},
        "BENIGN", "NONE", "ALLOW",
        "Bob queries his own resources passing $uid = 102.",
        target_object_id=102, target_object_type="User", true_owner_id=102
    )
    add_case(
        "CORPUS-066", "Named fragment legitimate collection traversal (Alice -> User 101)",
        "LEGITIMATE_OWNER", "FRAGMENT", 101, "user",
        """
        query { user(id: 101) { ...OwnUserFrag } }
        fragment OwnUserFrag on UserType { id resources { id name } }
        """, {},
        "BENIGN", "NONE", "ALLOW",
        "Alice traverses her resources via named fragment on UserType.",
        target_object_id=101, target_object_type="User", true_owner_id=101
    )
    add_case(
        "CORPUS-067", "Multiple own resources selection (Alice -> doc 101 and folder 201)",
        "LEGITIMATE_OWNER", "MULTI_FIELD", 101, "user",
        "query { doc: resource(id: 101) { name } folder: resource(id: 201) { name } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Alice requests two objects she legitimately owns in a single query.",
        target_object_id=101, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-068", "Named operation legitimate query (Alice -> own profile and docs)",
        "LEGITIMATE_OWNER", "BASIC", 101, "user",
        "query GetMyData { user(id: 101) { username resources { id name } } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Alice accesses her profile and resources in named operation 'GetMyData'.",
        operation_name="GetMyData",
        target_object_id=101, target_object_type="User", true_owner_id=101
    )
    add_case(
        "CORPUS-069", "Named operation legitimate query (Bob -> own profile and docs)",
        "LEGITIMATE_OWNER", "BASIC", 102, "user",
        "query GetBobData { user(id: 102) { username resources { id name } } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Bob accesses his profile and resources in named operation 'GetBobData'.",
        operation_name="GetBobData",
        target_object_id=102, target_object_type="User", true_owner_id=102
    )

    # =========================================================================
    # 4. ADMIN PRIVILEGED ACCESS — AUTHORIZED OVERRIDES (10 cases)
    # =========================================================================
    add_case(
        "CORPUS-070", "Admin override on Alice document (Charlie -> doc 101)",
        "ADMIN_PRIVILEGED", "BASIC", 103, "admin",
        "query { resource(id: 101) { id name owner_id } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Admin Charlie inspects Alice's document 101. Admin role grants override.",
        target_object_id=101, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-071", "Admin override on Bob document (Charlie -> doc 102)",
        "ADMIN_PRIVILEGED", "BASIC", 103, "admin",
        "query { resource(id: 102) { id name owner_id } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Admin Charlie inspects Bob's document 102. Admin role grants override.",
        target_object_id=102, target_object_type="Resource", true_owner_id=102
    )
    add_case(
        "CORPUS-072", "Admin access to own admin log (Charlie -> doc 103)",
        "ADMIN_PRIVILEGED", "BASIC", 103, "admin",
        "query { resource(id: 103) { id name owner_id } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Admin Charlie inspects his own admin log 103.",
        target_object_id=103, target_object_type="Resource", true_owner_id=103
    )
    add_case(
        "CORPUS-073", "Admin override on Alice profile (Charlie -> user 101)",
        "ADMIN_PRIVILEGED", "BASIC", 103, "admin",
        "query { user(id: 101) { id username role } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Admin Charlie inspects Alice's profile 101.",
        target_object_id=101, target_object_type="User", true_owner_id=101
    )
    add_case(
        "CORPUS-074", "Admin override on Bob profile (Charlie -> user 102)",
        "ADMIN_PRIVILEGED", "BASIC", 103, "admin",
        "query { user(id: 102) { id username role } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Admin Charlie inspects Bob's profile 102.",
        target_object_id=102, target_object_type="User", true_owner_id=102
    )
    add_case(
        "CORPUS-075", "Admin override on Alice resources collection (Charlie -> User 101 resources)",
        "ADMIN_PRIVILEGED", "BASIC", 103, "admin",
        "query { user(id: 101) { resources { id name } } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Admin Charlie audits Alice's resources collection.",
        target_object_id=101, target_object_type="User", true_owner_id=101
    )
    add_case(
        "CORPUS-076", "Admin override on Bob resources collection (Charlie -> User 102 resources)",
        "ADMIN_PRIVILEGED", "BASIC", 103, "admin",
        "query { user(id: 102) { resources { id name } } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Admin Charlie audits Bob's resources collection.",
        target_object_id=102, target_object_type="User", true_owner_id=102
    )
    add_case(
        "CORPUS-077", "Admin aliased inspection (Charlie -> Bob doc 102)",
        "ADMIN_PRIVILEGED", "ALIAS", 103, "admin",
        "query { auditDoc: resource(id: 102) { id name } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Admin Charlie audits Bob's document using alias 'auditDoc'.",
        target_object_id=102, target_object_type="Resource", true_owner_id=102
    )
    add_case(
        "CORPUS-078", "Admin variable-driven inspection (Charlie -> Alice folder 201)",
        "ADMIN_PRIVILEGED", "VARIABLE", 103, "admin",
        "query AuditFolder($fId: Int!) { resource(id: $fId) { id name children { id } } }", {"fId": 201},
        "BENIGN", "NONE", "ALLOW",
        "Admin Charlie audits Alice's folder hierarchy using a variable.",
        target_object_id=201, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-079", "Admin fragment-driven multi-tenant audit (Charlie -> User 101 and 102)",
        "ADMIN_PRIVILEGED", "MULTI_FIELD", 103, "admin",
        """
        query {
            u1: user(id: 101) { ...AuditFrag }
            u2: user(id: 102) { ...AuditFrag }
        }
        fragment AuditFrag on UserType { id username resources { id } }
        """, {},
        "BENIGN", "NONE", "ALLOW",
        "Admin Charlie performs a multi-tenant audit across Alice and Bob using fragments.",
        target_object_id=101, target_object_type="User", true_owner_id=101
    )

    # =========================================================================
    # 5. PUBLIC FIELDS & INTROSPECTION (10 cases)
    # =========================================================================
    add_case(
        "CORPUS-080", "Public health check (Alice)",
        "PUBLIC_INTROSPECTION", "PUBLIC", 101, "user",
        "query { health { status message } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Public health check executed by authenticated user Alice."
    )
    add_case(
        "CORPUS-081", "Public health check (Bob)",
        "PUBLIC_INTROSPECTION", "PUBLIC", 102, "user",
        "query { health { status message } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Public health check executed by authenticated user Bob."
    )
    add_case(
        "CORPUS-082", "Public health check (Charlie Admin)",
        "PUBLIC_INTROSPECTION", "PUBLIC", 103, "admin",
        "query { health { status message } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Public health check executed by Admin Charlie."
    )
    add_case(
        "CORPUS-083", "Public health check with alias",
        "PUBLIC_INTROSPECTION", "PUBLIC_ALIAS", 101, "user",
        "query { ping: health { status } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Public health check with alias 'ping'."
    )
    add_case(
        "CORPUS-084", "Root typename introspection query",
        "PUBLIC_INTROSPECTION", "INTROSPECTION", 101, "user",
        "query { __typename }", {},
        "BENIGN", "NONE", "ALLOW",
        "Standard GraphQL root typename introspection."
    )
    add_case(
        "CORPUS-085", "Schema query type introspection",
        "PUBLIC_INTROSPECTION", "INTROSPECTION", 101, "user",
        "query { __schema { queryType { name } } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Standard GraphQL schema queryType introspection."
    )
    add_case(
        "CORPUS-086", "Specific type introspection (UserType)",
        "PUBLIC_INTROSPECTION", "INTROSPECTION", 101, "user",
        "query { __type(name: \"UserType\") { name kind fields { name } } }", {},
        "BENIGN", "NONE", "ALLOW",
        "GraphQL schema introspection on UserType."
    )
    add_case(
        "CORPUS-087", "Named operation public health query",
        "PUBLIC_INTROSPECTION", "PUBLIC", 101, "user",
        "query PingServer { health { status } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Named operation 'PingServer' on public health field.",
        operation_name="PingServer"
    )
    add_case(
        "CORPUS-088", "Public query with leading comments",
        "PUBLIC_INTROSPECTION", "PUBLIC", 101, "user",
        "# System status check\n# Health ping\nquery { health { status } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Public health query with GraphQL comments."
    )
    add_case(
        "CORPUS-089", "Introspection query using named fragment",
        "PUBLIC_INTROSPECTION", "INTROSPECTION_FRAGMENT", 101, "user",
        """
        query { __schema { ...SchemaFrag } }
        fragment SchemaFrag on __Schema { queryType { name } }
        """, {},
        "BENIGN", "NONE", "ALLOW",
        "Introspection query using fragment spread."
    )

    # =========================================================================
    # 6. MULTI-ROOT FIELD SELECTIONS (10 cases)
    # =========================================================================
    add_case(
        "CORPUS-090", "Dual unauthorized roots (Alice -> Bob doc and Bob user)",
        "MULTI_ROOT", "MULTI_ATTACK", 101, "user",
        "query { r: resource(id: 102) { name } u: user(id: 102) { username } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Alice combines two unauthorized targets in one query.",
        target_object_id=102, target_object_type="Resource", true_owner_id=102
    )
    add_case(
        "CORPUS-091", "Mixed root: legitimate first, attack second (Alice -> own doc 101 + Bob doc 102)",
        "MULTI_ROOT", "MIXED_ROOT", 101, "user",
        "query { legit: resource(id: 101) { name } attack: resource(id: 102) { name } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Alice attempts to smuggle an attack on Bob doc 102 alongside her own document 101.",
        target_object_id=102, target_object_type="Resource", true_owner_id=102
    )
    add_case(
        "CORPUS-092", "Mixed root: attack first, legitimate second (Bob -> Alice doc 101 + Bob doc 102)",
        "MULTI_ROOT", "MIXED_ROOT", 102, "user",
        "query { attack: resource(id: 101) { name } legit: resource(id: 102) { name } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Bob places unauthorized access to Alice doc 101 before his own document 102.",
        target_object_id=101, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-093", "Mixed root: public health + unauthorized document (Alice -> health + Bob doc 102)",
        "MULTI_ROOT", "MIXED_ROOT", 101, "user",
        "query { h: health { status } attack: resource(id: 102) { name } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Alice combines a benign public health query with an unauthorized target.",
        target_object_id=102, target_object_type="Resource", true_owner_id=102
    )
    add_case(
        "CORPUS-094", "Mixed root: public health + legitimate document (Alice -> health + own doc 101)",
        "MULTI_ROOT", "MIXED_LEGIT", 101, "user",
        "query { h: health { status } legit: resource(id: 101) { name } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Alice combines benign public health query with her own legitimate document.",
        target_object_id=101, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-095", "Dual legitimate roots (Alice -> own doc 101 and own folder 201)",
        "MULTI_ROOT", "MULTI_LEGIT", 101, "user",
        "query { r1: resource(id: 101) { name } r2: resource(id: 201) { name } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Alice requests two distinct objects she legitimately owns.",
        target_object_id=101, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-096", "Dual legitimate roots (Bob -> own doc 102 and own user profile 102)",
        "MULTI_ROOT", "MULTI_LEGIT", 102, "user",
        "query { r: resource(id: 102) { name } u: user(id: 102) { username } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Bob requests his own document and his own user profile.",
        target_object_id=102, target_object_type="Resource", true_owner_id=102
    )
    add_case(
        "CORPUS-097", "Triple roots: all legitimate (Alice -> doc 101, folder 201, plan 202)",
        "MULTI_ROOT", "MULTI_LEGIT", 101, "user",
        "query { d: resource(id: 101) { name } f: resource(id: 201) { name } p: resource(id: 202) { name } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Alice requests three objects she owns.",
        target_object_id=101, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-098", "Triple roots: two legitimate, one unauthorized (Alice -> doc 101, plan 202, Bob doc 102)",
        "MULTI_ROOT", "MIXED_ROOT", 101, "user",
        "query { d1: resource(id: 101) { name } d2: resource(id: 202) { name } bad: resource(id: 102) { name } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Alice bundles two owned objects with one unowned victim document.",
        target_object_id=102, target_object_type="Resource", true_owner_id=102
    )
    add_case(
        "CORPUS-099", "Admin multi-root cross-user access (Charlie -> doc 101 and doc 102)",
        "MULTI_ROOT", "ADMIN_MULTI", 103, "admin",
        "query { aliceDoc: resource(id: 101) { name } bobDoc: resource(id: 102) { name } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Admin Charlie requests documents belonging to two distinct users.",
        target_object_id=101, target_object_type="Resource", true_owner_id=101
    )

    # =========================================================================
    # 7. SYNTAX ERRORS & MALFORMED QUERIES (10 cases)
    # =========================================================================
    add_case(
        "CORPUS-100", "Malformed GraphQL syntax: unclosed brace",
        "MALFORMED_SYNTAX", "SYNTAX_ERROR", 101, "user",
        "query { resource(id: 101) { id name }", {},
        "MALFORMED", "SYNTAX_ERROR", "ERROR",
        "Query is syntactically invalid due to missing closing curly brace."
    )
    add_case(
        "CORPUS-101", "Malformed GraphQL syntax: unknown field on ResourceType",
        "MALFORMED_SYNTAX", "SYNTAX_ERROR", 101, "user",
        "query { resource(id: 101) { nonExistentFieldXYZ } }", {},
        "MALFORMED", "SYNTAX_ERROR", "ERROR",
        "Query selects an undefined schema field."
    )
    add_case(
        "CORPUS-102", "Malformed GraphQL syntax: unclosed string literal in argument",
        "MALFORMED_SYNTAX", "SYNTAX_ERROR", 101, "user",
        "query { resource(id: \"101) { name } }", {},
        "MALFORMED", "SYNTAX_ERROR", "ERROR",
        "Query has an unclosed string quotation mark."
    )
    add_case(
        "CORPUS-103", "Malformed query: unknown directive",
        "MALFORMED_SYNTAX", "SYNTAX_ERROR", 101, "user",
        "query @nonExistentDirectiveXYZ { health { status } }", {},
        "MALFORMED", "SYNTAX_ERROR", "ERROR",
        "Query specifies an undefined directive."
    )
    add_case(
        "CORPUS-104", "Malformed query: missing required argument on resource",
        "MALFORMED_SYNTAX", "SYNTAX_ERROR", 101, "user",
        "query { resource { name } }", {},
        "MALFORMED", "SYNTAX_ERROR", "ERROR",
        "Query omits mandatory 'id' argument on Query.resource."
    )
    add_case(
        "CORPUS-105", "Malformed query: wrong argument scalar type literal",
        "MALFORMED_SYNTAX", "SYNTAX_ERROR", 101, "user",
        "query { resource(id: \"notAnInteger\") { name } }", {},
        "MALFORMED", "SYNTAX_ERROR", "ERROR",
        "Query supplies a string literal where Int is required."
    )
    add_case(
        "CORPUS-106", "Empty query document string",
        "MALFORMED_SYNTAX", "EMPTY_INPUT", 101, "user",
        "", {},
        "MALFORMED", "SYNTAX_ERROR", "ERROR",
        "Query string is completely empty."
    )
    add_case(
        "CORPUS-107", "Whitespace-only query document",
        "MALFORMED_SYNTAX", "EMPTY_INPUT", 101, "user",
        "   \n\t   \n   ", {},
        "MALFORMED", "SYNTAX_ERROR", "ERROR",
        "Query string consists only of whitespace characters."
    )
    add_case(
        "CORPUS-108", "Comments-only query document",
        "MALFORMED_SYNTAX", "EMPTY_INPUT", 101, "user",
        "# Only comments\n# No GraphQL operations here", {},
        "MALFORMED", "SYNTAX_ERROR", "ERROR",
        "Query string contains comments without an operation definition."
    )
    add_case(
        "CORPUS-109", "Unbound required variable definition",
        "MALFORMED_SYNTAX", "VARIABLE_ERROR", 101, "user",
        "query GetRes($resId: Int!) { resource(id: $resId) { name } }", {},
        "MALFORMED", "SYNTAX_ERROR", "ERROR",
        "Non-null variable $resId is defined in query header but omitted from variables map."
    )

    # =========================================================================
    # 8. EDGE CASES & BOUNDARY CONDITIONS (6 cases)
    # =========================================================================
    add_case(
        "CORPUS-110", "Probe ID boundary zero (Alice -> resource 0)",
        "EDGE_CASE", "BOUNDARY_ID", 101, "user",
        "query { resource(id: 0) { id name } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Alice queries boundary ID 0 (unowned; fails-closed at authorization boundary).",
        target_object_id=0, target_object_type="Resource", true_owner_id=None
    )
    add_case(
        "CORPUS-111", "Probe ID boundary negative (Alice -> resource -1)",
        "EDGE_CASE", "BOUNDARY_ID", 101, "user",
        "query { resource(id: -1) { id name } }", {},
        "VULNERABLE", "DIRECT_BOLA", "DENY",
        "Alice queries negative boundary ID -1 (unowned; fails-closed).",
        target_object_id=-1, target_object_type="Resource", true_owner_id=None
    )
    add_case(
        "CORPUS-112", "Deep nested own hierarchy (Alice -> folder 201 -> children -> children)",
        "EDGE_CASE", "DEEP_TRAVERSAL", 101, "user",
        "query { resource(id: 201) { children { children { id name } } } }", {},
        "BENIGN", "NONE", "ALLOW",
        "Alice navigates deep hierarchy within her legitimately owned project folder.",
        target_object_id=201, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-113", "Multi-fragment reuse on own resource (Alice -> doc 101)",
        "EDGE_CASE", "MULTI_FRAGMENT", 101, "user",
        """
        query { resource(id: 101) { ...F1 ...F2 } }
        fragment F1 on ResourceType { id name }
        fragment F2 on ResourceType { object_type parent_id }
        """, {},
        "BENIGN", "NONE", "ALLOW",
        "Alice uses multiple distinct fragments on her own document.",
        target_object_id=101, target_object_type="Resource", true_owner_id=101
    )
    add_case(
        "CORPUS-114", "Multi-variable query on own nested resource (Alice -> user 101 + doc 101)",
        "EDGE_CASE", "MULTI_VAR", 101, "user",
        "query MyData($uid: Int!, $rid: Int!) { user(id: $uid) { resource(id: $rid) { name } } }",
        {"uid": 101, "rid": 101},
        "BENIGN", "NONE", "ALLOW",
        "Alice binds two variables simultaneously for her own user and document.",
        target_object_id=101, target_object_type="User", true_owner_id=101
    )
    add_case(
        "CORPUS-115", "Multi-variable query on cross-user target (Alice -> user 101 + Bob doc 102)",
        "EDGE_CASE", "MULTI_VAR", 101, "user",
        "query StealData($uid: Int!, $rid: Int!) { user(id: $uid) { resource(id: $rid) { name } } }",
        {"uid": 101, "rid": 102},
        "VULNERABLE", "INDIRECT_BOLA", "DENY",
        "Alice binds her own user ID 101 with Bob's document ID 102 using multiple variables.",
        target_object_id=102, target_object_type="Resource", true_owner_id=102
    )

    return cases


def validate_corpus(cases: List[Dict[str, Any]]) -> None:
    """Strictly validates the corpus schema, uniqueness, and label integrity."""
    seen_ids = set()
    valid_security_labels = {"VULNERABLE", "BENIGN", "MALFORMED"}
    valid_attack_types = {"DIRECT_BOLA", "INDIRECT_BOLA", "NONE", "SYNTAX_ERROR"}
    valid_decisions = {"ALLOW", "DENY", "ERROR"}

    for c in cases:
        case_id = c["id"]
        if case_id in seen_ids:
            raise ValueError(f"Duplicate test case ID: {case_id}")
        seen_ids.add(case_id)

        if c["ground_truth_security"] not in valid_security_labels:
            raise ValueError(f"Invalid security label in {case_id}: {c['ground_truth_security']}")

        if c["ground_truth_attack_type"] not in valid_attack_types:
            raise ValueError(f"Invalid attack type in {case_id}: {c['ground_truth_attack_type']}")

        if c["expected_gateway_decision"] not in valid_decisions:
            raise ValueError(f"Invalid expected decision in {case_id}: {c['expected_gateway_decision']}")

        if not c["query"] and c["category"] != "MALFORMED_SYNTAX":
            raise ValueError(f"Empty query in non-malformed case {case_id}")


def main() -> None:
    corpus = generate_corpus()
    validate_corpus(corpus)

    os.makedirs("data", exist_ok=True)
    out_path = os.path.join("data", "ground_truth_corpus.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(corpus, f, indent=2)

    # Print summary statistics
    total = len(corpus)
    vulnerable_count = sum(1 for c in corpus if c["ground_truth_security"] == "VULNERABLE")
    benign_count = sum(1 for c in corpus if c["ground_truth_security"] == "BENIGN")
    malformed_count = sum(1 for c in corpus if c["ground_truth_security"] == "MALFORMED")

    direct_count = sum(1 for c in corpus if c["ground_truth_attack_type"] == "DIRECT_BOLA")
    indirect_count = sum(1 for c in corpus if c["ground_truth_attack_type"] == "INDIRECT_BOLA")

    print("\n" + "=" * 65)
    print("  GROUND-TRUTH BENCHMARK CORPUS GENERATION SUMMARY (PHASE 6)")
    print("=" * 65)
    print(f"Total Test Cases Generated : {total}")
    print(f"  Vulnerable (Attack Cases): {vulnerable_count}")
    print(f"  Benign (Authorized Cases): {benign_count}")
    print(f"  Malformed (Syntax Errors): {malformed_count}")
    print("-" * 65)
    print(f"Attack Type Breakdown:")
    print(f"  Direct BOLA              : {direct_count}")
    print(f"  Indirect / Nested BOLA   : {indirect_count}")
    print("-" * 65)
    print(f"Output File Saved To       : {out_path}")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    main()
