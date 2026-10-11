# GraphQL Security Graph Model Specification

**Phase:** Phase 2 — GraphQL Security Graph Construction  
**Module:** `app/security/security_graph.py`  
**Research Target:** Authorization-Aware Context-Sensitive Taint Analysis for Direct and Indirect GraphQL BOLA  

---

## 1. Architectural Purpose

The **GraphQL Security Graph** $G = (V, E)$ provides an authoritative, typed, in-memory structural representation of the GraphQL schema. It serves as the foundational topology for subsequent research phases:

1. **Precise Return-Type Resolution:** Replaces brittle naming heuristics (such as `field_name.capitalize()`) with authoritative GraphQL type-system resolution.
2. **Context-Sensitive Navigation Mapping:** Formally distinguishes direct entry points, collection navigations (`ONE_TO_MANY`), and nested field hops (`ONE_TO_ONE`).
3. **Taint Source and Sink Anchoring (Phase 3 & 4):** Provides verified type and argument boundaries where client-supplied parameters can be modeled as taint sources and sensitive attributes as taint sinks.
4. **Cycle-Safe Relationship Traversal:** Enables relationship path discovery without risk of infinite recursion when types reference each other.

---

## 2. Node Taxonomy ($V$)

Nodes in the Security Graph represent GraphQL types, individual fields, and formal arguments. Each node has a globally unique, deterministic identifier format.

### 2.1 `TypeNode` (`type:{type_name}`)
Represents an object type, interface, union, scalar, or enum defined in the schema.

```json
{
  "id": "type:UserType",
  "name": "UserType",
  "kind": "OBJECT",
  "is_root": false,
  "root_operation": null,
  "interfaces": [],
  "fields": ["id", "username", "role", "resources", "resource"],
  "candidate_id_fields": ["id"],
  "description": null
}
```

- **Kinds:** `OBJECT`, `INTERFACE`, `UNION`, `SCALAR`, `ENUM`, `INPUT_OBJECT`.
- **Root Operation Attributes:** Flags root types (`Query`, `Mutation`, `Subscription`) with their associated operation string.
- **Candidate Identifiers:** Identifies field names matching identifier patterns (`id`, `*_id`, `pk`, `uuid`) to assist boundary tracking.

### 2.2 `FieldNode` (`field:{parent_type}.{field_name}`)
Represents a field declaration belonging to a parent type.

```json
{
  "id": "field:UserType.resource",
  "name": "resource",
  "parent_type": "UserType",
  "raw_type": "ResourceType",
  "base_type": "ResourceType",
  "base_kind": "OBJECT",
  "is_list": false,
  "list_depth": 0,
  "is_non_null": false,
  "is_base_non_null": false,
  "has_id_argument": true,
  "is_identifier_candidate": false,
  "arguments": {
    "id": {
      "name": "id",
      "raw_type": "Int!",
      "base_type": "Int",
      "is_required": true,
      "is_list": false,
      "default_value": null,
      "is_identifier_candidate": true
    }
  }
}
```

- **Type Unwrapping:** Unwraps arbitrary nestings of `GraphQLNonNull` and `GraphQLList` wrappers into primitive traits:
  - `raw_type`: Exact GraphQL syntax string, e.g., `[ResourceType!]!`.
  - `base_type`: Name of the inner core type, e.g., `ResourceType`.
  - `list_depth`: Depth of list nesting (`0` for scalars/objects, `1` for `[T]`, `2` for `[[T]]`).
  - `is_non_null`: Boolean indicating if top-level value is non-nullable.
  - `is_base_non_null`: Boolean indicating if the inner element is non-nullable.

### 2.3 `ArgumentNode`
Represents an argument declared on a field. Stored within `FieldNode.arguments`.
- Captures argument type signature, unwrapped base type, nullability/requirement, and identifier candidacy.

---

## 3. Edge Taxonomy ($E$)

Edges in the Security Graph capture directed structural relationships:

| Edge Type | Source Node | Target Node | Semantics |
|---|---|---|---|
| `DEFINES_FIELD` | `TypeNode` | `FieldNode` | Containment: parent type declares this field. |
| `RETURNS_TYPE` | `FieldNode` | `TypeNode` | Field return typing: field returns an instance/collection of target type. |
| `NAVIGATES_TO` | `TypeNode` | `TypeNode` | High-level relationship: parent type navigates to target object type via a named field. |
| `IMPLEMENTS` | `TypeNode` (Object) | `TypeNode` (Interface) | Type inheritance: object type implements an interface. |
| `UNRESOLVED_RELATIONSHIP` | `FieldNode` | Missing `TypeNode` | Fail-closed marker: field references a type not registered in the schema. |

### Navigation Edge Metadata
`NAVIGATES_TO` edges carry operational metadata to facilitate taint and boundary analysis:
- `cardinality`: `ONE_TO_ONE` or `ONE_TO_MANY`.
- `via_field`: ID of the field enabling the navigation.
- `is_collection`: True if return type is wrapped in a List.
- `requires_arguments`: True if any field argument is required (`non-null`).
- `has_id_argument`: True if an argument matches candidate identifier heuristics (`id`, `Int!`, etc.).

---

## 4. Formal Return-Type Resolution Algorithm

To completely eliminate string-based inference heuristics (`field_name.capitalize()`), return type resolution in the Security Graph executes as follows:

```
Input: parent_type_name, field_name
1. Lookup field_id = "field:{parent_type_name}.{field_name}" in SecurityGraph.fields.
2. If field_id does not exist:
     Return None (Unresolvable / Schema violation).
3. Extract field_node.base_type.
4. Lookup base_type in SecurityGraph.types.
5. If type_node does not exist:
     Log UnresolvedRelationship and Return None (Fail Closed).
6. Return type_node.
```

**Verification:** In the active schema:
- `resolve_field_return_type("Query", "resource")` -> `TypeNode(name="ResourceType")`
- `resolve_field_return_type("UserType", "resources")` -> `TypeNode(name="ResourceType")`
- `resolve_field_return_type("UserType", "resource")` -> `TypeNode(name="ResourceType")`
- `resolve_field_return_type("ResourceType", "children")` -> `TypeNode(name="ResourceType")`

---

## 5. Cycle Safety & Traversal Guarantees

In real-world GraphQL schemas, types frequently reference each other circularly:
- `User` references `[Resource]`, which references `User` (`owner`).
- `Resource` references `[Resource]` (`children`).
- `User` references `[User]` (`friends`).

### Handling in SecurityGraph
- **Storage:** Stored as an adjacency graph using node IDs. No nested Python object references exist, avoiding `RecursionError` during construction or JSON dumping.
- **Path Search (`find_navigation_paths`):** Implements Depth-First Search (DFS) equipped with a branch-local `visited_types` set. If a branch encounters a type already present in the active path, traversal stops or records target arrival without looping infinitely.

---

## 6. Concrete Example on the Active Application Schema

### Schema Overview
```graphql
type Query {
  health: HealthCheckType!
  user(id: Int!): UserType
  resource(id: Int!): ResourceType
}

type UserType {
  id: Int!
  username: String!
  role: String!
  resources: [ResourceType!]!
  resource(id: Int!): ResourceType
}

type ResourceType {
  id: Int!
  name: String!
  owner_id: Int!
  object_type: String!
  parent_id: Int
  children: [ResourceType!]!
}

type HealthCheckType {
  status: String!
  message: String!
}
```

### Generated Graph Topology
- **Types:** 7 total (`Query`, `UserType`, `ResourceType`, `HealthCheckType`, `Int`, `String`, `Boolean`).
- **Fields:** 16 total.
- **Edges:** 38 total:
  - 16 `DEFINES_FIELD` edges.
  - 16 `RETURNS_TYPE` edges.
  - 6 `NAVIGATES_TO` edges:
    - `Query -> HealthCheckType` via `health` (`ONE_TO_ONE`)
    - `Query -> UserType` via `user` (`ONE_TO_ONE`, requires `id: Int!`)
    - `Query -> ResourceType` via `resource` (`ONE_TO_ONE`, requires `id: Int!`)
    - `UserType -> ResourceType` via `resources` (`ONE_TO_MANY`, unparameterized)
    - `UserType -> ResourceType` via `resource` (`ONE_TO_ONE`, requires `id: Int!`)
    - `ResourceType -> ResourceType` via `children` (`ONE_TO_MANY`, unparameterized self-loop)

### Navigation Paths Discovered from `Query` to `ResourceType`:
1. **Direct Path:** `Query -> resource(id) -> ResourceType`
2. **Indirect Unparameterized Path:** `Query -> user(id) -> UserType -> resources -> ResourceType`
3. **Indirect Parameterized Path:** `Query -> user(id) -> UserType -> resource(id) -> ResourceType`

Notice Path 2: This path exposes the **indirect BOLA vulnerability** identified in Phase 1 where child collections can be traversed without field arguments!

---

## 7. Inspection APIs

### Python API
```python
from app.security.security_graph import get_security_graph

graph = get_security_graph()
print(graph.summary())
target_node = graph.resolve_field_return_type("UserType", "resources")
paths = graph.find_navigation_paths("Query", "ResourceType")
```

### JSON Export CLI
```powershell
python scripts/export_security_graph.py docs/security_graph.json
```

### Admin HTTP Inspection Endpoint
```http
GET /api/v1/security/security-graph HTTP/1.1
Authorization: Bearer <ADMIN_JWT_TOKEN>
```
Returns HTTP 200 with the full deterministic JSON graph specification. Returns HTTP 403 for non-admin users.

---

## 8. Assumptions & Limitations

1. **Static Schema Topology:** The Security Graph reflects compile-time schema definitions. It models what fields *can* return, not the runtime database instance counts.
2. **Dynamic Directives:** Runtime directives such as `@skip` or `@include` conditionally alter execution paths at request time; the Security Graph retains the superset of possible structural edges.
3. **Identifier Candidacy:** Marking a field as `is_identifier_candidate` indicates structural candidacy (name/type), not guaranteed security authorization boundaries (which are handled in Phase 4).
