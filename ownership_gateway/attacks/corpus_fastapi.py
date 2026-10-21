"""Attack and benign corpus for the second target: the main FastAPI/Strawberry application,
reached through its unprotected /graphql-insecure endpoint (app/graphql/*, seeded by app/seed.py).

This target differs from ClinicHub in the ways that matter for ownership inference: object ids are
Int (not ID), the owner field is ownerId: Int, types are named UserType/ResourceType, it has no node
interface, and UserType.resource(id) lets a caller fetch ANY resource nested under their own profile.

Attacker = bob (uid 102). Victims = alice (uid 101) and charlie (uid 103, an admin, attacked as an object owner).
An attack SUCCEEDS if a victim canary appears in Bob's response, or a mutation changed victim data.
"""

ATTACKER = "bob"
CREDENTIALS = {"alice": "alice123", "bob": "bob123", "charlie": "charlie123"}

# Victim-owned values from the seed data: object names, per-object secret keys and per-user secret tokens.
VICTIM_CANARIES = ["Alice's Secret Note", "Alice's Projects", "Project Alpha Plan", "Project Beta Plan", "Charlie's Admin Log",
                   "sk_live_token_101_101", "sk_live_token_201_101", "sk_live_token_202_101", "sk_live_token_203_101",
                   "sk_live_token_103_103", "tok_secret_user_101", "tok_secret_user_103"]

CONSOLE = {"users": ["bob", "alice", "charlie"], "query": "{ resource(id: 101) { id name secretKey } }"}

ATTACKS = [
    {"id": "F01", "category": "Direct object reference", "title": "Read another user's resource and secret key by ID",
     "body": {"query": "{ resource(id: 101) { id name secretKey } }"}},
    {"id": "F02", "category": "Alias enumeration", "title": "Enumerate 5 foreign resources in one request using aliases",
     "body": {"query": "{ a: resource(id: 101) { name } b: resource(id: 201) { name } c: resource(id: 202) { name } "
                       "d: resource(id: 203) { name } e: resource(id: 103) { name } }"}},
    {"id": "F03", "category": "Query batching", "title": "Batched array of operations targeting other users",
     "body": [{"query": "{ resource(id: 101) { name } }"}, {"query": "{ resource(id: 103) { name } }"},
              {"query": "{ resource(id: 202) { name } }"}]},
    {"id": "F04", "category": "Variables", "title": "Victim ID hidden in GraphQL variables",
     "body": {"query": "query Q($id: Int!) { resource(id: $id) { name secretKey } }", "variables": {"id": 201}}},
    {"id": "F05", "category": "Fragments", "title": "Victim fields requested through a named fragment",
     "body": {"query": "{ resource(id: 103) { ...S } } fragment S on ResourceType { name secretKey }"}},
    {"id": "F06", "category": "Nested traversal", "title": "Pivot from a PUBLIC profile into the victim's resources",
     "body": {"query": "{ user(id: 101) { username resources { name secretKey } } }"}},
    {"id": "F07", "category": "Nested traversal", "title": "Fetch a foreign resource nested under the attacker's OWN profile",
     "body": {"query": "{ user(id: 102) { username resource(id: 101) { name secretKey } } }"}},
    {"id": "F08", "category": "Nested traversal", "title": "Walk a foreign folder's children",
     "body": {"query": "{ resource(id: 201) { children { name secretKey } } }"}},
    {"id": "F09", "category": "Field-level exposure", "title": "Read a private field (secretToken) of a public type",
     "body": {"query": "{ user(id: 101) { username secretToken } }"}},
    {"id": "F10", "category": "Mutation tampering", "title": "Rename another user's resource",
     "body": {"query": 'mutation { updateResource(id: 101, name: "HACKED") { id } }'},
     "verify": {"query": "{ resource(id: 101) { name } }", "tampered": lambda d: (d["resource"] or {}).get("name") == "HACKED"}},
    {"id": "F11", "category": "Mutation tampering", "title": "Transfer another user's resource to the attacker",
     "body": {"query": "mutation { transferOwnership(id: 202, newOwnerId: 102) { id } }"},
     "verify": {"query": "{ resource(id: 202) { ownerId } }", "tampered": lambda d: (d["resource"] or {}).get("ownerId") == 102}},
    {"id": "F12", "category": "Mutation tampering", "title": "Delete another user's resource (Boolean return, no object)",
     "body": {"query": "mutation { deleteResource(id: 203) }"},
     "verify": {"query": "{ resource(id: 203) { id } }", "tampered": lambda d: d["resource"] is None}},
]

BENIGN = [
    {"id": "G01", "title": "Read own resource and its secret key", "user": "bob",
     "body": {"query": "{ resource(id: 102) { name secretKey } }"}, "expect": "sk_live_token_102_102"},
    {"id": "G02", "title": "Own profile with private token and resources", "user": "bob",
     "body": {"query": "{ user(id: 102) { username secretToken resources { name } } }"}, "expect": "tok_secret_user_102"},
    {"id": "G03", "title": "View another user's PUBLIC profile (username/role only)", "user": "bob",
     "body": {"query": "{ user(id: 101) { username role } }"}, "expect": '"alice"'},
    {"id": "G04", "title": "Own resource via fragment + variables", "user": "bob",
     "body": {"query": "query($r: Int!) { resource(id: $r) { ...F } } fragment F on ResourceType { name }", "variables": {"r": 102}},
     "expect": "Bob's Financial Record"},
    {"id": "G05", "title": "Own data with aliases", "user": "bob",
     "body": {"query": "{ a: resource(id: 102) { name } b: user(id: 102) { username } }"}, "expect": "Bob's Financial Record"},
    {"id": "G06", "title": "Rename own resource", "user": "bob",
     "body": {"query": 'mutation { updateResource(id: 102, name: "Bob Renamed") { name } }'}, "expect": "Bob Renamed"},
    {"id": "G07", "title": "Alice walks her own folder's children", "user": "alice",
     "body": {"query": "{ resource(id: 201) { name children { name secretKey } } }"}, "expect": "sk_live_token_202_101"},
    {"id": "G08", "title": "Admin reads any user's resource", "user": "charlie",
     "body": {"query": "{ resource(id: 101) { name } }"}, "expect": "Alice's Secret Note"},
    {"id": "G09", "title": "Admin batch over several users", "user": "charlie",
     "body": [{"query": "{ resource(id: 101) { name } }"}, {"query": "{ resource(id: 102) { name } }"}], "expect": "Bob's Financial Record"},
    {"id": "G10", "title": "Unowned health query", "user": "bob",
     "body": {"query": "{ health { status message } }"}, "expect": "GraphQL API is healthy"},
]
