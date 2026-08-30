import requests
import json

base_url = "http://localhost:8000"

print("1. Testing login...")
r = requests.post(f"{base_url}/login", data={"email": "alice@example.com", "password": "alice123"})
assert r.status_code == 200
token = r.json()["access_token"]
print("Token:", token)

print("\n2. Testing GraphQL ALLOW (Object 501)...")
headers = {"Authorization": f"Bearer {token}"}
query = """
query GetObject($id: Int!) {
  object(id: $id) {
    id
    name
    owner_id
    data
  }
}
"""
payload = {"query": query, "variables": {"id": 501}}
r2 = requests.post(f"{base_url}/graphql", json=payload, headers=headers)
print("Status:", r2.status_code)
print("Response:", r2.json())
assert r2.status_code == 200

print("\n3. Testing GraphQL BLOCK (Object 601)...")
payload3 = {"query": query, "variables": {"id": 601}}
r3 = requests.post(f"{base_url}/graphql", json=payload3, headers=headers)
print("Status:", r3.status_code)
print("Response:", r3.json())
assert r3.status_code == 403

print("\n4. Testing Audit Logs...")
r4 = requests.get(f"{base_url}/logs")
print("Logs:", json.dumps(r4.json(), indent=2))
assert len(r4.json()) >= 2

print("\nALL TESTS PASSED!")
