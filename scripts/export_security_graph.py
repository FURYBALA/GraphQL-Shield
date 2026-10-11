"""
Export GraphQL Security Graph to JSON

Generates a deterministic JSON report of the constructed GraphQL Security Graph G = (V, E)
derived from the active schema.
"""

import os
import sys

# Ensure root directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.graphql.schema import schema
from app.security.security_graph import SecurityGraph


def export_graph(output_path: str = "docs/security_graph.json") -> str:
    """Builds and serializes the Security Graph deterministically to a file."""
    graph = SecurityGraph.from_schema(schema)
    json_str = graph.to_json(indent=2)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(json_str)

    summary = graph.summary()
    print(f"[Security Graph] Successfully exported to {output_path}")
    print(f"  Types: {summary['total_types']} ({summary['types_by_kind']})")
    print(f"  Fields: {summary['total_fields']}")
    print(f"  Edges: {summary['total_edges']} ({summary['edges_by_type']})")
    print(f"  Root Operations: {summary['root_operations']}")
    return output_path


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "docs/security_graph.json"
    export_graph(out)
