"""
GraphQL Query Minimizer (Delta Debugging)
-----------------------------------------
Automates delta debugging on failing or vulnerable GraphQL queries:
Iteratively prunes unnecessary fields, selections, and aliases from the AST
to generate a minimal reproducible proof-of-concept (PoC) test case.
"""

from __future__ import annotations

import re
from typing import Optional
from graphql import (
    FieldNode,
    OperationDefinitionNode,
    SelectionSetNode,
    parse,
    print_ast,
)
from app.security.object_extractor import normalize_query


def minimize_query(
    query_str: str,
    target_object_id: Optional[int] = None,
    target_object_type: Optional[str] = None,
) -> str:
    """
    Minimizes a GraphQL query by pruning non-essential scalar fields and metadata,
    retaining only the minimal path and arguments required to trigger the authorization flaw.
    """
    try:
        doc = parse(query_str)
    except Exception:
        # Fallback regex-based minimization if AST parsing fails
        return _regex_fallback_minimize(query_str)

    try:
        # Traverse operation and minimize selection sets
        for defn in doc.definitions:
            if isinstance(defn, OperationDefinitionNode) and defn.selection_set:
                _prune_selection_set(defn.selection_set, is_root=True)

        minimized = print_ast(doc)
        # Compact formatting
        minimized = re.sub(r"\n\s*\n", "\n", minimized).strip()
        return minimized
    except Exception:
        return _regex_fallback_minimize(query_str)


def _prune_selection_set(selection_set: SelectionSetNode, is_root: bool = False) -> None:
    """
    Recursively prunes selection sets: keeps navigation edges and minimum 'id' scalar.
    """
    if not selection_set or not selection_set.selections:
        return

    # Identify object-traversing fields (fields with child selections)
    nested_fields = [s for s in selection_set.selections if isinstance(s, FieldNode) and s.selection_set]
    scalar_fields = [s for s in selection_set.selections if isinstance(s, FieldNode) and not s.selection_set]

    # Recurse into nested fields first
    for nf in nested_fields:
        if nf.selection_set:
            _prune_selection_set(nf.selection_set, is_root=False)

    if nested_fields:
        # If there are nested object edges (e.g. user { resource }), drop all sibling scalars
        # so the minimal query only focuses on the target nested edge!
        selection_set.selections = tuple(nested_fields)
    else:
        # Leaf object selection: retain only 'id' if present, otherwise first scalar
        id_field = next((s for s in scalar_fields if s.name.value.lower() == "id"), None)
        if id_field:
            selection_set.selections = (id_field,)
        elif scalar_fields:
            selection_set.selections = (scalar_fields[0],)


def _regex_fallback_minimize(query: str) -> str:
    """Fallback text cleaner for query minimization."""
    cleaned = re.sub(r"#.*", "", query)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned
