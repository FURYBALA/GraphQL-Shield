from typing import Optional, Tuple
from graphql import (
    parse,
    DocumentNode,
    FieldNode,
    OperationDefinitionNode,
    FragmentDefinitionNode,
    InlineFragmentNode,
    FragmentSpreadNode,
)

_PARSED_CACHE = {}
_MAX_CACHE_SIZE = 512

def parse_query(query: str) -> Optional[DocumentNode]:
    """
    Parses a GraphQL query string into an Abstract Syntax Tree (AST).
    Uses in-memory cache to eliminate redundant parsing on identical query strings.
    Returns None if the query is invalid.
    """
    if not query or not isinstance(query, str):
        return None
    
    if query in _PARSED_CACHE:
        return _PARSED_CACHE[query]
    
    try:
        ast = parse(query)
        if len(_PARSED_CACHE) >= _MAX_CACHE_SIZE:
            _PARSED_CACHE.clear()
        _PARSED_CACHE[query] = ast
        return ast
    except Exception:
        return None

def calculate_ast_depth(node, current_depth: int = 0) -> int:
    """Calculates maximum selection nesting depth of a GraphQL AST."""
    if not node:
        return current_depth
        
    max_d = current_depth
    if hasattr(node, "selection_set") and node.selection_set:
        for selection in node.selection_set.selections:
            d = calculate_ast_depth(selection, current_depth + (1 if isinstance(selection, FieldNode) else 0))
            if d > max_d:
                max_d = d
    elif isinstance(node, DocumentNode):
        for defn in node.definitions:
            d = calculate_ast_depth(defn, 0)
            if d > max_d:
                max_d = d
    return max_d

def calculate_ast_complexity(node) -> int:
    """Calculates query complexity score by summing field selections with relation weighting."""
    if not node:
        return 0
    complexity = 0
    if hasattr(node, "selection_set") and node.selection_set:
        for selection in node.selection_set.selections:
            if isinstance(selection, FieldNode):
                weight = 5 if selection.selection_set else 1
                complexity += weight + calculate_ast_complexity(selection)
            elif isinstance(selection, (InlineFragmentNode, FragmentSpreadNode)):
                complexity += calculate_ast_complexity(selection)
    elif isinstance(node, DocumentNode):
        for defn in node.definitions:
            complexity += calculate_ast_complexity(defn)
    return complexity

def validate_query_budget(query: str, max_depth: int = 15, max_complexity: int = 150) -> Tuple[bool, Optional[str], int, int]:
    """
    Enforces AST depth and complexity budgets to mitigate Denial of Service (DoS) attacks.
    Returns (is_valid, error_reason, depth, complexity).
    """
    ast = parse_query(query)
    if not ast:
        return True, None, 0, 0
        
    depth = calculate_ast_depth(ast)
    complexity = calculate_ast_complexity(ast)
    
    if depth > max_depth:
        return False, f"QUERY_DEPTH_EXCEEDED: Maximum permitted depth is {max_depth}, got {depth}.", depth, complexity
    if complexity > max_complexity:
        return False, f"QUERY_COMPLEXITY_EXCEEDED: Maximum permitted complexity is {max_complexity}, got {complexity}.", depth, complexity
        
    return True, None, depth, complexity
