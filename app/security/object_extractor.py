from graphql import (
    FieldNode,
    VariableNode,
    IntValueNode,
    StringValueNode,
    BooleanValueNode,
    OperationDefinitionNode,
    FragmentSpreadNode,
    FragmentDefinitionNode,
    InlineFragmentNode,
)
from .graphql_parser import parse_query

MAX_AST_DEPTH = 25

def normalize_query(query: str, variables: dict = None) -> dict | None:
    """
    Analyzes GraphQL queries to identify operation type, fields, object IDs, and paths.
    Supports variables, nested queries, named fragments with cycle detection, inline fragments,
    and directive-aware pruning (@skip and @include).
    
    Returns a normalized internal representation, e.g.:
    {
      "operation": "query",
      "objects": [
        {
          "type": "User",
          "id": 102,
          "path": "user"
        }
      ]
    }
    """
    ast = parse_query(query)
    if not ast:
        return None
        
    variables = variables or {}
    result = {
        "operation": None,
        "objects": []
    }
    
    fragments = {}
    
    # Pass 1: Collect fragments
    for definition in ast.definitions:
        if isinstance(definition, FragmentDefinitionNode):
            fragments[definition.name.value] = definition
            
    # Pass 2: Traverse operations and extract objects
    for definition in ast.definitions:
        if isinstance(definition, OperationDefinitionNode):
            result["operation"] = definition.operation.value
            
            # Resolve effective variable values: explicit variables override AST default values
            effective_vars = dict(variables) if variables else {}
            if definition.variable_definitions:
                for var_def in definition.variable_definitions:
                    var_name = var_def.variable.name.value
                    if var_name not in effective_vars and var_def.default_value is not None:
                        if isinstance(var_def.default_value, (IntValueNode, StringValueNode, BooleanValueNode)):
                            effective_vars[var_name] = var_def.default_value.value

            def visit(node, current_path, visited_fragments=None, depth=0, current_resp_path=""):
                if depth > MAX_AST_DEPTH:
                    return

                if isinstance(node, FieldNode):
                    # Directive-aware pruning: evaluate @skip and @include
                    if node.directives:
                        skip_field = False
                        for directive in node.directives:
                            d_name = directive.name.value
                            val = None
                            for arg in directive.arguments:
                                if arg.name.value == "if":
                                    if isinstance(arg.value, VariableNode):
                                        val = effective_vars.get(arg.value.name.value)
                                    elif hasattr(arg.value, "value"):
                                        val = arg.value.value
                            if d_name == "skip" and val is True:
                                skip_field = True
                                break
                            elif d_name == "include" and val is False:
                                skip_field = True
                                break
                        if skip_field:
                            return

                    field_name = node.name.value
                    alias_name = node.alias.value if node.alias else None
                    resp_name = alias_name if alias_name else field_name

                    path = f"{current_path}.{field_name}" if current_path else field_name
                    resp_path = f"{current_resp_path}.{resp_name}" if current_resp_path else resp_name
                    
                    obj_id = None
                    for arg in node.arguments:
                        if arg.name.value == "id":
                            if isinstance(arg.value, VariableNode):
                                var_name = arg.value.name.value
                                obj_id = effective_vars.get(var_name)
                            elif isinstance(arg.value, (IntValueNode, StringValueNode)):
                                obj_id = arg.value.value
                                
                    if obj_id is not None:
                        try:
                            obj_id = int(obj_id)
                        except (ValueError, TypeError):
                            pass
                            
                        # Infer object type: strip mutation prefixes if present
                        clean_name = field_name
                        for prefix in ("update_", "delete_", "transfer_", "update", "delete", "transfer"):
                            if clean_name.lower().startswith(prefix) and len(clean_name) > len(prefix):
                                clean_name = clean_name[len(prefix):]
                                break

                        if clean_name.lower() in ("ownership", "resource", "document", "folder", "object"):
                            inferred_type = "Resource"
                        elif clean_name.lower() == "user":
                            inferred_type = "User"
                        else:
                            inferred_type = clean_name.capitalize()

                        has_sensitive_field = False
                        if node.selection_set:
                            for sel in node.selection_set.selections:
                                if isinstance(sel, FieldNode) and sel.name.value in (
                                    "secret_key", "secretKey", "secret_token", "secretToken", "apiKey", "api_key"
                                ):
                                    has_sensitive_field = True

                        result["objects"].append({
                            "type": inferred_type,
                            "id": obj_id,
                            "path": path,
                            "alias": alias_name,
                            "response_path": resp_path,
                            "has_sensitive_field": has_sensitive_field,
                        })
                        
                    if node.selection_set:
                        for selection in node.selection_set.selections:
                            visit(selection, path, visited_fragments, depth + 1, resp_path)
                            
                elif isinstance(node, FragmentSpreadNode):
                    frag_name = node.name.value
                    # Cycle detection: guard against circular fragment definitions
                    active_fragments = set(visited_fragments or set())
                    if frag_name in active_fragments:
                        return
                    active_fragments.add(frag_name)

                    if frag_name in fragments:
                        fragment = fragments[frag_name]
                        if fragment.selection_set:
                            for selection in fragment.selection_set.selections:
                                visit(selection, current_path, active_fragments, depth + 1, current_resp_path)

                elif isinstance(node, InlineFragmentNode):
                    # Handle inline fragments (... on Type { ... })
                    if node.selection_set:
                        for selection in node.selection_set.selections:
                            visit(selection, current_path, visited_fragments, depth + 1, current_resp_path)

            if definition.selection_set:
                for selection in definition.selection_set.selections:
                    visit(selection, "", None, 0, "")
                    
    return result

def extract_resource_id(query: str, variables: dict = None) -> int | None:
    """Backward compatibility helper to find the first Resource ID."""
    normalized = normalize_query(query, variables)
    if not normalized:
        return None
        
    for obj in normalized["objects"]:
        if obj["type"].lower() == "resource":
            return obj["id"]
            
    return None
