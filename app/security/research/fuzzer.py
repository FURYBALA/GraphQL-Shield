"""
CCNS Research Lab - Synthetic Adversarial Query Fuzzer
======================================================
Automated programmatic query mutation engine for stress-testing GraphQL
authorization defenses, static taint propagation, and AST path correlation.

Generates 5 distinct adversarial mutation classes:
1. ALIAS_INDIRECT: Generates unique client aliases to confuse naive path matchers.
2. VARIABLE_INDIRECTION: Injects dynamic GraphQL variables with default or bound arguments.
3. FRAGMENT_ENCAPSULATION: Wraps object targets into nested inline and named fragments.
4. DIRECTIVE_COMPLEXITY: Injects transparent conditional directives (@include(if: true)).
5. WHITESPACE_OBFUSCATION: Injects comment tokens and variable casing to test parser robustness.
"""

from __future__ import annotations
import random
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel

class FuzzedVariant(BaseModel):
    original_query: str
    fuzzed_query: str
    mutation_class: str
    injected_aliases: List[str]
    injected_variables: Dict[str, Any]


class AdversarialFuzzingReport(BaseModel):
    total_variants_generated: int
    by_mutation_class: Dict[str, int]
    static_taint_robustness_pct: float
    correlated_defense_robustness_pct: float
    path_attribution_exact_match_pct: float
    summary: str


class SyntheticQueryFuzzer:
    """Generates deterministic adversarial GraphQL query mutations."""

    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)

    def apply_alias_mutation(self, query: str) -> FuzzedVariant:
        """Injects client aliases on target selection fields (e.g. res_alias_123: resource)."""
        aliases = []
        def _alias_sub(match):
            field = match.group(1)
            alias = f"adv_alias_{self.rng.randint(100, 999)}"
            aliases.append(alias)
            return f"{alias}: {field}("

        fuzzed = re.sub(r'\b(resource|document|user)\s*\(', _alias_sub, query)
        return FuzzedVariant(
            original_query=query,
            fuzzed_query=fuzzed,
            mutation_class="ALIAS_INDIRECT",
            injected_aliases=aliases,
            injected_variables={}
        )

    def apply_variable_indirection(self, query: str, target_id: int = 101) -> FuzzedVariant:
        """Converts literal IDs into dynamic query variables."""
        var_name = f"var_obj_{self.rng.randint(10, 99)}"
        # Check if already has query header
        if "query" in query.lower():
            fuzzed = re.sub(r'id:\s*\d+', f'id: ${var_name}', query)
            fuzzed = re.sub(r'query\s*(\w*)\s*(\([^)]*\))?', f'query AdvOp(${var_name}: Int = {target_id})', fuzzed, count=1)
        else:
            fuzzed = re.sub(r'id:\s*\d+', f'id: ${var_name}', query)
            fuzzed = f"query AdvOp(${var_name}: Int = {target_id}) {{\n{fuzzed}\n}}"

        return FuzzedVariant(
            original_query=query,
            fuzzed_query=fuzzed,
            mutation_class="VARIABLE_INDIRECTION",
            injected_aliases=[],
            injected_variables={var_name: target_id}
        )

    def apply_fragment_encapsulation(self, query: str) -> FuzzedVariant:
        """Wraps inner fields into an inline fragment (... on Resource { ... })."""
        frag_type = "Resource" if "resource" in query.lower() else "User"
        # Match inside braces
        fuzzed = re.sub(
            r'\{\s*(id[^{}]*)\}',
            f'{{ ... on {frag_type} {{ \\1 }} }}',
            query
        )
        return FuzzedVariant(
            original_query=query,
            fuzzed_query=fuzzed,
            mutation_class="FRAGMENT_ENCAPSULATION",
            injected_aliases=[],
            injected_variables={}
        )

    def apply_directive_complexity(self, query: str) -> FuzzedVariant:
        """Injects non-filtering directives @include(if: true) into field selections."""
        fuzzed = re.sub(
            r'\{\s*(id|name|title)\b',
            r'{\1 @include(if: true)',
            query,
            count=1
        )
        return FuzzedVariant(
            original_query=query,
            fuzzed_query=fuzzed,
            mutation_class="DIRECTIVE_COMPLEXITY",
            injected_aliases=[],
            injected_variables={}
        )

    def apply_whitespace_obfuscation(self, query: str) -> FuzzedVariant:
        """Injects comments and arbitrary line wrapping to test scanner resilience."""
        comment = f"# [ADVERSARIAL_NOISE_TOKEN_{self.rng.randint(1000, 9999)}]\n"
        fuzzed = comment + query.replace("{", "{\n  " + comment).replace("}", "\n}\n")
        return FuzzedVariant(
            original_query=query,
            fuzzed_query=fuzzed,
            mutation_class="WHITESPACE_OBFUSCATION",
            injected_aliases=[],
            injected_variables={}
        )

    def generate_fuzzed_suite(self, base_queries: List[str]) -> List[FuzzedVariant]:
        """Generates all 5 mutation classes across supplied base queries."""
        variants = []
        for q in base_queries:
            variants.append(self.apply_alias_mutation(q))
            variants.append(self.apply_variable_indirection(q))
            variants.append(self.apply_fragment_encapsulation(q))
            variants.append(self.apply_directive_complexity(q))
            variants.append(self.apply_whitespace_obfuscation(q))
        return variants


def run_adversarial_fuzzing_evaluation(sample_queries: Optional[List[str]] = None) -> AdversarialFuzzingReport:
    """Executes a complete synthetic fuzzing stress test against the security engine."""
    from app.security.object_extractor import normalize_query
    from app.security.taint_engine import analyze_query_taint

    queries = sample_queries or [
        "query { resource(id: 101) { id name secret_key } }",
        "query { resource(id: 102) { id name } }",
        "query { user(id: 1) { id username secret_token } }"
    ]

    fuzzer = SyntheticQueryFuzzer(seed=42)
    variants = fuzzer.generate_fuzzed_suite(queries)

    static_success = 0
    correlated_success = 0
    path_exact_matches = 0
    by_class: Dict[str, int] = {}

    for var in variants:
        by_class[var.mutation_class] = by_class.get(var.mutation_class, 0) + 1

        # Evaluate Static Taint Engine
        try:
            report = analyze_query_taint(var.fuzzed_query, variables=var.injected_variables)
            if report.is_valid_query:
                static_success += 1
        except Exception:
            pass

        # Evaluate Object Extractor & Path Correlation
        try:
            norm = normalize_query(var.fuzzed_query, variables=var.injected_variables)
            if norm and norm.get("objects"):
                correlated_success += 1
                # If alias was injected, verify response_path matches injected alias
                if var.injected_aliases:
                    obj = norm["objects"][0]
                    if obj.get("alias") in var.injected_aliases:
                        path_exact_matches += 1
                else:
                    path_exact_matches += 1
        except Exception:
            pass

    total = len(variants)
    return AdversarialFuzzingReport(
        total_variants_generated=total,
        by_mutation_class=by_class,
        static_taint_robustness_pct=round((static_success / total) * 100, 1) if total else 0.0,
        correlated_defense_robustness_pct=round((correlated_success / total) * 100, 1) if total else 0.0,
        path_attribution_exact_match_pct=round((path_exact_matches / total) * 100, 1) if total else 0.0,
        summary=f"Synthesized {total} adversarial variants across 5 mutation classes. Correlated defense maintained {round((correlated_success/total)*100, 1)}% extraction resilience under obfuscation."
    )


def mutate_single_query(query: str, target_id: int = 101) -> List[Dict[str, Any]]:
    """Mutates a single GraphQL query across all 5 adversarial classes with metadata."""
    fuzzer = SyntheticQueryFuzzer(seed=random.randint(1, 10000))
    explanations = {
        "ALIAS_INDIRECT": (
            "Field Aliasing",
            "Prefixes root and child selections with synthetic client aliases (e.g. adv_alias_xxx: resource). "
            "Attempts to bypass naive path matchers that expect exact schema field names in JSON response trees."
        ),
        "VARIABLE_INDIRECTION": (
            "Variable Indirection",
            "Extracts literal object IDs into dynamic operation variables ($var_obj_xx). "
            "Tests whether the authorization gateway correctly resolves AST variable definitions rather than only literal arguments."
        ),
        "FRAGMENT_ENCAPSULATION": (
            "Inline Fragment Encapsulation",
            "Wraps field selections in typed inline fragments (... on Type { ... }). "
            "Verifies that AST traversal and taint tracking navigate through FragmentSpread and InlineFragment AST nodes."
        ),
        "DIRECTIVE_COMPLEXITY": (
            "Conditional Directive Injection",
            "Applies @include(if: true) directives to target fields. "
            "Tests directive-aware pruning to ensure active selections remain guarded while bypassed fields are pruned."
        ),
        "WHITESPACE_OBFUSCATION": (
            "Syntactic Noise & Comments",
            "Injects adversarial comments (# [ADVERSARIAL_NOISE]) and irregular spacing. "
            "Tests lexer and scanner resilience against regex-based or token-splitting bypasses."
        ),
    }

    variants = [
        fuzzer.apply_alias_mutation(query),
        fuzzer.apply_variable_indirection(query, target_id=target_id),
        fuzzer.apply_fragment_encapsulation(query),
        fuzzer.apply_directive_complexity(query),
        fuzzer.apply_whitespace_obfuscation(query),
    ]

    result = []
    for v in variants:
        title, desc = explanations.get(v.mutation_class, (v.mutation_class, "Adversarial mutation."))
        result.append({
            "mutation_class": v.mutation_class,
            "title": title,
            "description": desc,
            "fuzzed_query": v.fuzzed_query,
            "variables": v.injected_variables,
            "aliases": v.injected_aliases,
        })
    return result
