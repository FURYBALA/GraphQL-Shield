"""
Schema-Aware Ownership Inference Engine

Analyzes the Strawberry GraphQL schema ONCE at application startup in order to
discover candidate ownership relationships between object types.

The engine is deliberately conservative and explainable:

  Priority order
    1. Explicit authorization / ownership rules (configured or database truth)
    2. Validated schema-inferred ownership rule (this module)
    3. UNKNOWN OWNERSHIP -> explicit policy required -> DENY (fail-closed)

The engine NEVER grants access by itself. It produces inspectable candidate
rules that the ownership resolution layer and the policy engine can consult,
and it never overrides an explicit rule.

Supported inference patterns
    OWNER_FIELD     Resource.owner -> User            (object reference)
                    Resource.ownerId -> User          (scalar identifier)
    COLLECTION      User.resources -> Resource        (collection of owned objects)
    SELF_OWNERSHIP  User owns its own record

Every rule carries a confidence level and a human readable reason so that the
inference can be audited (see GET /api/v1/security/schema-ownership).
"""

import re
import time
from dataclasses import dataclass, field as dataclass_field
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Configurable naming patterns (matched against snake_cased field names)
# ---------------------------------------------------------------------------

OWNERSHIP_FIELD_PATTERNS = [
    "owner",
    "owner_id",
    "ownerid",
    "user",
    "user_id",
    "userid",
    "created_by",
    "created_by_id",
    "createdby",
    "createdbyid",
    "author",
    "author_id",
    "authorid",
]

COLLECTION_FIELD_PATTERNS = [
    "resources",
    "objects",
    "items",
    "posts",
    "orders",
    "documents",
    "files",
    "entries",
]

# Types that represent the "owner" entity when a scalar ownership id is found
USER_TYPE_PATTERNS = ["user", "usertype", "account", "member", "person", "profile"]

# Root operation types are API entry points, not domain objects
ROOT_TYPE_NAMES = {"query", "mutation", "subscription"}

_SCALAR_NAMES = {"int", "id", "string", "boolean", "float"}

_PYTHON_SCALARS = {
    int: "Int",
    str: "String",
    bool: "Boolean",
    float: "Float",
}

_CONFIDENCE_ORDER = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "EXPLICIT": 4}

_TYPE_SUFFIXES = ("type", "node", "entity", "model", "dto", "object")


def normalize_field_name(name: str) -> str:
    """camelCase / PascalCase / snake_case -> snake_case (lowercase)."""
    step = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    step = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", step)
    return step.lower()


def normalize_type_name(name: str) -> str:
    """
    Normalizes type names so that 'Resource' (query field derived type) and
    'ResourceType' (schema type) resolve to the same identity.
    """
    cleaned = re.sub(r"[^a-z0-9]", "", (name or "").lower())
    if not cleaned:
        return ""
    for suffix in _TYPE_SUFFIXES:
        if cleaned.endswith(suffix) and len(cleaned) > len(suffix):
            stripped = cleaned[: -len(suffix)]
            if stripped:
                return stripped
    return cleaned


def is_user_type(type_name: str) -> bool:
    normalized = normalize_type_name(type_name)
    return any(normalize_type_name(p) == normalized for p in USER_TYPE_PATTERNS)


@dataclass
class OwnershipRule:
    """A single ownership relationship (inferred or explicitly configured)."""

    source_type: str
    source_field: str
    target_type: str
    owner_field: str
    confidence: str  # HIGH, MEDIUM, LOW
    inference_reason: str
    pattern: str  # OWNER_FIELD, COLLECTION, SELF_OWNERSHIP
    source: str = "INFERRED"  # INFERRED or EXPLICIT

    def to_dict(self) -> dict:
        return {
            "source_type": self.source_type,
            "source_field": self.source_field,
            "target_type": self.target_type,
            "owner_field": self.owner_field,
            "confidence": self.confidence,
            "pattern": self.pattern,
            "source": self.source,
            "reason": self.inference_reason,
        }


@dataclass
class RejectedRelationship:
    """A relationship that was inspected but NOT accepted as ownership."""

    source_type: str
    source_field: str
    observed_type: str
    reason: str
    category: str  # AMBIGUOUS, UNSUPPORTED, UNKNOWN_TARGET

    def to_dict(self) -> dict:
        return {
            "source_type": self.source_type,
            "source_field": self.source_field,
            "observed_type": self.observed_type,
            "category": self.category,
            "reason": self.reason,
        }


@dataclass
class InferenceReport:
    """Summary of a single schema analysis run."""

    types_analyzed: int = 0
    relationships_detected: int = 0
    high_confidence: int = 0
    medium_confidence: int = 0
    low_confidence: int = 0
    ambiguous: int = 0
    analyzed_types: List[str] = dataclass_field(default_factory=list)
    rules: List[OwnershipRule] = dataclass_field(default_factory=list)
    rejected: List[RejectedRelationship] = dataclass_field(default_factory=list)
    analysis_time_ms: float = 0.0


class OwnershipInferenceEngine:
    """
    Builds an internal, read-only ownership model from the GraphQL schema.

    The model is built once (startup or first use) and is then only read,
    which keeps request processing free of repeated schema analysis.
    """

    def __init__(self):
        self._rules: List[OwnershipRule] = []
        self._explicit_rules: List[OwnershipRule] = []
        self._report: Optional[InferenceReport] = None
        self._built = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def rules(self) -> List[OwnershipRule]:
        return list(self._rules)

    @property
    def explicit_rules(self) -> List[OwnershipRule]:
        return list(self._explicit_rules)

    @property
    def report(self) -> Optional[InferenceReport]:
        return self._report

    @property
    def is_built(self) -> bool:
        return self._built

    def build_from_strawberry_schema(self, schema) -> InferenceReport:
        """
        Analyze a strawberry.Schema once and populate the ownership model.
        Subsequent calls are no-ops and return the cached report.
        """
        if self._built:
            return self._report

        start = time.perf_counter()
        report = InferenceReport()

        type_map = self._collect_types(schema)
        report.types_analyzed = len(type_map)
        report.analyzed_types = sorted(type_map.keys())

        for type_name, fields in type_map.items():
            self._analyze_type(type_name, fields, type_map, report)

        report.analysis_time_ms = round((time.perf_counter() - start) * 1000, 3)
        report.relationships_detected = len(report.rules)
        report.high_confidence = sum(1 for r in report.rules if r.confidence == "HIGH")
        report.medium_confidence = sum(1 for r in report.rules if r.confidence == "MEDIUM")
        report.low_confidence = sum(1 for r in report.rules if r.confidence == "LOW")
        report.ambiguous = len(report.rejected)

        self._rules = report.rules
        self._report = report
        self._built = True
        return report

    def add_explicit_rule(self, rule: OwnershipRule) -> None:
        """
        Register an explicitly configured ownership rule.
        Explicit rules always take precedence over inferred rules.
        """
        rule.source = "EXPLICIT"
        self._explicit_rules.append(rule)

    def get_owner_type_for(self, object_type: str) -> Optional[OwnershipRule]:
        """
        Return the strongest ownership rule for a type name.

        Precedence: explicit rule > inferred OWNER_FIELD/SELF_OWNERSHIP rule.
        Returns None when nothing matches -> caller must fail closed.
        """
        normalized = normalize_type_name(object_type)

        explicit = [
            r for r in self._explicit_rules
            if normalize_type_name(r.source_type) == normalized
        ]
        if explicit:
            return max(explicit, key=lambda r: _CONFIDENCE_ORDER.get(r.confidence, 0))

        inferred = [
            r for r in self._rules
            if normalize_type_name(r.source_type) == normalized
            and r.pattern in ("OWNER_FIELD", "SELF_OWNERSHIP")
        ]
        if not inferred:
            return None
        return max(inferred, key=lambda r: _CONFIDENCE_ORDER.get(r.confidence, 0))

    def to_dict(self) -> dict:
        """Serialize the report for the debug/inspection endpoint."""
        if not self._report:
            return {"status": "not_analyzed"}

        return {
            "status": "analyzed",
            "types_analyzed": self._report.types_analyzed,
            "analyzed_types": self._report.analyzed_types,
            "relationships_detected": self._report.relationships_detected,
            "high_confidence_rules": self._report.high_confidence,
            "medium_confidence_rules": self._report.medium_confidence,
            "low_confidence_rules": self._report.low_confidence,
            "ambiguous_relationships": self._report.ambiguous,
            "analysis_time_ms": self._report.analysis_time_ms,
            "priority": [
                "1. Explicit configured authorization / ownership rule",
                "2. Validated schema-inferred ownership rule",
                "3. UNKNOWN OWNERSHIP -> explicit policy required -> DENY",
            ],
            "rules": [r.to_dict() for r in self._report.rules],
            "explicit_rules": [r.to_dict() for r in self._explicit_rules],
            "rejected": [r.to_dict() for r in self._report.rejected],
        }

    # ------------------------------------------------------------------
    # Schema introspection
    # ------------------------------------------------------------------

    def _collect_types(self, schema) -> Dict[str, List[Tuple[str, Any]]]:
        """
        Extract concrete object types and their fields from the schema.
        Returns {type_name: [(field_name, field_type), ...]}.
        """
        type_map: Dict[str, List[Tuple[str, Any]]] = {}

        converter = getattr(schema, "schema_converter", None)
        strawberry_type_map = getattr(converter, "type_map", None)
        if strawberry_type_map:
            for name, concrete in strawberry_type_map.items():
                if self._is_root_type(name):
                    continue
                definition = getattr(concrete, "definition", None)
                if definition is None:
                    continue
                if getattr(definition, "is_input", False):
                    continue
                if not (getattr(definition, "is_object_type", False)
                        or getattr(definition, "is_interface", False)):
                    continue
                fields = getattr(definition, "fields", None)
                if not fields:
                    continue
                type_map[definition.name or name] = [
                    (f.name, f.type) for f in fields if getattr(f, "name", None)
                ]
            return type_map

        # Fallback: graphql-core schema (camelCase field names are normalized
        # later by normalize_field_name).
        core_schema = getattr(schema, "_schema", None) or getattr(schema, "schema", None)
        core_type_map = getattr(core_schema, "type_map", None)
        if core_type_map:
            for name, type_def in core_type_map.items():
                if self._is_root_type(name) or name.startswith("__"):
                    continue
                fields = getattr(type_def, "fields", None)
                if not fields:
                    continue
                type_map[name] = list(fields.items())
        return type_map

    @staticmethod
    def _is_root_type(name: str) -> bool:
        return (name or "").lower() in ROOT_TYPE_NAMES

    # ------------------------------------------------------------------
    # Pattern analysis
    # ------------------------------------------------------------------

    def _analyze_type(
        self,
        type_name: str,
        fields: Sequence[Tuple[str, Any]],
        type_map: Dict[str, List[Tuple[str, Any]]],
        report: InferenceReport,
    ) -> None:
        ownership_set = set(OWNERSHIP_FIELD_PATTERNS)
        collection_set = set(COLLECTION_FIELD_PATTERNS)

        for field_name, field_type in fields:
            normalized_field = normalize_field_name(field_name)
            base_type_name = self._resolve_field_type_name(field_type)

            if normalized_field in ownership_set:
                self._analyze_ownership_field(
                    type_name, field_name, normalized_field,
                    base_type_name, type_map, report,
                )
            elif normalized_field in collection_set:
                self._analyze_collection_field(
                    type_name, field_name, base_type_name, type_map, report,
                )

        if is_user_type(type_name):
            report.rules.append(OwnershipRule(
                source_type=type_name,
                source_field="id",
                target_type=type_name,
                owner_field="id",
                confidence="HIGH",
                inference_reason=f"Type {type_name} owns its own record (self-ownership)",
                pattern="SELF_OWNERSHIP",
            ))

    def _analyze_ownership_field(self, type_name, field_name, normalized_field,
                                 base_type_name, type_map, report) -> None:
        if base_type_name and base_type_name in type_map:
            confidence = "HIGH" if is_user_type(base_type_name) else "MEDIUM"
            report.rules.append(OwnershipRule(
                source_type=type_name,
                source_field=field_name,
                target_type=base_type_name,
                owner_field="id",
                confidence=confidence,
                inference_reason=(
                    f"Field '{field_name}' on {type_name} references user type "
                    f"{base_type_name}" if confidence == "HIGH" else
                    f"Field '{field_name}' on {type_name} references type {base_type_name}"
                ),
                pattern="OWNER_FIELD",
            ))
            return

        if base_type_name and base_type_name.lower() in _SCALAR_NAMES:
            if base_type_name.lower() in ("int", "id"):
                user_type = self._find_user_type(type_map)
                confidence = "HIGH" if "owner" in normalized_field else "MEDIUM"
                if user_type is None:
                    confidence = "MEDIUM"
                    reason = (
                        f"Field '{field_name}' on {type_name} is a scalar ownership "
                        f"identifier; no user type present, target assumed to be User"
                    )
                else:
                    reason = (
                        f"Field '{field_name}' on {type_name} is a scalar ownership "
                        f"identifier referencing {user_type}"
                    )
                report.rules.append(OwnershipRule(
                    source_type=type_name,
                    source_field=field_name,
                    target_type=user_type or "User",
                    owner_field="id",
                    confidence=confidence,
                    inference_reason=reason,
                    pattern="OWNER_FIELD",
                ))
                return

            report.rejected.append(RejectedRelationship(
                source_type=type_name,
                source_field=field_name,
                observed_type=base_type_name,
                category="AMBIGUOUS",
                reason=(
                    f"Field '{field_name}' on {type_name} matches an ownership name "
                    f"but is a {base_type_name} value, not an identifier or reference"
                ),
            ))
            return

        report.rejected.append(RejectedRelationship(
            source_type=type_name,
            source_field=field_name,
            observed_type=base_type_name or "unknown",
            category="UNKNOWN_TARGET",
            reason=(
                f"Field '{field_name}' on {type_name} matches an ownership name "
                f"but its type is not part of the analyzed schema"
            ),
        ))

    def _analyze_collection_field(self, type_name, field_name,
                                  base_type_name, type_map, report) -> None:
        if base_type_name and base_type_name in type_map:
            report.rules.append(OwnershipRule(
                source_type=type_name,
                source_field=field_name,
                target_type=base_type_name,
                owner_field="id",
                confidence="MEDIUM",
                inference_reason=(
                    f"Field '{field_name}' on {type_name} is a collection of "
                    f"{base_type_name}"
                ),
                pattern="COLLECTION",
            ))
            return

        report.rejected.append(RejectedRelationship(
            source_type=type_name,
            source_field=field_name,
            observed_type=base_type_name or "unknown",
            category="UNSUPPORTED",
            reason=(
                f"Collection field '{field_name}' on {type_name} does not point to "
                f"an analyzed object type"
            ),
        ))

    def _find_user_type(self, type_map: Dict[str, Any]) -> Optional[str]:
        for name in type_map:
            if is_user_type(name):
                return name
        return None

    def _resolve_field_type_name(self, field_type) -> Optional[str]:
        """Unwrap NonNull/List wrappers and resolve the base GraphQL type name."""
        base = field_type
        while hasattr(base, "of_type"):
            base = base.of_type
        if base is None:
            return None
        if isinstance(base, type) and base in _PYTHON_SCALARS:
            return _PYTHON_SCALARS[base]
        graphql_name = getattr(base, "graphql_name", None)
        if graphql_name:
            return graphql_name
        definition = getattr(base, "__strawberry_definition__", None)
        if definition is not None and getattr(definition, "name", None):
            return definition.name
        name = getattr(base, "name", None)
        if isinstance(name, str):
            return name
        return getattr(base, "__name__", None)


# ------------------------------------------------------------------
# Module-level singleton + lazy readiness helper
# ------------------------------------------------------------------

inference_engine = OwnershipInferenceEngine()


def ensure_inference_ready() -> OwnershipInferenceEngine:
    """Build the ownership model on first use if startup has not done so."""
    if not inference_engine.is_built:
        from app.graphql.schema import schema as app_schema
        inference_engine.build_from_strawberry_schema(app_schema)
    return inference_engine
