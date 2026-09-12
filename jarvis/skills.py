"""Native reusable skills and bounded context-priming contracts."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from jarvis.tools.models import SemanticVersion


class SkillClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    CONFIDENTIAL = "confidential"


@dataclass(frozen=True, slots=True)
class SkillContextRequirements:
    """Retrieval hints; these are never permission or authority requests."""

    memory_categories: tuple[str, ...] = ()
    knowledge_library_queries: tuple[str, ...] = ()
    workspace_documents: tuple[str, ...] = ()
    project_knowledge_queries: tuple[str, ...] = ()
    preferred_examples: tuple[str, ...] = ()
    required_prior_artifacts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for field_name in (
            "memory_categories",
            "knowledge_library_queries",
            "workspace_documents",
            "project_knowledge_queries",
            "preferred_examples",
            "required_prior_artifacts",
        ):
            values = getattr(self, field_name)
            if len(values) > 32 or any(
                type(value) is not str or not value.strip() or len(value) > 512 for value in values
            ):
                raise ValueError(f"Skill context requirement {field_name} is invalid")


@dataclass(frozen=True, slots=True)
class SkillManifest:
    skill_id: str
    version: SemanticVersion
    purpose: str
    prerequisites: tuple[str, ...] = ()
    tools: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    procedure: tuple[str, ...] = ()
    output: str = ""
    verification_hints: tuple[str, ...] = ()
    fallback_guidance: tuple[str, ...] = ()
    provenance: tuple[str, ...] = ()
    workspace_scope: frozenset[str] = frozenset()
    profile_scope: frozenset[str] = frozenset()
    context_requirements: SkillContextRequirements = SkillContextRequirements()

    def __post_init__(self) -> None:
        _bounded_text(self.skill_id, "Skill ID", 128)
        _bounded_text(self.purpose, "Skill purpose", 2_000)
        _bounded_text(self.output, "Skill output", 2_000)
        if not self.procedure or len(self.procedure) > 64:
            raise ValueError("Skill procedure is required and bounded")
        for field_name in (
            "prerequisites",
            "tools",
            "capabilities",
            "verification_hints",
            "fallback_guidance",
            "provenance",
        ):
            values = getattr(self, field_name)
            if len(values) > 64 or any(
                type(value) is not str or not value.strip() or len(value) > 512 for value in values
            ):
                raise ValueError(f"Skill {field_name} is invalid")
        if any(not item.strip() or len(item) > 128 for item in self.workspace_scope):
            raise ValueError("Skill workspace scope is invalid")
        if any(not item.strip() or len(item) > 128 for item in self.profile_scope):
            raise ValueError("Skill profile scope is invalid")


class SkillRegistry:
    """Explicit skill catalog; registration does not register tools or authority."""

    def __init__(self, skills: Iterable[SkillManifest] = ()) -> None:
        self._skills: dict[str, SkillManifest] = {}
        for skill in skills:
            self.register(skill)

    def register(self, skill: SkillManifest) -> None:
        if skill.skill_id in self._skills:
            raise ValueError("Duplicate skill ID")
        missing = set(skill.prerequisites) - self._skills.keys()
        if missing:
            raise ValueError("Skill prerequisites are not registered")
        self._skills[skill.skill_id] = skill

    def get(self, skill_id: str) -> SkillManifest:
        try:
            return self._skills[skill_id]
        except KeyError as error:
            raise KeyError("Unknown skill") from error

    def resolve(self, skill_id: str, *, workspace_id: str, profile_id: str) -> SkillManifest:
        skill = self.get(skill_id)
        if skill.workspace_scope and workspace_id not in skill.workspace_scope:
            raise PermissionError("Skill is outside the workspace scope")
        if skill.profile_scope and profile_id not in skill.profile_scope:
            raise PermissionError("Skill is outside the profile scope")
        return skill

    def manifests(self) -> tuple[SkillManifest, ...]:
        return tuple(self._skills.values())


@dataclass(frozen=True, slots=True)
class SkillContextItem:
    source: str
    key: str
    text: str
    workspace_id: str
    classification: SkillClassification
    tokens: int
    provenance: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _bounded_text(self.source, "Context source", 64)
        _bounded_text(self.key, "Context key", 256)
        _bounded_text(self.text, "Context text", 16_000)
        _bounded_text(self.workspace_id, "Context workspace", 128)
        if self.tokens < 1 or self.tokens > 16_000:
            raise ValueError("Context item token estimate is invalid")
        if not isinstance(self.classification, SkillClassification):
            raise ValueError("Context classification is invalid")


class SkillContextProvider(Protocol):
    def retrieve(
        self, source: str, query: str, *, workspace_id: str
    ) -> tuple[SkillContextItem, ...]: ...


@dataclass(frozen=True, slots=True)
class SkillContextSources:
    retrieve: Callable[[str, str, str], tuple[SkillContextItem, ...]]


@dataclass(frozen=True, slots=True)
class PrimedSkillContext:
    skill_id: str
    items: tuple[SkillContextItem, ...]
    token_estimate: int
    missing_requirements: tuple[str, ...]


def prime_skill_context(
    skill: SkillManifest,
    *,
    workspace_id: str,
    profile_id: str,
    sources: SkillContextSources,
    token_budget: int,
    allowed_classifications: frozenset[SkillClassification],
    privacy_mode: bool = False,
) -> PrimedSkillContext:
    """Retrieve only declared hints and fail closed on scope/privacy violations."""

    if token_budget < 1:
        raise ValueError("Skill context token budget must be positive")
    if skill.workspace_scope and workspace_id not in skill.workspace_scope:
        raise PermissionError("Skill is outside the workspace scope")
    if skill.profile_scope and profile_id not in skill.profile_scope:
        raise PermissionError("Skill is outside the profile scope")
    requirement_groups = (
        ("memory", skill.context_requirements.memory_categories),
        ("knowledge_library", skill.context_requirements.knowledge_library_queries),
        ("workspace_document", skill.context_requirements.workspace_documents),
        ("project_knowledge", skill.context_requirements.project_knowledge_queries),
        ("example", skill.context_requirements.preferred_examples),
        ("prior_artifact", skill.context_requirements.required_prior_artifacts),
    )
    selected: list[SkillContextItem] = []
    missing: list[str] = []
    used = 0
    for source, queries in requirement_groups:
        for query in queries:
            items = sources.retrieve(source, query, workspace_id)
            if not items:
                missing.append(f"{source}:{query}")
            for item in items:
                if item.workspace_id != workspace_id:
                    raise PermissionError("Skill context crossed workspace scope")
                if item.classification not in allowed_classifications:
                    raise PermissionError("Skill context classification is not allowed")
                if privacy_mode and item.classification not in {
                    SkillClassification.PUBLIC,
                    SkillClassification.INTERNAL,
                }:
                    raise PermissionError("Skill context is unavailable in privacy mode")
                if used + item.tokens > token_budget:
                    continue
                selected.append(item)
                used += item.tokens
    return PrimedSkillContext(skill.skill_id, tuple(selected), used, tuple(missing))


def _bounded_text(value: str, name: str, limit: int) -> None:
    if type(value) is not str or not value.strip() or len(value) > limit:
        raise ValueError(f"{name} is invalid")
