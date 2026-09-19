from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest
from jarvis.agent_runtime import ContextManager
from jarvis.skills import (
    PrimedSkillContext,
    SkillClassification,
    SkillContextItem,
    SkillContextRequirements,
    SkillContextSources,
    SkillManifest,
    SkillRegistry,
)
from jarvis.tools.models import SemanticVersion


def skill(skill_id: str = "writing", **kwargs: Any) -> SkillManifest:
    kwargs.setdefault("output", "text")
    kwargs.setdefault("procedure", ("prepare", "write", "verify"))
    return SkillManifest(
        skill_id=skill_id,
        version=SemanticVersion(1, 0, 0),
        purpose="Write a bounded result",
        **kwargs,
    )


def test_skill_registration_dependencies_scope_and_permission_independence() -> None:
    registry = SkillRegistry()
    with pytest.raises(ValueError):
        registry.register(skill("dependent", prerequisites=("missing",)))
    registry.register(skill("base"))
    registry.register(skill("dependent", prerequisites=("base",), tools=("calculator",)))
    assert registry.resolve("dependent", workspace_id="w", profile_id="p").tools == ("calculator",)
    scoped = skill("scoped", workspace_scope=frozenset({"w"}), profile_scope=frozenset({"p"}))
    registry.register(scoped)
    with pytest.raises(PermissionError):
        registry.resolve("scoped", workspace_id="other", profile_id="p")
    with pytest.raises(PermissionError):
        registry.resolve("scoped", workspace_id="w", profile_id="other")
    assert scoped.tools == ()
    with pytest.raises(ValueError):
        registry.register(scoped)
    with pytest.raises(KeyError):
        registry.get("missing")


def test_skill_context_retrieval_budget_missing_and_classification() -> None:
    requirements = SkillContextRequirements(
        memory_categories=("preferences",),
        knowledge_library_queries=("style",),
        workspace_documents=("README.md",),
        project_knowledge_queries=("testing",),
        preferred_examples=("example-1",),
        required_prior_artifacts=("draft",),
    )
    manifest = skill("contextual", context_requirements=requirements)
    available = {
        ("memory", "preferences"): (
            SkillContextItem(
                "memory", "preferences", "concise", "w", SkillClassification.INTERNAL, 3
            ),
        ),
        ("knowledge_library", "style"): (
            SkillContextItem(
                "knowledge_library", "style", "plain language", "w", SkillClassification.PUBLIC, 4
            ),
        ),
    }

    def retrieve(source: str, query: str, workspace_id: str) -> tuple[SkillContextItem, ...]:
        assert workspace_id == "w"
        return available.get((source, query), ())

    manager = ContextManager()
    primed = manager.prime_skill(
        manifest,
        workspace_id="w",
        profile_id="p",
        sources=SkillContextSources(retrieve),
        token_budget=5,
        allowed_classifications=frozenset(
            {SkillClassification.PUBLIC, SkillClassification.INTERNAL}
        ),
    )
    assert isinstance(primed, PrimedSkillContext)
    assert primed.token_estimate == 3
    assert "knowledge_library:style" not in primed.missing_requirements
    assert "workspace_document:README.md" in primed.missing_requirements

    secret = replace(
        manifest,
        context_requirements=SkillContextRequirements(memory_categories=("credentials",)),
    )

    def secret_retrieve(_: str, __: str, ___: str) -> tuple[SkillContextItem, ...]:
        return (
            SkillContextItem(
                "memory", "credentials", "secret", "w", SkillClassification.CONFIDENTIAL, 1
            ),
        )

    with pytest.raises(PermissionError):
        manager.prime_skill(
            secret,
            workspace_id="w",
            profile_id="p",
            sources=SkillContextSources(secret_retrieve),
            token_budget=10,
            allowed_classifications=frozenset({SkillClassification.PUBLIC}),
        )


def test_skill_context_workspace_privacy_malicious_requirement_and_budget() -> None:
    manifest = skill(
        "private",
        context_requirements=SkillContextRequirements(memory_categories=("anything",)),
    )

    def wrong_workspace(_: str, __: str, ___: str) -> tuple[SkillContextItem, ...]:
        return (SkillContextItem("memory", "x", "data", "other", SkillClassification.PUBLIC, 1),)

    with pytest.raises(PermissionError):
        ContextManager().prime_skill(
            manifest,
            workspace_id="w",
            profile_id="p",
            sources=SkillContextSources(wrong_workspace),
            token_budget=10,
            allowed_classifications=frozenset({SkillClassification.PUBLIC}),
        )

    def sensitive(_: str, __: str, ___: str) -> tuple[SkillContextItem, ...]:
        return (SkillContextItem("memory", "x", "private", "w", SkillClassification.SENSITIVE, 1),)

    with pytest.raises(PermissionError):
        ContextManager().prime_skill(
            manifest,
            workspace_id="w",
            profile_id="p",
            sources=SkillContextSources(sensitive),
            token_budget=10,
            allowed_classifications=frozenset({SkillClassification.SENSITIVE}),
            privacy_mode=True,
        )
    with pytest.raises(ValueError):
        ContextManager().prime_skill(
            manifest,
            workspace_id="w",
            profile_id="p",
            sources=SkillContextSources(sensitive),
            token_budget=0,
            allowed_classifications=frozenset(),
        )


def test_skill_manifest_and_context_item_validation() -> None:
    with pytest.raises(ValueError):
        SkillContextRequirements(memory_categories=("",))
    with pytest.raises(ValueError):
        skill("empty", procedure=())
    with pytest.raises(ValueError):
        skill("bad-workspace", workspace_scope=frozenset({""}))
    with pytest.raises(ValueError):
        skill("bad-profile", profile_scope=frozenset({""}))
    with pytest.raises(ValueError):
        SkillContextItem("memory", "key", "text", "w", SkillClassification.PUBLIC, 0)
    with pytest.raises(ValueError):
        SkillContextItem("memory", "key", "text", "w", "secret", 1)  # type: ignore[arg-type]
    scoped = skill("scoped-prime", workspace_scope=frozenset({"w"}), profile_scope=frozenset({"p"}))
    with pytest.raises(PermissionError):
        ContextManager().prime_skill(
            scoped,
            workspace_id="other",
            profile_id="p",
            sources=SkillContextSources(lambda *_: ()),
            token_budget=1,
            allowed_classifications=frozenset(),
        )
    with pytest.raises(PermissionError):
        ContextManager().prime_skill(
            scoped,
            workspace_id="w",
            profile_id="other",
            sources=SkillContextSources(lambda *_: ()),
            token_budget=1,
            allowed_classifications=frozenset(),
        )
