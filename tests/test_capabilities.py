from __future__ import annotations

from dataclasses import asdict, replace
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from jarvis.capabilities import (
    CapabilityError,
    CapabilityHealth,
    CapabilityLifecycle,
    CapabilityManifest,
    CapabilityRegistry,
    EffectClassification,
    EffectMetadata,
    EnvironmentEdge,
    EnvironmentGraph,
    EnvironmentNode,
    EnvironmentNodeKind,
    Reversibility,
    capability_hash,
)
from jarvis.permissions.models import Permission, Risk
from jarvis.tools.models import SemanticVersion, ToolHealthStatus, ToolPlatform


def manifest(
    *, capability_id: str | None = None, dependencies: tuple[str, ...] = ()
) -> CapabilityManifest:
    capability_id = capability_id or f"cap-{uuid4()}"
    version = SemanticVersion(1, 0, 0)
    return CapabilityManifest(
        capability_id=capability_id,
        name="Native capability",
        version=version,
        integration_owner="jarvis-core",
        actions=("inspect", "apply"),
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        permissions=(Permission.FILESYSTEM_READ,),
        risk=Risk.LOW,
        supported_platforms=frozenset({ToolPlatform.WINDOWS}),
        network_required=False,
        network_domains=(),
        credential_references=("profile-reference",),
        dependencies=dependencies,
        configuration=("root",),
        health=CapabilityHealth(ToolHealthStatus.AVAILABLE, "fixture", datetime.now(UTC)),
        verification=("independent-check",),
        ui_voice=("desktop", "voice"),
        provenance=("fixture",),
        content_hash=capability_hash(capability_id, version, ("inspect", "apply")),
        lifecycle=CapabilityLifecycle.ACTIVE,
        effect=EffectMetadata(
            EffectClassification.LOCAL_MUTATION,
            Reversibility.REVERSIBLE,
            preview_supported=True,
            compensation="restore prior revision",
            produced_artifacts=("artifact",),
            emitted_events=("capability.changed",),
        ),
        confidence=0.9,
        last_verified=datetime.now(UTC),
    )


def test_capability_manifest_registry_search_gaps_and_metadata() -> None:
    dependency = manifest()
    dependent = manifest(dependencies=(dependency.capability_id,))
    registry = CapabilityRegistry((dependency, dependent))
    assert registry.inspect(dependent.capability_id) is dependent
    assert registry.permission(dependent.capability_id) == (Permission.FILESYSTEM_READ,)
    assert registry.dependency_lookup(dependent.capability_id) == (dependency.capability_id,)
    assert registry.health(dependent.capability_id).status is ToolHealthStatus.AVAILABLE
    assert registry.search("NATIVE") == (dependency, dependent)
    assert registry.gap_detection(
        (dependency.capability_id, dependent.capability_id, "missing")
    ) == ("missing",)
    removed = registry.unregister(dependency.capability_id)
    assert removed is dependency
    assert registry.gap_detection((dependent.capability_id,)) == (dependent.capability_id,)
    with pytest.raises(CapabilityError):
        registry.register(dependent)
    with pytest.raises(KeyError):
        registry.inspect("missing")


def test_capability_validation_rejects_unsafe_metadata() -> None:
    base = manifest()
    with pytest.raises(CapabilityError):
        replace(base, capability_id="")
    with pytest.raises(CapabilityError):
        replace(base, network_required=False, network_domains=("example",))
    with pytest.raises(CapabilityError):
        replace(base, credential_references=("token=secret",))
    with pytest.raises(CapabilityError):
        CapabilityHealth(ToolHealthStatus.AVAILABLE, "\x00")
    with pytest.raises(CapabilityError):
        EffectMetadata(
            EffectClassification.OBSERVATION, Reversibility.READ_ONLY, compensation="\x00"
        )
    with pytest.raises(CapabilityError):
        capability_hash("", SemanticVersion(1, 0, 0), ("x",))
    assert asdict(base.effect)["reversibility"] is Reversibility.REVERSIBLE


def test_environment_graph_uses_randomized_ids_and_never_stores_credentials() -> None:
    graph = EnvironmentGraph()
    nodes = [
        EnvironmentNode(f"{kind.value}-{uuid4()}", kind, kind.value, confidence=0.8)
        for kind in EnvironmentNodeKind
    ]
    for node in nodes:
        graph.add_node(node)
    graph.add_edge(EnvironmentEdge(nodes[0].node_id, nodes[1].node_id, "runs", confidence=0.7))
    graph.add_edge(EnvironmentEdge(nodes[1].node_id, nodes[2].node_id, "hosts", confidence=0.6))
    assert len(graph.nodes()) == len(EnvironmentNodeKind)
    assert graph.nodes(EnvironmentNodeKind.WORKSPACE)[0].kind is EnvironmentNodeKind.WORKSPACE
    assert {node.node_id for node in graph.related(nodes[1].node_id)} == {
        nodes[0].node_id,
        nodes[2].node_id,
    }
    with pytest.raises(CapabilityError):
        EnvironmentNode(
            "bad", EnvironmentNodeKind.ACCOUNT_REF, "account", account_ref="token=secret"
        )
    with pytest.raises(CapabilityError):
        graph.add_edge(EnvironmentEdge("unknown", nodes[0].node_id, "related"))
    removed = graph.remove_node(nodes[1].node_id)
    assert removed is nodes[1]
    assert not graph.edges()
