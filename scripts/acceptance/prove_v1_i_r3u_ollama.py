"""Run the bounded real-local Ollama proof for V1-I-R3U.

The script only observes the local status catalog and performs one minimal
inference against an already-installed model.  It never pulls, installs,
changes credentials, or changes provider/account state.
"""

from __future__ import annotations

import argparse
import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from jarvis.ai.models import (
    ChatMessage,
    GenerationRequest,
    MessageRole,
    ModelRole,
    PrivacyClassification,
    PrivacyContext,
)
from jarvis.ai.routing import InferenceDispatcher, ProviderRouter, RouteRequest, RoutingPolicy
from jarvis.bootstrap import create_provider_registry


def _message() -> ChatMessage:
    conversation_id = uuid4()
    return ChatMessage(
        uuid4(),
        conversation_id,
        MessageRole.USER,
        "Return exactly R3U_OLLAMA_OK and nothing else.",
        datetime.now(UTC),
    )


async def _run(model_id: str, missing_model_id: str) -> dict[str, object]:
    endpoint = "http://127.0.0.1:11434"
    context_limit = 4_096
    configuration = {
        "model": model_id,
        "endpoint": endpoint,
        "timeout_seconds": 60.0,
        "context_limit": context_limit,
    }
    registry = create_provider_registry(model_id=model_id, context_limit=context_limit)
    router = ProviderRouter(registry)
    evidence = await router.refresh_usability("ollama", configuration)
    intent = RouteRequest(
        task="bounded R3U local usability proof",
        profile="v1-i-r3u-ollama",
        role=ModelRole.GENERAL,
        classification=PrivacyClassification.LOCAL_ONLY.value,
        policy=RoutingPolicy.LOCAL_ONLY,
        privacy_context=PrivacyContext(PrivacyClassification.LOCAL_ONLY),
        preferred_provider_id="ollama",
        preferred_model_id=model_id,
        context_tokens=64,
    )
    decision = router.route(intent)
    if evidence.model_usable is not True:
        raise RuntimeError(f"installed Ollama model was not proven usable: {evidence.status.value}")
    if decision.primary is None:
        raise RuntimeError("usable Ollama evidence did not produce a route")
    dispatcher = InferenceDispatcher(
        router,
        registry,
        configurations={"ollama": configuration},
        max_attempts=1,
    )
    try:
        dispatched = await dispatcher.generate(
            GenerationRequest(
                (_message(),),
                model_id,
                context_limit,
                PrivacyContext(PrivacyClassification.LOCAL_ONLY),
            ),
            intent,
            decision=decision,
        )
    finally:
        await dispatcher.aclose()
    content = dispatched.result.content.strip()
    if content != "R3U_OLLAMA_OK":
        raise RuntimeError("Ollama returned a response but the independent semantic check failed")
    post_success = router.usability_for("ollama", model_id)
    if not post_success.proven_usable:
        raise RuntimeError("successful Ollama inference did not close current request usability")

    missing_registry = create_provider_registry(
        model_id=missing_model_id, context_limit=context_limit
    )
    missing_router = ProviderRouter(missing_registry)
    missing_configuration = {**configuration, "model": missing_model_id}
    missing_evidence = await missing_router.refresh_usability("ollama", missing_configuration)
    missing_decision = missing_router.route(
        RouteRequest(
            task="bounded R3U missing-model proof",
            profile="v1-i-r3u-ollama-missing-model",
            classification=PrivacyClassification.LOCAL_ONLY.value,
            policy=RoutingPolicy.LOCAL_ONLY,
            privacy_context=PrivacyContext(PrivacyClassification.LOCAL_ONLY),
            preferred_provider_id="ollama",
            preferred_model_id=missing_model_id,
        )
    )
    if missing_evidence.reason.value != "model_not_found" or missing_decision.primary is not None:
        raise RuntimeError("reachable Ollama server did not reject the missing model")
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "provider": "ollama",
        "endpoint": endpoint,
        "installed_model": model_id,
        "probe_evidence_status": evidence.status.value,
        "usable_evidence_status": post_success.status.value,
        "usable_evidence_source": evidence.source,
        "selected_provider": decision.primary.provider_id,
        "selected_model": decision.primary.model_id,
        "executed_provider": "ollama",
        "executed_model": dispatched.result.model,
        "semantic_check": "R3U_OLLAMA_OK",
        "missing_model": missing_model_id,
        "missing_model_evidence_status": missing_evidence.status.value,
        "missing_model_reason": missing_evidence.reason.value,
        "missing_model_route_status": missing_decision.status.value,
        "download_or_install_performed": False,
        "credential_or_billing_change_performed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True)
    parser.add_argument("--missing-model", default="r3u-not-installed:latest")
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    result = asyncio.run(_run(arguments.model, arguments.missing_model))
    encoded = json.dumps(result, sort_keys=True)
    print(encoded)
    if arguments.output is not None:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(encoded + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
