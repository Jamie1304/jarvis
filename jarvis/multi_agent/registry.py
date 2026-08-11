"""Explicit registry for trusted agent contracts and bounded worker adapters."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod

from jarvis.multi_agent.models import AgentContract, AgentInvocation, AgentResult, AgentType


class AgentRegistryError(ValueError):
    pass


class AgentWorker(ABC):
    """A worker receives one typed node and no registry, broker, or delegation handle."""

    @property
    @abstractmethod
    def contract(self) -> AgentContract: ...

    @abstractmethod
    async def execute(
        self, invocation: AgentInvocation, cancellation: asyncio.Event
    ) -> AgentResult: ...


class AgentRegistry:
    """Trusted exact-ID registry; workers cannot register or spawn other workers."""

    def __init__(self, workers: tuple[AgentWorker, ...] = ()) -> None:
        self._workers: dict[str, AgentWorker] = {}
        self._contracts: dict[str, AgentContract] = {}
        for worker in workers:
            self.register(worker)

    def register(self, worker: AgentWorker) -> None:
        contract = worker.contract
        if contract.agent_id in self._workers:
            raise AgentRegistryError(f"Duplicate agent ID: {contract.agent_id}")
        if contract.agent_type is AgentType.ORCHESTRATOR:
            raise AgentRegistryError("The orchestrator is application code, not a delegated worker")
        if contract.may_delegate:
            raise AgentRegistryError("Delegated workers cannot receive delegation authority")
        self._workers[contract.agent_id] = worker
        self._contracts[contract.agent_id] = contract

    def get(self, agent_id: str) -> AgentWorker:
        try:
            worker = self._workers[agent_id]
        except KeyError as error:
            raise AgentRegistryError(f"Unknown agent ID: {agent_id}") from error
        if worker.contract != self._contracts[agent_id]:
            raise AgentRegistryError(f"Agent contract changed after registration: {agent_id}")
        return worker

    def inspect(self, agent_id: str) -> AgentContract:
        self.get(agent_id)
        return self._contracts[agent_id]

    def list_contracts(self) -> tuple[AgentContract, ...]:
        return tuple(self._contracts[agent_id] for agent_id in sorted(self._workers))
