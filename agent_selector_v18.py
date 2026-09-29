from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Set


@dataclass(frozen=True)
class AgentSelectionRequest:
    required_capabilities: List[str]
    required_tools: List[str]
    risk_level: str
    require_independent_verification: bool = False


@dataclass(frozen=True)
class AgentSelectionResult:
    eligible: bool
    agent_id: str | None
    reason: str
    candidates: List[str]


class AgentSelector:
    """
    Seleciona agentes de forma determinística.

    NÃO executa agentes.
    NÃO executa ferramentas.
    NÃO altera o Registry.

    Apenas determina quais agentes satisfazem os requisitos.
    """

    def select(
        self,
        registry: Any,
        request: AgentSelectionRequest,
    ) -> AgentSelectionResult:

        candidates = []

        for agent in registry.list_agents(enabled_only=True):

            agent_capabilities: Set[str] = set(agent.capabilities)
            agent_tools: Set[str] = set(agent.allowed_tools)

            required_capabilities = set(
                request.required_capabilities
            )

            required_tools = set(
                request.required_tools
            )

            if not required_capabilities.issubset(
                agent_capabilities
            ):
                continue

            if not required_tools.issubset(
                agent_tools
            ):
                continue

            if agent.risk_level != request.risk_level:
                continue

            if (
                request.require_independent_verification
                and not agent.independent_verification
            ):
                continue

            candidates.append(agent.agent_id)

        candidates.sort()

        if not candidates:
            return AgentSelectionResult(
                eligible=False,
                agent_id=None,
                reason="NENHUM_AGENTE_ELEGIVEL",
                candidates=[],
            )

        selected = candidates[0]

        if len(candidates) == 1:
            reason = "AGENTE_ELEGIVEL"
        else:
            reason = "MULTIPLOS_ELEGIVEIS_ESCOLHA_DETERMINISTICA"

        return AgentSelectionResult(
            eligible=True,
            agent_id=selected,
            reason=reason,
            candidates=candidates,
        )
