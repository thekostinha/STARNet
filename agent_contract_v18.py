from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List
import hashlib
import json
import uuid


VERSION = "V18.0-T4"


def rid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


@dataclass(frozen=True)
class AgentAssignment:
    assignment_id: str
    task_id: str
    agent_id: str
    objective: str
    authorized_context: Dict[str, Any]
    required_capabilities: List[str]
    allowed_tools: List[str]
    risk_level: str
    expected_evidence: List[str]
    completion_criteria: List[str]
    max_attempts: int = 1
    status: str = "ASSIGNED"
    created_by: str = "AUTOMATO"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def fingerprint(self) -> str:
        raw = json.dumps(
            self.to_dict(),
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


class AssignmentValidator:
    """
    Validador de contratos de missão.

    Não executa ferramentas.
    Não executa agentes.
    Apenas verifica se o contrato é coerente com o AgentSpec.
    """

    @staticmethod
    def validate(assignment: AgentAssignment, agent: Any) -> List[str]:
        errors: List[str] = []

        if not assignment.assignment_id.strip():
            errors.append("assignment_id vazio")

        if not assignment.task_id.strip():
            errors.append("task_id vazio")

        if not assignment.objective.strip():
            errors.append("objective vazio")

        if assignment.agent_id != agent.agent_id:
            errors.append(
                f"agent_id incompatível: {assignment.agent_id} != {agent.agent_id}"
            )

        if not assignment.authorized_context:
            errors.append("authorized_context vazio")

        if not assignment.required_capabilities:
            errors.append("required_capabilities vazio")

        if not assignment.allowed_tools:
            errors.append("allowed_tools vazio")

        if not assignment.expected_evidence:
            errors.append("expected_evidence vazio")

        if not assignment.completion_criteria:
            errors.append("completion_criteria vazio")

        if assignment.max_attempts < 1:
            errors.append("max_attempts inválido")

        if assignment.risk_level != agent.risk_level:
            errors.append(
                f"risk_level incompatível: "
                f"{assignment.risk_level} != {agent.risk_level}"
            )

        agent_capabilities = set(agent.capabilities)
        missing_capabilities = [
            c for c in assignment.required_capabilities
            if c not in agent_capabilities
        ]

        if missing_capabilities:
            errors.append(
                "capacidades não autorizadas: "
                + ", ".join(missing_capabilities)
            )

        agent_tools = set(agent.allowed_tools)
        unauthorized_tools = [
            t for t in assignment.allowed_tools
            if t not in agent_tools
        ]

        if unauthorized_tools:
            errors.append(
                "ferramentas não autorizadas: "
                + ", ".join(unauthorized_tools)
            )

        if agent.independent_verification:
            joined = " ".join(
                item.casefold()
                for item in assignment.completion_criteria
            )

            verification_terms = (
                "evidência",
                "evidencia",
                "verificar",
                "verificação",
                "verificacao",
            )

            if not any(term in joined for term in verification_terms):
                errors.append(
                    "agente independente exige critério explícito de verificação"
                )

        return errors

    @staticmethod
    def assert_valid(assignment: AgentAssignment, agent: Any) -> None:
        errors = AssignmentValidator.validate(assignment, agent)

        if errors:
            raise ValueError(
                "Assignment inválido:\n- "
                + "\n- ".join(errors)
            )
