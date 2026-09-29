from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List
import hashlib
import json

VERSION = "V18.0-T1"
RISK_LEVELS = {"READ_ONLY", "INTERNAL", "WRITE", "EXTERNAL_ACTION", "SENSITIVE"}


@dataclass(frozen=True)
class AgentSpec:
    agent_id: str
    name: str
    role: str
    purpose: str
    capabilities: List[str]
    allowed_tools: List[str]
    risk_level: str
    preferred_model: str
    limits: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    independent_verification: bool = False

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


class AgentRegistry:
    """V18 T1: catálogo declarativo. Não executa agentes nem ferramentas."""

    def __init__(self, registry_file: Path):
        self.registry_file = Path(registry_file)
        self.agents: Dict[str, AgentSpec] = {}

    def register(self, agent: AgentSpec) -> None:
        self._validate_spec(agent)
        if agent.agent_id in self.agents:
            raise ValueError(f"Agente já registado: {agent.agent_id}")
        if any(a.name.casefold() == agent.name.casefold() for a in self.agents.values()):
            raise ValueError(f"Nome de agente duplicado: {agent.name}")
        self.agents[agent.agent_id] = agent

    def get(self, agent_id: str) -> AgentSpec:
        if agent_id not in self.agents:
            raise KeyError(f"Agente inexistente: {agent_id}")
        return self.agents[agent_id]

    def list_agents(self, enabled_only: bool = False) -> List[AgentSpec]:
        agents = list(self.agents.values())

        if enabled_only:
            agents = [agent for agent in agents if agent.enabled]

        return sorted(agents, key=lambda a: a.agent_id)

    def validate_registry(self) -> List[str]:
        errors: List[str] = []
        ids, names = set(), set()
        for agent in self.agents.values():
            try:
                self._validate_spec(agent)
            except (TypeError, ValueError) as exc:
                errors.append(str(exc))
            if agent.agent_id in ids:
                errors.append(f"ID duplicado: {agent.agent_id}")
            ids.add(agent.agent_id)
            name = agent.name.casefold()
            if name in names:
                errors.append(f"Nome duplicado: {agent.name}")
            names.add(name)
        return errors

    def save(self) -> None:
        errors = self.validate_registry()
        if errors:
            raise ValueError("Registry inválido:\n- " + "\n- ".join(errors))
        payload = {
            "version": VERSION,
            "agents": [{**a.to_dict(), "fingerprint": a.fingerprint()} for a in self.list_agents()],
        }
        self.registry_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.registry_file.with_suffix(self.registry_file.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.registry_file)

    def load(self) -> None:
        if not self.registry_file.exists():
            raise FileNotFoundError(str(self.registry_file))
        payload = json.loads(self.registry_file.read_text(encoding="utf-8"))
        if payload.get("version") != VERSION:
            raise ValueError(f"Versão incompatível: {payload.get('version')}")
        loaded: Dict[str, AgentSpec] = {}
        for raw in payload.get("agents", []):
            raw = dict(raw)
            stored = raw.pop("fingerprint", None)
            agent = AgentSpec(**raw)
            if stored != agent.fingerprint():
                raise ValueError(f"Fingerprint inválido: {agent.agent_id}")
            if agent.agent_id in loaded:
                raise ValueError(f"ID duplicado no ficheiro: {agent.agent_id}")
            loaded[agent.agent_id] = agent
        self.agents = loaded
        errors = self.validate_registry()
        if errors:
            raise ValueError("Registry inválido após load:\n- " + "\n- ".join(errors))

    @staticmethod
    def _validate_spec(agent: AgentSpec) -> None:
        if not agent.agent_id.strip():
            raise ValueError("agent_id não pode estar vazio")
        if not agent.name.strip():
            raise ValueError(f"{agent.agent_id}: name vazio")
        if not agent.role.strip():
            raise ValueError(f"{agent.agent_id}: role vazio")
        if not agent.purpose.strip():
            raise ValueError(f"{agent.agent_id}: purpose vazio")
        if not agent.capabilities:
            raise ValueError(f"{agent.agent_id}: capabilities vazio")
        if not agent.preferred_model.strip():
            raise ValueError(f"{agent.agent_id}: preferred_model vazio")
        if agent.risk_level not in RISK_LEVELS:
            raise ValueError(f"{agent.agent_id}: risk_level inválido: {agent.risk_level}")
        if not isinstance(agent.limits, dict):
            raise TypeError(f"{agent.agent_id}: limits tem de ser dict")


def build_default_registry(path: Path) -> AgentRegistry:
    r = AgentRegistry(path)
    defaults = [
        AgentSpec("AUTOMATO", "Automato", "Supervisor operacional",
                  "Receber missões validadas, coordenar agentes e pedir verificação ou replaneamento.",
                  ["decomposicao", "delegacao", "coordenacao", "replaneamento"],
                  ["agent_registry", "task_manager", "context_manager", "memory_search", "evaluator"],
                  "INTERNAL", "qwen3.5:9b", {"max_attempts": 3, "max_parallel_agents": 4}),
        AgentSpec("WEB", "Web", "Pesquisa externa",
                  "Pesquisar fontes autorizadas e entregar resultados com referências.",
                  ["pesquisa_web", "leitura", "evidencia"], ["web_search", "web_open"],
                  "READ_ONLY", "qwen3.5:9b", {"max_attempts": 2, "max_sources": 10}),
        AgentSpec("FILES", "Files", "Gestão de ficheiros",
                  "Localizar, ler e organizar documentos dentro das permissões atribuídas.",
                  ["pesquisa_ficheiros", "leitura", "classificacao"], ["files_search", "files_read"],
                  "READ_ONLY", "qwen3.5:9b", {"max_attempts": 2, "max_files_per_task": 20}),
        AgentSpec("CODE", "Code", "Desenvolvimento controlado",
                  "Criar e testar código com backups e aprovação adequada para escrita.",
                  ["criacao_codigo", "analise_codigo", "testes", "execucao_controlada"],
                  ["code_read", "code_write", "python", "powershell_safe"],
                  "WRITE", "qwen3.5:9b", {"max_attempts": 3, "require_backup_before_write": True}),
        AgentSpec("ANALYSIS", "Analysis", "Análise e síntese",
                  "Analisar informação, comparar hipóteses e detetar contradições.",
                  ["analise", "comparacao", "sintese", "contradicoes"],
                  ["context_manager", "memory_search"], "INTERNAL", "qwen3.5:9b", {"max_attempts": 2}),
        AgentSpec("VALIDATOR", "Validator", "Verificador independente",
                  "Tentar provar que o resultado do executor está incompleto, incorreto ou sem evidência.",
                  ["verificacao", "evidencia", "contradicoes", "falsos_positivos"],
                  ["evaluator", "evidence_store", "context_manager"],
                  "INTERNAL", "qwen3.5:9b", {"max_attempts": 3, "reject_without_evidence": True},
                  independent_verification=True),
        AgentSpec("GUARDIAN", "Guardian", "Segurança e controlo de risco",
                  "Questionar permissões, risco, alcance e condições antes de operações sensíveis.",
                  ["analise_risco", "permissoes", "scope_creep", "bloqueio"],
                  ["tool_registry", "approval_store", "audit_log", "context_manager"],
                  "SENSITIVE", "qwen3.5:9b", {"max_attempts": 2, "block_on_unknown_risk": True},
                  independent_verification=True),
        AgentSpec("REPORTS", "Reports", "Relatórios e documentação",
                  "Transformar resultados verificados em documentação rastreável para o humano.",
                  ["relatorios", "documentacao", "resumos"], ["evidence_store", "audit_log"],
                  "INTERNAL", "qwen3.5:9b", {"max_attempts": 2}),
    ]
    for a in defaults:
        r.register(a)
    return r
