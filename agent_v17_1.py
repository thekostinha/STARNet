from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Tuple

VERSION = "17.1"
BASE = Path(__file__).resolve().parent
STATE_FILE = BASE / "state_v17_1.json"
AUDIT_FILE = BASE / "audit_v17_1.jsonl"
REGISTRY_FILE = BASE / "registry_v17_1.json"
MEMORY_FILE = BASE / "memory_v17_1.json"
MEMORY_DIR = Path(os.getenv("STARNET_OBSIDIAN_VAULT", str(BASE / "memory_v17_1"))).resolve()
SANDBOX = BASE / "sandbox"
SANDBOX.mkdir(parents=True, exist_ok=True)
WORKSPACE = BASE / "workspace"
WORKSPACE.mkdir(parents=True, exist_ok=True)
MEMORY_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_MAX_ATTEMPTS = 3


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def rid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def atomic_json(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def audit(event: str, **data: Any) -> None:
    with AUDIT_FILE.open("a", encoding="utf-8") as f:
        f.write(
            json.dumps(
                {"ts": now(), "version": VERSION, "event": event, **data},
                ensure_ascii=False,
            )
            + "\n"
        )


@dataclass
class ToolSpec:
    name: str
    description: str
    command: List[str]
    risk: str
    expected_evidence: str
    enabled: bool = True

    def fingerprint(self) -> str:
        raw = json.dumps(asdict(self), sort_keys=True, ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


class ToolRegistry:
    def __init__(self) -> None:
        self.tools: Dict[str, ToolSpec] = {}
        defaults = [
            ToolSpec(
                "whoami",
                "Identifica o utilizador atual.",
                ["whoami"],
                "READ_ONLY",
                "stdout + return code",
            ),
            ToolSpec(
                "hostname",
                "Obtém o nome do computador.",
                ["hostname"],
                "READ_ONLY",
                "stdout + return code",
            ),
            ToolSpec(
                "windows_version",
                "Obtém a versão do Windows.",
                ["cmd", "/c", "ver"],
                "READ_ONLY",
                "stdout + return code",
            ),
            ToolSpec(
                "sandbox_write_test",
                "Escreve e valida um ficheiro de teste dentro do sandbox.",
                ["__internal_write_test__"],
                "WRITE",
                "ficheiro + conteúdo real + hash",
            ),
            ToolSpec(
                "sandbox_failure_once",
                "Ferramenta de teste controlada: falha uma vez e depois consegue.",
                ["__internal_failure_once__"],
                "READ_ONLY",
                "evidência real de falha/sucesso",
            ),
        ]
        for tool in defaults:
            self.tools[tool.name] = tool
        self._save()

    def _save(self) -> None:
        payload = {
            "version": VERSION,
            "updated_at": now(),
            "tools": [asdict(t) | {"fingerprint": t.fingerprint()} for t in self.tools.values()],
        }
        atomic_json(REGISTRY_FILE, payload)

    def get(self, name: str) -> ToolSpec:
        if name not in self.tools:
            raise KeyError(f"Tool inexistente: {name}")
        tool = self.tools[name]
        if not tool.enabled:
            raise PermissionError(f"Tool desativada: {name}")
        return tool

    def show(self) -> None:
        print("=" * 68)
        print("                     TOOL REGISTRY V17.1")
        print("=" * 68)
        for t in self.tools.values():
            print(f"[{t.name}] {t.risk} | {'ENABLED' if t.enabled else 'DISABLED'}")
            print(f"  Descrição: {t.description}")
            print(f"  Comando:   {t.command}")
            print(f"  Evidência: {t.expected_evidence}")
            print(f"  FP:        {t.fingerprint()}")
            print()


@dataclass
class Evidence:
    id: str
    subtask_id: str
    tool: str
    return_code: int
    stdout: str
    stderr: str
    verified: bool
    details: Dict[str, Any] = field(default_factory=dict)
    ts: str = field(default_factory=now)


@dataclass
class Subtask:
    id: str
    tool: str
    deps: List[str] = field(default_factory=list)
    status: str = "PENDING"
    attempts: int = 0
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    evidence_id: Optional[str] = None
    reason: str = ""
    plan_note: str = ""
    manual_retry_allowance: int = 0


@dataclass
class Task:
    id: str
    description: str
    subtasks: List[Subtask]
    status: str = "PENDING"
    attempt_cycle: int = 0
    created_at: str = field(default_factory=now)
    updated_at: str = field(default_factory=now)


class Store:
    def __init__(self) -> None:
        default = {
            "version": VERSION,
            "tasks": {},
            "approvals": {},
            "evidence": {},
            "interventions": {},
            "context": {},
        }
        self.data = load_json(STATE_FILE, default)
        self._normalize()
        self.recover_crashed()

    def _normalize(self) -> None:
        self.data.setdefault("version", VERSION)
        self.data.setdefault("tasks", {})
        self.data.setdefault("approvals", {})
        self.data.setdefault("evidence", {})
        self.data.setdefault("interventions", {})
        self.data.setdefault("context", {})
        for task in self.data.get("tasks", {}).values():
            task.setdefault("attempt_cycle", 0)
            for sub in task.get("subtasks", []):
                sub.setdefault("max_attempts", DEFAULT_MAX_ATTEMPTS)
                sub.setdefault("plan_note", "")
                sub.setdefault("manual_retry_allowance", 0)

    def save(self) -> None:
        self.data["version"] = VERSION
        atomic_json(STATE_FILE, self.data)

    def recover_crashed(self) -> None:
        changed = False
        for task in self.data.get("tasks", {}).values():
            for sub in task.get("subtasks", []):
                if sub.get("status") == "EXECUTING":
                    sub["status"] = "RECOVERY_REQUIRED"
                    sub["reason"] = "Execução interrompida; checkpoint recuperado antes do executor."
                    changed = True
            if any(s.get("status") == "RECOVERY_REQUIRED" for s in task.get("subtasks", [])):
                task["status"] = "RECOVERY_REQUIRED"
                task["updated_at"] = now()
        if changed:
            self.save()
            audit("RECOVERY_MARKED", state_file=str(STATE_FILE))


def get_task(store: Store, task_id: str) -> Dict[str, Any]:
    task = store.data["tasks"].get(task_id)
    if not task:
        raise KeyError(f"Task inexistente: {task_id}")
    return task


def build_task(
    registry: ToolRegistry,
    store: Store,
    tools: List[str],
    description: str = "Tarefa V17.1",
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> Task:
    if max_attempts < 1:
        raise ValueError("max_attempts deve ser >= 1")
    subs: List[Subtask] = []
    for tool_name in tools:
        registry.get(tool_name)
        deps = [subs[-1].id] if subs else []
        subs.append(Subtask(rid("SUB"), tool_name, deps, max_attempts=max_attempts))
    if not subs:
        raise ValueError("A tarefa precisa de pelo menos uma ferramenta")
    task = Task(rid("TASK"), description, subs)
    task_dict = asdict(task)
    store.data["tasks"][task.id] = task_dict
    store.data["context"][task.id] = {
        "task_id": task.id,
        "goal": description,
        "facts": [],
        "gaps": [],
        "attempt_history": [],
        "recovery_notes": [],
        "sources": [],
        "updated_at": now(),
    }
    store.save()
    audit("TASK_CREATED", task=task_dict)
    return task


def dependencies_met(sub: Dict[str, Any], task: Dict[str, Any]) -> Tuple[bool, str]:
    for dep_id in sub.get("deps", []):
        dep = next((x for x in task["subtasks"] if x["id"] == dep_id), None)
        if not dep:
            return False, f"Dependência {dep_id} inexistente"
        if dep["status"] != "COMPLETED":
            return False, f"Dependência {dep_id} está {dep['status']}"
    return True, ""


class MemoryStore:
    """Memória persistente legível, com índice JSON + notas Markdown compatíveis com Obsidian."""

    def __init__(self) -> None:
        self.data = load_json(MEMORY_FILE, {"version": VERSION, "entries": []})
        self.data.setdefault("version", VERSION)
        self.data.setdefault("entries", [])

    def save(self) -> None:
        atomic_json(MEMORY_FILE, self.data)

    def add(
        self,
        kind: str,
        title: str,
        content: str,
        task_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> str:
        entry_id = rid("MEM")
        entry = {
            "id": entry_id,
            "kind": kind,
            "title": title,
            "content": content,
            "task_id": task_id,
            "tags": tags or [],
            "created_at": now(),
            "version": VERSION,
        }
        self.data["entries"].append(entry)
        self.save()
        safe_title = "_".join("".join(c if c.isalnum() else "_" for c in title).split())[:70]
        note = MEMORY_DIR / f"{entry_id}_{safe_title or 'memory'}.md"
        note.write_text(
            "---\n"
            f"id: {entry_id}\n"
            f"kind: {kind}\n"
            f"task_id: {task_id or ''}\n"
            f"created_at: {entry['created_at']}\n"
            "tags:\n"
            + "".join(f"  - {tag}\n" for tag in (tags or []))
            + "---\n\n"
            + f"# {title}\n\n{content}\n",
            encoding="utf-8",
        )
        audit("MEMORY_SAVED", memory_id=entry_id, kind=kind, task_id=task_id)
        return entry_id

    def search(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        terms = [t.lower() for t in query.split() if t.strip()]
        scored: List[Tuple[int, Dict[str, Any]]] = []
        for entry in self.data.get("entries", []):
            hay = " ".join(
                [
                    entry.get("title", ""),
                    entry.get("content", ""),
                    " ".join(entry.get("tags", [])),
                ]
            ).lower()
            score = sum(1 for term in terms if term in hay)
            if score:
                scored.append((score, entry))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [entry for _, entry in scored[:limit]]


class ContextManager:
    def __init__(self, store: Store, memory: MemoryStore) -> None:
        self.store = store
        self.memory = memory

    def get(self, task_id: str) -> Dict[str, Any]:
        return self.store.data["context"].setdefault(
            task_id,
            {
                "task_id": task_id,
                "goal": get_task(self.store, task_id)["description"],
                "facts": [],
                "gaps": [],
                "attempt_history": [],
                "recovery_notes": [],
                "sources": [],
                "updated_at": now(),
            },
        )

    def add_fact(self, task_id: str, fact: str, source: str = "runtime") -> None:
        ctx = self.get(task_id)
        if fact and fact not in ctx["facts"]:
            ctx["facts"].append(fact)
        ctx["sources"].append({"source": source, "at": now()})
        ctx["updated_at"] = now()
        self.store.save()

    def add_gap(self, task_id: str, gap: str) -> None:
        ctx = self.get(task_id)
        if gap and gap not in ctx["gaps"]:
            ctx["gaps"].append(gap)
        ctx["updated_at"] = now()
        self.store.save()
        audit("CONTEXT_GAP", task_id=task_id, gap=gap)

    def resolve_gap(self, task_id: str, gap: str) -> None:
        ctx = self.get(task_id)
        if gap in ctx.get("gaps", []):
            ctx["gaps"].remove(gap)
            ctx["updated_at"] = now()
            self.store.save()
            audit("CONTEXT_GAP_RESOLVED", task_id=task_id, gap=gap)

    def resolve_gaps_from_memory(self, task_id: str) -> List[Dict[str, Any]]:
        ctx = self.get(task_id)
        matches: List[Dict[str, Any]] = []
        for gap in list(ctx.get("gaps", [])):
            gap_matches = self.memory.search(gap, limit=3)
            for match in gap_matches:
                if match not in matches:
                    matches.append(match)
                self.add_fact(task_id, f"Memória {match['id']}: {match['title']} — {match['content']}", "memory")
            if gap_matches:
                self.resolve_gap(task_id, gap)
        return matches

    def record_attempt(self, task_id: str, subtask_id: str, attempt: int, result: str) -> None:
        ctx = self.get(task_id)
        ctx["attempt_history"].append(
            {"subtask_id": subtask_id, "attempt": attempt, "result": result, "at": now()}
        )
        ctx["updated_at"] = now()
        self.store.save()

    def record_recovery_note(self, task_id: str, note: str) -> None:
        ctx = self.get(task_id)
        ctx["recovery_notes"].append({"note": note, "at": now()})
        ctx["updated_at"] = now()
        self.store.save()


@dataclass
class ContextAssistReport:
    query: str
    memory_matches: List[str] = field(default_factory=list)
    workspace_matches: List[str] = field(default_factory=list)
    facts_added: int = 0
    gaps_resolved: List[str] = field(default_factory=list)


class ContextAssistant:
    """Ajuda o contexto a procurar informação antes de desistir. Read-only por desenho."""

    SEARCH_EXTENSIONS = {".md", ".txt", ".json", ".py", ".log", ".yaml", ".yml"}
    SKIP_DIRS = {".venv", "__pycache__", ".git"}
    MAX_FILE_BYTES = 1_000_000

    def __init__(self, context_manager: ContextManager, memory: MemoryStore) -> None:
        self.context_manager = context_manager
        self.memory = memory

    @staticmethod
    def _terms(query: str) -> List[str]:
        return [t.lower() for t in query.split() if len(t.strip()) >= 3]

    def _workspace_search(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        terms = self._terms(query)
        if not terms:
            return []
        results: List[Tuple[int, Dict[str, Any]]] = []
        for path in WORKSPACE.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in self.SEARCH_EXTENSIONS:
                continue
            if any(part in self.SKIP_DIRS for part in path.parts):
                continue
            try:
                if path.stat().st_size > self.MAX_FILE_BYTES:
                    continue
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            hay = (str(path) + "\n" + content).lower()
            score = sum(1 for term in terms if term in hay)
            if score:
                excerpt = content[:1200].replace("\x00", " ")
                results.append((score, {"path": str(path), "score": score, "excerpt": excerpt}))
        results.sort(key=lambda item: item[0], reverse=True)
        return [item for _, item in results[:limit]]

    def assist(self, task_id: str, query: str) -> ContextAssistReport:
        ctx = self.context_manager.get(task_id)
        report = ContextAssistReport(query=query)

        # 1) Memória persistente
        memory_matches = self.memory.search(query, limit=5)
        for match in memory_matches:
            report.memory_matches.append(match["id"])
            self.context_manager.add_fact(
                task_id,
                f"Memória {match['id']}: {match['title']} — {match['content']}",
                "context_assistant.memory",
            )
            report.facts_added += 1

        # 2) Workspace local
        workspace_matches = self._workspace_search(query, limit=5)
        for match in workspace_matches:
            report.workspace_matches.append(match["path"])
            self.context_manager.add_fact(
                task_id,
                f"Workspace: {match['path']} — correspondência encontrada (score={match['score']}). Exerto: {match['excerpt']}",
                "context_assistant.workspace",
            )
            report.facts_added += 1

        # Só fechamos um gap quando encontrámos algo relacionado com ele.
        for gap in list(ctx.get("gaps", [])):
            gap_matches = self.memory.search(gap, limit=3)
            gap_workspace = self._workspace_search(gap, limit=3)
            if gap_matches or gap_workspace:
                self.context_manager.resolve_gap(task_id, gap)
                report.gaps_resolved.append(gap)

        audit(
            "CONTEXT_ASSISTED",
            task_id=task_id,
            query=query,
            memory_matches=report.memory_matches,
            workspace_matches=report.workspace_matches,
            gaps_resolved=report.gaps_resolved,
        )
        return report


class Evaluator:
    """Validação independente: execução e conclusão não são a mesma coisa."""

    def evaluate(self, evidence: Evidence, tool: ToolSpec) -> Tuple[bool, str]:
        if tool.name == "sandbox_write_test":
            verified = bool(evidence.details.get("content_matches")) and bool(
                evidence.details.get("content_sha256")
            )
            return verified, "Conteúdo escrito e hash confirmados." if verified else "Escrita não confirmada."
        if tool.name == "sandbox_failure_once":
            return evidence.return_code == 0 and evidence.verified, (
                "Teste de recuperação concluído." if evidence.return_code == 0 else "Falha controlada."
            )
        verified = evidence.return_code == 0
        return verified, "Return code 0 confirmado." if verified else f"Return code {evidence.return_code}."


class Planner(Protocol):
    def recover(self, task: Dict[str, Any], sub: Dict[str, Any], context: Dict[str, Any], failure_reason: str) -> str:
        ...


class DeterministicRecoveryPlanner:
    """Planner seguro para a V17: replaneia sem inventar capacidades."""

    def recover(self, task: Dict[str, Any], sub: Dict[str, Any], context: Dict[str, Any], failure_reason: str) -> str:
        if sub["tool"] == "sandbox_failure_once":
            return "Falha controlada; repetir a mesma sub-tarefa para validar recuperação."
        if "Dependência" in failure_reason:
            return "Aguardar dependência concluída; não executar ainda."
        if "aprovação" in failure_reason.lower():
            return "Obter aprovação humana antes da próxima execução."
        if context.get("gaps"):
            return "Contexto ainda insuficiente; procurar memória/workspace antes de nova execução."
        if context.get("facts"):
            return "Novo contexto disponível; reformular a abordagem antes da próxima execução."
        return "Falha sem informação suficiente para uma nova estratégia; preparar intervenção humana."


class OllamaRecoveryPlanner:
    """Adaptador opcional para o modelo local. Não é obrigatório para o núcleo da V17."""

    def __init__(self, model: Optional[str] = None) -> None:
        self.model = model or os.getenv("STARNET_OLLAMA_MODEL", "qwen3.5:9b")
        try:
            from ollama import Client  # type: ignore
        except ImportError as exc:
            raise RuntimeError("Pacote Python 'ollama' não instalado.") from exc
        self.client = Client(host=os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434"))

    def recover(self, task: Dict[str, Any], sub: Dict[str, Any], context: Dict[str, Any], failure_reason: str) -> str:
        prompt = (
            "És o módulo de recuperação do STARNet V17.\n"
            "Não inventes factos nem ferramentas. Analisa a falha e devolve uma única estratégia curta "
            "para a próxima tentativa.\n\n"
            f"Objetivo: {task['description']}\n"
            f"Subtarefa: {sub['tool']}\n"
            f"Tentativa: {sub['attempts']}\n"
            f"Falha: {failure_reason}\n"
            f"Contexto: {json.dumps(context, ensure_ascii=False)}"
        )
        response = self.client.chat(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1},
        )
        content = response["message"]["content"].strip()
        if not content:
            raise RuntimeError("O planner Ollama devolveu resposta vazia.")
        return content


def approval_fingerprint(task_id: str, subtask_id: str, tool: ToolSpec) -> str:
    raw = f"{task_id}|{subtask_id}|{tool.name}|{tool.risk}|{tool.fingerprint()}"
    return hashlib.sha256(raw.encode()).hexdigest()


def create_approval(store: Store, task_id: str, subtask_id: str, tool: ToolSpec, attempt: int) -> str:
    for ap in store.data["approvals"].values():
        if (
            ap["task_id"] == task_id
            and ap["subtask_id"] == subtask_id
            and ap["attempt"] == attempt
            and ap["state"] in {"WAITING_APPROVAL", "APPROVED"}
        ):
            return ap["id"]
    ap_id = rid("APR")
    store.data["approvals"][ap_id] = {
        "id": ap_id,
        "task_id": task_id,
        "subtask_id": subtask_id,
        "tool": tool.name,
        "risk": tool.risk,
        "attempt": attempt,
        "fingerprint": approval_fingerprint(task_id, subtask_id, tool),
        "state": "WAITING_APPROVAL",
        "execution_count": 0,
        "created_at": now(),
        "updated_at": now(),
    }
    store.save()
    audit("APPROVAL_CREATED", approval_id=ap_id, task_id=task_id, subtask_id=subtask_id, attempt=attempt)
    return ap_id


def verify_write(target: Path, expected: str) -> Dict[str, Any]:
    content = target.read_text(encoding="utf-8")
    return {
        "path": str(target),
        "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        "content_matches": content == expected,
    }


def _failure_once_marker(task_id: str) -> Path:
    return SANDBOX / f"failure_once_{task_id}.marker"


def dispatch(registry: ToolRegistry, task_id: str, subtask_id: str, tool_name: str, allow_write: bool = False) -> Evidence:
    tool = registry.get(tool_name)
    if tool.risk != "READ_ONLY" and not allow_write:
        raise PermissionError(f"Aprovação humana necessária: {tool.risk}")

    if tool.name == "sandbox_write_test":
        target = SANDBOX / "v17_0_write_test.txt"
        expected = "V17.1 — escrita autorizada pelo utilizador.\n"
        target.write_text(expected, encoding="utf-8")
        details = verify_write(target, expected)
        return Evidence(
            rid("EVD"),
            subtask_id,
            tool.name,
            0,
            "",
            "",
            bool(details["content_matches"]),
            details,
        )

    if tool.name == "sandbox_failure_once":
        marker = _failure_once_marker(task_id)
        if not marker.exists():
            marker.write_text("fail-once", encoding="utf-8")
            return Evidence(rid("EVD"), subtask_id, tool.name, 1, "", "Falha controlada da V17.1", False, {"recoverable": True})
        return Evidence(rid("EVD"), subtask_id, tool.name, 0, "RECOVERY_SUCCESS", "", True, {"recovered": True})

    proc = subprocess.run(
        tool.command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
    )
    stdout = proc.stdout.strip()
    stderr = proc.stderr.strip()
    return Evidence(
        rid("EVD"),
        subtask_id,
        tool.name,
        proc.returncode,
        stdout,
        stderr,
        proc.returncode == 0,
        {"command": tool.command, "risk": tool.risk},
    )


def ensure_approval(store: Store, task_id: str, subtask_id: str, tool: ToolSpec, attempt: int) -> str:
    return create_approval(store, task_id, subtask_id, tool, attempt)


def set_intervention(store: Store, task_id: str, subtask_id: str, reason: str) -> str:
    intervention_id = rid("HUM")
    store.data["interventions"][intervention_id] = {
        "id": intervention_id,
        "task_id": task_id,
        "subtask_id": subtask_id,
        "reason": reason,
        "state": "WAITING_HUMAN",
        "created_at": now(),
        "updated_at": now(),
    }
    store.save()
    audit("HUMAN_INTERVENTION_REQUESTED", intervention_id=intervention_id, task_id=task_id, subtask_id=subtask_id)
    return intervention_id


def execute_subtask(
    registry: ToolRegistry,
    store: Store,
    context_manager: ContextManager,
    memory: MemoryStore,
    evaluator: Evaluator,
    planner: Planner,
    context_assistant: ContextAssistant,
    task_id: str,
    subtask_id: str,
    approved: bool = False,
    allow_replan: bool = True,
) -> bool:
    task = get_task(store, task_id)
    sub = next((s for s in task["subtasks"] if s["id"] == subtask_id), None)
    if not sub:
        print("Subtask inexistente.")
        return False
    if sub["status"] == "COMPLETED":
        print(f"{subtask_id} já está COMPLETED.")
        return True

    ok, reason = dependencies_met(sub, task)
    if not ok:
        sub["status"] = "BLOCKED"
        sub["reason"] = reason
        task["status"] = "BLOCKED"
        context_manager.add_gap(task_id, reason)
        store.save()
        print(f"{subtask_id} → BLOCKED")
        print(f"Razão: {reason}")
        return False

    tool = registry.get(sub["tool"])
    next_attempt = sub["attempts"] + 1

    if tool.risk != "READ_ONLY" and not approved:
        ap_id = ensure_approval(store, task_id, subtask_id, tool, next_attempt)
        sub["status"] = "WAITING_APPROVAL"
        sub["reason"] = f"Aguardando aprovação {ap_id} para a tentativa {next_attempt}."
        task["status"] = "WAITING_APPROVAL"
        store.save()
        print(f"APROVAÇÃO HUMANA NECESSÁRIA: {tool.risk}")
        print(f"Approval {ap_id}")
        return False

    manual_retry = sub.get("manual_retry_allowance", 0) > 0
    if next_attempt > sub["max_attempts"] and not manual_retry:
        sub["status"] = "HUMAN_INTERVENTION"
        reason = f"Limite de {sub['max_attempts']} tentativas atingido."
        sub["reason"] = reason
        task["status"] = "HUMAN_INTERVENTION"
        intervention_id = set_intervention(store, task_id, subtask_id, reason)
        sub["reason"] = f"{reason} Intervenção {intervention_id}."
        store.save()
        print(f"HUMAN_INTERVENTION {intervention_id}")
        return False
    if manual_retry:
        sub["manual_retry_allowance"] = max(0, sub.get("manual_retry_allowance", 0) - 1)

    sub["status"] = "EXECUTING"
    sub["attempts"] = next_attempt
    task["status"] = "EXECUTING"
    task["attempt_cycle"] += 1
    task["updated_at"] = now()
    store.save()  # checkpoint antes do executor

    try:
        evidence = dispatch(registry, task_id, subtask_id, sub["tool"], allow_write=approved)
    except Exception as exc:
        sub["status"] = "FAILED"
        sub["reason"] = str(exc)
        task["status"] = "FAILED"
        context_manager.add_fact(task_id, f"Falha de execução: {exc}", "executor")
        context_manager.add_gap(task_id, str(exc))
        assist_report = context_assistant.assist(task_id, str(exc))
        memory_matches = context_manager.resolve_gaps_from_memory(task_id)
        if assist_report.facts_added:
            context_manager.record_recovery_note(
                task_id,
                f"Context Assistant encontrou {assist_report.facts_added} evidência(s) antes do replaneamento."
            )
        if memory_matches:
            context_manager.record_recovery_note(task_id, f"Memória recuperada antes do replaneamento: {len(memory_matches)} entrada(s).")
        context_manager.record_attempt(task_id, subtask_id, sub["attempts"], f"EXECUTION_ERROR: {exc}")
        memory.add(
            "failure",
            f"Falha na tarefa {task_id} — tentativa {sub['attempts']}",
            f"Ferramenta: {sub['tool']}\nMotivo: {exc}",
            task_id,
            ["starnet", "failure"],
        )
        store.save()
        if allow_replan and sub["attempts"] < sub["max_attempts"]:
            plan = planner.recover(task, sub, context_manager.get(task_id), str(exc))
            sub["status"] = "RETRY_PENDING"
            sub["plan_note"] = plan
            sub["reason"] = f"Replaneamento: {plan}"
            task["status"] = "RETRYING"
            context_manager.record_recovery_note(task_id, plan)
            store.save()
            print(f"RETRY_PENDING: {plan}")
        return False

    verified, verification_reason = evaluator.evaluate(evidence, tool)
    evidence.verified = verified
    evidence.details["verification_reason"] = verification_reason
    store.data["evidence"][evidence.id] = asdict(evidence)
    sub["evidence_id"] = evidence.id
    context_manager.record_attempt(
        task_id,
        subtask_id,
        sub["attempts"],
        f"{'SUCCESS' if verified else 'FAILED_VERIFICATION'}: {verification_reason}",
    )

    if verified:
        sub["status"] = "COMPLETED"
        sub["reason"] = ""
        sub["plan_note"] = ""
        memory.add(
            "success",
            f"Sucesso na tarefa {task_id} — {sub['tool']}",
            f"Tentativa: {sub['attempts']}\nEvidência: {evidence.id}\nVerificação: {verification_reason}",
            task_id,
            ["starnet", "success"],
        )
        # Uma lacuna só é fechada aqui quando a própria tarefa produziu evidência verificável de sucesso.
        prior_gaps = list(context_manager.get(task_id).get("gaps", []))
        for gap in prior_gaps:
            if "Falha" in gap or "falhou" in gap.lower():
                context_manager.resolve_gap(task_id, gap)
        task["status"] = (
            "COMPLETED"
            if all(s["status"] == "COMPLETED" for s in task["subtasks"])
            else "RUNNING"
        )
        store.save()
        print(f"Subtask {subtask_id} → COMPLETED")
        print(f"Evidence {evidence.id}")
        print(f"Verified {verified}")
        return True

    sub["status"] = "FAILED_VERIFICATION"
    sub["reason"] = verification_reason
    context_manager.add_fact(task_id, f"Verificação falhou: {verification_reason}", "evaluator")
    context_manager.add_gap(task_id, verification_reason)
    assist_report = context_assistant.assist(task_id, verification_reason)
    memory_matches = context_manager.resolve_gaps_from_memory(task_id)
    if assist_report.facts_added:
        context_manager.record_recovery_note(
            task_id,
            f"Context Assistant encontrou {assist_report.facts_added} evidência(s) após falha de verificação."
        )
    if memory_matches:
        context_manager.record_recovery_note(task_id, f"Memória recuperada após falha de verificação: {len(memory_matches)} entrada(s).")
    memory.add(
        "failure",
        f"Falha de verificação na tarefa {task_id} — tentativa {sub['attempts']}",
        f"Ferramenta: {sub['tool']}\nMotivo: {verification_reason}\nEvidência: {evidence.id}",
        task_id,
        ["starnet", "verification"],
    )

    if sub["attempts"] < sub["max_attempts"] and allow_replan:
        plan = planner.recover(task, sub, context_manager.get(task_id), verification_reason)
        sub["status"] = "RETRY_PENDING"
        sub["plan_note"] = plan
        sub["reason"] = f"Replaneamento: {plan}"
        task["status"] = "RETRYING"
        context_manager.record_recovery_note(task_id, plan)
        store.save()
        print(f"RETRY_PENDING: {plan}")
    else:
        task["status"] = "HUMAN_INTERVENTION"
        intervention_id = set_intervention(store, task_id, subtask_id, verification_reason)
        sub["status"] = "HUMAN_INTERVENTION"
        sub["reason"] = f"{verification_reason} Intervenção {intervention_id}."
        store.save()
        print(f"HUMAN_INTERVENTION {intervention_id}")
    return False


def run_all(
    registry: ToolRegistry,
    store: Store,
    context_manager: ContextManager,
    memory: MemoryStore,
    evaluator: Evaluator,
    planner: Planner,
    context_assistant: ContextAssistant,
    task_id: str,
) -> None:
    task = get_task(store, task_id)
    task["status"] = "RUNNING"
    store.save()

    while True:
        task = get_task(store, task_id)
        progress = False
        unresolved = False

        for sub in task["subtasks"]:
            if sub["status"] == "COMPLETED":
                continue
            unresolved = True

            if sub["status"] == "WAITING_APPROVAL":
                print(f"A aguardar aprovação: {sub['reason']}")
                task["status"] = "WAITING_APPROVAL"
                store.save()
                return

            if sub["status"] in {"HUMAN_INTERVENTION", "BLOCKED", "RECOVERY_REQUIRED"}:
                task["status"] = "HUMAN_INTERVENTION" if sub["status"] == "HUMAN_INTERVENTION" else sub["status"]
                store.save()
                return

            if sub["status"] == "RETRY_PENDING":
                sub["status"] = "PENDING"
                task["status"] = "RETRYING"
                store.save()

            before = sub["status"]
            result = execute_subtask(
                registry,
                store,
                context_manager,
                memory,
                evaluator,
                planner,
                context_assistant,
                task_id,
                sub["id"],
            )
            task = get_task(store, task_id)
            if result or sub["status"] != before:
                progress = True

            if sub["status"] == "WAITING_APPROVAL":
                task["status"] = "WAITING_APPROVAL"
                store.save()
                return
            if sub["status"] == "HUMAN_INTERVENTION":
                return

        task = get_task(store, task_id)
        if all(s["status"] == "COMPLETED" for s in task["subtasks"]):
            task["status"] = "COMPLETED"
            task["updated_at"] = now()
            store.save()
            print("============================================================")
            print("STARNet V17.1 — TAREFA CONCLUÍDA E VERIFICADA")
            print("============================================================")
            return

        if not progress or not unresolved:
            task["status"] = "HUMAN_INTERVENTION"
            intervention_id = set_intervention(
                store,
                task_id,
                "ALL",
                "O loop não encontrou progresso seguro adicional.",
            )
            store.save()
            print(f"HUMAN_INTERVENTION {intervention_id}")
            return



def resume_recovery(
    registry: ToolRegistry,
    store: Store,
    context_manager: ContextManager,
    memory: MemoryStore,
    evaluator: Evaluator,
    planner: Planner,
    context_assistant: ContextAssistant,
    task_id: str,
) -> None:
    """
    Retoma tarefas interrompidas de forma controlada.

    READ_ONLY:
        Pode ser retomada automaticamente porque a repeticao
        nao produz uma alteracao externa conhecida.

    WRITE / outras operacoes:
        Nao sao retomadas automaticamente. O estado passa para
        HUMAN_INTERVENTION porque um estado EXECUTING interrompido
        nao permite provar se o efeito externo chegou ou nao a ocorrer.
    """
    task = get_task(store, task_id)

    recovery_subtasks = [
        sub
        for sub in task["subtasks"]
        if sub["status"] == "RECOVERY_REQUIRED"
    ]

    if not recovery_subtasks:
        print("RECOVERY_NOT_FOUND: nenhuma subtask em RECOVERY_REQUIRED.")
        return

    blocked_for_human = False

    for sub in recovery_subtasks:
        tool = registry.get(sub["tool"])

        if tool.risk == "READ_ONLY":
            sub["status"] = "PENDING"
            sub["reason"] = (
                "Recovery retomado com seguranca: "
                "ferramenta READ_ONLY."
            )

            task["status"] = "RUNNING"
            task["updated_at"] = now()

            audit(
                "RECOVERY_RESUMED",
                task_id=task_id,
                subtask_id=sub["id"],
                tool=tool.name,
                risk=tool.risk,
            )

            context_manager.record_recovery_note(
                task_id,
                f"Recovery retomado automaticamente para {tool.name}: READ_ONLY.",
            )

        else:
            reason = (
                "Recuperacao requer decisao humana: "
                "a ferramenta nao e READ_ONLY e o estado EXECUTING "
                "interrompido nao permite confirmar se houve efeito externo."
            )

            intervention_id = set_intervention(
                store,
                task_id,
                sub["id"],
                reason,
            )

            sub["status"] = "HUMAN_INTERVENTION"
            sub["reason"] = (
                f"{reason} Intervencao {intervention_id}."
            )

            task["status"] = "HUMAN_INTERVENTION"
            task["updated_at"] = now()

            audit(
                "RECOVERY_HUMAN_REQUIRED",
                task_id=task_id,
                subtask_id=sub["id"],
                tool=tool.name,
                risk=tool.risk,
                intervention_id=intervention_id,
            )

            blocked_for_human = True

    store.save()

    if blocked_for_human:
        print("RECOVERY_HUMAN_INTERVENTION_REQUIRED")
        return

    run_all(
        registry,
        store,
        context_manager,
        memory,
        evaluator,
        planner,
        context_assistant,
        task_id,
    )

def show_status(store: Store, task_id: Optional[str]) -> None:
    if task_id:
        task = store.data["tasks"].get(task_id)
        if not task:
            print("Task inexistente.")
            return
        print(json.dumps(task, ensure_ascii=False, indent=2))
        print("--- CONTEXTO ---")
        print(json.dumps(store.data.get("context", {}).get(task_id, {}), ensure_ascii=False, indent=2))
        return
    for task in store.data["tasks"].values():
        print(f"{task['id']} | {task['status']} | {task['description']}")
        for sub in task["subtasks"]:
            print(
                f"  {sub['id']} | {sub['tool']} | {sub['status']} | "
                f"attempts={sub['attempts']}/{sub.get('max_attempts', DEFAULT_MAX_ATTEMPTS)} | "
                f"evidence={sub.get('evidence_id')}"
            )


def approve(
    store: Store,
    registry: ToolRegistry,
    context_manager: ContextManager,
    memory: MemoryStore,
    evaluator: Evaluator,
    planner: Planner,
    context_assistant: ContextAssistant,
    approval_id: str,
) -> None:
    ap = store.data["approvals"].get(approval_id)
    if not ap:
        print("Approval inexistente.")
        return
    if ap["state"] != "WAITING_APPROVAL":
        print(f"ERRO: Approval já está em estado {ap['state']}.")
        return

    task = get_task(store, ap["task_id"])
    sub = next((s for s in task["subtasks"] if s["id"] == ap["subtask_id"]), None)
    if not sub:
        print("Subtask inexistente.")
        return
    tool = registry.get(ap["tool"])

    expected = approval_fingerprint(task["id"], sub["id"], tool)
    if expected != ap["fingerprint"]:
        ap["state"] = "INTEGRITY_BLOCKED"
        store.save()
        print("ERRO: fingerprint inválido. Execução bloqueada.")
        return
    if ap["execution_count"] >= 1:
        ap["state"] = "REPLAY_BLOCKED"
        store.save()
        print("REPLAY_BLOCKED: esta approval já teve uma execução.")
        return

    ap["state"] = "APPROVED"
    ap["approved_at"] = now()
    store.save()
    print(f"APROVACAO REGISTADA: {approval_id}")

    ok = execute_subtask(
        registry,
        store,
        context_manager,
        memory,
        evaluator,
        planner,
        context_assistant,
        task["id"],
        sub["id"],
        approved=True,
    )
    ap["execution_count"] += 1
    ap["state"] = "EXECUTED" if ok else "EXECUTION_FAILED"
    ap["updated_at"] = now()
    store.save()
    print(f"ApprovalState {ap['state']}")
    print(f"ExecutionCnt {ap['execution_count']}")


def human_approve_retry(store: Store, intervention_id: str, note: str = "Retry autorizado pelo humano.") -> None:
    intervention = store.data["interventions"].get(intervention_id)
    if not intervention:
        raise KeyError(f"Intervenção inexistente: {intervention_id}")
    if intervention["state"] != "WAITING_HUMAN":
        raise ValueError(f"Intervenção não está aguardando humano: {intervention['state']}")
    task = get_task(store, intervention["task_id"])
    sub = next((s for s in task["subtasks"] if s["id"] == intervention["subtask_id"]), None)
    if not sub:
        raise KeyError("Subtask da intervenção inexistente.")
    sub["status"] = "PENDING"
    sub["reason"] = note
    sub["manual_retry_allowance"] = sub.get("manual_retry_allowance", 0) + 1
    task["status"] = "RUNNING"
    task["updated_at"] = now()
    intervention["state"] = "HUMAN_APPROVED_RETRY"
    intervention["resolution"] = note
    intervention["updated_at"] = now()
    store.save()
    audit("HUMAN_RETRY_APPROVED", intervention_id=intervention_id, task_id=task["id"], subtask_id=sub["id"], note=note)
    print(f"HUMAN_RETRY_APPROVED {intervention_id}")
    print(f"Subtask {sub['id']} preparada para nova tentativa.")


def main() -> None:
    parser = argparse.ArgumentParser(description="STARNet V17.1 — Context + State + Memory + Evaluator + Recovery Loop")
    sp = parser.add_subparsers(dest="cmd", required=True)

    sp.add_parser("tools")

    c = sp.add_parser("create-chain")
    c.add_argument("tools", nargs="+")
    c.add_argument("--description", default="Tarefa V17.1")
    c.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS)

    e = sp.add_parser("run")
    e.add_argument("task_id")
    e.add_argument("subtask_id")

    ra = sp.add_parser("run-all")
    ra.add_argument("task_id")
    ra.add_argument("--planner", choices=["deterministic", "ollama"], default="deterministic")
    ra.add_argument("--model", default=None)

    ap = sp.add_parser("approve")
    ap.add_argument("approval_id")
    ap.add_argument("--planner", choices=["deterministic", "ollama"], default="deterministic")
    ap.add_argument("--model", default=None)

    st = sp.add_parser("status")
    st.add_argument("task_id", nargs="?")

    hi = sp.add_parser("human-approve-retry")
    hi.add_argument("intervention_id")
    hi.add_argument("--note", default="Retry autorizado pelo humano.")

    rm = sp.add_parser("memory-search")
    rm.add_argument("query", nargs="+")

    cm = sp.add_parser("context")
    cm.add_argument("task_id")
    cm.add_argument("--resolve", action="store_true")

    ca = sp.add_parser("context-assist")
    ca.add_argument("task_id")
    ca.add_argument("query", nargs="+")

    rr = sp.add_parser("resume-recovery")
    rr.add_argument("task_id")
    rr.add_argument("--planner", choices=["deterministic", "ollama"], default="deterministic")
    rr.add_argument("--model", default=None)

    demo = sp.add_parser("demo-loop")
    demo.add_argument("--planner", choices=["deterministic", "ollama"], default="deterministic")
    demo.add_argument("--model", default=None)

    args = parser.parse_args()
    registry = ToolRegistry()
    store = Store()
    memory = MemoryStore()
    context_manager = ContextManager(store, memory)
    context_assistant = ContextAssistant(context_manager, memory)
    evaluator = Evaluator()
    planner: Planner = DeterministicRecoveryPlanner()

    try:
        if getattr(args, "planner", "deterministic") == "ollama" and args.cmd in {"run-all", "approve", "demo-loop"}:
            planner = OllamaRecoveryPlanner(getattr(args, "model", None))

        if args.cmd == "tools":
            registry.show()

        elif args.cmd == "create-chain":
            task = build_task(
                registry,
                store,
                args.tools,
                args.description,
                args.max_attempts,
            )
            print("============================================================")
            print("                         STARNet V17.1")
            print("============================================================")
            print(f"Task {task.id}")
            print(f"Description {task.description}")
            for i, sub in enumerate(task.subtasks, 1):
                sd = asdict(sub)
                print(
                    f"S{i} {sd['id']} | {sd['tool']} | deps={sd['deps']} | "
                    f"max_attempts={sd['max_attempts']}"
                )
            print("TaskState PENDING")

        elif args.cmd == "run":
            ok = execute_subtask(
                registry,
                store,
                context_manager,
                memory,
                evaluator,
                planner,
                args.task_id,
                args.subtask_id,
            )
            raise SystemExit(0 if ok else 1)

        elif args.cmd == "run-all":
            run_all(registry, store, context_manager, memory, evaluator, planner, context_assistant, args.task_id)

        elif args.cmd == "approve":
            approve(store, registry, context_manager, memory, evaluator, planner, context_assistant, args.approval_id)

        elif args.cmd == "status":
            show_status(store, args.task_id)

        elif args.cmd == "human-approve-retry":
            human_approve_retry(store, args.intervention_id, args.note)

        elif args.cmd == "memory-search":
            query = " ".join(args.query)
            results = memory.search(query)
            print(json.dumps(results, ensure_ascii=False, indent=2))

        elif args.cmd == "context":
            if args.resolve:
                matches = context_manager.resolve_gaps_from_memory(args.task_id)
                print(f"MemoryMatches {len(matches)}")
            print(json.dumps(context_manager.get(args.task_id), ensure_ascii=False, indent=2))

        elif args.cmd == "context-assist":
            query = " ".join(args.query)
            report = context_assistant.assist(args.task_id, query)
            print(json.dumps(asdict(report), ensure_ascii=False, indent=2))

        elif args.cmd == "resume-recovery":
            resume_recovery(
                registry,
                store,
                context_manager,
                memory,
                evaluator,
                planner,
                context_assistant,
                args.task_id,
            )

        elif args.cmd == "demo-loop":
            task = build_task(
                registry,
                store,
                ["sandbox_failure_once"],
                "DEMO V17.1 — demonstrar falha → contexto → replaneamento → sucesso",
                max_attempts=3,
            )
            print(f"DemoTask {task.id}")
            run_all(registry, store, context_manager, memory, evaluator, planner, context_assistant, task.id)
            print("--- FINAL STATUS ---")
            show_status(store, task.id)

    except Exception as exc:
        print(f"ERRO: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
