STARNet V17.0

Base: Automato V16.6

Ficheiros principais:
- agent_v17_0.py  -> nova versão
- STARNet_V17_CORE.md -> arquitetura
- agent_v16_6_backup.py -> cópia da V16.6 usada como base

Teste seguro:
python agent_v17_0.py demo-loop

Ferramentas:
python agent_v17_0.py tools

Criar tarefa:
python agent_v17_0.py create-chain whoami hostname --description "Diagnóstico"

Executar tarefa:
python agent_v17_0.py run-all TASK-ID

Consultar estado/contexto:
python agent_v17_0.py status TASK-ID

Memória:
python agent_v17_0.py memory-search "falha relatório"

Para ligar as notas Markdown diretamente a um Vault do Obsidian (PowerShell):
$env:STARNET_OBSIDIAN_VAULT = "C:\caminho\do\Vault"

Planner local opcional:
python agent_v17_0.py demo-loop --planner ollama --model qwen3.5:9b

IMPORTANTE:
A V17 usa ficheiros state_v17_0.json, audit_v17_0.jsonl, registry_v17_0.json e memory_v17_0.json separados da V16.6. Não apaga a V16.6.
