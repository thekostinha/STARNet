STARNet V17.1

Base: V16.6 + V17.0

Novidade principal:
Context Assistant read-only para procurar informação em memória e workspace antes de desistir.

Ficheiro principal:
agent_v17_1.py

Comandos:
  python agent_v17_1.py tools
  python agent_v17_1.py demo-loop
  python agent_v17_1.py context-assist TASK-ID "consulta"
  python agent_v17_1.py memory-search "consulta"
  python agent_v17_1.py context TASK-ID
  python agent_v17_1.py create-chain ...
  python agent_v17_1.py run-all TASK-ID
  python agent_v17_1.py human-approve-retry HUM-ID

Ollama opcional:
  python agent_v17_1.py demo-loop --planner ollama --model qwen3.5:9b

Obsidian:
  $env:STARNET_OBSIDIAN_VAULT = "C:\caminho\para\Vault"

Notas:
- Não substituir a V16.6.
- A V17.1 usa um estado/memória/auditoria próprios.
- Ferramentas não READ_ONLY continuam sujeitas a aprovação.
