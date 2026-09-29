# STARNet V17.0 — Core

## Objetivo
A V17.0 evolui a V16.6 sem apagar a base existente. O núcleo passa a tratar explicitamente contexto, estado, memória, verificação, recuperação e intervenção humana.

## Fluxo

Humano → STARNet Controller → Context Manager + State → Inteligência/Planner → Plano → Aprovação quando exigida → Automato → Execução → Evaluator →

- Sucesso: memória → COMPLETED
- Falha: diagnóstico → contexto/memória → replaneamento → novo ciclo
- Limite/impasse: HUMAN_INTERVENTION

## Regra central
Executar não é concluir. Uma tarefa só termina quando existe evidência de que o resultado esperado foi verificado.

## Estado
PENDING, RUNNING, WAITING_APPROVAL, RETRYING, COMPLETED, BLOCKED, HUMAN_INTERVENTION, RECOVERY_REQUIRED.

## Memória
A V17 grava um índice JSON e notas Markdown. As notas Markdown podem residir diretamente num Vault do Obsidian através da variável de ambiente `STARNET_OBSIDIAN_VAULT`.

Exemplo PowerShell:
`$env:STARNET_OBSIDIAN_VAULT = "C:\\caminho\\para\\o\\Vault"`

## Inteligência local
A V17 inclui um adaptador opcional para Ollama/Qwen (`--planner ollama`). O núcleo determinístico funciona sem depender do modelo.

## Segurança
Ferramentas com risco diferente de `READ_ONLY` exigem aprovação. A aprovação é associada à ferramenta e ao identificador da tarefa/subtarefa através de fingerprint; replay da mesma aprovação é bloqueado.

## Próxima evolução natural
1. Router de modelos (local vs. remoto).
2. Agentes especializados e delegação pelo Automato.
3. Recuperação de contexto mais rica.
4. Avaliadores por tipo de tarefa.
5. Interface do STARNet.
