# Security Gate

Critério de aceite de segurança do pipeline. O job `security-gate` do
workflow reprova o build quando a política abaixo é violada.

## Política

| Camada | Critério para reprovar | Por quê |
|---|---|---|
| SCA (Trivy) | CVE **HIGH ou CRITICAL** com correção disponível (`ignore-unfixed`) | Só bloqueia o que o time consegue corrigir; CVE sem correção vira risco aceito documentado |
| SAST (Semgrep) | Finding de severidade **ERROR** no código da aplicação (`./app`) | Escopo restrito à aplicação; achados do próprio workflow ficam fora (ver TRIAGE.md) |
| DAST (ZAP) | Não bloqueia | Baseline scan passivo gera muito alerta informativo; entra na triagem manual |

## Modos

O comportamento é controlado pela variável de repositório `GATE_MODE`
(Settings → Secrets and variables → Actions → Variables):

| Valor | Efeito |
|---|---|
| `enforce` (padrão) | O build **falha** se algum critério for violado |
| `report` | O build passa, mas o resumo e um aviso mostram que o gate reprovaria |

Este repositório contém uma aplicação **vulnerável de propósito**, então em
`enforce` o gate reprova. Isso é o comportamento esperado e comprova que o
critério bloqueia. Para manter a branch principal verde, use `report`.

## Exceções

Uma exceção é válida somente com:

1. **Justificativa técnica** (ex.: componente não alcançável, documentado no TRIAGE.md);
2. **Prazo de revisão**;
3. **Aprovação** de quem responde pelo risco.

No Trivy, a forma recomendada é um arquivo de exceções com a justificativa
e a data de expiração, ou um documento VEX. Nunca desligar a verificação.

## Limites desta política

- O Trivy reporta por **presença** da biblioteca, não por **uso efetivo**.
  Um HIGH em código não alcançável bloqueia, e a saída é a exceção justificada.
- O gate usa severidade nominal como filtro de entrada; a **priorização**
  real (alcançabilidade, exposição, dado sensível) continua na triagem manual.
- Falhas de lógica de negócio (IDOR, enumeração de usuários) não são
  detectadas por nenhuma camada do gate. Dependem de revisão.
