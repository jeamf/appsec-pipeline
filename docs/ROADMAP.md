# Roteiro de execução

Plano realista para dois dias. O ponto de corte está marcado: se acabar o
tempo no fim do Dia 1, o projeto já é publicável.

## Dia 1 — pipeline funcionando

### 1. Preparar o repositório (30 min)
- Criar repo `appsec-pipeline` no GitHub (público)
- Subir a estrutura de arquivos
- Confirmar que a aplicação compila: `cd app && mvn clean package -DskipTests`

### 2. Validar localmente antes do CI (1h)
Rodar as três ferramentas na mão primeiro. É mais rápido depurar local do que
esperar o Actions.

```bash
docker run --rm -v "$PWD:/src" semgrep/semgrep \
  semgrep scan --config=p/java --config=p/owasp-top-ten --config=p/secrets

docker run --rm -v "$PWD:/src" aquasec/trivy fs /src/app
```

Anotar o que cada ferramenta pegou — isso vira material do TRIAGE.

### 3. Ativar o CI (1h)
- Commit do workflow
- Acompanhar a primeira execução em Actions
- Ajustar o que quebrar (normalmente é path ou versão de action)
- Confirmar que os findings aparecem em Security → Code scanning

### 4. Capturar evidências (30 min)
Prints para `docs/`:
- Actions com os três jobs verdes
- Aba Security com os findings
- Terminal mostrando a exploração de VULN-01

**➜ PONTO DE CORTE.** Com isso feito, o repositório já é apresentável.

---

## Dia 2 — o diferencial

### 5. Triagem real (2-3h)
Esta é a parte que importa. O `TRIAGE.md` do repositório é um **modelo
preenchido com a análise esperada** — reescreva com o que as ferramentas
realmente reportaram na sua execução.

Para cada finding:
- A ferramenta apontou algo que existe?
- É alcançável por entrada do usuário?
- Existe barreira que impeça exploração?
- Qual o impacto real neste contexto?

Não invente falso positivo. Se o Semgrep não gerou nenhum, diga isso — é uma
observação honesta e vale mais que um FP fabricado.

### 6. Validar as explorações (1h)
Testar na mão pelo menos três: SQLi, path traversal e command injection.
Guardar o output como evidência.

### 7. Finalizar o README (30 min)
- Adicionar screenshot do pipeline no topo
- Conferir se os números da tabela batem com a triagem real

---

## Depois (opcional)

- Branch `fix/` com as correções aplicadas, mostrando o pipeline passando
- Dockerfile e docker-compose
- Testes automatizados que provam cada exploração
- Estender para uma segunda linguagem (Python ou Node)

---

## Como falar disso em entrevista

O ponto forte não é "rodei três ferramentas". É:

> "Montei um pipeline com SAST, DAST e SCA sobre uma API que escrevi com
> vulnerabilidades conhecidas, para comparar cobertura entre as camadas. O
> resultado que achei mais interessante é que duas das falhas — um IDOR e uma
> enumeração de usuários — não foram detectadas por nenhuma ferramenta, porque
> são falhas de lógica de negócio e o código está sintaticamente correto. Isso
> me deu uma noção prática de onde o automatizado ajuda e onde a revisão
> manual é insubstituível."

Essa frase demonstra critério, não só execução.
