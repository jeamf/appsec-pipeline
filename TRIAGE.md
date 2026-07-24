# Triagem de Findings

Este documento é o núcleo do projeto. Rodar ferramenta é fácil; o trabalho de
AppSec começa depois, quando é preciso decidir **o que é real, o que é ruído
e o que a ferramenta não viu**.

Os números abaixo vêm da execução real do pipeline, não de estimativa.

Cada finding passou por quatro perguntas:

1. A ferramenta apontou algo que existe de fato no código?
2. O trecho é alcançável por entrada controlada pelo usuário?
3. Existe alguma barreira que impeça a exploração?
4. Qual o impacto real neste contexto específico?

---

## Resumo da execução — SAST (Semgrep)

**17 findings reportados** sobre 14 arquivos, com 595 regras.

| Classificação | Qtd | Observação |
|---|---:|---|
| Vulnerabilidades reais da aplicação | 5 | confirmadas manualmente |
| Duplicação entre regras | 1 | mesma linha, 2 regras |
| Fora do escopo da aplicação | 11 | achados sobre o próprio workflow |
| **Findings brutos** | **17** | |

**A conta que importa:** dos 17 findings, apenas **5 apontam vulnerabilidades
reais na aplicação**. Os outros 12 são duplicação ou escopo diferente.

E na direção oposta: **4 vulnerabilidades reais do código não foram
detectadas** por nenhuma regra.

---

## Confirmados pelo SAST

### VULN-01 · SQL Injection
**Onde:** `UserController.search()` — linha 38
**Regras:** `java.spring.security.injection.tainted-sql-string` e
`java.spring.security.audit.spring-sqli`
**CWE-89 · OWASP A03:2021 · Severidade: Crítica**

```java
String sql = "SELECT id, username, email FROM users WHERE username = '" + name + "'";
```

**Nota de triagem — deduplicação:** duas regras distintas dispararam sobre a
mesma vulnerabilidade, em linhas adjacentes (38 e 39). Uma rastreia o fluxo de
dados até a string; a outra aponta o consumo dessa string pelo `JdbcTemplate`.
São dois findings para **um** problema.

Isso importa na prática: relatar "17 vulnerabilidades" quando há duplicação
inflaciona a métrica e desgasta a relação com o time de desenvolvimento. A
contagem que deve chegar ao dev é por vulnerabilidade única, não por linha
sinalizada.

**Validação da explorabilidade:** confirmada.

```
GET /api/users/search?name=' OR '1'='1
```

Retorna todos os registros, comprovando que a entrada altera a estrutura da
query. O endpoint não exige autenticação e a tabela contém CPF e hash de
senha.

**Correção:** query parametrizada — implementada em `searchFixed()` no mesmo
arquivo, para comparação direta.

---

### VULN-10 · Command Injection
**Onde:** `FileController.info()` — linha 74
**Regra:** `java.spring.security.injection.tainted-system-command`
**CWE-78 · OWASP A03:2021 · Severidade: Crítica**

```java
Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
```

O uso de `sh -c` faz o shell interpretar metacaracteres, então `;`, `|` e
`$()` encadeiam comandos arbitrários.

**Correção:** substituir por API nativa (`Files.readAttributes`). Se um
processo externo for necessário, usar `ProcessBuilder` com argumentos em array
separado — sem shell.

---

### VULN-08 · Path Traversal
**Onde:** `FileController.read()` — linha 32
**Regra:** `java.spring.security.injection.tainted-file-path`
**CWE-22 · OWASP A01:2021 · Severidade: Alta**

```java
File file = new File(UPLOAD_DIR + name);
```

**Correção:** resolver o caminho e validar que permanece dentro do diretório
permitido:

```java
Path base = Paths.get(UPLOAD_DIR).toRealPath();
Path target = base.resolve(name).normalize();
if (!target.startsWith(base)) {
    throw new SecurityException("Caminho fora do diretorio permitido");
}
```

---

### VULN-09 · Upload sem validação
**Onde:** `FileController.upload()` — linha 55
**Regra:** `tainted-file-path` (mesma regra de VULN-08)
**CWE-434 · OWASP A04:2021**

```java
Files.write(Paths.get(UPLOAD_DIR + original), file.getBytes());
```

**Nota de triagem:** a regra detectou o *path traversal* no nome do arquivo,
que é real. Mas a vulnerabilidade mais grave aqui é outra: **não há validação
de extensão nem de content-type**. A ferramenta viu metade do problema.

Esse é um padrão que vale registrar — o finding está correto, porém
incompleto. Quem só corrige o que a ferramenta apontou (normalizar o path)
deixa o upload irrestrito de pé.

**Severidade neste contexto:** o diretório `/tmp/uploads/` não é servido pelo
container web, então o caminho clássico de exploração (subir `.jsp` e acessar
via HTTP) não se aplica neste deploy. Mas a proteção é **ambiental, não de
código** — se o diretório for exposto no futuro, a falha volta a ser crítica.

**Decisão:** documentado como dívida técnica com correção prevista.

---

### VULN-05 · Hash de senha com MD5
**Onde:** `AuthController.hashPassword()` — linha 47
**Regra:** `java.lang.security.audit.crypto.use-of-md5`
**CWE-327 · OWASP A02:2021 · Severidade: Alta**

**Nota sobre o autofix sugerido:** o Semgrep ofereceu substituir `MD5` por
`SHA-512`. **A sugestão é inadequada para este caso.**

SHA-512 é mais forte contra colisão, mas continua sendo um hash rápido — e
velocidade é exatamente o que favorece força bruta em senha. A correção certa
é um algoritmo deliberadamente lento e com salt: **BCrypt, Argon2 ou PBKDF2**.

Aceitar o autofix aqui daria uma falsa sensação de correção. É um bom exemplo
de por que sugestão automática precisa de revisão humana.

---

## Não detectados pelo SAST

Esta seção é a mais importante do documento. Quatro vulnerabilidades reais
passaram pelas 595 regras sem gerar um único finding.

### VULN-04 · Segredo hardcoded — *não detectado*
**Onde:** `AuthController.JWT_SECRET`
**CWE-798 · OWASP A07:2021 · Severidade: Crítica**

```java
private static final String JWT_SECRET = "minha-chave-secreta-123";
```

**Por que não foi detectado:** o scan rodou com `--config=p/secrets`, que é o
ruleset específico para segredos — e ainda assim não pegou.

A hipótese mais provável é que as regras de detecção de segredo procuram
padrões de alta entropia ou formatos reconhecíveis (chaves AWS, tokens do
GitHub, certificados). Uma string em português, curta e legível, não bate com
nenhum desses padrões — parece um valor de configuração comum.

**Por que isso é grave:** é uma das vulnerabilidades mais críticas do projeto.
Com essa chave, qualquer pessoa forja um token com `role: ADMIN` sem depender
de nenhuma outra falha. E ela está no histórico do Git, então permanece
exposta mesmo após remoção do código.

**Lição prática:** detecção de segredo por entropia falha justamente nos
segredos fracos — que são os mais fáceis de explorar. Complementar com
revisão manual e com hooks de pre-commit é necessário.

---

### VULN-11 · CORS permissivo — *não detectado*
**Onde:** `SecurityConfig.addCorsMappings()`
**CWE-942 · OWASP A05:2021 · Severidade: Alta**

```java
registry.addMapping("/**")
        .allowedOriginPatterns("*")
        .allowCredentials(true);
```

**Por que não foi detectado:** a combinação perigosa está distribuída em
chamadas encadeadas. Cada método isolado é legítimo; o risco surge da
**combinação** de origem coringa com credenciais habilitadas. Regra baseada em
padrão sintático não captura bem esse tipo de composição.

Vale notar que o DAST tende a pegar isso, porque observa os headers da
resposta HTTP real — é um caso onde as camadas se complementam.

---

### VULN-02 · IDOR — *não detectado*
**Onde:** `UserController.getById()`
**CWE-639 · OWASP A01:2021 · Severidade: Alta**

Este é o exemplo mais claro do limite do SAST. O código está **sintaticamente
correto**: a query é parametrizada, não há concatenação, não há padrão
inseguro algum.

O problema é de **lógica de negócio** — o endpoint não verifica se quem pede
tem direito de ver aquele recurso. Nenhuma ferramenta infere isso sem
conhecer a intenção da aplicação.

Controle de acesso quebrado é a categoria **A01 do OWASP Top 10** — a primeira
da lista — e é justamente onde a análise automatizada é mais fraca.

---

### VULN-06 · Enumeração de usuários — *não detectado*
**Onde:** `AuthController.login()`
**CWE-209 · Severidade: Média**

A resposta distingue "usuário não encontrado" de "senha incorreta". Também é
falha de lógica: o código funciona exatamente como foi escrito, mas o
comportamento vaza informação.

---

## Fora do escopo da aplicação

**11 dos 17 findings** são da regra
`yaml.github-actions.security.github-actions-mutable-action-tag`, aplicada ao
próprio `.github/workflows/appsec.yml`.

A regra alerta que referenciar actions por tag (`@v4`) em vez de commit SHA
permite que o mantenedor reaponte a tag silenciosamente.

**É um achado legítimo?** Sim. E é oportuno: a própria `trivy-action`
[sofreu comprometimento de supply chain](https://github.com/aquasecurity/trivy-action/releases/tag/v0.35.0)
e migrou o esquema de tags por causa disso.

**Por que classifiquei como fora de escopo:** o objetivo deste scan era
avaliar a segurança da *aplicação*. Achados sobre a infraestrutura de CI são
uma superfície diferente, com outro dono e outro nível de risco.

**Nota de triagem — o problema da razão sinal/ruído:** 11 de 17 findings
(65%) vinham de uma única regra sobre arquivos que não são a aplicação. Um
relatório entregue sem essa separação faria o time de desenvolvimento gastar a
atenção no lugar errado — e, pior, ensina o time a ignorar o relatório
seguinte.

**Ação:** separado em escopo próprio. Pinar as actions por SHA está no backlog
de melhoria do repositório, com prioridade menor que as vulnerabilidades da
aplicação.

---

## Resumo da execução — SCA (Trivy)

**28 CVEs** em `pom.xml` — 5 CRITICAL, 9 HIGH, 14 MEDIUM.

| Origem | Qtd | Observação |
|---|---:|---|
| Dependências declaradas de propósito | 8 | log4j-core (6), commons-text (1), h2 (1) |
| **Dependências transitivas** | **20** | jackson, spring-web, spring-webmvc, commons-lang3 |
| **Total** | **28** | |

**A descoberta mais relevante deste scan:** eu declarei 3 dependências
vulneráveis intencionalmente. O Trivy encontrou 28 CVEs — porque **20 delas
vêm de bibliotecas que ninguém escolheu**, arrastadas transitivamente pelo
`spring-boot-starter-parent:2.7.5`.

Nenhuma linha do `pom.xml` menciona `jackson-databind`, `spring-web`,
`spring-webmvc` ou `commons-lang3`. Elas entraram junto com o starter.

---

### Declaradas intencionalmente

**`log4j-core:2.14.1` — 6 CVEs**

| CVE | Severidade | O que é |
|---|---|---|
| CVE-2021-44228 | CRITICAL | Log4Shell — RCE via lookup JNDI |
| CVE-2021-45046 | CRITICAL | DoS via thread context |
| CVE-2021-45105 | HIGH | DoS via recursão em MDC |
| CVE-2021-44832 | MEDIUM | RCE via JDBC Appender |
| CVE-2025-68161 | MEDIUM | Falta de verificação de hostname TLS |
| CVE-2026-34477 | MEDIUM | MITM por verificação incompleta de hostname |

**Nota de triagem:** o Log4Shell é o caso didático perfeito para explicar
**alcançabilidade**. A CVE-2021-44228 só é explorável se a aplicação logar
conteúdo controlado pelo atacante. Nesta aplicação, o Log4j está declarado mas
não é usado ativamente para logar entrada de usuário — o Spring Boot usa
Logback por padrão.

Ou seja: a biblioteca vulnerável **está presente**, mas o caminho de
exploração **não está ativo**. Isso não significa ignorar — significa
priorizar corretamente. Uma dependência não usada deve ser **removida**, que é
mais simples e definitivo que atualizar.

**`commons-text:1.9` — CVE-2022-42889 (CRITICAL)**
Text4Shell. RCE via interpolação de variável. Mesma análise: presente, mas sem
caminho de execução ativo nesta aplicação.

**`h2:2.1.214` — CVE-2022-45868 (HIGH)**
Console administrativo web do H2. **Esta é diferente das anteriores:**
`application.properties` tem `spring.h2.console.enabled=true`, então o
componente vulnerável **está ativo e exposto**.

Aqui o caminho de exploração existe de fato. Prioridade mais alta que as duas
CRITICAL acima, apesar da severidade nominal ser menor — exemplo claro de por
que CVSS sozinho não define prioridade.

---

### Transitivas — o volume real

**`jackson-databind:2.13.4.2` — 5 CVEs** (2 HIGH, 3 MEDIUM)
Duas permitem execução arbitrária de código via bypass de validação de tipo
polimórfico. A aplicação usa Jackson indiretamente — o Spring serializa as
respostas JSON com ela.

**`spring-web:5.3.23` — 6 CVEs** (1 CRITICAL, 3 HIGH, 2 MEDIUM)
A CRITICAL (CVE-2016-1000027) é desserialização insegura no
`HttpInvokerServiceExporter`. **Componente não utilizado nesta aplicação** — é
um mecanismo de RMI legado que exigiria configuração explícita.

Este é um bom candidato a supressão com justificativa (VEX), não a correção
urgente.

**`spring-webmvc:5.3.23` — 7 CVEs** (1 CRITICAL, 2 HIGH, 4 MEDIUM)
Várias de path traversal em `RouterFunctions` e recursos estáticos — recursos
que esta aplicação não usa.

**`commons-lang3:3.12.0` — 1 CVE** (MEDIUM)
Recursão descontrolada.

---

### Como eu priorizaria

Se este relatório chegasse a um time de desenvolvimento, entregar as 28 CVEs
em ordem de CVSS seria inútil. A ordem que faz sentido:

| Prioridade | Ação | Por quê |
|---|---|---|
| 1 | Desabilitar console H2 | Componente vulnerável ativo e exposto |
| 2 | Remover log4j-core e commons-text | Não são usados — remover é mais simples que atualizar |
| 3 | Atualizar spring-boot-starter-parent | Resolve ~20 CVEs transitivas de uma vez |
| 4 | Avaliar supressão com VEX | Componentes comprovadamente não alcançáveis |

**O ponto do item 3:** subir a versão do starter corrige a maioria das CVEs
transitivas em uma única mudança. Tratar cada CVE individualmente seria 20
tickets para o que é, na prática, uma linha no `pom.xml`.

**Nota sobre VEX:** o próprio Trivy sugeriu isso na saída do scan. VEX permite
declarar formalmente que uma vulnerabilidade não é explorável no contexto do
produto — é a forma correta de documentar "não alcançável" sem simplesmente
silenciar o alerta.

---

### Nota de triagem — o que o SCA não diz

O Trivy reporta por **presença no grafo de dependências**, não por **uso
efetivo**. Das 28 CVEs, a maioria está em código que esta aplicação nunca
executa.

Isso não torna o relatório errado — torna incompleto. A ferramenta responde
"esta biblioteca vulnerável está no seu projeto?". A pergunta que interessa é
"o código vulnerável é alcançável a partir de alguma entrada?", e essa exige
análise de contexto.

Ferramentas de *reachability analysis* tentam preencher essa lacuna, mas ainda
dependem de revisão para os casos de borda.

---

## Resumo da execução — DAST (OWASP ZAP)

### Primeira execução — falso negativo por configuração

O relatório inicial parecia positivo:

```
FAIL-NEW: 0   WARN-NEW: 4   INFO: 0   PASS: 66
```

Quatro warnings, 66 checagens aprovadas, nenhuma falha. Em uma aplicação com
12 vulnerabilidades conhecidas, esse resultado não faz sentido — e foi o que
motivou a revisão do log.

**O que estava errado:**

```
Job spider error accessing URL http://localhost:8080 status code returned : 404 expected 200
```

O spider do ZAP inicia a navegação pela raiz e descobre as demais rotas a
partir dos links encontrados. A aplicação só expunha `/api/*`, sem rota raiz —
então a primeira requisição retornou 404 e a varredura parou ali.

**Os 4 warnings confirmam o diagnóstico.** Todos apontam para páginas que não
existem:

| Alerta | Alvo |
|---|---|
| Content Security Policy Header Not Set | `/` (404) |
| Storable and Cacheable Content | `/`, `/favicon.ico` (404) |
| Permissions Policy Header Not Set | `/` (404) |
| Sec-Fetch-Dest Header is Missing | `/`, `/robots.txt`, `/sitemap.xml` (404) |

**O que isso significa:** `PASS: 66` não indica que 66 checagens passaram na
aplicação. Indica que passaram em uma página de erro vazia. Nenhum endpoint
real foi testado.

**Classificação: falso negativo de configuração.**

Este é o tipo de erro mais perigoso em DAST, justamente porque o resultado
*parece* bom. Um relatório com zero falhas entregue sem revisão daria ao time
de desenvolvimento a impressão de que a aplicação foi testada e aprovada.

Não houve falha de ferramenta — o ZAP fez exatamente o que foi instruído a
fazer. A falha foi de configuração do scan, e só apareceu na leitura do log.

**Lição prática:** um resultado limpo em aplicação conhecidamente vulnerável é
sinal de alerta, não de aprovação. Vale sempre conferir se o scanner
efetivamente alcançou a superfície pretendida — quantas URLs percorreu, quais
respostas obteve.

---

### Correção aplicada

1. **Endpoint raiz** (`IndexController`) devolvendo um índice HTML com links
   para todas as rotas, dando ao spider um ponto de partida navegável.
   Inclui também um formulário de login, que fornece ponto de entrada para o
   scan ativo.

2. **Parâmetros do scan ajustados** — `-m 3` para o tempo de spider e `-T 5`
   para o limite total.

3. **Verificação prévia no pipeline** — um passo confere o código HTTP da raiz
   antes do scan, para que uma falha desse tipo apareça imediatamente em vez
   de gerar um relatório silenciosamente vazio.

---

### Segunda execução

> **[A PREENCHER]** — resultado após a correção.
>
> Registrar:
> - Novo total de FAIL / WARN / PASS
> - Quais alertas apareceram e em quais endpoints
> - Se o CORS permissivo (VULN-11) foi detectado — o SAST não pegou, e esta é
>   a hipótese de complementaridade entre camadas
> - Se o stack trace exposto (VULN-12) apareceu
> - Comparação direta com a primeira execução

**Hipótese a validar:** VULN-11 (CORS com `allowedOriginPatterns("*")` e
`allowCredentials(true)`) não foi detectada pelo SAST porque o risco emerge da
combinação de chamadas encadeadas. O DAST observa os headers da resposta HTTP
real, então deveria identificá-la. Se confirmado, é a demonstração prática de
que as camadas cobrem superfícies diferentes.

---

## O que o exercício mostrou

**Onde o SAST foi bom:** padrões sintáticos com assinatura clara — SQL
concatenado, `Runtime.exec` com variável, MD5, concatenação em path. Detecção
rápida, precisa e com localização exata.

**Onde o SAST não chegou:**

| Vulnerabilidade | Por quê |
|---|---|
| Segredo hardcoded | Baixa entropia, não bate com padrão de token conhecido |
| CORS permissivo | Risco emerge da combinação, não de uma chamada isolada |
| IDOR | Lógica de negócio — código sintaticamente correto |
| Enumeração de usuários | Lógica de negócio — comportamento, não sintaxe |

**Números que resumem o exercício:**

*SAST (Semgrep) — 17 findings brutos:*
- 5 vulnerabilidades reais da aplicação
- 4 vulnerabilidades reais **não detectadas**
- 65% dos findings eram de escopo diferente (workflow, não aplicação)
- 1 autofix sugerido que **não corrigia adequadamente** o problema

*SCA (Trivy) — 28 CVEs:*
- 8 em dependências declaradas; **20 em transitivas** que ninguém escolheu
- A CVE de maior prioridade real (console H2) **não é** a de maior CVSS
- ~20 CVEs se resolvem com **uma linha** — atualizar o starter parent

*DAST (ZAP) — primeira execução:*
- Relatório aparentemente limpo: 0 falhas, 66 checagens aprovadas
- **Nenhum endpoint foi efetivamente testado** — o spider parou em 404 na raiz
- Falso negativo de configuração, detectado apenas na leitura do log

**Conclusão:** SAST e SCA produziram 45 findings brutos; o DAST, na primeira
execução, não produziu nenhum resultado válido. Depois da triagem, o que chega
ao time de desenvolvimento é uma lista bem menor, ordenada por risco real e
agrupada por ação — não por severidade nominal.

Vale notar que os três problemas mais relevantes deste exercício não foram
*achados* pelas ferramentas, e sim identificados ao revisar o que elas
produziram: as 4 vulnerabilidades que o SAST não detectou, a diferença entre
CVE presente e CVE alcançável no SCA, e o falso negativo de configuração no
DAST.

Essa diferença entre o output bruto e o relatório acionável é o trabalho de
AppSec. O pipeline encontra; a triagem decide o que importa.

---

## Próximos passos

- [ ] Registrar a segunda execução do DAST e comparar com a primeira
- [ ] Confirmar se o ZAP detecta o CORS permissivo que o SAST não pegou
- [ ] Validar exploração de VULN-08 e VULN-10 com evidência registrada
- [ ] Criar branch `fix/` com as correções e comparar o resultado do pipeline
