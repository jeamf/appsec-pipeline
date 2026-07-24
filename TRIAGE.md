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

- 17 findings brutos → **5 vulnerabilidades reais** da aplicação
- 4 vulnerabilidades reais **não detectadas**
- 65% dos findings eram de escopo diferente
- 1 autofix sugerido que **não corrigia adequadamente** o problema

**Conclusão:** o pipeline automatizado encontrou 5 das 9 vulnerabilidades
reais — pouco mais da metade. É valioso e deve existir, mas o relatório bruto
não é o produto final. Entre a saída da ferramenta e a conversa com o time de
desenvolvimento existe um trabalho de leitura, deduplicação, definição de
escopo e revisão manual que nenhuma ferramenta faz sozinha.

---

## Próximos passos

- [ ] Consolidar findings do Trivy (SCA) neste documento
- [ ] Consolidar findings do ZAP (DAST) e verificar se o CORS aparece lá
- [ ] Validar exploração de VULN-08 e VULN-10 com evidência registrada
- [ ] Criar branch `fix/` com as correções e comparar o resultado do pipeline
