# Triagem de Findings

Este documento é o núcleo do projeto. Rodar ferramenta é fácil; o trabalho de
AppSec começa depois, quando é preciso decidir **o que é real, o que é falso
positivo e o que é aceito como risco**.

Cada finding abaixo passou por quatro perguntas:

1. A ferramenta apontou algo que existe de fato no código?
2. O trecho é alcançável por entrada controlada pelo usuário?
3. Existe alguma barreira (autenticação, validação, contexto) que impeça a exploração?
4. Qual o impacto real se explorado neste contexto específico?

---

## Resumo

| Classificação | Quantidade |
|---|---|
| Confirmado — corrigir | 9 |
| Confirmado — risco aceito | 1 |
| Falso positivo | 2 |
| **Total analisado** | **12** |

> Os números acima refletem a análise manual, não a contagem bruta da
> ferramenta. Semgrep e Trivy juntos reportaram mais itens; parte era
> duplicação entre regras e parte não era alcançável.

---

## Confirmados — correção necessária

### VULN-01 · SQL Injection
**Onde:** `UserController.search()`
**Detectado por:** Semgrep (`java.lang.security.audit.formatted-sql-string`)
**CWE-89 · OWASP A03:2021 · Severidade: Crítica**

O parâmetro `name` é concatenado diretamente na string SQL. Não há
sanitização nem allowlist.

**Validação da explorabilidade:** confirmada manualmente.

```
GET /api/users/search?name=' OR '1'='1
```

Retorna todos os registros da tabela, comprovando que a entrada altera a
estrutura da query e não apenas o valor comparado.

**Por que é crítico neste contexto:** o endpoint não exige autenticação e a
tabela contém CPF e hash de senha. Um atacante não autenticado consegue
extrair a base inteira.

**Correção:** query parametrizada. A versão corrigida está no próprio
repositório em `searchFixed()` para comparação:

```java
String sql = "SELECT id, username, email FROM users WHERE username = ?";
return jdbc.queryForList(sql, name);
```

---

### VULN-04 · Segredo hardcoded
**Onde:** `AuthController.JWT_SECRET`
**Detectado por:** Semgrep (`generic.secrets.security.detected-generic-secret`)
**CWE-798 · OWASP A07:2021 · Severidade: Crítica**

A chave de assinatura do JWT está commitada em texto claro.

**Por que é crítico:** qualquer pessoa com acesso ao repositório — incluindo
histórico do Git, mesmo após remoção — pode forjar tokens válidos com
`role: ADMIN`. Não depende de nenhuma outra falha para ser explorada.

**Correção:** carregar de variável de ambiente ou cofre (AWS Secrets Manager,
Azure Key Vault). Rotacionar a chave existente, já que ela deve ser
considerada comprometida.

---

### VULN-10 · Command Injection
**Onde:** `FileController.info()`
**Detectado por:** Semgrep (`java.lang.security.audit.command-injection-process-builder`)
**CWE-78 · OWASP A03:2021 · Severidade: Crítica**

Entrada do usuário concatenada em comando passado para `/bin/sh -c`.

**Validação:** confirmada. O uso de `sh -c` faz o shell interpretar
metacaracteres, então `;`, `|` e `$()` encadeiam comandos arbitrários.

**Correção:** substituir por API nativa (`Files.readAttributes`). Se um
processo externo for realmente necessário, usar `ProcessBuilder` com
argumentos em array separado — sem shell — e validar a entrada contra
allowlist.

---

### VULN-08 · Path Traversal
**Onde:** `FileController.read()`
**Detectado por:** Semgrep · ZAP (indiretamente, via resposta 200 em payload de traversal)
**CWE-22 · OWASP A01:2021 · Severidade: Alta**

Nome de arquivo concatenado ao diretório base sem normalização.

**Correção:** resolver o caminho e validar que ele permanece dentro do
diretório permitido:

```java
Path base = Paths.get(UPLOAD_DIR).toRealPath();
Path target = base.resolve(name).normalize();
if (!target.startsWith(base)) {
    throw new SecurityException("Caminho fora do diretorio permitido");
}
```

---

### VULN-05 · Hash de senha com MD5
**Onde:** `AuthController.hashPassword()`
**Detectado por:** Semgrep (`java.lang.security.audit.crypto.use-of-md5`)
**CWE-327 · OWASP A02:2021 · Severidade: Alta**

MD5 sem salt. Rápido de calcular, o que favorece força bruta, e vulnerável a
rainbow tables.

**Correção:** BCrypt (`spring-security-crypto`) ou Argon2. Migração pode ser
gradual: re-hashear no próximo login bem-sucedido.

---

### VULN-11 · CORS permissivo com credenciais
**Onde:** `SecurityConfig.addCorsMappings()`
**Detectado por:** Semgrep · ZAP
**CWE-942 · OWASP A05:2021 · Severidade: Alta**

`allowedOriginPatterns("*")` combinado com `allowCredentials(true)`.

**Por que a combinação importa:** origem coringa sozinha seria menos grave.
Com credenciais habilitadas, um site controlado pelo atacante consegue fazer
requisições autenticadas usando a sessão da vítima e ler a resposta.

**Correção:** allowlist explícita de origens.

---

### VULN-02 · IDOR
**Onde:** `UserController.getById()`
**Detectado por:** análise manual — **nenhuma ferramenta apontou**
**CWE-639 · OWASP A01:2021 · Severidade: Alta**

Este é o ponto mais relevante do exercício. Falhas de controle de acesso
dependem de entender a **intenção** da aplicação — quem deveria poder ver o
quê. Nenhum SAST identifica isso, porque o código está sintaticamente
correto: a query é parametrizada e não há padrão inseguro.

É a demonstração prática de que pipeline automatizado não substitui revisão
humana.

**Correção:** validar no endpoint que o usuário autenticado é dono do recurso
ou possui perfil administrativo.

---

### VULN-06 · Enumeração de usuários
**Onde:** `AuthController.login()`
**Detectado por:** análise manual
**CWE-209 · Severidade: Média**

A resposta distingue "usuário não encontrado" de "senha incorreta",
permitindo mapear contas válidas antes de um ataque de credenciais.

**Correção:** mensagem genérica única para ambos os casos.

---

### VULN-12 · Stack trace exposto
**Onde:** `application.properties`
**Detectado por:** ZAP (baseline)
**CWE-209 · Severidade: Média**

`server.error.include-stacktrace=always` revela caminhos internos, versões de
biblioteca e estrutura de pacotes — informação útil para encadear outros
ataques.

**Correção:** `never` em produção, com handler global retornando erro genérico.

---

## Confirmado — risco aceito

### VULN-09 · Upload sem validação de extensão
**Onde:** `FileController.upload()`
**CWE-434 · Severidade: Alta na origem → Média neste contexto**

O endpoint aceita qualquer extensão e grava com o nome original.

**Por que classifiquei como risco aceito (e não crítico):** o diretório
`/tmp/uploads/` não é servido pelo container web e não há interpretador
configurado para executar conteúdo dali. O caminho clássico de exploração —
subir um `.jsp` e acessá-lo via HTTP — não se aplica neste deploy.

**O que mantém o risco:** a proteção é ambiental, não de código. Se em algum
momento esse diretório for exposto estaticamente ou o deploy mudar, a falha
volta a ser crítica imediatamente.

**Decisão:** documentado como dívida técnica, com correção prevista. Não
bloqueia o pipeline, mas fica registrado com data e responsável.

> Este é o tipo de finding que gera discussão real entre AppSec e
> desenvolvimento. A classificação depende do deploy, não só do código — e
> por isso precisa ser revisitada a cada mudança de infraestrutura.

---

## Falsos positivos

### FP-01 · SQL Injection em `searchFixed()`
**Reportado por:** Semgrep, em uma execução com regra genérica de
concatenação SQL

**Por que é falso positivo:** o método usa `?` como placeholder e passa o
valor como argumento separado ao `JdbcTemplate`. O driver JDBC envia o
parâmetro fora da estrutura da query, então a entrada não pode alterar a
sintaxe SQL.

A regra disparou por proximidade textual — o método está no mesmo arquivo que
VULN-01 e tem estrutura parecida.

**Validação:** testei com o mesmo payload que explora VULN-01
(`' OR '1'='1`). Em `searchFixed` a busca simplesmente não retorna resultado,
porque a string inteira é tratada como valor literal de username.

**Ação:** marcado como falso positivo. Nenhuma mudança no código.

---

### FP-02 · CVE em dependência transitiva não alcançável
**Reportado por:** Trivy

Uma CVE apontada em biblioteca transitiva cujo componente afetado não é
carregado por nenhum caminho de execução da aplicação.

**Por que é falso positivo neste contexto:** SCA reporta por presença no
grafo de dependências, não por uso efetivo. A vulnerabilidade existe na
biblioteca, mas o código vulnerável não é alcançável a partir de nenhum
endpoint desta aplicação.

**Ressalva importante:** "não alcançável hoje" não é o mesmo que "seguro".
Se uma futura feature passar a usar aquele componente, a CVE volta a valer.
Por isso a marcação tem prazo de revisão em vez de supressão permanente.

**Ação:** suprimido com justificativa documentada e revisão em 90 dias.

---

## Notas sobre as ferramentas

**Onde o SAST foi bom:** padrões sintáticos com assinatura clara —
concatenação SQL, uso de MD5, segredo em string literal, `Runtime.exec` com
variável. Detecção rápida e precisa.

**Onde o SAST não chegou:** VULN-02 (IDOR) e VULN-06 (enumeração). Ambas são
falhas de lógica de negócio. O código está correto; o que está errado é a
regra de negócio que ele implementa. Ferramenta nenhuma infere isso sem
entender a intenção da aplicação.

**Onde o DAST complementou:** VULN-12 e VULN-11 apareceram porque o ZAP
observa a resposta HTTP real. SAST não vê configuração de runtime com a mesma
clareza.

**Conclusão prática:** SAST, DAST e SCA cobrem superfícies diferentes e
parcialmente disjuntas. Nenhum substitui os outros — e nenhum substitui
leitura de código. Neste exercício, 2 das 10 vulnerabilidades reais
(20%) só apareceram na revisão manual.
