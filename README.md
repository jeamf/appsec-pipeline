# AppSec Pipeline

Pipeline de segurança de aplicações rodando **SAST, DAST e SCA** em CI, com a
triagem manual dos resultados documentada.

O foco deste repositório não é rodar as ferramentas — isso é a parte fácil. É
mostrar o que vem depois: **decidir quais findings são reais, quais são falsos
positivos e por quê**.

> 📄 **[TRIAGE.md](TRIAGE.md) — a análise dos findings.** É o documento
> principal deste projeto.

---

## O que tem aqui

| Camada | Ferramenta | O que cobre |
|---|---|---|
| **SAST** | Semgrep | Análise estática do código-fonte |
| **SCA** | Trivy | CVEs em dependências de terceiros |
| **DAST** | OWASP ZAP | Aplicação rodando, do lado de fora |
| **Manual** | Revisão de código | O que ferramenta nenhuma pega |

A aplicação-alvo é uma API Spring Boot escrita para este projeto, com **12
vulnerabilidades introduzidas de propósito** — cada uma comentada no código
com ID, CWE e a categoria correspondente do OWASP Top 10.

---

## Estrutura

```
appsec-pipeline/
├── app/                      # API Spring Boot (vulnerável de propósito)
│   ├── src/main/java/...     # controllers com as falhas documentadas
│   └── pom.xml               # dependências com CVEs conhecidas
├── .github/workflows/
│   └── appsec.yml            # pipeline SAST + SCA + DAST
├── TRIAGE.md                 # ★ análise dos findings
└── docs/                     # evidências e prints
```

---

## Vulnerabilidades implementadas

| ID | Vulnerabilidade | CWE | OWASP | Detectado por |
|---|---|---|---|---|
| VULN-01 | SQL Injection | CWE-89 | A03 | SAST |
| VULN-02 | IDOR / Broken Access Control | CWE-639 | A01 | **manual** |
| VULN-03 | Exposição de dados sensíveis | CWE-200 | A02 | manual |
| VULN-04 | Segredo hardcoded | CWE-798 | A07 | SAST |
| VULN-05 | Hash MD5 | CWE-327 | A02 | SAST |
| VULN-06 | Enumeração de usuários | CWE-209 | — | **manual** |
| VULN-07 | JWT sem expiração adequada | CWE-613 | A07 | manual |
| VULN-08 | Path Traversal | CWE-22 | A01 | SAST + DAST |
| VULN-09 | Upload sem validação | CWE-434 | A04 | SAST |
| VULN-10 | Command Injection | CWE-78 | A03 | SAST |
| VULN-11 | CORS permissivo | CWE-942 | A05 | SAST + DAST |
| VULN-12 | Stack trace exposto | CWE-209 | — | DAST |

**2 de 12 só apareceram na revisão manual** — as duas de lógica de negócio.
Esse é o ponto que o projeto quer demonstrar.

---

## Rodando localmente

**Requisitos:** Java 17, Maven, Docker

### Subir a aplicação

```bash
cd app
mvn clean package -DskipTests
java -jar target/vulnapi-1.0.0.jar
```

A API sobe em `http://localhost:8080`.

### Testar uma vulnerabilidade

```bash
# VULN-01 — SQL Injection
curl "http://localhost:8080/api/users/search?name=' OR '1'='1"

# comparar com a versão corrigida (mesmo payload, sem efeito)
curl "http://localhost:8080/api/users/search-fixed?name=' OR '1'='1"
```

### Rodar as ferramentas

```bash
# SAST
docker run --rm -v "$PWD:/src" semgrep/semgrep \
  semgrep scan --config=p/java --config=p/owasp-top-ten --config=p/secrets

# SCA
docker run --rm -v "$PWD:/src" aquasec/trivy fs /src/app

# DAST (com a aplicação rodando)
docker run --rm --network host ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost:8080
```

---

## CI

O workflow roda em todo push e pull request para `main`. Os relatórios são
publicados em **Security → Code scanning** e ficam disponíveis como artefato
de cada execução.

O pipeline **não bloqueia o build**, de propósito: em um repositório cujo
objetivo é conter vulnerabilidades, falhar sempre não teria utilidade. Em
projeto real, o critério de bloqueio seria severidade a partir de HIGH em
findings confirmados — nunca na contagem bruta da ferramenta, que inclui
falsos positivos.

---

## ⚠️ Aviso

Esta aplicação é **intencionalmente insegura** e existe apenas para fins
educacionais. Não implante em ambiente acessível pela internet e não reutilize
este código em produção.

---

## Autor

**Jean Fogaça** — Desenvolvedor com background em segurança da informação.

[LinkedIn](https://linkedin.com/in/jean-fogaca) · [GitHub](https://github.com/jeamf)
