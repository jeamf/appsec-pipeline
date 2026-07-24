package com.jeamf.vulnapi.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Endpoints de usuario.
 *
 * ATENCAO: este controller contem vulnerabilidades INTENCIONAIS,
 * usadas para validar a deteccao do pipeline de AppSec.
 * Cada uma esta marcada com um ID rastreado em TRIAGE.md.
 */
@RestController
@RequestMapping("/api/users")
public class UserController {

    private final JdbcTemplate jdbc;

    @Autowired
    public UserController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * VULN-01 | SQL Injection | CWE-89 | OWASP A03:2021
     *
     * O parametro 'name' e concatenado diretamente na query.
     * Exploracao: /api/users/search?name=' OR '1'='1
     *
     * Correcao: usar query parametrizada (ver searchFixed abaixo).
     */
    @GetMapping("/search")
    public List<Map<String, Object>> search(@RequestParam String name) {
        String sql = "SELECT id, username, email FROM users WHERE username = '" + name + "'";
        return jdbc.queryForList(sql);
    }

    /**
     * Versao corrigida de VULN-01 — mantida no repositorio de proposito.
     * Serve para comparar o antes/depois e para validar que a regra do
     * Semgrep nao gera falso positivo aqui.
     */
    @GetMapping("/search-fixed")
    public List<Map<String, Object>> searchFixed(@RequestParam String name) {
        String sql = "SELECT id, username, email FROM users WHERE username = ?";
        return jdbc.queryForList(sql, name);
    }

    /**
     * VULN-02 | IDOR / Broken Access Control | CWE-639 | OWASP A01:2021
     *
     * Retorna qualquer usuario pelo ID, sem verificar se o solicitante
     * tem permissao para ve-lo. Nao ha checagem de sessao.
     *
     * Correcao: validar que o usuario autenticado e o dono do recurso
     * (ou possui perfil administrativo) antes de retornar.
     */
    @GetMapping("/{id}")
    public Map<String, Object> getById(@PathVariable Long id) {
        String sql = "SELECT id, username, email, role, cpf FROM users WHERE id = ?";
        return jdbc.queryForMap(sql, id);
    }

    /**
     * VULN-03 | Exposicao de dados sensiveis | CWE-200 | OWASP A02:2021
     *
     * Retorna a tabela inteira, incluindo hash de senha e CPF.
     *
     * Correcao: selecionar apenas os campos necessarios e aplicar DTO.
     */
    @GetMapping("/all")
    public List<Map<String, Object>> all() {
        return jdbc.queryForList("SELECT * FROM users");
    }
}
