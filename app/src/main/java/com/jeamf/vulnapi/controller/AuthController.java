package com.jeamf.vulnapi.controller;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.security.MessageDigest;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Autenticacao. Contem vulnerabilidades INTENCIONAIS — ver TRIAGE.md.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    /**
     * VULN-04 | Segredo hardcoded | CWE-798 | OWASP A07:2021
     *
     * Chave de assinatura do JWT commitada no codigo-fonte. Qualquer
     * pessoa com acesso ao repositorio pode forjar tokens validos.
     *
     * Correcao: carregar de variavel de ambiente ou cofre de segredos.
     */
    private static final String JWT_SECRET = "minha-chave-secreta-123";

    private final JdbcTemplate jdbc;

    @Autowired
    public AuthController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /**
     * VULN-05 | Hash de senha inseguro | CWE-327 | OWASP A02:2021
     *
     * MD5 e rapido e sem salt — vulneravel a rainbow table e forca bruta.
     *
     * Correcao: usar BCrypt, Argon2 ou PBKDF2 com salt por usuario.
     */
    private String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    @PostMapping("/login")
    public Map<String, Object> login(@RequestBody Map<String, String> body) throws Exception {
        String username = body.get("username");
        String password = body.get("password");

        String hashed = hashPassword(password);

        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?",
                username, hashed);

        Map<String, Object> response = new HashMap<>();

        if (rows.isEmpty()) {
            /**
             * VULN-06 | Mensagem de erro verbosa | CWE-209
             *
             * A resposta diferencia "usuario inexistente" de "senha errada",
             * permitindo enumeracao de contas validas.
             *
             * Correcao: retornar mensagem generica ("credenciais invalidas").
             */
            List<Map<String, Object>> userExists = jdbc.queryForList(
                    "SELECT id FROM users WHERE username = ?", username);

            response.put("error", userExists.isEmpty()
                    ? "Usuario nao encontrado no sistema"
                    : "Senha incorreta para o usuario " + username);
            return response;
        }

        Map<String, Object> user = rows.get(0);

        /**
         * VULN-07 | JWT sem expiracao adequada | CWE-613
         *
         * Token valido por 30 dias, sem mecanismo de revogacao.
         *
         * Correcao: access token curto (15 min) + refresh token revogavel.
         */
        String token = Jwts.builder()
                .setSubject(String.valueOf(user.get("id")))
                .claim("role", user.get("role"))
                .setExpiration(new Date(System.currentTimeMillis() + 30L * 24 * 60 * 60 * 1000))
                .signWith(SignatureAlgorithm.HS256, JWT_SECRET)
                .compact();

        response.put("token", token);
        response.put("user", user);
        return response;
    }
}
