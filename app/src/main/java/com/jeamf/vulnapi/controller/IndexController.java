package com.jeamf.vulnapi.controller;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Indice da API.
 *
 * Existe por um motivo especifico de DAST: o spider do ZAP inicia a
 * navegacao pela raiz e descobre as demais rotas a partir dos links
 * encontrados. Sem uma pagina raiz, o scan retorna 404 na primeira
 * requisicao e nao alcanca nenhum endpoint — produzindo um relatorio
 * limpo que nao reflete a superficie real da aplicacao.
 *
 * Ver TRIAGE.md, secao "DAST — primeira execucao".
 */
@RestController
public class IndexController {

    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    public String index() {
        return """
            <!DOCTYPE html>
            <html lang="pt-BR">
            <head>
              <meta charset="utf-8">
              <title>vulnapi — indice de endpoints</title>
            </head>
            <body>
              <h1>vulnapi</h1>
              <p>Aplicacao intencionalmente vulneravel para demonstracao de
                 pipeline AppSec. Nao implantar em ambiente exposto.</p>

              <h2>Usuarios</h2>
              <ul>
                <li><a href="/api/users/all">/api/users/all</a></li>
                <li><a href="/api/users/1">/api/users/1</a></li>
                <li><a href="/api/users/search?name=admin">/api/users/search?name=admin</a></li>
                <li><a href="/api/users/search-fixed?name=admin">/api/users/search-fixed?name=admin</a></li>
              </ul>

              <h2>Autenticacao</h2>
              <ul>
                <li>POST /api/auth/login</li>
              </ul>

              <h2>Arquivos</h2>
              <ul>
                <li><a href="/api/files/read?name=teste.txt">/api/files/read?name=teste.txt</a></li>
                <li><a href="/api/files/info?filename=teste.txt">/api/files/info?filename=teste.txt</a></li>
                <li>POST /api/files/upload</li>
              </ul>

              <h2>Formulario de login</h2>
              <form method="POST" action="/api/auth/login">
                <input type="text" name="username" placeholder="usuario">
                <input type="password" name="password" placeholder="senha">
                <button type="submit">Entrar</button>
              </form>
            </body>
            </html>
            """;
    }
}
