package com.jeamf.vulnapi.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Configuracao web. Vulnerabilidade INTENCIONAL — ver TRIAGE.md.
 */
@Configuration
public class SecurityConfig implements WebMvcConfigurer {

    /**
     * VULN-11 | CORS permissivo | CWE-942 | OWASP A05:2021
     *
     * Aceita requisicoes de qualquer origem com credenciais habilitadas.
     * Permite que um site malicioso faca chamadas autenticadas em nome
     * da vitima.
     *
     * Correcao: allowlist explicita de origens confiaveis.
     */
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOriginPatterns("*")
                .allowedMethods("*")
                .allowedHeaders("*")
                .allowCredentials(true);
    }
}
