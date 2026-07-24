package com.jeamf.vulnapi.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

/**
 * Manipulacao de arquivos. Vulnerabilidades INTENCIONAIS — ver TRIAGE.md.
 */
@RestController
@RequestMapping("/api/files")
public class FileController {

    private static final String UPLOAD_DIR = "/tmp/uploads/";

    /**
     * VULN-08 | Path Traversal | CWE-22 | OWASP A01:2021
     *
     * O nome do arquivo vem do usuario sem normalizacao.
     * Exploracao: /api/files/read?name=../../../../etc/passwd
     *
     * Correcao: normalizar o path e validar que o caminho resolvido
     * permanece dentro do diretorio permitido.
     */
    @GetMapping("/read")
    public String read(@RequestParam String name) throws Exception {
        File file = new File(UPLOAD_DIR + name);
        return new String(Files.readAllBytes(file.toPath()));
    }

    /**
     * VULN-09 | Upload sem validacao | CWE-434 | OWASP A04:2021
     *
     * Aceita qualquer extensao e qualquer tamanho, gravando o arquivo
     * com o nome original fornecido pelo cliente.
     *
     * Correcao: allowlist de extensoes, validacao de content-type real,
     * limite de tamanho e nome de arquivo gerado pelo servidor.
     */
    @PostMapping("/upload")
    public Map<String, Object> upload(@RequestParam("file") MultipartFile file) throws Exception {
        Map<String, Object> response = new HashMap<>();

        File dir = new File(UPLOAD_DIR);
        if (!dir.exists()) {
            dir.mkdirs();
        }

        String original = file.getOriginalFilename();
        Files.write(Paths.get(UPLOAD_DIR + original), file.getBytes());

        response.put("saved", UPLOAD_DIR + original);
        return response;
    }

    /**
     * VULN-10 | Command Injection | CWE-78 | OWASP A03:2021
     *
     * Entrada do usuario concatenada em comando de sistema.
     * Exploracao: /api/files/info?filename=test.txt; cat /etc/passwd
     *
     * Correcao: nao invocar shell; usar API nativa (java.nio.file.Files).
     * Se comando externo for inevitavel, usar ProcessBuilder com
     * argumentos separados e validacao estrita da entrada.
     */
    @GetMapping("/info")
    public String info(@RequestParam String filename) throws Exception {
        String cmd = "ls -la " + UPLOAD_DIR + filename;
        Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
        return new String(process.getInputStream().readAllBytes());
    }
}
