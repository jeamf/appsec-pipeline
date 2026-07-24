-- Dados ficticios para demonstracao. Senhas em MD5 (ver VULN-05).
-- 'admin123' -> 0192023a7bbd73250516f069df18b500
-- 'user123'  -> 6ad14ba9986e3615423dfca256d04e3f
INSERT INTO users (username, email, password_hash, role, cpf) VALUES
  ('admin', 'admin@example.com', '0192023a7bbd73250516f069df18b500', 'ADMIN', '000.000.000-00'),
  ('joao',  'joao@example.com',  '6ad14ba9986e3615423dfca256d04e3f', 'USER',  '111.111.111-11'),
  ('maria', 'maria@example.com', '6ad14ba9986e3615423dfca256d04e3f', 'USER',  '222.222.222-22');
