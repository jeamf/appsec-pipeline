CREATE TABLE IF NOT EXISTS users (
    id            INT PRIMARY KEY AUTO_INCREMENT,
    username      VARCHAR(50) NOT NULL,
    email         VARCHAR(100),
    password_hash VARCHAR(255),
    role          VARCHAR(20),
    cpf           VARCHAR(14)
);
