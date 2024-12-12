CREATE TABLE IF NOT EXISTS users (
                                     id BIGINT AUTO_INCREMENT PRIMARY KEY,
                                     username VARCHAR(255) NOT NULL UNIQUE,
                                     password VARCHAR(255) NOT NULL,
                                     role VARCHAR(255) NOT NULL,
                                     failed_attempts INT DEFAULT 0,
                                     is_account_non_locked BOOLEAN DEFAULT TRUE
);
