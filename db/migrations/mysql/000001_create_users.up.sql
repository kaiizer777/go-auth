CREATE TABLE IF NOT EXISTS users (
    id                 VARCHAR(36) PRIMARY KEY,
    email              VARCHAR(255) NOT NULL,
    password_hash      TEXT NOT NULL,
    credential_version INT NOT NULL DEFAULT 0,
    email_verified     TINYINT(1) NOT NULL DEFAULT 0,
    created_at         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at         DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE UNIQUE INDEX idx_users_email_lower ON users ((LOWER(email)));
