CREATE TABLE IF NOT EXISTS sessions (
    id                  VARCHAR(36) PRIMARY KEY,
    user_id             VARCHAR(36) NOT NULL,
    id_hash             CHAR(64) NOT NULL,
    session_type        VARCHAR(10) NOT NULL DEFAULT 'cookie',
    ip_address          VARCHAR(45) NOT NULL DEFAULT '',
    user_agent          TEXT NOT NULL,
    credential_version  INT NOT NULL DEFAULT 0,
    last_active_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    absolute_expires_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    created_at          DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_sessions_id_hash UNIQUE (id_hash),
    CONSTRAINT fk_sessions_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
