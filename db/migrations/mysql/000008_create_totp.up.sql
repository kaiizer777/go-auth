CREATE TABLE IF NOT EXISTS totp_secrets (
    id               VARCHAR(36) PRIMARY KEY,
    user_id          VARCHAR(36) NOT NULL,
    encrypted_secret BLOB NOT NULL,
    backup_codes     JSON NOT NULL,
    enabled          TINYINT(1) NOT NULL DEFAULT 0,
    created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_totp_secrets_user_id UNIQUE (user_id),
    CONSTRAINT fk_totp_secrets_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS totp_used_codes (
    id        VARCHAR(36) PRIMARY KEY,
    user_id   VARCHAR(36) NOT NULL,
    code_hash VARBINARY(32) NOT NULL,
    used_at   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_totp_used_codes_user_code UNIQUE (user_id, code_hash),
    CONSTRAINT fk_totp_used_codes_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_totp_used_codes_user_used_at ON totp_used_codes(user_id, used_at);

CREATE TABLE IF NOT EXISTS two_factor_tokens (
    id         VARCHAR(36) PRIMARY KEY,
    user_id    VARCHAR(36) NOT NULL,
    token_hash VARBINARY(32) NOT NULL,
    expires_at DATETIME(6) NOT NULL,
    attempts   INT NOT NULL DEFAULT 0,
    CONSTRAINT uq_two_factor_tokens_token_hash UNIQUE (token_hash),
    CONSTRAINT fk_two_factor_tokens_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_two_factor_tokens_user_id ON two_factor_tokens(user_id);
CREATE INDEX idx_two_factor_tokens_expires_at ON two_factor_tokens(expires_at);
