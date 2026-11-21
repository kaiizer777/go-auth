CREATE TABLE IF NOT EXISTS oauth_accounts (
    id               VARCHAR(36) PRIMARY KEY,
    user_id          VARCHAR(36) NOT NULL,
    provider_id      VARCHAR(32) NOT NULL,
    provider_user_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
    email            VARCHAR(255) NOT NULL,
    created_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at       DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_oauth_accounts_provider_uid UNIQUE (provider_id, provider_user_id),
    CONSTRAINT fk_oauth_accounts_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE INDEX idx_oauth_accounts_user_id ON oauth_accounts(user_id);
CREATE INDEX idx_oauth_accounts_email ON oauth_accounts(email);
