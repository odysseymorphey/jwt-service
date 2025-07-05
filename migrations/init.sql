CREATE TABLE IF NOT EXISTS refresh_tokens (
    jti         TEXT PRIMARY KEY,
    user_id     UUID NOT NULL,
    hash        TEXT NOT NULL,
    user_agent  TEXT NOT NULL,
    ip          VARCHAR(30) NOT NULL,
    issued_at   TIMESTAMP NOT NULL,
    revoked     BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_refresh_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_revoked ON refresh_tokens(revoked);

CREATE TABLE IF NOT EXISTS jwt_blacklist (
    jti TEXT PRIMARY KEY,
    blacklisted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
