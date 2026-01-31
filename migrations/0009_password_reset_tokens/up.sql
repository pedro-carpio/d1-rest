PRAGMA foreign_keys = ON;

-- Migración 0009: Tabla para tokens de reset de contraseña

CREATE TABLE password_reset_token (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used INTEGER DEFAULT 0 CHECK(used IN (0, 1)),
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user_account(id) ON DELETE CASCADE
);

-- Índice para búsqueda rápida por token
CREATE INDEX idx_password_reset_token ON password_reset_token(token);

-- Índice para búsqueda por user_id
CREATE INDEX idx_password_reset_user_id ON password_reset_token(user_id);

-- Registrar migración
INSERT OR IGNORE INTO schema_migrations (version) VALUES ('0009_password_reset_tokens');
