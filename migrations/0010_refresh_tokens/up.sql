PRAGMA foreign_keys = ON;

-- Migración 0010: Tabla para refresh tokens (permite múltiples sesiones por usuario)

CREATE TABLE refresh_token (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    revoked INTEGER DEFAULT 0 CHECK(revoked IN (0, 1)),
    device_info TEXT,  -- Información del dispositivo/navegador (opcional)
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_used_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user_account(id) ON DELETE CASCADE
);

-- Índice para búsqueda rápida por token
CREATE INDEX idx_refresh_token ON refresh_token(token);

-- Índice para búsqueda por user_id
CREATE INDEX idx_refresh_token_user_id ON refresh_token(user_id);

-- Registrar migración
INSERT OR IGNORE INTO schema_migrations (version) VALUES ('0010_refresh_tokens');
