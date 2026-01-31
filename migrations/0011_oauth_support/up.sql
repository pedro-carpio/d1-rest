PRAGMA foreign_keys = ON;

-- Hacer password_hash nullable para permitir usuarios solo con OAuth
-- Un usuario puede tener password, OAuth, o ambos métodos simultáneamente
-- SQLite no permite ALTER COLUMN directamente, necesitamos recrear la tabla

CREATE TABLE user_account_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT,  -- NULLABLE: permite usuarios solo con OAuth
    full_name TEXT,
    role_id INTEGER NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (role_id) REFERENCES role(id)
);

-- Copiar datos existentes
INSERT INTO user_account_new (id, email, password_hash, full_name, role_id, is_active, created_at, updated_at)
SELECT id, email, password_hash, full_name, role_id, is_active, created_at, updated_at
FROM user_account;

-- Reemplazar tabla
DROP TABLE user_account;
ALTER TABLE user_account_new RENAME TO user_account;

-- Actualizar schema_migrations
INSERT OR IGNORE INTO schema_migrations (version) VALUES ('0011_oauth_support');
