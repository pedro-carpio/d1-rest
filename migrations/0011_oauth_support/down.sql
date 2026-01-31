PRAGMA foreign_keys = ON;

-- Revertir password_hash a NOT NULL (estructura de migración 0008)
-- Esto puede fallar si hay usuarios solo con OAuth (sin password)

CREATE TABLE user_account_old (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,  -- NOT NULL nuevamente
    full_name TEXT,
    role_id INTEGER NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (role_id) REFERENCES role(id)
);

-- Copiar datos (NOTA: esto fallará si hay usuarios con password_hash NULL)
INSERT INTO user_account_old (id, email, password_hash, full_name, role_id, is_active, created_at, updated_at)
SELECT id, email, password_hash, full_name, role_id, is_active, created_at, updated_at
FROM user_account
WHERE password_hash IS NOT NULL;  -- Solo copiar usuarios con password

-- Eliminar tabla nueva
DROP TABLE user_account;

-- Renombrar tabla antigua
ALTER TABLE user_account_old RENAME TO user_account;

-- Remover de schema_migrations
DELETE FROM schema_migrations WHERE version = '0011_oauth_support';
