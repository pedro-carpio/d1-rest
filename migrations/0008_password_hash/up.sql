PRAGMA foreign_keys = ON;

-- Migración 0008: Agregar columna password_hash a user_account
-- Eliminar firebase_uid (ya no se usa)
-- Hacer email NOT NULL y UNIQUE

-- 1. Crear tabla temporal con la nueva estructura
CREATE TABLE user_account_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name TEXT,
    role_id INTEGER NOT NULL,
    is_active INTEGER DEFAULT 0 CHECK(is_active IN (0, 1)),
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES role(id)
);

-- 2. Copiar datos existentes (sin firebase_uid)
-- NOTA: Los usuarios existentes necesitarán resetear su contraseña
-- Por ahora, generamos un hash dummy que nunca coincidirá
INSERT INTO user_account_new (id, email, password_hash, full_name, role_id, is_active, created_at, updated_at)
SELECT 
    id, 
    COALESCE(email, 'user' || id || '@temp.com') as email,
    'INVALID_HASH_RESET_PASSWORD_REQUIRED' as password_hash,
    full_name, 
    role_id, 
    is_active, 
    created_at, 
    updated_at
FROM user_account;

-- 3. Eliminar tabla antigua
DROP TABLE user_account;

-- 4. Renombrar tabla nueva
ALTER TABLE user_account_new RENAME TO user_account;

-- 5. Registrar migración
INSERT OR IGNORE INTO schema_migrations (version) VALUES ('0008_password_hash');
