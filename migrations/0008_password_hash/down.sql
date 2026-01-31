PRAGMA foreign_keys = ON;

-- Revertir migración 0008: Restaurar firebase_uid
-- NOTA: Esta reversión causará pérdida de datos de password_hash

-- 1. Crear tabla temporal con estructura antigua
CREATE TABLE user_account_old (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    firebase_uid TEXT UNIQUE,
    email TEXT,
    full_name TEXT,
    role_id INTEGER NOT NULL,
    is_active INTEGER DEFAULT 0 CHECK(is_active IN (0, 1)),
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES role(id)
);

-- 2. Copiar datos (sin password_hash)
INSERT INTO user_account_old (id, firebase_uid, email, full_name, role_id, is_active, created_at, updated_at)
SELECT 
    id, 
    NULL as firebase_uid,
    email, 
    full_name, 
    role_id, 
    is_active, 
    created_at, 
    updated_at
FROM user_account;

-- 3. Eliminar tabla nueva
DROP TABLE user_account;

-- 4. Renombrar tabla antigua
ALTER TABLE user_account_old RENAME TO user_account;

-- 5. Eliminar registro de migración
DELETE FROM schema_migrations WHERE version = '0008_password_hash';
