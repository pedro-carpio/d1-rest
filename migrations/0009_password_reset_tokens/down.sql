PRAGMA foreign_keys = ON;

-- Revertir migración 0009: Eliminar tabla de tokens de reset

DROP INDEX IF EXISTS idx_password_reset_token;
DROP INDEX IF EXISTS idx_password_reset_user_id;
DROP TABLE IF EXISTS password_reset_token;

-- Eliminar registro de migración
DELETE FROM schema_migrations WHERE version = '0009_password_reset_tokens';
