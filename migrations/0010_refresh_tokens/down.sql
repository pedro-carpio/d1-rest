PRAGMA foreign_keys = ON;

-- Revertir migración 0010: Eliminar tabla de refresh tokens

DROP INDEX IF EXISTS idx_refresh_token;
DROP INDEX IF EXISTS idx_refresh_token_user_id;
DROP TABLE IF EXISTS refresh_token;

-- Eliminar registro de migración
DELETE FROM schema_migrations WHERE version = '0010_refresh_tokens';
