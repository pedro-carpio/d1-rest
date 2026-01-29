DROP TABLE IF EXISTS user_account;
DROP TABLE IF EXISTS role;

DELETE FROM schema_migrations WHERE version = '0001_core_roles';
