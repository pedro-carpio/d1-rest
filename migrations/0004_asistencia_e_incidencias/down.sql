DROP TABLE IF EXISTS incidencia;
DROP TABLE IF EXISTS asistencia_incidencia;

DELETE FROM schema_migrations WHERE version = '0004_asistencia_e_incidencias';
