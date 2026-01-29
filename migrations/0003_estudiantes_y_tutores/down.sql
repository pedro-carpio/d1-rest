DROP TABLE IF EXISTS estudiante_tutor;
DROP TABLE IF EXISTS tutor;
DROP TABLE IF EXISTS estudiante;

DELETE FROM schema_migrations WHERE version = '0003_estudiantes_y_tutores';
