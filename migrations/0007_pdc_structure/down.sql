DROP TABLE IF EXISTS pdc_conocimiento;
DROP TABLE IF EXISTS pdc_indicador;
DROP TABLE IF EXISTS pdc_fase_recurso;
DROP TABLE IF EXISTS pdc_fase_actividad;
DROP TABLE IF EXISTS pdc_fase_perfil_inciso;
DROP TABLE IF EXISTS pdc_fase_perfil;
DROP TABLE IF EXISTS pdc_fase;
DROP TABLE IF EXISTS pdc;
DROP TABLE IF EXISTS evaluacion_trimestral;
DROP TABLE IF EXISTS evaluacion_actividad;

DELETE FROM schema_migrations WHERE version = '0007_pdc_structure';