DROP TABLE IF EXISTS indicador_bank;
DROP TABLE IF EXISTS actividad_bank;
DROP TABLE IF EXISTS recurso_bank;
DROP TABLE IF EXISTS perfil_inciso;
DROP TABLE IF EXISTS perfil_bank;
DROP TABLE IF EXISTS conocimiento_inciso;
DROP TABLE IF EXISTS conocimiento_bank;


DELETE FROM schema_migrations WHERE version = '0006_baterias_pedagogicas';
