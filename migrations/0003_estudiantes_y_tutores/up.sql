-- migrations/0003_estudiantes_y_tutores/up.sql
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS estudiante (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  primer_apellido TEXT NOT NULL,
  segundo_apellido TEXT,
  nombres TEXT NOT NULL,
  sexo TEXT,
  rude TEXT,
  fecha_nacimiento TEXT,
  lugar_nacimiento TEXT,
  numero_carnet TEXT,
  fecha_inscripcion TEXT,
  estado TEXT DEFAULT 'activo',
  tiene_obs_salud INTEGER DEFAULT 0, -- booleano 0/1
  tiene_observaciones INTEGER DEFAULT 0,
  domicilio TEXT,
  curso_id INTEGER NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (curso_id) REFERENCES curso(id)
);

CREATE TABLE IF NOT EXISTS tutor (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  apellidos TEXT,
  nombres TEXT,
  ocupacion TEXT,
  relacion TEXT,
  telefono TEXT,
  domicilio TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS estudiante_tutor (
  estudiante_id INTEGER NOT NULL,
  tutor_id INTEGER NOT NULL,
  es_tutor_principal INTEGER DEFAULT 0,
  PRIMARY KEY (estudiante_id, tutor_id),
  FOREIGN KEY (estudiante_id) REFERENCES estudiante(id),
  FOREIGN KEY (tutor_id) REFERENCES tutor(id)
);

INSERT OR IGNORE INTO schema_migrations (version) VALUES ('0003_estudiantes_y_tutores');
