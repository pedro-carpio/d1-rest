PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS asistencia_incidencia (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  estudiante_id INTEGER NOT NULL,
  curso_id INTEGER NOT NULL,
  tipo TEXT NOT NULL, -- falta | retraso
  motivo TEXT,
  observaciones TEXT,
  turno TEXT CHECK(turno IN ('manana','tarde')),
  fecha TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (estudiante_id) REFERENCES estudiante(id),
  FOREIGN KEY (curso_id) REFERENCES curso(id)
);

CREATE TABLE IF NOT EXISTS incidencia (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  estudiante_id INTEGER NOT NULL,
  tipo TEXT,
  descripcion TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (estudiante_id) REFERENCES estudiante(id)
);

INSERT OR IGNORE INTO schema_migrations (version) VALUES ('0004_asistencia_e_incidencias');