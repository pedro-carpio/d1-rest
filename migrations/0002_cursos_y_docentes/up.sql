PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS curso (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  unidad_educativa TEXT NOT NULL,
  distrito_educativo TEXT NOT NULL,
  director TEXT NOT NULL,
  nivel TEXT NOT NULL,        -- e.g., "INICIAL EN FAMILIA COMUNITARIA"
  seccion TEXT NOT NULL,      -- e.g., "SEGUNDO AÑO"
  gestion TEXT NOT NULL,     -- e.g., "2026"
  turno_manana INTEGER DEFAULT 0, -- 0/1 (boolean)
  turno_tarde INTEGER DEFAULT 0,
  docente_id INTEGER NOT NULL, -- referencia a user.id
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (docente_id) REFERENCES user_account(id)
);

INSERT OR IGNORE INTO schema_migrations (version) VALUES ('0002_cursos_y_docentes');
