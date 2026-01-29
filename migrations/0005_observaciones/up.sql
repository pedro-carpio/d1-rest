PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS observacion (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  estudiante_id INTEGER NOT NULL,
  observacion TEXT NOT NULL,
  es_salud INTEGER DEFAULT 0,  -- booleano: 0 = no, 1 = sí
  created_by_user_id INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (estudiante_id) REFERENCES estudiante(id),
  FOREIGN KEY (created_by_user_id) REFERENCES user_account(id)
);

-- registrar la migración
INSERT OR IGNORE INTO schema_migrations (version) VALUES ('0005_observaciones');
