PRAGMA foreign_keys = ON;

-- Tabla de bateria de conocimientos
CREATE TABLE IF NOT EXISTS conocimiento_bank (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  campo TEXT NOT NULL CHECK (
    campo IN (
      'cosmos_pensamiento',
      'comunidad_sociedad',
      'vida_tierra_territorio',
      'ciencia_tecnologia_produccion'
    )
  ),
  titulo TEXT NOT NULL, -- e.g., "Identidad personal, cultural, lingüística, mi nombre, mi familia y autoestima."
  nivel_sugerido TEXT,        -- ej: "Inicial 1", "Inicial 2"
  owner_id INTEGER,           -- user.id que lo creó
  school_id INTEGER,          -- opcional, para visibility por escuela
  visibility TEXT NOT NULL CHECK (visibility IN ('system','school','private')),
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Incisos de cada conocimiento describe un conocimiento específico
CREATE TABLE IF NOT EXISTS conocimiento_inciso (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  conocimiento_id INTEGER NOT NULL,
  contenido TEXT NOT NULL,        -- el inciso (ej: "Normas de convivencia (saludo, orden, pedir permiso)")
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (conocimiento_id) REFERENCES conocimiento_bank(id)
);

-- Tabla de bateria de perfiles, una bateria de perfiles resuelve un conocimiento
CREATE TABLE IF NOT EXISTS perfil_bank (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  conocimiento_inciso_id INTEGER NOT NULL,
  tipo TEXT NOT NULL CHECK (
    tipo IN ('socioafectivo','lenguaje','psicomotor','autonomia','cognitivo')
  ),
  FOREIGN KEY (conocimiento_inciso_id) REFERENCES conocimiento_inciso(id)
);

-- Incisos de cada perfil describe un aspecto específico del perfil
CREATE TABLE IF NOT EXISTS perfil_inciso (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  perfil_id INTEGER NOT NULL,
  contenido TEXT NOT NULL,         -- el inciso (ej: "Normas de convivencia: saludo, orden...")
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (perfil_id) REFERENCES perfil_bank(id)
);

-- Recursos o materiales
CREATE TABLE IF NOT EXISTS recurso_bank (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  resource_type TEXT,         -- materiales_vida | materiales_analogicos | materiales_produccion | etc.
  contenido TEXT
);


-- Tabla de bateria de actividades, cada actividad está vinculada a un aspecto especifico de perfil
CREATE TABLE IF NOT EXISTS actividad_bank (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  perfil_inciso_id INTEGER NOT NULL,
  contenido TEXT NOT NULL,         -- descripción de la actividad
  FOREIGN KEY (perfil_inciso_id) REFERENCES perfil_inciso(id)
);

-- Indicadores (rubricas / descriptors) corresponden a un perfil de salida
CREATE TABLE IF NOT EXISTS indicador_bank (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  perfil_inciso_id INTEGER,
  perfil_id INTEGER,
  dimension TEXT NOT NULL CHECK (dimension IN ('ser','saber','hacer')),
  measurement_type TEXT NOT NULL CHECK (measurement_type IN ('observacional','producto','actividad')),
  rubric JSON,                -- { "desarrollo_deficiente":"desc", "desarrollo_optimo":"desc"... }
  weight REAL DEFAULT 1.0,
  FOREIGN KEY (perfil_inciso_id) REFERENCES perfil_inciso(id),
  FOREIGN KEY (perfil_id) REFERENCES perfil_bank(id)
);


-- Registrar la migración
INSERT OR IGNORE INTO schema_migrations (version) VALUES ('0006_baterias_pedagogicas');
