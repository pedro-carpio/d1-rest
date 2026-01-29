PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS evaluacion_actividad (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER NOT NULL,
  curso_id INTEGER NOT NULL,
  actividad_id INTEGER NOT NULL,
  overall_ser REAL DEFAULT 0,
  overall_saber REAL DEFAULT 0,
  overall_hacer REAL DEFAULT 0,
  autoeval_score REAL DEFAULT 0,
  cosmos_comment TEXT,            -- comentario textual para campo COSMOS Y PENSAMIENTO
  comunidad_comment TEXT,         -- comentario textual para CAMPO COMUNIDAD Y SOCIEDAD
  vida_comment TEXT,              -- comentario textual para VIDA, TIERRA Y TERRITORIO
  ciencia_comment TEXT,           -- comentario textual para CIENCIA, TECNOLOGIA Y PRODUCCION
  general_comments TEXT,
  created_by_user_id INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (student_id) REFERENCES estudiante(id),
  FOREIGN KEY (curso_id) REFERENCES curso(id),
  FOREIGN KEY (actividad_id) REFERENCES actividad_bank(id),
  FOREIGN KEY (created_by_user_id) REFERENCES user_account(id)
);

CREATE TABLE IF NOT EXISTS evaluacion_trimestral (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  student_id INTEGER NOT NULL,
  curso_id INTEGER NOT NULL,
  conocimiento_id INTEGER NOT NULL,
  trimestre INTEGER NOT NULL,        -- 1 | 2 | 3
  overall_ser REAL DEFAULT 0,
  overall_saber REAL DEFAULT 0,
  overall_hacer REAL DEFAULT 0,
  autoeval_score REAL DEFAULT 0,
  cosmos_comment TEXT,            -- comentario textual para campo COSMOS Y PENSAMIENTO
  comunidad_comment TEXT,         -- comentario textual para CAMPO COMUNIDAD Y SOCIEDAD
  vida_comment TEXT,              -- comentario textual para VIDA, TIERRA Y TERRITORIO
  ciencia_comment TEXT,           -- comentario textual para CIENCIA, TECNOLOGIA Y PRODUCCION
  general_comments TEXT,
  created_by_user_id INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (student_id) REFERENCES estudiante(id),
  FOREIGN KEY (curso_id) REFERENCES curso(id),
  FOREIGN KEY (created_by_user_id) REFERENCES user_account(id)
);

CREATE TABLE IF NOT EXISTS pdc (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  curso_id INTEGER NOT NULL,
  unidad_educativa TEXT NOT NULL,
  distrito_educativo TEXT NOT NULL,
  maestro TEXT NOT NULL,
  director TEXT NOT NULL,
  nivel TEXT,                    -- e.g., "INICIAL EN FAMILIA COMUNITARIA"
  subtitulo TEXT,                -- e.g., "PLAN DE DESARROLLO CURRICULAR Nº 1"
  trimestre TEXT,                -- e.g., "Primer"
  objetivos_generales TEXT,
  fecha_inicio TEXT,
  fecha_fin TEXT,
  created_by_user_id INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (curso_id) REFERENCES curso(id),
  FOREIGN KEY (created_by_user_id) REFERENCES user_account(id)
);

-- Unidad del PDC: cada unidad se liga a un único "campo+area" (contenido) y a un único grupo de criterios
CREATE TABLE IF NOT EXISTS pdc_fase (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pdc_id INTEGER NOT NULL,
  periodo TEXT NOT NULL,                  -- e.g., "Semana 1-2", "Semana 1", "Mes 1", "Trimestre 1"
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (pdc_id) REFERENCES pdc(id)
);

CREATE TABLE IF NOT EXISTS pdc_fase_perfil (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pdc_fase_id INTEGER NOT NULL,
  perfil_id INTEGER NOT NULL,
  tipo TEXT NOT NULL CHECK (
    tipo IN ('socioafectivo','lenguaje','psicomotor','autonomia','cognitivo')
  ),
  FOREIGN KEY (pdc_fase_id) REFERENCES pdc_fase(id),
  FOREIGN KEY (perfil_id) REFERENCES perfil_bank(id)
);

CREATE TABLE IF NOT EXISTS pdc_fase_perfil_inciso (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pdc_fase_perfil_id INTEGER NOT NULL,
  perfil_inciso_id INTEGER NOT NULL,
  FOREIGN KEY (pdc_fase_perfil_id) REFERENCES pdc_fase_perfil(id),
  FOREIGN KEY (perfil_inciso_id) REFERENCES perfil_inciso(id)
);

CREATE TABLE IF NOT EXISTS pdc_fase_actividad (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pdc_fase_id INTEGER NOT NULL,
  actividad_id INTEGER NOT NULL,
  FOREIGN KEY (pdc_fase_id) REFERENCES pdc_fase(id),
  FOREIGN KEY (actividad_id) REFERENCES actividad_bank(id)
);

CREATE TABLE IF NOT EXISTS pdc_fase_recurso (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pdc_fase_id INTEGER NOT NULL,
  recurso_id INTEGER NOT NULL,
  FOREIGN KEY (pdc_fase_id) REFERENCES pdc_fase(id),
  FOREIGN KEY (recurso_id) REFERENCES recurso_bank(id)
);

CREATE TABLE IF NOT EXISTS pdc_indicador (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pdc_id INTEGER NOT NULL,
  indicador_id INTEGER NOT NULL,
  FOREIGN KEY (pdc_id) REFERENCES pdc(id),
  FOREIGN KEY (indicador_id) REFERENCES indicador_bank(id)
);

CREATE TABLE IF NOT EXISTS pdc_conocimiento (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pdc_id INTEGER NOT NULL,
  conocimiento_id INTEGER NOT NULL,
  FOREIGN KEY (pdc_id) REFERENCES pdc(id),
  FOREIGN KEY (conocimiento_id) REFERENCES conocimiento_bank(id)
);

INSERT INTO schema_migrations (version) VALUES ('0007_pdc_structure');