-- ═══════════════════════════════════════════
--  BLNDR. — Schema D1
--  Ejecutar con: wrangler d1 execute blndr-db --file=schema.sql
-- ═══════════════════════════════════════════

CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT    NOT NULL,
  username      TEXT    NOT NULL UNIQUE,
  password_hash TEXT    NOT NULL,
  color         TEXT    NOT NULL DEFAULT '#c8ff00',
  avatar        TEXT    NOT NULL DEFAULT '🦋',
  created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS events (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type           TEXT    NOT NULL DEFAULT 'otro',   -- trabajo | estudio | juntada | otro
  description    TEXT    NOT NULL,
  date_start     TEXT,                              -- YYYY-MM-DD (para eventos puntuales)
  date_end       TEXT,                              -- YYYY-MM-DD (opcional)
  time_start     TEXT,                              -- HH:MM
  time_end       TEXT,                              -- HH:MM
  recurring_days TEXT    NOT NULL DEFAULT '[]',     -- JSON array: [0,1,2,3,4,5,6] (0=dom)
  location       TEXT,                              -- nombre del lugar
  lat            REAL,
  lng            REAL,
  created_at     TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id);
CREATE INDEX IF NOT EXISTS idx_events_date ON events(date_start);
